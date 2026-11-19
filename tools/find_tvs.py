#!/usr/bin/env python3
"""Finds Google TV / Android TV devices that the dashboard could control, on your LAN and
over Tailscale.

Run this on the server (it has to be able to reach the TVs):

    python tools/find_tvs.py                          # this machine's /24 + your tailnet
    python tools/find_tvs.py --subnet 192.168.1.0/24  # name the LAN(s) yourself (repeatable)
    python tools/find_tvs.py --no-tailscale           # LAN only
    python tools/find_tvs.py --json                   # machine-readable

Networks searched:
  * LAN: every address of this machine's /24 (or each --subnet) is tried on port 6466,
    the Android TV Remote protocol port. TVs on the LAN are also looked for by mDNS
    ("_androidtvremote2._tcp") if `pip install zeroconf` is done.
  * Tailscale (uses `tailscale status --json`; skipped if tailscale isn't available): the
    tailnet itself is far too big to scan, so only what it names is tried - each online
    peer's own Tailscale address (a TV running the Tailscale app), and the subnets that
    peers advertise as routes (a TV on a remote LAN behind a subnet router).

For each TV it reports the network it was found on, whether the ADB port (5555) is open,
and - if androidtvremote2 is installed and a pairing certificate exists - whether this
machine is already paired with it, plus the model the TV reports.

It only reads. It never pairs and never sends a key. To use a TV, set TV_IP in .env to
its address and pair with `python tools/tv_remote_test.py pair`.
"""
import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import socket
import sys

REMOTE_PORT = 6466
ADB_PORT = 5555
MDNS_TYPE = "_androidtvremote2._tcp.local."
CERT_DIR = os.path.expanduser(os.environ.get("TV_CERT_DIR", "~/.config/dashboard-tv"))
TAILNET = ipaddress.ip_network("100.64.0.0/10")
MAX_SUBNET = 1024            # addresses per scanned subnet (a /22)
REMOTE_MIN_TIMEOUT = 1.5     # Tailscale paths can be relayed, so they get more time


def local_subnet() -> str:
    """The /24 around this machine's LAN address (the one used to reach the internet)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))      # UDP "connect" sends nothing; it only picks a route
            ip = s.getsockname()[0]
        except OSError:
            sys.exit("Could not work out this machine's LAN address - pass --subnet")
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def check_subnet(text: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as e:
        sys.exit(f"Bad --subnet: {e}")
    if net.version != 4 or net.num_addresses > MAX_SUBNET:
        sys.exit(f"{text}: pass an IPv4 subnet of /22 or smaller")
    return net


def hosts_of(net: ipaddress.IPv4Network) -> list:
    return [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]


async def tailscale_targets(notes: list) -> tuple:
    """(peer addresses, routed subnets) from `tailscale status --json`, each as (target, label)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "tailscale", "status", "--json",
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), 8)
        status = json.loads(out)
    except FileNotFoundError:
        notes.append("Tailscale skipped: the tailscale command isn't installed")
        return [], []
    except (asyncio.TimeoutError, ValueError, OSError):
        notes.append("Tailscale skipped: couldn't read `tailscale status --json` (is tailscaled running?)")
        return [], []

    peers, routes = [], []
    for peer in (status.get("Peer") or {}).values():
        if not peer.get("Online"):
            continue
        host = peer.get("HostName") or peer.get("DNSName") or "peer"
        for ip in peer.get("TailscaleIPs") or []:
            if ":" not in ip:
                peers.append((ip, f"tailscale: {host}"))
        for route in peer.get("PrimaryRoutes") or []:
            net = ipaddress.ip_network(route, strict=False)
            if net.version != 4 or net.prefixlen == 0 or net.subnet_of(TAILNET):
                continue                                    # exit-node default routes, IPv6, tailnet itself
            if net.num_addresses > MAX_SUBNET:
                notes.append(f"Tailscale route {route} (via {host}) is too large to scan; use --subnet with a smaller part of it")
                continue
            routes.append((net, f"tailscale route {route} via {host}"))
    return peers, routes


async def port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True


async def scan(targets: dict, port: int, base_timeout: float, concurrency: int = 128) -> list:
    """targets: ip -> label. LAN addresses use base_timeout, Tailscale ones get at least 1.5s."""
    sem = asyncio.Semaphore(concurrency)

    async def probe(ip: str):
        async with sem:
            return ip if await port_open(ip, port, timeout_for(targets[ip], base_timeout)) else None

    return [ip for ip in await asyncio.gather(*(probe(ip) for ip in targets)) if ip]


def timeout_for(label: str, base: float) -> float:
    return base if label.startswith("lan") else max(base, REMOTE_MIN_TIMEOUT)


async def mdns(seconds: float):
    """ip -> advertised name, or None if zeroconf is not installed."""
    try:
        from zeroconf import ServiceStateChange
        from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf
    except ImportError:
        return None
    found: dict = {}
    aiozc = AsyncZeroconf()

    def on_change(zeroconf, service_type, name, state_change):
        if state_change is not ServiceStateChange.Removed:
            asyncio.ensure_future(resolve(name))

    async def resolve(name: str):
        info = await aiozc.async_get_service_info(MDNS_TYPE, name, 2000)
        if info:
            for addr in info.parsed_addresses():
                if ":" not in addr:                         # IPv4 only
                    found[addr] = name.removesuffix("." + MDNS_TYPE)

    browser = AsyncServiceBrowser(aiozc.zeroconf, MDNS_TYPE, handlers=[on_change])
    await asyncio.sleep(seconds)
    await browser.async_cancel()
    await aiozc.async_close()
    return found


async def pairing_info(ip: str) -> dict:
    """Connects briefly with the existing certificate to see if this machine is paired."""
    cert, key = os.path.join(CERT_DIR, "cert.pem"), os.path.join(CERT_DIR, "key.pem")
    try:
        from androidtvremote2 import AndroidTVRemote, CannotConnect, ConnectionClosed, InvalidAuth
    except ImportError:
        return {"paired": None, "note": "androidtvremote2 not installed"}
    if not (os.path.isfile(cert) and os.path.isfile(key)):
        return {"paired": None, "note": f"no certificate in {CERT_DIR} yet"}
    remote = AndroidTVRemote("TV finder", cert, key, ip)
    try:
        await asyncio.wait_for(remote.async_connect(), 8)
    except InvalidAuth:
        return {"paired": False}
    except (CannotConnect, ConnectionClosed, asyncio.TimeoutError, OSError) as e:
        return {"paired": None, "note": f"could not connect ({type(e).__name__})"}
    try:
        info = remote.device_info or {}
        return {"paired": True, "model": " ".join(
            str(info[k]) for k in ("manufacturer", "model") if info.get(k)) or None}
    finally:
        remote.disconnect()


async def describe(ip: str, name, label: str, check_pairing: bool, base_timeout: float) -> dict:
    tv = {"ip": ip, "name": name, "network": label,
          "adb": await port_open(ip, ADB_PORT, timeout_for(label, base_timeout))}
    if check_pairing:
        tv.update(await pairing_info(ip))
    return tv


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subnet", action="append", metavar="CIDR",
                    help="LAN to scan, e.g. 192.168.1.0/24; repeat for more (default: this machine's /24)")
    ap.add_argument("--no-tailscale", action="store_true", help="don't look at the tailnet")
    ap.add_argument("--timeout", type=float, default=0.6,
                    help="seconds to wait per LAN address (default 0.6; Tailscale gets at least 1.5)")
    ap.add_argument("--no-mdns", action="store_true", help="skip the mDNS lookup")
    ap.add_argument("--no-pairing-check", action="store_true", help="don't connect to see if you are paired")
    ap.add_argument("--port", type=int, default=REMOTE_PORT, help=argparse.SUPPRESS)   # for testing
    ap.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = ap.parse_args()

    notes: list = []
    lan_nets = [check_subnet(c) for c in (args.subnet or [local_subnet()])]
    targets: dict = {}                       # ip -> label; the first label given to an address wins
    for net in lan_nets:
        for ip in hosts_of(net):
            targets.setdefault(ip, f"lan {net}")
    searched = [str(n) for n in lan_nets]

    if not args.no_tailscale:
        peers, routes = await tailscale_targets(notes)
        for ip, label in peers:
            targets.setdefault(ip, label)
        for net, label in routes:
            if any(net.overlaps(n) for n in lan_nets):
                continue                     # already covered as a LAN
            for ip in hosts_of(net):
                targets.setdefault(ip, label)
            searched.append(f"{net} (tailscale)")
        if peers:
            searched.append(f"{len(peers)} tailscale peer(s)")

    log = (lambda m: None) if args.json else (lambda m: print(m, file=sys.stderr))
    log(f"Checking {len(targets)} addresses for port {args.port}: {', '.join(searched)}"
        + ("" if args.no_mdns else " (+ mDNS on the LAN)") + " ...")

    names: dict = {}
    mdns_task = None if args.no_mdns else asyncio.create_task(mdns(4.0))
    ips = set(await scan(targets, args.port, args.timeout))
    if mdns_task:
        names = await mdns_task
        if names is None:
            names = {}
            notes.append("mDNS skipped: pip install zeroconf to also find LAN TVs by their announcement")
        else:
            for ip in names:
                if any(ipaddress.ip_address(ip) in n for n in lan_nets):
                    ips.add(ip)
                    targets.setdefault(ip, f"lan {lan_nets[0]}")

    tvs = sorted(await asyncio.gather(*(
        describe(ip, names.get(ip), targets[ip], not args.no_pairing_check, args.timeout) for ip in ips
    )), key=lambda t: ipaddress.ip_address(t["ip"]))

    if args.json:
        print(json.dumps({"searched": searched, "tvs": tvs, "notes": notes}, indent=2))
        return
    for n in notes:
        print(f"Note: {n}", file=sys.stderr)
    if not tvs:
        print("No TVs found. Check the TV is on (not just standby) and reachable from this machine, "
              "and use --subnet if the guessed LAN is wrong.")
        return
    print(f"{'ADDRESS':<16} {'NAME':<20} {'ADB':<5} {'PAIRED':<7} NETWORK")
    for t in tvs:
        paired = {True: "yes", False: "no", None: "?"}[t.get("paired")]
        print(f"{t['ip']:<16} {(t['name'] or '-'):<20} {'open' if t['adb'] else '-':<5} {paired:<7} {t['network']}")
        extra = t.get("model") or t.get("note")
        if extra:
            print(f"{'':<16} {extra}")
    print("\nTo use one: set TV_IP=<address> in .env, then pair with `python tools/tv_remote_test.py pair`.")


if __name__ == "__main__":
    asyncio.run(main())
