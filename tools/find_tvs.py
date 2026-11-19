#!/usr/bin/env python3
"""Finds Google TV / Android TV devices on the LAN that the dashboard could control.

Run this on the server (it has to be on the same network as the TVs):

    python tools/find_tvs.py                       # scan this machine's /24
    python tools/find_tvs.py --subnet 192.168.1.0/24
    python tools/find_tvs.py --json                # machine-readable

Two methods are combined, and a TV found by either is listed:
  * mDNS: Android TVs announce "_androidtvremote2._tcp" while they are on. Needs
    `pip install zeroconf`; skipped (with a note) if it is not installed.
  * Port scan: every address in the subnet is tried on port 6466, the Android TV
    Remote protocol port. Needs nothing extra.

For each TV it also reports whether the ADB port (5555) is open, and - if
androidtvremote2 is installed and a pairing certificate exists - whether this
machine is already paired with it, plus the model the TV reports.

It only reads. It never pairs and never sends a key. To use a TV, set TV_IP in .env
to its address and pair with `python tools/tv_remote_test.py pair`.
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


def local_subnet() -> str:
    """The /24 around this machine's LAN address (the one used to reach the internet)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))      # UDP "connect" sends nothing; it only picks a route
            ip = s.getsockname()[0]
        except OSError:
            sys.exit("Could not work out this machine's LAN address - pass --subnet")
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


async def port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True


async def scan(hosts, port: int, timeout: float, concurrency: int = 128) -> list:
    sem = asyncio.Semaphore(concurrency)

    async def probe(ip: str):
        async with sem:
            return ip if await port_open(ip, port, timeout) else None

    return [ip for ip in await asyncio.gather(*(probe(str(h)) for h in hosts)) if ip]


async def mdns(seconds: float) -> dict:
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


async def describe(ip: str, name, check_pairing: bool, timeout: float) -> dict:
    tv = {"ip": ip, "name": name, "adb": await port_open(ip, ADB_PORT, timeout)}
    if check_pairing:
        tv.update(await pairing_info(ip))
    return tv


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subnet", help="network to scan, e.g. 192.168.1.0/24 (default: this machine's /24)")
    ap.add_argument("--timeout", type=float, default=0.6, help="seconds to wait per address (default 0.6)")
    ap.add_argument("--no-mdns", action="store_true", help="skip the mDNS lookup")
    ap.add_argument("--no-pairing-check", action="store_true", help="don't connect to see if you are paired")
    ap.add_argument("--port", type=int, default=REMOTE_PORT, help=argparse.SUPPRESS)   # for testing
    ap.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = ap.parse_args()

    try:
        net = ipaddress.ip_network(args.subnet or local_subnet(), strict=False)
    except ValueError as e:
        sys.exit(f"Bad --subnet: {e}")
    if net.version != 4 or net.num_addresses > 1024:
        sys.exit("Pass an IPv4 subnet of /22 or smaller")

    notes = []
    log = (lambda m: None) if args.json else (lambda m: print(m, file=sys.stderr))
    log(f"Scanning {net} for port {args.port}" + ("" if args.no_mdns else " and listening for mDNS") + " ...")

    names: dict = {}
    mdns_task = None if args.no_mdns else asyncio.create_task(mdns(4.0))
    ips = set(await scan(net.hosts() if net.num_addresses > 1 else [net.network_address], args.port, args.timeout))
    if mdns_task:
        names = await mdns_task
        if names is None:
            names = {}
            notes.append("mDNS skipped: pip install zeroconf to also find TVs by their announcement")
        else:
            ips |= {ip for ip in names if ipaddress.ip_address(ip) in net}

    tvs = sorted(await asyncio.gather(*(
        describe(ip, names.get(ip), not args.no_pairing_check, args.timeout) for ip in ips
    )), key=lambda t: ipaddress.ip_address(t["ip"]))

    if args.json:
        print(json.dumps({"subnet": str(net), "tvs": tvs, "notes": notes}, indent=2))
        return
    for n in notes:
        print(f"Note: {n}", file=sys.stderr)
    if not tvs:
        print("No TVs found. Check the TV is on (not just standby), on the same network, "
              "and try --subnet if the guessed network is wrong.")
        return
    print(f"{'ADDRESS':<16} {'NAME':<24} {'ADB':<5} PAIRED")
    for t in tvs:
        paired = {True: "yes", False: "no", None: "?"}[t.get("paired")]
        extra = t.get("model") or t.get("note") or ""
        print(f"{t['ip']:<16} {(t['name'] or '-'):<24} {'open' if t['adb'] else '-':<5} {paired}  {extra}")
    print("\nTo use one: set TV_IP=<address> in .env, then pair with `python tools/tv_remote_test.py pair`.")


if __name__ == "__main__":
    asyncio.run(main())
