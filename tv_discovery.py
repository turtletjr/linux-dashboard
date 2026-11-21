"""Finds Google TV / Android TV devices on the LAN and over Tailscale.

Shared by the dashboard's "Find TVs" button and by `python tools/find_tvs.py`. Read-only:
it opens TCP connections and listens for mDNS announcements, nothing more.

  * LAN: every address of each LAN is tried on port 6466 (the Android TV Remote protocol
    port), and `_androidtvremote2._tcp` mDNS announcements are collected if the optional
    `zeroconf` package is installed. The LANs are the private addresses on this machine's
    real interfaces - never the route to the internet, which points at the tunnel when a
    VPN is up.
  * Tailscale: the tailnet is far too big to scan, so only what `tailscale status --json`
    names is tried - each online peer's own address, and the subnets peers advertise.
"""
import asyncio
import contextlib
import ipaddress
import json
import subprocess
from typing import Any, Dict, List, Optional, Tuple

REMOTE_PORT = 6466
ADB_PORT = 5555
MDNS_TYPE = "_androidtvremote2._tcp.local."
TAILNET = ipaddress.ip_network("100.64.0.0/10")
MAX_SUBNET = 1024            # addresses per scanned subnet (a /22)
REMOTE_MIN_TIMEOUT = 1.5     # Tailscale paths can be relayed, so they get more time
PRIVATE_RANGES = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
VIRTUAL_IFACE_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "tailscale", "wg", "tun", "tap",
                          "zt", "ppp", "ifb", "windscribe")


class DiscoveryError(Exception):
    """Something the caller can show to the user (bad subnet, no LAN found)."""


def local_subnets() -> List[str]:
    """The LAN(s) this machine is on: private (10/172.16/192.168) addresses on real interfaces.

    The route to the internet is deliberately not used: with a VPN up it points at the tunnel,
    not at your LAN. Tunnel interfaces and Tailscale/CGNAT addresses (100.64/10) are ignored."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope", "global"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    nets: List[ipaddress.IPv4Network] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet" or parts[1].startswith(VIRTUAL_IFACE_PREFIXES):
            continue
        iface = ipaddress.ip_interface(parts[3])
        if not any(iface.ip in r for r in PRIVATE_RANGES):
            continue
        net = iface.network if iface.network.prefixlen >= 22 else ipaddress.ip_network(f"{iface.ip}/24", strict=False)
        if net not in nets:
            nets.append(net)
    if not nets:
        raise DiscoveryError("Could not find this machine's LAN address - pass a subnet")
    return [str(n) for n in nets]


def check_subnet(text: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as e:
        raise DiscoveryError(f"Bad subnet: {e}") from None
    if net.version != 4 or net.num_addresses > MAX_SUBNET:
        raise DiscoveryError(f"{text}: use an IPv4 subnet of /22 or smaller")
    return net


def hosts_of(net: ipaddress.IPv4Network) -> List[str]:
    return [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]


async def tailscale_targets(notes: List[str]) -> Tuple[list, list]:
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
                notes.append(f"Tailscale route {route} (via {host}) is too large to scan; use a smaller subnet")
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


def timeout_for(label: str, base: float) -> float:
    return base if label.startswith("lan") else max(base, REMOTE_MIN_TIMEOUT)


async def scan(targets: Dict[str, str], port: int, base_timeout: float, concurrency: int = 128) -> List[str]:
    """targets: ip -> label. LAN addresses use base_timeout, Tailscale ones get at least 1.5s."""
    sem = asyncio.Semaphore(concurrency)

    async def probe(ip: str) -> Optional[str]:
        async with sem:
            return ip if await port_open(ip, port, timeout_for(targets[ip], base_timeout)) else None

    return [ip for ip in await asyncio.gather(*(probe(ip) for ip in targets)) if ip]


async def mdns(seconds: float) -> Optional[Dict[str, str]]:
    """ip -> advertised name, or None if zeroconf is not installed."""
    try:
        from zeroconf import ServiceStateChange
        from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf
    except ImportError:
        return None
    found: Dict[str, str] = {}
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
    try:
        await asyncio.sleep(seconds)
    finally:
        await browser.async_cancel()
        await aiozc.async_close()
    return found


async def discover(subnets: Optional[List[str]] = None, use_tailscale: bool = True, use_mdns: bool = True,
                   port: int = REMOTE_PORT, timeout: float = 0.6) -> Dict[str, Any]:
    """Returns {"searched": [...], "notes": [...], "tvs": [{ip, name, network, adb}]}."""
    notes: List[str] = []
    lan_nets = [check_subnet(c) for c in (subnets or local_subnets())]
    targets: Dict[str, str] = {}                 # ip -> label; the first label given to an address wins
    for net in lan_nets:
        for ip in hosts_of(net):
            targets.setdefault(ip, f"lan {net}")
    searched = [str(n) for n in lan_nets]

    if use_tailscale:
        peers, routes = await tailscale_targets(notes)
        for ip, label in peers:
            targets.setdefault(ip, label)
        for net, label in routes:
            if any(net.overlaps(n) for n in lan_nets):
                continue                         # already covered as a LAN
            for ip in hosts_of(net):
                targets.setdefault(ip, label)
            searched.append(f"{net} (tailscale)")
        if peers:
            searched.append(f"{len(peers)} tailscale peer(s)")

    names: Dict[str, str] = {}
    mdns_task = asyncio.create_task(mdns(4.0)) if use_mdns else None
    ips = set(await scan(targets, port, timeout))
    if mdns_task:
        found = await mdns_task
        if found is None:
            notes.append("mDNS skipped: pip install zeroconf to also find LAN TVs by their announcement")
        else:
            names = found
            for ip in names:
                if any(ipaddress.ip_address(ip) in n for n in lan_nets):
                    ips.add(ip)
                    targets.setdefault(ip, f"lan {lan_nets[0]}")

    adb = await asyncio.gather(*(port_open(ip, ADB_PORT, timeout_for(targets[ip], timeout)) for ip in ips))
    tvs = sorted(
        ({"ip": ip, "name": names.get(ip), "network": targets[ip], "adb": ok} for ip, ok in zip(ips, adb, strict=True)),
        key=lambda t: ipaddress.ip_address(t["ip"]),
    )
    return {"searched": searched, "notes": notes, "tvs": tvs}
