#!/usr/bin/env python3
"""Finds Google TV / Android TV devices that the dashboard could control, on your LAN and
over Tailscale.

Run this on the server (it has to be able to reach the TVs):

    python tools/find_tvs.py                          # this machine's LAN(s) + your tailnet
    python tools/find_tvs.py --subnet 192.168.1.0/24  # name the LAN(s) yourself (repeatable)
    python tools/find_tvs.py --no-tailscale           # LAN only
    python tools/find_tvs.py --json                   # machine-readable

The dashboard's TV Remote widget has a "Find TVs" button that does the same search and lets
you add what it finds; this command-line version is for checking from a terminal. See
tv_discovery.py for how the networks are searched.

For each TV it reports the network it was found on, whether the ADB port (5555) is open,
and - if androidtvremote2 is installed and a pairing certificate exists - whether this
machine is already paired with it, plus the model the TV reports.

It only reads. It never pairs and never sends a key.
"""
import argparse
import asyncio
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # repo root
import tv_discovery  # noqa: E402

CERT_DIR = os.path.expanduser(os.environ.get("TV_CERT_DIR", "~/.config/dashboard-tv"))


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


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subnet", action="append", metavar="CIDR",
                    help="LAN to scan, e.g. 192.168.1.0/24; repeat for more (default: the LAN(s) this machine is on)")
    ap.add_argument("--no-tailscale", action="store_true", help="don't look at the tailnet")
    ap.add_argument("--timeout", type=float, default=0.6,
                    help="seconds to wait per LAN address (default 0.6; Tailscale gets at least 1.5)")
    ap.add_argument("--no-mdns", action="store_true", help="skip the mDNS lookup")
    ap.add_argument("--no-pairing-check", action="store_true", help="don't connect to see if you are paired")
    ap.add_argument("--port", type=int, default=tv_discovery.REMOTE_PORT, help=argparse.SUPPRESS)   # for testing
    ap.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = ap.parse_args()

    if not args.json:
        print("Searching (a few seconds) ...", file=sys.stderr)
    try:
        result = await tv_discovery.discover(args.subnet, not args.no_tailscale, not args.no_mdns,
                                             args.port, args.timeout)
    except tv_discovery.DiscoveryError as e:
        sys.exit(str(e))
    tvs = result["tvs"]
    if not args.no_pairing_check:
        for tv, info in zip(tvs, await asyncio.gather(*(pairing_info(t["ip"]) for t in tvs)), strict=True):
            tv.update(info)

    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"Searched: {', '.join(result['searched'])}", file=sys.stderr)
    for n in result["notes"]:
        print(f"Note: {n}", file=sys.stderr)
    if not tvs:
        print("No TVs found. Check the TV is on (not just standby) and reachable from this machine, "
              "and use --subnet if the guessed LAN is wrong.")
        return
    print(f"{'ADDRESS':<16} {'NAME':<20} {'ADB':<5} {'PAIRED':<7} NETWORK")
    for t in sorted(tvs, key=lambda t: ipaddress.ip_address(t["ip"])):
        paired = {True: "yes", False: "no", None: "?"}[t.get("paired")]
        print(f"{t['ip']:<16} {(t['name'] or '-'):<20} {'open' if t['adb'] else '-':<5} {paired:<7} {t['network']}")
        extra = t.get("model") or t.get("note")
        if extra:
            print(f"{'':<16} {extra}")
    print("\nTo use one: add it from the dashboard's TV Remote widget (Find TVs).")


if __name__ == "__main__":
    asyncio.run(main())
