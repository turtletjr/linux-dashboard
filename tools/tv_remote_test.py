#!/usr/bin/env python3
"""Standalone prototype for controlling a Google TV / Android TV over the LAN.

Run this on the server (it needs to reach the TV), not from your laptop:

    pip install androidtvremote2
    python tools/tv_remote_test.py pair              # one-time, shows a code on the TV
    python tools/tv_remote_test.py status
    python tools/tv_remote_test.py key HOME
    python tools/tv_remote_test.py key DPAD_UP
    python tools/tv_remote_test.py key VOLUME_UP VOLUME_UP VOLUME_DOWN VOLUME_DOWN
    python tools/tv_remote_test.py --debug status     # log every protocol message
    python tools/tv_remote_test.py launch youtube

TV address comes from --host or the TV_IP environment variable. (The dashboard itself pairs TVs from its TV Remote widget; this tool is for doing it from a terminal.)
The pairing certificate is stored outside the repo (default ~/.config/dashboard-tv)
so it can never be committed. Override with TV_CERT_DIR.
"""
import argparse
import asyncio
import logging
import os
import sys

from androidtvremote2 import AndroidTVRemote, CannotConnect, ConnectionClosed, InvalidAuth

CERT_DIR = os.path.expanduser(os.environ.get("TV_CERT_DIR", "~/.config/dashboard-tv"))
CERT_FILE = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE = os.path.join(CERT_DIR, "key.pem")

# Friendly names -> deep links. Package IDs can vary by TV; `status` shows the
# package currently in the foreground, which is the easiest way to find one.
# Some TVs (the TCL this was built on) reject market:// and package links, so apps
# without a working link (e.g. Wholphin) are launched by the dashboard over ADB instead.
APPS = {
    "youtube": "https://www.youtube.com",
    "netflix": "https://www.netflix.com/title",
}


def make_remote(host: str) -> AndroidTVRemote:
    os.makedirs(CERT_DIR, mode=0o700, exist_ok=True)
    return AndroidTVRemote(f'{os.environ.get("DASHBOARD_NAME", "").strip() or "Server"} Dashboard', CERT_FILE, KEY_FILE, host)


async def pair(host: str) -> None:
    remote = make_remote(host)
    if await remote.async_generate_cert_if_missing():
        print(f"Generated a new client certificate in {CERT_DIR}")
    await remote.async_start_pairing()
    while True:
        code = input("Enter the code shown on the TV: ").strip()
        try:
            await remote.async_finish_pairing(code)
            break
        except InvalidAuth:
            print("Wrong code, try again.")
        except (CannotConnect, ConnectionClosed) as e:
            print(f"Pairing connection dropped ({e}); run `pair` again.")
            return
    print("Paired. You will not need to do this again unless the TV is reset.")


async def connected(host: str) -> AndroidTVRemote:
    remote = make_remote(host)
    await remote.async_generate_cert_if_missing()
    try:
        await remote.async_connect()
    except InvalidAuth:
        sys.exit("Not paired with this TV yet. Run: tv_remote_test.py pair")
    except CannotConnect as e:
        sys.exit(f"Could not reach the TV at {host}: {e}")
    return remote


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=os.environ.get("TV_IP"), help="TV IP address (or set TV_IP)")
    ap.add_argument("--debug", action="store_true", help="log protocol traffic to the terminal")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pair")
    sub.add_parser("status")
    k = sub.add_parser("key")
    k.add_argument("names", nargs="+", help="one or more of HOME, BACK, DPAD_UP, DPAD_CENTER, VOLUME_UP, MUTE, MEDIA_PLAY_PAUSE ...")
    launch = sub.add_parser("launch")
    launch.add_argument("app", help=f"one of {', '.join(APPS)} or a full deep link")
    args = ap.parse_args()
    if not args.host:
        sys.exit("No TV address: pass --host or set TV_IP")
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(name)s: %(message)s")

    if args.cmd == "pair":
        await pair(args.host)
        return

    remote = await connected(args.host)
    try:
        if args.cmd == "status":
            # app / volume / power updates arrive as separate messages shortly after
            # connecting, so give them a moment instead of reading them instantly.
            await asyncio.sleep(3)
            print("device:  ", remote.device_info)
            print("is_on:   ", remote.is_on)
            print("app:     ", remote.current_app)
            print("volume:  ", remote.volume_info)
        elif args.cmd == "key":
            for name in args.names:
                remote.send_key_command(name.upper(), "SHORT")
                print(f"sent {name.upper()}")
                await asyncio.sleep(0.6)
        elif args.cmd == "launch":
            remote.send_launch_app_command(APPS.get(args.app.lower(), args.app))
            print(f"launch requested: {args.app}")
        await asyncio.sleep(2)   # let commands flush and any error reply from the TV arrive
    finally:
        remote.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
