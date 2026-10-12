# GreenPlanet Dashboard

A self-hosted homelab dashboard for a single Linux server. FastAPI backend,
a single-page dark-themed frontend (Tailwind + Chart.js), live system
metrics pulled straight from `/proc`, and control panels for a handful of
common homelab services.

![status](https://img.shields.io/badge/status-homelab--use--only-orange)

> **⚠️ Before you deploy this: read [Security](#security) first.**
> The dashboard is protected by a single shared login (HTTP Basic Auth) —
> it is **not** a multi-user permissions system, and Basic Auth sends
> credentials unencrypted unless you're on HTTPS or a private network.
> This is written for a box that's only reachable over your LAN or a VPN
> like Tailscale — **do not expose it directly to the internet.**

---

## Table of contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration reference](#configuration-reference)
- [Running as a systemd service](#running-as-a-systemd-service)
- [Components](#components)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## What it does

The dashboard is one page, split into three columns:

- **Left** — hardware power controls, OS package updates, a live list of
  monitored systemd services, Pi-hole stats/controls, Pi-hole's own
  update checker.
- **Center** — CPU/RAM history chart, network + disk I/O history chart,
  per-core CPU + RAM + per-drive usage (used/free/total, whole-disk size,
  SMART health/temperature/life remaining, an Unmount button for
  non-system drives, and a Mount All button that mounts anything in
  `/etc/fstab` that isn't mounted yet), and a process
  monitor that flags processes hogging CPU or stuck in an uninterruptible
  (`D`) state, plus a media integrity checker that scans the media library
  for blank, truncated or corrupt video files on demand.
- **Right** — active Jellyfin streams with playback controls, public IP,
  WireGuard + Tailscale tunnel status, qBittorrent transfer stats.

Everything refreshes itself every 2–10 seconds depending on the widget — no
manual refresh needed.

## Architecture

```
main.py       FastAPI backend. Serves index.html and a set of JSON/websocket
              endpoints. Background asyncio tasks poll /proc, systemd, and
              a few third-party APIs on a loop and cache the results, so
              frontend polling is always answered from cache (fast, and
              doesn't hammer /proc or external services every request).

index.html    Single-file frontend. Tailwind CSS via CDN, Chart.js for the
              two history charts, vanilla JS (no build step) for polling
              and DOM updates.
```

Most system metrics (CPU%, RAM%, disk I/O, network throughput) are read
directly from `/proc` — no `psutil` dependency. Three integrations
(Jellyfin, Pi-hole, qBittorrent) talk to those services' own HTTP APIs
using credentials from `.env`.

## Prerequisites

- A Linux host (this reads `/proc`, and shells out to `systemctl`,
  `smartctl`, `wg`, `apt-get`, `kill`, `shutdown`, `mount`, `umount` — it will not run on
  macOS or Windows as-is)
- Python 3.9+
- `sudo` access for the user running the app (see
  [systemd/dashboard-sudoers.example](systemd/dashboard-sudoers.example))
- Optional, only if you want the relevant widget to populate:
  - A Jellyfin server with an API key
  - Pi-hole v6+ (uses the newer session-based API)
  - qBittorrent with the WebUI enabled
  - `smartmontools` installed (`smartctl`) for drive health
  - `ffprobe`/`ffmpeg` for the Media Integrity widget's *probe* and *full* modes
    (Jellyfin's bundled copy in `/usr/lib/jellyfin-ffmpeg` is found automatically)
  - WireGuard (`wg-quick@<tunnel>.service`) and/or Tailscale running
  - The `windscribe-switch` script at `/usr/local/bin/windscribe-switch`,
    with its `/etc/wireguard/locations/*.env` files already set up — this
    script is not included in this repo, see [Components](#components)

## Installation

```bash
# 1. Clone
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure
cp .env.example .env
nano .env                          # set DASHBOARD_USERNAME/PASSWORD + your real URLs/credentials
                                    # the app refuses all requests until the dashboard
                                    # username/password are set — see Security below

# 5. Set up sudo access for the commands the app needs
sudo cp systemd/dashboard-sudoers.example /etc/sudoers.d/dashboard
sudo nano /etc/sudoers.d/dashboard # replace <YOUR_USERNAME> with your actual user
sudo chmod 440 /etc/sudoers.d/dashboard
sudo visudo -c                     # validates syntax — fix anything it flags

# 6. Run it
uvicorn main:app --host 0.0.0.0 --port 8000
```

Visit `http://<server-ip>:8000` — you should see the dashboard. Widgets for
services you haven't configured yet will just show "Offline" or `--`
rather than erroring.

For anything beyond a quick test, see
[Running as a systemd service](#running-as-a-systemd-service) below so it
survives reboots and terminal closes.

## Configuration reference

All configuration lives in `.env` (copy from `.env.example` — never commit
the real `.env`, it's already covered by `.gitignore`).

| Variable | Default | Required for |
|---|---|---|
| `DASHBOARD_USERNAME` | *(empty)* | Logging into the dashboard at all — see [Security](#security) |
| `DASHBOARD_PASSWORD` | *(empty)* | same |
| `JELLYFIN_URL` | `http://192.168.1.10:8096` | Active Streams widget, subtitle toggle |
| `JELLYFIN_API_KEY` | *(empty)* | same — generate one in Jellyfin under Dashboard → API Keys |
| `PIHOLE_URL` | `http://192.168.1.10/api` | Network Protection + Pi-hole Updates widgets |
| `PIHOLE_PASSWORD` | *(empty)* | same — your Pi-hole admin password |
| `QBITTORRENT_URL` | `http://192.168.1.10:8080` | BitTorrent Engine widget |
| `QBITTORRENT_USERNAME` | `admin` | same |
| `QBITTORRENT_PASSWORD` | *(empty)* | same — enable the WebUI in qBittorrent's settings first |
| `MEDIA_LIBRARY` | `/mnt/Media` | Media Integrity widget — folder to scan |
| `MEDIA_REPORT` | `~/bad_media_files.txt` | same — where the report is written (must be outside the library) |
| `MEDIA_CHECK_SCRIPT` | `check_media_headers.sh` next to `main.py` | same |

Missing `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD` is treated differently: the
app fails closed and returns a `500` on every request until both are set,
rather than just logging a warning — see [Security](#security).

The app also prints a `[Config Warning]` to stdout/logs on startup listing
any of `JELLYFIN_API_KEY`, `PIHOLE_PASSWORD`, `QBITTORRENT_PASSWORD` that
are still blank, so a misconfigured integration fails loud instead of
silently returning empty widgets.

A few things are currently hardcoded in `main.py` rather than pulled from
`.env` — worth editing directly if they don't match your setup:

- `SERVICES_TO_MONITOR` — the list of systemd units shown in "Core Services
  Daemon" and available to the Process Monitor's "Restart" action
  (defaults to Jellyfin, Pi-hole FTL, qBittorrent, a WireGuard tunnel named
  `windscribe`, and Tailscale)
- The network interface used for throughput stats (defaults to `eth0`,
  falls back to auto-detecting the first non-loopback interface)
- `HIGH_CPU_THRESHOLD` / `HANG_SUSTAIN_CYCLES` and similar process-monitor
  tuning constants

## Running as a systemd service

A template unit file is at
[systemd/dashboard.service.example](systemd/dashboard.service.example).

```bash
sudo cp systemd/dashboard.service.example /etc/systemd/system/dashboard.service
sudo nano /etc/systemd/system/dashboard.service   # fill in <PLACEHOLDER> values
sudo systemctl daemon-reload
sudo systemctl enable --now dashboard
```

Two things that commonly trip people up:

- **`ExecStart` must point at the venv's `uvicorn`**, not the system
  Python — otherwise the service won't see your installed dependencies.
- **`WorkingDirectory` must be the project directory** — `.env` is loaded
  relative to the process's current working directory, so if this is
  wrong the app silently falls back to empty config.

Check it's running and pulling `.env` correctly:

```bash
sudo systemctl status dashboard
sudo journalctl -u dashboard -n 200 | grep -i "Config Warning"   # should be empty
```

## Components

| Widget | Backend source | Notes |
|---|---|---|
| System Compute Timeline / Hardware | `/proc/stat`, `/proc/meminfo`, `/sys/class/thermal` | Per-core CPU computed from tick deltas between polls |
| I/O Throughput | `/proc/net/dev` equivalent via interface stats, `/proc/diskstats` | |
| Disk usage / SMART health | `/proc/mounts` + `statvfs`, `/sys/block` for whole-disk size, `smartctl -j` | Background loop polls every 30s so `smartctl` (slow, needs sudo) isn't run per-request. SATA, USB-bridged and NVMe drives are supported; drives that are spun down are skipped (last known values kept) so polling doesn't wake them — see `SMART_SKIP_STANDBY` in `main.py`. A drive that reports no SMART data shows `N/A`, never a false `OK`. |
| Drive Unmount | `POST /api/control/unmount` → `sudo umount` | Plain (never forced) unmount, only for mount points currently in `/proc/mounts`. System mounts (`/`, `/boot/firmware`, `/home`, …) are refused server-side. Fails with "target is busy" if a service still has files open on the drive. To bring drives back, use **Mount All** (below). |
| Drive Mount All | `POST /api/control/mount-all` → `sudo mount -a` | Mounts every `/etc/fstab` entry that isn't mounted yet (skips `noauto`), so unmounted drives reappear as cards. The widget lists which fstab drives are currently unmounted (and flags ones that aren't plugged in), and highlights the button when there's something it can mount. Safe to click with everything already mounted. Only mounts what's already in fstab — the dashboard can't mount arbitrary devices. |
| Process Monitor | `/proc/[pid]/stat`, `/status`, `/cmdline` | Flags sustained ≥80% CPU or `D`-state processes; can terminate/kill any listed PID, or `systemctl restart` if it maps to a monitored service |
| Core Services Daemon | `systemctl is-active` | Start/stop/restart any service in `SERVICES_TO_MONITOR` |
| Hardware Controls | `shutdown` | Reboot / shutdown the host |
| Package Manager | `apt-get -s upgrade` / `apt-get upgrade -y` | Debian/Ubuntu-specific |
| Network Protection (Pi-hole) | Pi-hole v6 API (`/api/dns/blocking`, `/api/stats/...`) | Enable/disable blocking, timed disable, top blocked domains |
| Pi-hole Updates | `pihole -v` (parsed) + `pihole -up` | |
| Active Streams (Jellyfin) | Jellyfin `/Sessions` API | Play/pause, stop, toggle English subtitles. Poster art is proxied through the dashboard (`/api/jellyfin/poster/<id>`, using `JELLYFIN_URL`), so your browser only needs to reach the dashboard, not Jellyfin directly. |
| Tunnel Routing Topology | `wg show <tunnel> dump`, `tailscale status --json` | |
| Windscribe Location Switcher | `windscribe-switch` — a bash script at `/usr/local/bin/windscribe-switch` (not part of this repo) | Switches between pre-configured Windscribe WireGuard locations, with handshake verification and automatic revert if the new location fails to connect. This app only shells out to it — see the script's own header comment for the expected `/etc/wireguard/locations/*.env` layout. |
| Media Integrity | `check_media_headers.sh` (in this repo) via `POST /api/media/check`, `POST /api/media/cancel`, `GET /api/media/status` | Read-only scan for blank, truncated or corrupt video files. Three modes: *header* (first bytes only, fast), *probe* (`ffprobe` reads every packet — reads the whole drive) and *full* (`ffmpeg` decodes everything — very slow on a Pi). Runs as one background job at a time, at low CPU/disk priority, with a progress bar and a Cancel button. Results come from the script's report file and survive a dashboard restart; **Re-check listed** re-tests only the files from the last report. Refuses to run when the library isn't mounted, so an unmounted drive can't produce a false "clean". It never modifies, moves or deletes media. |
| BitTorrent Engine | qBittorrent WebUI API (`/api/v2/...`) | Session-cookie auth, cached and re-authenticated on expiry |

## Security

**The dashboard requires a login (HTTP Basic Auth) before anything loads.**
Set `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD` in `.env` — the app
refuses every request (fails closed) until both are set, so there's no way
to accidentally run it unauthenticated. Your browser will show its native
login prompt on first visit and remember the credentials for the rest of
the browser session.

A few things worth understanding about that setup:

- **Basic Auth sends credentials on every request**, base64-encoded (not
  encrypted) in the `Authorization` header. That's fine over HTTPS or a
  private network (Tailscale, WireGuard, your LAN); it's **not** fine over
  plain HTTP on an untrusted network. Don't put this behind a public IP
  without TLS in front of it.
- **There's intentionally no CORS policy** (see `main.py` — no
  `CORSMiddleware`). Since the frontend and API are served from the same
  origin, cross-origin access isn't needed, and a permissive CORS policy
  combined with Basic Auth would let any other website in your browser
  ride your cached dashboard credentials. If you ever build a separate
  client that needs to call this API from another origin, add
  `CORSMiddleware` back with an explicit, narrow `allow_origins` — never
  `"*"`.
- This is single-user auth, not a permissions system — anyone with the
  credentials has full control (reboot, kill processes, package upgrades,
  everything). Don't share the login the way you might a Jellyfin account.

Beyond the login itself:

- Don't port-forward the dashboard or expose it to the public internet,
  even with auth in place — treat it the same as you would SSH or a router
  admin panel: LAN-only, or behind Tailscale/WireGuard.
- If you do need remote access, a reverse proxy with TLS
  (Caddy/nginx + Let's Encrypt, or Tailscale Serve/Funnel) sits well in
  front of this.

Secrets (`DASHBOARD_PASSWORD`, `JELLYFIN_API_KEY`, `PIHOLE_PASSWORD`,
`QBITTORRENT_PASSWORD`) live in `.env`, which is gitignored. If this repo
was ever committed *before* `.gitignore` was in place, those secrets are in
your git history even after adding `.gitignore` now — check with
`git log --all --full-history -- .env` and rotate/scrub if so.

Sudo access is scoped per-command in
[systemd/dashboard-sudoers.example](systemd/dashboard-sudoers.example)
rather than granting the app broad root access — still, `sudo systemctl`
and `sudo kill` are powerful primitives, so this is defense-in-depth
alongside the login, not a replacement for it.

## Troubleshooting

**Every request returns a 500 with "Dashboard authentication is not configured"**
`DASHBOARD_USERNAME` and/or `DASHBOARD_PASSWORD` are blank or missing from
`.env`. This is intentional — the app fails closed rather than running
unauthenticated. Set both and restart.

**Browser keeps re-prompting for login / 401 after entering credentials**
Double-check for trailing whitespace or mismatched values between what
you're typing and what's in `.env` — comparison is exact and
case-sensitive. If you changed `DASHBOARD_PASSWORD` after already logging
in once, your browser may be resending the old cached credentials; a hard
refresh or clearing that site's saved credentials fixes it.

**A widget shows `--` or "Offline" forever**
Check `sudo journalctl -u dashboard -f` while reloading the page — most
integration failures print an exception message there (e.g. Jellyfin
auth failure, Pi-hole session errors).

**`[Config Warning] Missing environment variables` in the logs**
`.env` either isn't present in `WorkingDirectory`, or one of the required
values is still blank. Confirm the path with `pwd` from inside the
systemd unit's `WorkingDirectory`.

**Power/service/process controls return a 500 error**
Almost always a sudoers issue — the command isn't in
`/etc/sudoers.d/dashboard`, or the path in that file doesn't match the
binary's actual location (`which smartctl`, `which wg`, etc. to confirm).

**Unmount says "target is busy"**
Something still has files open on that drive (Jellyfin, qBittorrent, Samba, a shell `cd`'d into it). Stop it first, or find the culprit with `sudo lsof +f -- /mnt/<drive>`. The dashboard deliberately never force-unmounts.

**Mount All fails or only mounts some drives**
The alert shows `mount`'s own error. Check `sudo mount -a` on the server for the full picture. An NTFS drive that wasn't unmounted cleanly (power loss) can be refused as a dirty volume — run chkdsk on it from Windows, or as a last resort `sudo ntfsfix -d /dev/sdXN`. A drive that isn't plugged in is listed as "not connected" and can't be mounted until it is.

**SMART shows N/A for a drive**
USB enclosures often don't pass SMART through; try `sudo smartctl -a -d sat /dev/sdX` manually. Drives that are asleep keep their last known values rather than being woken up.

**SMART data never populates**
`smartmontools` isn't installed, or the device paths returned by
`smartctl --scan -j` don't match your actual drives — check
`sudo smartctl --scan -j` manually.

**qBittorrent/Pi-hole show "Offline" but the services are clearly running**
Double check `QBITTORRENT_URL`/`PIHOLE_URL` in `.env` match the actual
host/port, and that the WebUI (qBittorrent) or API (Pi-hole) is reachable
from wherever the dashboard process runs — not just from your browser.

**Windscribe location dropdown is empty or shows "Failed to load"**
Confirm `windscribe-switch` is actually at `/usr/local/bin/windscribe-switch`
and the sudoers entry for it is in place (`sudo -l` as the dashboard's user
should list it). Test the script directly first —
`sudo windscribe-switch list` — before assuming it's a dashboard issue.

**Switching Windscribe location times out or reports "unknown state"**
The script's own handshake wait plus a possible auto-revert can take close
to 30 seconds in the worst case. If it's consistently timing out, check
`sudo windscribe-switch status` directly on the server — the tunnel may be
stuck mid-transition and need a manual `sudo windscribe-switch down`.

## License

[MIT](LICENSE)
