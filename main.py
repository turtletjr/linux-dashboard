import asyncio
import collections
import json
import os
import secrets
import time
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, BackgroundTasks, APIRouter, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from dotenv import load_dotenv
import httpx
import subprocess
import re
import ipaddress

load_dotenv()  # reads .env in the working directory, if present

# --- Auth ---
# Every route in this app is gated behind HTTP Basic Auth (see the
# FastAPI(dependencies=...) below). The browser handles the login prompt
# and caches credentials per-origin for the session — no custom login page
# or cookie/session management needed for a single-user homelab tool.
DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")

if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD:
    print("[SECURITY WARNING] DASHBOARD_USERNAME and/or DASHBOARD_PASSWORD are not "
          "set in .env. Every request to this app will be rejected until both are "
          "set — see .env.example. This app has no other access control.")

security = HTTPBasic()

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """Global auth dependency, applied to every route via FastAPI(dependencies=...).
    Fails closed: if DASHBOARD_USERNAME/PASSWORD aren't configured, every request
    is rejected rather than silently running unauthenticated."""
    if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD:
        raise HTTPException(
            status_code=500,
            detail="Dashboard authentication is not configured. Set DASHBOARD_USERNAME "
                   "and DASHBOARD_PASSWORD in .env — see .env.example."
        )
    # secrets.compare_digest: constant-time comparison so response timing can't
    # be used to guess characters of the username/password one at a time.
    username_ok = secrets.compare_digest(credentials.username, DASHBOARD_USERNAME)
    password_ok = secrets.compare_digest(credentials.password, DASHBOARD_PASSWORD)
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

app = FastAPI(title="GreenPlanet Server Engine", dependencies=[Depends(verify_credentials)])
router = APIRouter()

# No CORS middleware: the frontend is served by this same app (same origin),
# so cross-origin access isn't needed. This matters more than usual here
# because browsers cache Basic Auth credentials per-origin and attach them
# automatically to matching requests from any page — a permissive CORS
# policy (e.g. allow_origins=["*"]) would let any other site open in your
# browser silently ride those cached credentials against this API. If you
# ever need cross-origin access, add CORSMiddleware back with an explicit,
# narrow allow_origins list — never "*" combined with credentials.

# --- GLOBAL CACHES FOR BACKGROUND METRICS ---
disk_smart_cache: Dict[str, Any] = {}
network_speed_cache: Dict[str, Any] = {
    "down": "0 B/s", "up": "0 B/s", 
    "down_kbps": 0.0, "up_kbps": 0.0
}
disk_io_cache: Dict[str, Any] = {"read_kbps": 0.0, "write_kbps": 0.0}
public_ip_cache: str = "--"
qb_session_cookie: str = ""

# Status + telemetry for the SERVICES_TO_MONITOR systemd units, plus WireGuard,
# Tailscale, qBittorrent, and Jellyfin. All of this used to be fetched live on
# every /api/dashboard/metrics request (subprocess spawns for `systemctl
# is-active` / `wg show` / `tailscale status`, plus Jellyfin HTTP calls) — that
# meant up to 5 subprocess forks + 4 HTTP requests every 2s, multiplied by
# however many browser tabs had the dashboard open. A single shared background
# loop (update_service_telemetry_loop, below) now populates these caches once
# per TELEMETRY_POLL_INTERVAL regardless of how many clients are polling, and
# /api/dashboard/services reads from the same service_status_cache instead of
# re-running `systemctl is-active` on its own overlapping timer.
service_status_cache: Dict[str, str] = {}
wireguard_cache: Dict[str, Any] = {
    "status": "inactive", "handshake": "--", "endpoint": "--",
    "transfer_rx": "0 B", "transfer_tx": "0 B"
}
tailscale_cache: Dict[str, Any] = {
    "status": "inactive", "node_ip": "--", "active_peers": 0, "exit_node_active": False
}
qbittorrent_cache: Dict[str, Any] = {
    "status": "inactive", "active_torrents": 0, "dl_speed": "0 B/s", "ul_speed": "0 B/s"
}
jellyfin_cache: Dict[str, Any] = {"version": "v--", "playing": []}
TELEMETRY_POLL_INTERVAL = 3  # seconds between service-status / tunnel / qBittorrent / Jellyfin refreshes

pihole_update_cache: dict = {
    "core": {"current": "Unknown", "latest": "Unknown", "update_available": False},
    "web": {"current": "Unknown", "latest": "Unknown", "update_available": False},
    "ftl": {"current": "Unknown", "latest": "Unknown", "update_available": False},
    "has_updates": False
}

# --- External Request Map (Pi-hole allowed domains, geolocated) ---
# Pi-hole doesn't record the resolved IP for a query, only the domain, so this
# resolves each top domain ourselves and geolocates the resulting public IP via
# ip-api.com's free batch endpoint (no key, up to 100 IPs per call, counts as a
# single request against its 45 req/min limit). geoip_cache is keyed by IP and
# never expires within the process lifetime — a given IP's location essentially
# never changes, so there's no reason to re-look it up every cycle, only for
# genuinely new IPs. external_requests_cache is what /api/telemetry/pihole/geomap
# actually serves.
geoip_cache: Dict[str, Dict[str, Any]] = {}
external_requests_cache: List[Dict[str, Any]] = []
GEOMAP_POLL_INTERVAL = 300     # 5 min — this hits Pi-hole's stats API and (for new
                                # IPs only) ip-api.com, neither of which needs to be
                                # polled anywhere near as often as live telemetry
GEOMAP_MAX_DOMAINS = 40        # cap on distinct top domains resolved+geolocated per
                                # cycle — bounds DNS lookups and keeps the ip-api.com
                                # batch comfortably within its free-tier limits
# Domains under these suffixes are never going to resolve to a public, mappable
# address (mDNS, router/NAS admin UIs, RFC 6762/8375/7788 special-use names) —
# skip resolving them entirely rather than eating a DNS timeout for each one.
GEOMAP_SKIP_SUFFIXES = (".local", ".lan", ".home", ".internal", ".home.arpa")

# Global state to keep track of CPU core tick deltas and disk I/O
prev_cpu_cores_ticks: Dict[str, List[float]] = {}
prev_disk_io_ticks: Dict[str, Any] = {"time": 0.0, "read_sectors": 0, "write_sectors": 0}

# --- Process monitoring ---
# "High CPU" = sustained usage at/above this percent across several consecutive
# samples (avoids flagging brief legitimate spikes).
HIGH_CPU_THRESHOLD = 80.0
HIGH_CPU_SUSTAIN_CYCLES = 2
# "Hanging" here means stuck in uninterruptible sleep (D state) — the classic
# Linux signal of a process blocked on I/O that isn't coming back — across
# several consecutive samples. This is a heuristic, not a guarantee.
HANG_STATE_CHAR = "D"
HANG_SUSTAIN_CYCLES = 5
PROCESS_POLL_INTERVAL = 3  # seconds between /proc samples
PROCESS_LIST_LIMIT = 20    # rows returned to the frontend

process_cache: List[Dict[str, Any]] = []
_process_prev_ticks: Dict[int, Dict[str, float]] = {}
_process_streaks: Dict[int, Dict[str, int]] = {}
_CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

# get_service_main_pids() shells out to `systemctl show -p MainPID` once per
# monitored service (5 subprocess spawns as currently configured). Main PIDs
# only change when a service restarts, so re-resolving them every single
# PROCESS_POLL_INTERVAL cycle (every 3s) is wasted work — refresh on a longer
# cadence instead and reuse the cached map in between.
_service_pid_cache: Dict[int, str] = {}
_service_pid_cycle_count = 0
SERVICE_PID_REFRESH_CYCLES = 10  # ~30s at the default PROCESS_POLL_INTERVAL

# Live Services Monitored
SERVICES_TO_MONITOR = [
    "jellyfin",
    "pihole-FTL",
    "qbittorrent",
    "wg-quick@windscribe",
    "tailscaled",
    "smbd"
]

# windscribe-switch (github location: /usr/local/bin/windscribe-switch) —
# a separately-maintained bash script that switches Windscribe WireGuard
# locations via a shared template + per-location .env files, with handshake
# verification and auto-revert on failure. This app shells out to it; it
# does not reimplement any of that logic.
WINDSCRIBE_SWITCH_BIN = "/usr/local/bin/windscribe-switch"
WINDSCRIBE_LOCATION_RE = re.compile(r'^[A-Za-z0-9_-]+$')

# --- Package manager ---
APT_LOG_LINES = 30
APT_FLAGS = ["-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]
APT_ENV = {**os.environ, "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"}  # C locale: output parsing below is English-only

package_state: Dict[str, Any] = {
    "status": "idle",              # idle | checking | running
    "operation": None,             # upgrade | full-upgrade | autoremove (while running)
    "progress": 0,
    "phase": "",
    "current_package": "",
    "log_tail": [],
    "available_packages": 0,
    "packages": [],
    "kept_back": [],               # packages plain `upgrade` refuses to touch
    "full_upgrade_removes": [],    # what full-upgrade WOULD remove (only computed if kept_back)
    "autoremove": [],              # what autoremove WOULD remove
    "reboot_required": False,
    "last_checked": "Never",
    "last_result": None,
}
_apt_lock = asyncio.Lock()         # apt/dpkg allow one operation at a time
_background_tasks: set = set()

def parse_apt_simulation(text: str):
    installs, removes, kept_back = [], [], []
    in_kept = False
    for line in text.splitlines():
        if line.startswith("The following packages have been kept back"):
            in_kept = True
            continue
        if in_kept:
            if line.startswith("  "):
                kept_back.extend(line.split())
                continue
            in_kept = False
        if line.startswith("Inst "):
            parts = line.split()
            if len(parts) >= 4:
                installs.append({
                    "name": parts[1],
                    "old_version": parts[2].strip("[]") if parts[2].startswith("[") else "N/A",
                    "new_version": parts[3].strip("()") if parts[3].startswith("(") else parts[2].strip("()"),
                })
        elif line.startswith("Remv "):
            parts = line.split()
            removes.append({"name": parts[1], "version": parts[2].strip("[]") if len(parts) > 2 else ""})
    return installs, removes, kept_back

async def simulate_apt(operation: str):
    proc = await asyncio.create_subprocess_exec(
        "apt-get", "-s", operation,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=APT_ENV
    )
    stdout, _ = await proc.communicate()
    return parse_apt_simulation(stdout.decode(errors="replace"))

async def refresh_package_lists(update_index: bool):
    if update_index:
        p = await asyncio.create_subprocess_exec(
            "sudo", "apt-get", "update", "-y",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await p.wait()
    installs, _, kept_back = await simulate_apt("upgrade")
    _, autoremovable, _ = await simulate_apt("autoremove")
    fu_removes = []
    if kept_back:
        _, fu_removes, _ = await simulate_apt("full-upgrade")
    package_state.update(
        packages=installs, available_packages=len(installs), kept_back=kept_back,
        full_upgrade_removes=fu_removes, autoremove=autoremovable,
        reboot_required=os.path.exists("/var/run/reboot-required"),
        last_checked=time.strftime("%H:%M:%S"),
    )

async def run_apt_operation(operation: str):
    log = collections.deque(maxlen=APT_LOG_LINES)
    package_state.update(status="running", operation=operation, progress=0,
                         phase="starting", current_package="", log_tail=[])
    try:
        installs, removes, _ = await simulate_apt(operation)
        total = len(removes) if operation == "autoremove" else len(installs)

        proc = await asyncio.create_subprocess_exec(
            "sudo", "apt-get", *APT_FLAGS, operation,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=APT_ENV
        )
        gets = unpacked = configured = removed = 0
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            if not line:
                continue
            log.append(line)
            if line.startswith("Get:"):
                gets += 1; package_state["phase"] = "downloading"
            elif line.startswith("Unpacking "):
                unpacked += 1; package_state["phase"] = "unpacking"
                package_state["current_package"] = line.split()[1]
            elif line.startswith("Setting up "):
                configured += 1; package_state["phase"] = "configuring"
                package_state["current_package"] = line.split()[2]
            elif line.startswith("Removing "):
                removed += 1; package_state["phase"] = "removing"
                package_state["current_package"] = line.split()[1]
            if total:
                # upgrade: each package passes through download, unpack, configure (3 steps)
                done, steps = (removed, total) if operation == "autoremove" else (gets + unpacked + configured, total * 3)
                package_state["progress"] = min(99, int(done / steps * 100))
            package_state["log_tail"] = list(log)

        rc = await proc.wait()
        package_state["last_result"] = {
            "operation": operation, "success": rc == 0, "returncode": rc,
            "finished_at": time.strftime("%H:%M:%S"),
        }
        package_state["progress"] = 100 if rc == 0 else package_state["progress"]
        await refresh_package_lists(update_index=False)
    except Exception as e:
        print(f"[Package Operation Exception]: {e}")
        package_state["last_result"] = {"operation": operation, "success": False,
                                        "returncode": -1, "finished_at": time.strftime("%H:%M:%S")}
    finally:
        package_state.update(status="idle", operation=None, phase="", current_package="")

async def _run_and_release(operation: str):
    try:
        await run_apt_operation(operation)
    finally:
        _apt_lock.release()

class PackageOperation(BaseModel):
    operation: str  # "upgrade" | "full-upgrade" | "autoremove"

# Config Details — populated from environment variables (see .env.example)
JELLYFIN_URL = os.environ.get("JELLYFIN_URL", "http://192.168.1.10:8096")
JELLYFIN_API_KEY = os.environ.get("JELLYFIN_API_KEY", "")
PIHOLE_URL = os.environ.get("PIHOLE_URL", "http://192.168.1.10/api")
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")
QBITTORRENT_URL = os.environ.get("QBITTORRENT_URL", "http://192.168.1.10:8080")
QBITTORRENT_USERNAME = os.environ.get("QBITTORRENT_USERNAME", "admin")
QBITTORRENT_PASSWORD = os.environ.get("QBITTORRENT_PASSWORD", "")

REQUIRED_ENV_VARS = ["JELLYFIN_API_KEY", "PIHOLE_PASSWORD", "QBITTORRENT_PASSWORD"]
_missing_env = [v for v in REQUIRED_ENV_VARS if not os.environ.get(v)]
if _missing_env:
    print(f"[Config Warning] Missing environment variables: {', '.join(_missing_env)}. "
          f"Set them in a .env file — see .env.example. Related integrations will fail until then.")

# Torrent states that count as "active" (i.e. not paused/idle)
QB_INACTIVE_STATES = {"pausedUP", "pausedDL"}

class PowerAction(BaseModel):
    action: str

class ServiceAction(BaseModel):
    service: str
    action: str

class ProcessAction(BaseModel):
    pid: int
    action: str  # "terminate" | "kill" | "restart_service"

class PiholeAction(BaseModel):
    action: str
    duration: int = 0

class JellyfinCommand(BaseModel):
    session_id: str
    command: str

class SubtitleToggleRequest(BaseModel):
    session_id: str

class WindscribeSwitchRequest(BaseModel):
    location: str

@app.get("/")
async def serve_dashboard_frontend():
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    elif os.path.exists("index.html"):
        return FileResponse("index.html")
    raise HTTPException(status_code=404, detail="index.html file not found.")

# --- LIVE SYSTEM UTILITIES ---

def get_system_uptime() -> str:
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        days = int(uptime_seconds // (24 * 3600))
        hours = int((uptime_seconds % (24 * 3600)) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
    except Exception:
        return "0d 00:00:00"

def get_cpu_temperature() -> str:
    for zone in ["thermal_zone0", "hwmon0/temp1_input"]:
        path = f"/sys/class/thermal/{zone}/temp"
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    temp_raw = int(f.read().strip())
                return str(round(temp_raw / 1000))
            except Exception:
                continue
    return "0"

async def get_pihole_sid(client: httpx.AsyncClient) -> str:
    """Helper to authenticate with Pi-hole v6 API and return a session ID."""
    try:
        res = await client.post(
            f"{PIHOLE_URL}/auth",
            json={"password": PIHOLE_PASSWORD},
            timeout=2.0
        )
        if res.status_code == 200:
            return res.json().get("session", {}).get("sid", "")
    except Exception:
        pass
    return ""

def is_mappable_public_ip(ip_str: str) -> bool:
    """True only for a routable public address — excludes private/LAN
    (RFC1918), loopback, link-local, CGNAT, and other reserved/multicast
    ranges, none of which ip-api.com can (or should) geolocate."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
    )

async def resolve_domain_to_ip(domain: str, timeout: float = 1.5) -> str:
    """Resolve a domain's first A/AAAA address. Runs the (blocking) stdlib
    resolver in a thread via getaddrinfo's own async form so one slow/hung
    domain can't stall the whole geomap cycle. Returns '' on any failure —
    NXDOMAIN, timeout, or a domain that only resolves internally."""
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(domain, None, family=0, type=0), timeout=timeout
        )
        for info in infos:
            candidate = info[4][0]
            if is_mappable_public_ip(candidate):
                return candidate
    except Exception:
        pass
    return ""

async def geolocate_ips(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """Batch-geolocate IPs via ip-api.com's free /batch endpoint (HTTP only on
    the free tier — no key, up to 100 queries per call, one call = one request
    against its 45 req/min limit). Results merge into and are returned from
    geoip_cache; already-cached IPs aren't re-sent."""
    to_lookup = [ip for ip in ips if ip not in geoip_cache]
    if not to_lookup:
        return geoip_cache

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.post(
                "http://ip-api.com/batch?fields=status,country,city,lat,lon,query",
                json=[{"query": ip} for ip in to_lookup[:100]]
            )
            if res.status_code == 200:
                for entry in res.json():
                    ip = entry.get("query")
                    if ip and entry.get("status") == "success":
                        geoip_cache[ip] = {
                            "country": entry.get("country", "Unknown"),
                            "city": entry.get("city", ""),
                            "lat": entry.get("lat"),
                            "lon": entry.get("lon"),
                        }
    except Exception:
        pass
    return geoip_cache

async def get_cpu_ram_payload():
    global prev_cpu_cores_ticks
    try:
        # 1. Accurate RAM Percentage via MemAvailable
        with open('/proc/meminfo', 'r') as f:
            lines = f.readlines()
        
        mem_data = {}
        for line in lines:
            parts = line.split()
            if parts:
                mem_data[parts[0].replace(':', '')] = int(parts[1])
        
        total = mem_data.get("MemTotal", 0)
        available = mem_data.get("MemAvailable", 0)
        
        if total > 0 and available > 0:
            used = total - available
            # 1 decimal place — on an idle system, whole-percent rounding can
            # make this look frozen even though it's being recalculated live
            # every poll; the underlying value does move, just by <1%.
            ram_percent = round((used / total) * 100, 1)
        else:
            free = mem_data.get("MemFree", 0)
            buffers = mem_data.get("Buffers", 0)
            cached = mem_data.get("Cached", 0)
            sreclaimable = mem_data.get("SReclaimable", 0)
            used = total - free - buffers - cached - sreclaimable
            ram_percent = round((used / total) * 100, 1) if total > 0 else 0
        
        # 2. Per-Core & Overall CPU Utilization
        with open('/proc/stat', 'r') as f:
            stat_lines = f.readlines()
        
        current_cpu_ticks = {}
        for line in stat_lines:
            if line.startswith('cpu'):
                parts = line.strip().split()
                cpu_id = parts[0]
                ticks = [float(x) for x in parts[1:]]
                current_cpu_ticks[cpu_id] = ticks

        per_core_percentages = []
        overall_cpu = 0

        if prev_cpu_cores_ticks:
            for cpu_id, fields2 in current_cpu_ticks.items():
                if cpu_id in prev_cpu_cores_ticks:
                    fields1 = prev_cpu_cores_ticks[cpu_id]
                    idle1, idle2 = fields1[3] + fields1[4], fields2[3] + fields2[4]
                    total1, total2 = sum(fields1), sum(fields2)
                    
                    idle_delta = idle2 - idle1
                    total_delta = total2 - total1
                    
                    usage = round(((total_delta - idle_delta) / total_delta) * 100) if total_delta > 0 else 0
                    
                    if cpu_id == "cpu":
                        overall_cpu = usage
                    else:
                        core_label = f"Core {cpu_id.replace('cpu', '')}"
                        per_core_percentages.append({"core": core_label, "percent": usage})

        prev_cpu_cores_ticks = current_cpu_ticks
        return overall_cpu, ram_percent, per_core_percentages

    except Exception:
        return 0, 0, []

def get_whole_disk_names() -> set:
    """/sys/block lists exactly the whole-disk block devices on the system —
    never partitions — regardless of naming scheme (sd*, nvme*, mmcblk*, vd*,
    etc). This is the canonical way to distinguish a whole disk from a
    partition; pattern-matching on the device name (e.g. 'ends in a letter')
    breaks for nvme/mmcblk, where the whole-disk name itself ends in a digit
    (nvme0n1, mmcblk0)."""
    try:
        return set(os.listdir("/sys/block"))
    except Exception:
        return set()

def resolve_parent_disk(device_path: str) -> str:
    """Resolve a block device (partition or whole disk) to its whole-disk
    device name, via sysfs. A whole disk (sda, nvme0n1, mmcblk0) is detected
    by membership in /sys/block and returned as-is; a partition resolves via
    /sys/class/block/<part> -> .../block/<parent>/<part>, so the parent dir's
    name is the whole-disk name. The parent is only trusted if it really is
    in /sys/block (the old version returned bogus names like '/dev/0:0:0:0'
    for whole-disk devices). Symlinks such as /dev/disk/by-uuid/... and
    /dev/mapper/... are resolved first. Falls back to digit-stripping."""
    try:
        real_dev = os.path.realpath(device_path)
    except Exception:
        real_dev = device_path
    dev_name = os.path.basename(real_dev)
    whole_disks = get_whole_disk_names()
    if dev_name in whole_disks:
        return f"/dev/{dev_name}"
    try:
        real_path = os.path.realpath(f"/sys/class/block/{dev_name}")
        parent_name = os.path.basename(os.path.dirname(real_path))
        if parent_name in whole_disks:
            return f"/dev/{parent_name}"
    except Exception:
        pass
    # Fallback: old heuristic, kept only as a last resort
    return "/dev/" + "".join(c for c in dev_name if not c.isdigit())

# --- Mounted-drive helpers (sizes + mount/unmount) ---
# Mount points the dashboard will never offer to unmount (and the unmount
# endpoint refuses outright, regardless of what the frontend sends).
PROTECTED_MOUNTS = {
    "/", "/boot", "/boot/firmware", "/boot/efi", "/home", "/usr", "/var",
    "/etc", "/opt", "/srv", "/tmp", "/root",
}
UNMOUNT_TIMEOUT = 20.0
MOUNT_ALL_TIMEOUT = 60.0   # NTFS/USB drives can take a while (journal replay etc.)
# Serializes mount/unmount operations so a double-click (or two browser tabs)
# can't run `mount -a` and `umount` against each other.
_mount_lock = asyncio.Lock()

_FSTAB_BY_DIR = {"UUID": "uuid", "LABEL": "label", "PARTUUID": "partuuid", "PARTLABEL": "partlabel"}

def fstab_device_present(spec: str) -> bool:
    """Is the device behind an fstab source (UUID=..., LABEL=..., /dev/...)
    actually plugged in right now? Lets the UI tell 'unmounted, can be
    mounted' apart from 'unmounted because the drive isn't connected'."""
    if spec.startswith("/dev/"):
        return os.path.exists(spec)
    kind, _, value = spec.partition("=")
    sub = _FSTAB_BY_DIR.get(kind)
    value = value.strip('"')
    if not sub or not value:
        return False
    if sub in ("label", "partlabel") and not re.fullmatch(r"[\w.-]+", value):
        return True   # udev escapes odd characters in by-label names; don't guess wrong
    try:
        names = os.listdir(f"/dev/disk/by-{sub}")
    except OSError:
        return False
    return value.lower() in (n.lower() for n in names)

def read_unmounted_fstab_drives(mounted_points: set, fstab_path: str = "/etc/fstab") -> List[Dict[str, Any]]:
    """/etc/fstab entries backed by a real block device that aren't mounted
    right now — i.e. exactly what `mount -a` would try to mount. Skips swap,
    pseudo filesystems, and `noauto` entries (which `mount -a` skips too)."""
    result: List[Dict[str, Any]] = []
    try:
        with open(fstab_path, "r") as f:
            lines = f.readlines()
    except OSError:
        return result
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        spec = _unescape_mount_field(parts[0])
        mount_point = _unescape_mount_field(parts[1])
        fstype = parts[2]
        options = parts[3].split(",") if len(parts) > 3 else []
        if not spec.startswith(("UUID=", "LABEL=", "PARTUUID=", "PARTLABEL=", "/dev/")):
            continue
        if fstype in ("swap", "none") or not mount_point.startswith("/"):
            continue
        if "noauto" in options or mount_point in mounted_points:
            continue
        result.append({
            "mount_point": mount_point,
            "fstype": fstype,
            "present": fstab_device_present(spec),
        })
    return result

def _unescape_mount_field(value: str) -> str:
    """/proc/mounts octal-escapes spaces/tabs/newlines/backslashes (\\040 etc.)."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)

def read_mounts() -> List[Dict[str, str]]:
    """Real block-device mounts from /proc/mounts, de-duplicated by mount
    point (a later entry stacked on the same path wins, matching what's
    actually visible). Skips loop devices and pseudo/snap filesystems."""
    by_path: Dict[str, Dict[str, str]] = {}
    with open("/proc/mounts", "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            device = _unescape_mount_field(parts[0])
            mount_point = _unescape_mount_field(parts[1])
            fstype = parts[2]
            if not device.startswith("/dev/") or device.startswith("/dev/loop"):
                continue
            if fstype in ("devtmpfs", "tmpfs", "squashfs"):
                continue
            by_path[mount_point] = {"device": device, "mount_point": mount_point, "fstype": fstype}
    return list(by_path.values())

def get_fs_usage(path: str):
    """(total, used, free) in bytes using statvfs, computed the way `df` does:
    free = space available to unprivileged users, percent = used/(used+avail).
    shutil.disk_usage divides by raw total, which under-reports usage on
    filesystems with reserved blocks (ext4's default 5%)."""
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    return total, used, free

def get_whole_disk_size_bytes(base_drive: str) -> int:
    """Size of the entire physical disk (not just the mounted partition),
    from /sys/block/<disk>/size, which is always in 512-byte sectors."""
    try:
        with open(f"/sys/block/{os.path.basename(base_drive)}/size", "r") as f:
            return int(f.read().strip()) * 512
    except Exception:
        return 0

def lookup_smart(base_drive: str) -> Dict[str, Any]:
    """Find cached SMART data for a whole-disk device. smartctl names NVMe
    devices by controller (/dev/nvme0) while /proc/mounts and sysfs use the
    namespace (/dev/nvme0n1), so try both."""
    empty = {"healthy": None, "temperature": None, "life": None}
    if base_drive in disk_smart_cache:
        return disk_smart_cache[base_drive]
    m = re.match(r"^(/dev/nvme\d+)n\d+$", base_drive)
    if m and m.group(1) in disk_smart_cache:
        return disk_smart_cache[m.group(1)]
    return empty

async def run_windscribe_switch(*args: str, timeout: float = 10.0):
    """Runs the windscribe-switch script with sudo, capturing combined
    stdout+stderr (the script writes its warning/revert messages to stderr,
    and we want those visible either way). Raises asyncio.TimeoutError if
    the script hangs past `timeout` — the caller decides how to handle that
    per-command, since 'up' legitimately needs longer than 'list'/'status'
    (handshake wait, possible auto-revert with a second handshake wait)."""
    proc = await asyncio.create_subprocess_exec(
        "sudo", WINDSCRIBE_SWITCH_BIN, *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise
    return proc.returncode, stdout.decode(errors="replace")

async def check_service_status(service_name: str) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "systemctl", "is-active", service_name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        status = stdout.decode().strip()
        return "active" if status == "active" else "inactive"
    except Exception:
        return "inactive"

def read_process_stat(pid: int):
    """Parse /proc/[pid]/stat. comm is bracketed by the first '(' and last ')'
    since process names can themselves contain spaces or parentheses."""
    with open(f"/proc/{pid}/stat", "r") as f:
        raw = f.read()
    lparen = raw.find("(")
    rparen = raw.rfind(")")
    comm = raw[lparen + 1:rparen]
    fields = raw[rparen + 2:].split()
    state = fields[0]
    utime = float(fields[11])
    stime = float(fields[12])
    return comm, state, utime, stime

def get_process_rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return 0

def get_process_cmdline(pid: int, fallback: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
        parts = [p.decode(errors="replace") for p in raw.split(b"\x00") if p]
        return " ".join(parts) if parts else fallback
    except Exception:
        return fallback

async def get_service_main_pids() -> Dict[int, str]:
    """Map PID -> service name for each monitored systemd unit, so the process
    monitor can offer a real 'restart service' action instead of a raw kill."""
    mapping: Dict[int, str] = {}
    for service in SERVICES_TO_MONITOR:
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "show", "-p", "MainPID", "--value", service,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            pid_str = stdout.decode().strip()
            if pid_str and pid_str != "0":
                mapping[int(pid_str)] = service
        except Exception:
            continue
    return mapping

def format_speed(bytes_per_sec: float) -> str:
    if bytes_per_sec < 1024:
        return f"{bytes_per_sec:.0f} B/s"
    elif bytes_per_sec < 1024 * 1024:
        return f"{bytes_per_sec / 1024:.1f} KB/s"
    return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"

async def qbittorrent_login(client: httpx.AsyncClient) -> str:
    """Authenticate with the qBittorrent WebUI API and return the SID cookie, or '' on failure."""
    try:
        res = await client.post(
            f"{QBITTORRENT_URL}/api/v2/auth/login",
            data={"username": QBITTORRENT_USERNAME, "password": QBITTORRENT_PASSWORD},
            headers={"Referer": QBITTORRENT_URL},
            timeout=2.5
        )
        if res.status_code == 200 and res.text.strip() == "Ok.":
            return res.cookies.get("SID", "")
    except Exception:
        pass
    return ""

async def get_qbittorrent_payload() -> Dict[str, Any]:
    """Fetch active torrent count and transfer speeds from qBittorrent's WebUI API.
    Re-authenticates automatically if the cached session cookie has expired."""
    global qb_session_cookie
    result = {"active_torrents": 0, "dl_speed": "0 B/s", "ul_speed": "0 B/s"}
    headers = {"Referer": QBITTORRENT_URL}

    async with httpx.AsyncClient(timeout=2.5) as client:
        for _ in range(2):  # one retry after a fresh login
            cookies = {"SID": qb_session_cookie} if qb_session_cookie else {}
            try:
                transfer_res = await client.get(f"{QBITTORRENT_URL}/api/v2/transfer/info", cookies=cookies, headers=headers)
                torrents_res = await client.get(f"{QBITTORRENT_URL}/api/v2/torrents/info", cookies=cookies, headers=headers)

                if transfer_res.status_code == 403 or torrents_res.status_code == 403:
                    qb_session_cookie = await qbittorrent_login(client)
                    if not qb_session_cookie:
                        break
                    continue  # retry the fetch with the fresh cookie

                if transfer_res.status_code == 200:
                    transfer_data = transfer_res.json()
                    result["dl_speed"] = format_speed(transfer_data.get("dl_info_speed", 0))
                    result["ul_speed"] = format_speed(transfer_data.get("up_info_speed", 0))

                if torrents_res.status_code == 200:
                    torrents = torrents_res.json()
                    result["active_torrents"] = sum(
                        1 for t in torrents if t.get("state") not in QB_INACTIVE_STATES
                    )
                break
            except Exception:
                break

    return result

# --- ASYNC BACKGROUND METRICS LOOPS ---

async def update_pihole_versions_loop():
    global pihole_update_cache
    while True:
        try:
            # Run the pihole version command
            process = await asyncio.create_subprocess_exec(
                "pihole", "-v",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            output = stdout.decode()

            def parse_component(text, keywords):
                for line in text.split('\n'):
                    if any(k.lower() in line.lower() for k in keywords):
                        # Extracts current and latest versions from string: "v5.18.2 (Latest: v5.18.2)"
                        match = re.search(r"v([0-9\.\-]+).*?Latest:.*?v([0-9\.\-]+)", line, re.IGNORECASE)
                        if match:
                            current = match.group(1).strip()
                            latest = match.group(2).strip()
                            return {"current": current, "latest": latest, "update_available": current != latest}
                return {"current": "Unknown", "latest": "Unknown", "update_available": False}

            core_data = parse_component(output, ["Pi-hole", "Core"])
            web_data = parse_component(output, ["AdminLTE", "Web"])
            ftl_data = parse_component(output, ["FTL"])
            
            has_updates = core_data["update_available"] or web_data["update_available"] or ftl_data["update_available"]
            
            pihole_update_cache = {
                "core": core_data,
                "web": web_data,
                "ftl": ftl_data,
                "has_updates": has_updates
            }
        except Exception:
            pass
            
        await asyncio.sleep(3600) # Check hourly

async def update_external_requests_map_loop():
    """Populates external_requests_cache for the External Request Map widget.
    Pulls Pi-hole's already-aggregated top *allowed* domains (blocked domains
    never actually got contacted, so they're not a "where did we go" signal),
    resolves each to a public IP ourselves (Pi-hole doesn't record the
    resolved address), and geolocates via geolocate_ips(). Domains that fail
    to resolve, resolve only to a private/local address, or geolocation
    misses for, are silently dropped from that cycle's points."""
    global external_requests_cache
    while True:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                sid = await get_pihole_sid(client)
                if sid:
                    res = await client.get(
                        f"{PIHOLE_URL}/stats/top_domains?blocked=false&count={GEOMAP_MAX_DOMAINS}",
                        headers={"X-FTL-SID": sid}
                    )
                    top_domains = (
                        {d["domain"]: d["count"] for d in res.json().get("domains", [])}
                        if res.status_code == 200 else {}
                    )
                    try:
                        await client.delete(f"{PIHOLE_URL}/auth", headers={"X-FTL-SID": sid})
                    except Exception:
                        pass
                else:
                    top_domains = {}

            domain_hits = {
                d: hits for d, hits in top_domains.items()
                if not d.lower().endswith(GEOMAP_SKIP_SUFFIXES)
            }

            # Resolve all candidate domains concurrently rather than one at a
            # time — with a 1.5s timeout each, a serial loop over 40 domains
            # could take up to a minute; concurrently it's bounded by the
            # single slowest lookup.
            domains = list(domain_hits.keys())
            resolved = await asyncio.gather(*(resolve_domain_to_ip(d) for d in domains))
            domain_to_ip = {d: ip for d, ip in zip(domains, resolved) if ip}

            if domain_to_ip:
                geo = await geolocate_ips(list(set(domain_to_ip.values())))
            else:
                geo = {}

            points = []
            for domain, ip in domain_to_ip.items():
                loc = geo.get(ip)
                if not loc or loc.get("lat") is None or loc.get("lon") is None:
                    continue
                points.append({
                    "domain": domain,
                    "ip": ip,
                    "country": loc["country"],
                    "city": loc["city"],
                    "lat": loc["lat"],
                    "lon": loc["lon"],
                    "hits": domain_hits.get(domain, 0)
                })

            external_requests_cache = points
        except Exception as e:
            print(f"[External Request Map Loop Exception]: {str(e)}")

        await asyncio.sleep(GEOMAP_POLL_INTERVAL)

async def fetch_public_ip() -> str:
    """Fetches the current public IP on demand — no longer runs on a timer.
    Called only when the frontend's Refresh button is clicked."""
    global public_ip_cache
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get("https://api.ipify.org?format=json")
            if res.status_code == 200:
                public_ip_cache = res.json().get("ip", "Unknown")
            else:
                public_ip_cache = "Unavailable"
    except Exception:
        public_ip_cache = "Unavailable"
    return public_ip_cache

VIRTUAL_IFACE_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "tailscale", "wg", "tun", "tap", "zt", "ppp", "ifb")

def pick_network_interface(preferred: str = "eth0") -> str:
    """Pick a real, physical network interface to measure throughput on.
    Prefers `preferred` if it exists. Otherwise scans /sys/class/net,
    skipping loopback and known virtual/tunnel interfaces (VPNs, docker,
    veth, etc.) by name, and preferring ones with a real sysfs 'device'
    symlink (present for physical NICs, absent for virtual ones) — so this
    doesn't accidentally lock onto a Tailscale or WireGuard tunnel instead
    of the actual NIC just because it happened to sort first."""
    if os.path.exists(f"/sys/class/net/{preferred}/statistics/rx_bytes"):
        return preferred
    try:
        candidates = [i for i in sorted(os.listdir("/sys/class/net/"))
                      if not i.startswith(VIRTUAL_IFACE_PREFIXES)]
        # Prefer interfaces with a real hardware backing (physical NICs)
        for iface in candidates:
            if os.path.exists(f"/sys/class/net/{iface}/device"):
                return iface
        # Fall back to the first non-virtual name, if nothing had a device symlink
        if candidates:
            return candidates[0]
    except Exception:
        pass
    return preferred  # last resort — same as the old default behavior

async def update_network_speeds_loop():
    global network_speed_cache
    interface = pick_network_interface("eth0")
    
    def format_bytes(bytes_val):
        if bytes_val < 1024: return f"{bytes_val} B/s"
        elif bytes_val < 1024 * 1024: return f"{bytes_val/1024:.1f} KB/s"
        return f"{bytes_val/(1024*1024):.1f} MB/s"

    while True:
        try:
            path_rx = f"/sys/class/net/{interface}/statistics/rx_bytes"
            path_tx = f"/sys/class/net/{interface}/statistics/tx_bytes"
            
            if not os.path.exists(path_rx):
                # Interface disappeared (renamed, unplugged, etc.) — re-pick
                interface = pick_network_interface("eth0")
                path_rx = f"/sys/class/net/{interface}/statistics/rx_bytes"
                path_tx = f"/sys/class/net/{interface}/statistics/tx_bytes"

            with open(path_rx, 'r') as f: rx_start = int(f.read().strip())
            with open(path_tx, 'r') as f: tx_start = int(f.read().strip())
            await asyncio.sleep(2)
            with open(path_rx, 'r') as f: rx_end = int(f.read().strip())
            with open(path_tx, 'r') as f: tx_end = int(f.read().strip())
            
            rx_rate = (rx_end - rx_start) / 2
            tx_rate = (tx_end - tx_start) / 2

            network_speed_cache = {
                "down": format_bytes(rx_rate),
                "up": format_bytes(tx_rate),
                "down_kbps": round(rx_rate / 1024, 1),
                "up_kbps": round(tx_rate / 1024, 1)
            }
        except Exception:
            await asyncio.sleep(2)

async def update_disk_io_loop():
    global disk_io_cache, prev_disk_io_ticks
    while True:
        try:
            now = time.time()
            total_read_sectors = 0
            total_write_sectors = 0
            whole_disks = get_whole_disk_names()

            with open('/proc/diskstats', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 14:
                        dev_name = parts[2]
                        if dev_name in whole_disks and not dev_name.startswith("loop") and not dev_name.startswith("zram"):
                            total_read_sectors += int(parts[5])
                            total_write_sectors += int(parts[9])

            if prev_disk_io_ticks["time"] > 0:
                elapsed = now - prev_disk_io_ticks["time"]
                if elapsed > 0:
                    read_delta = total_read_sectors - prev_disk_io_ticks["read_sectors"]
                    write_delta = total_write_sectors - prev_disk_io_ticks["write_sectors"]
                    
                    read_kbps = round((read_delta * 0.5) / elapsed, 1)
                    write_kbps = round((write_delta * 0.5) / elapsed, 1)

                    disk_io_cache = {
                        "read_kbps": max(0.0, read_kbps),
                        "write_kbps": max(0.0, write_kbps)
                    }

            prev_disk_io_ticks = {
                "time": now,
                "read_sectors": total_read_sectors,
                "write_sectors": total_write_sectors
            }
        except Exception:
            pass
        await asyncio.sleep(2)

# Some SSDs report remaining life in an attribute smartctl can't name (the drive
# isn't in its database, so it shows up as "Unknown_Attribute"). Map the model
# string smartctl reports to the SMART attribute ID that holds life remaining %.
SMART_LIFE_ATTR_ID_BY_MODEL = {
    "SPCC Solid State Disk": 169,  # ID 169 = remaining-life % on this controller family
}
# ATA attributes whose *normalized* value is "percent life remaining" (100 = new).
SMART_LIFE_ATTR_NAMES = (
    "Wear_Leveling_Count", "Percent_Lifetime_Remain", "Media_Wearout_Indicator",
    "SSD_Life_Left", "Remaining_Lifetime_Perc", "Perc_Rated_Life_Used",
)
# Skip drives that are spun down instead of waking them (smartctl -n standby).
# Without this, polling every 30s keeps a spinning HDD (e.g. the media drive)
# awake forever. A skipped drive keeps its last known SMART values.
SMART_SKIP_STANDBY = True

def parse_smart_json(drive_info: Dict[str, Any]) -> Dict[str, Any]:
    """Turn smartctl's JSON into {healthy, temperature, life}. Any field the
    drive doesn't report stays None (shown as N/A / -- in the UI) rather than
    defaulting to a made-up good value."""
    status = drive_info.get("smart_status")
    healthy = status.get("passed") if isinstance(status, dict) else None

    temp = (drive_info.get("temperature") or {}).get("current")
    life = None

    nvme_log = drive_info.get("nvme_smart_health_information_log")
    if nvme_log:
        # NVMe reports wear as percentage USED (can exceed 100); flip to remaining.
        used = nvme_log.get("percentage_used")
        if isinstance(used, (int, float)):
            life = max(0, 100 - used)
        if temp is None:
            temp = nvme_log.get("temperature")
    else:
        attr_table = (drive_info.get("ata_smart_attributes") or {}).get("table", [])
        for attr in attr_table:
            if attr.get("name") in SMART_LIFE_ATTR_NAMES:
                life = attr.get("value")
                break
        if life is None:
            life_id = SMART_LIFE_ATTR_ID_BY_MODEL.get(drive_info.get("model_name"))
            if life_id is not None:
                for attr in attr_table:
                    if attr.get("id") == life_id:
                        life = attr.get("value")
                        break
    if isinstance(life, (int, float)):
        life = max(0, min(100, life))
    return {"healthy": healthy, "temperature": temp, "life": life}

async def run_smartctl(dev: str, dtype: str = None):
    args = ["sudo", "-n", "smartctl", "-j", "-a"]
    if SMART_SKIP_STANDBY:
        args += ["-n", "standby"]
    if dtype:
        args += ["-d", dtype]
    args.append(dev)
    p = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, _ = await p.communicate()
    return p.returncode, out.decode(errors="replace")

async def update_smart_telemetry_loop():
    global disk_smart_cache
    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo", "-n", "smartctl", "--scan", "-j",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            devices = []  # (name, smartctl device type or None)
            if proc.returncode == 0:
                scan_data = json.loads(stdout.decode())
                devices = [(d.get("name"), d.get("type")) for d in scan_data.get("devices", []) if d.get("name")]
            if not devices: devices = [("/dev/sda", None)]

            new_cache = {}
            for dev, dtype in devices:
                try:
                    rc, out = await run_smartctl(dev, dtype)
                    if SMART_SKIP_STANDBY and "STANDBY" in out.upper() and rc == 2:
                        # Drive is asleep — keep what we last knew instead of waking it.
                        if dev in disk_smart_cache:
                            new_cache[dev] = disk_smart_cache[dev]
                        continue
                    # smartctl's exit code is a bitmask. Only bits 0-2 (1/2/4) mean the
                    # command itself failed (bad args, can't open device, SMART command
                    # failed). Bits 3+ are findings about the drive (failing attrs, error
                    # log entries, failed self-tests) and the JSON is still complete.
                    info = json.loads(out) if not (rc & 0b111) else None
                    # USB-to-SATA bridges are often scanned as "scsi" and expose no SMART
                    # data that way; retry once using SAT passthrough.
                    if (info is None or "smart_status" not in info) and dtype in (None, "scsi"):
                        rc2, out2 = await run_smartctl(dev, "sat")
                        if not (rc2 & 0b111):
                            info2 = json.loads(out2)
                            if "smart_status" in info2:
                                info = info2
                    if info is not None:
                        new_cache[dev] = parse_smart_json(info)
                except Exception as e:
                    print(f"[SMART Exception] {dev}: {e}")
                    continue
            if new_cache: disk_smart_cache = new_cache
        except Exception as e:
            print(f"[SMART Loop Exception]: {e}")
        await asyncio.sleep(30)

async def update_service_telemetry_loop():
    """Single shared background loop for everything /api/dashboard/metrics used
    to fetch live, per-request: systemd status for every SERVICES_TO_MONITOR
    entry, plus WireGuard, Tailscale, qBittorrent, and Jellyfin telemetry. Runs
    once every TELEMETRY_POLL_INTERVAL regardless of how many browser tabs are
    polling the dashboard. /api/dashboard/services reads service_status_cache
    from here too, so service status is no longer checked on two separate
    overlapping timers."""
    global service_status_cache, wireguard_cache, tailscale_cache, qbittorrent_cache, jellyfin_cache
    while True:
        try:
            # --- systemd status for every monitored service, once ---
            new_status = {}
            for service in SERVICES_TO_MONITOR:
                new_status[service] = await check_service_status(service)
            service_status_cache = new_status

            # --- WireGuard (Windscribe tunnel) ---
            wg_status = service_status_cache.get("wg-quick@windscribe", "inactive")
            wg_data = {"status": wg_status, "handshake": "--", "endpoint": "--", "transfer_rx": "0 B", "transfer_tx": "0 B"}
            if wg_status == "active":
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "sudo", "wg", "show", "windscribe", "dump",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await proc.communicate()
                    lines = stdout.decode().strip().splitlines()
                    if len(lines) > 1:
                        peer_data = lines[1].split("\t")
                        if len(peer_data) >= 6:
                            wg_data["endpoint"] = peer_data[2]

                            last_hs = int(peer_data[4])
                            wg_data["handshake"] = f"{int(time.time()) - last_hs}s ago" if last_hs > 0 else "Never"

                            def fmt_bytes(b):
                                b = int(b)
                                if b < 1024: return f"{b} B"
                                if b < 1024**2: return f"{b/1024:.1f} KB"
                                if b < 1024**3: return f"{b/1024**2:.1f} MB"
                                return f"{b/1024**3:.2f} GB"

                            wg_data["transfer_rx"] = fmt_bytes(peer_data[5])
                            wg_data["transfer_tx"] = fmt_bytes(peer_data[6])
                except Exception:
                    pass
            wireguard_cache = wg_data

            # --- Tailscale ---
            ts_status = service_status_cache.get("tailscaled", "inactive")
            ts_data = {"status": ts_status, "node_ip": "--", "active_peers": 0, "exit_node_active": False}
            if ts_status == "active":
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "tailscale", "status", "--json",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await proc.communicate()
                    if proc.returncode == 0:
                        parsed = json.loads(stdout.decode())
                        tailscale_ips = parsed.get("Self", {}).get("TailscaleIPs", [])
                        if tailscale_ips:
                            ts_data["node_ip"] = tailscale_ips[0]
                        peers = parsed.get("Peer", {})
                        ts_data["active_peers"] = sum(1 for p in peers.values() if p.get("Online", False))
                        # "ExitNodeStatus" (top-level) describes an exit node THIS device
                        # is using — always null for a device that serves as an exit node
                        # rather than using one. Whether this device is itself offered and
                        # approved as an exit node lives on Self.ExitNodeOption instead.
                        ts_data["exit_node_active"] = parsed.get("Self", {}).get("ExitNodeOption", False)
                except Exception:
                    pass
            tailscale_cache = ts_data

            # --- qBittorrent ---
            qb_status = service_status_cache.get("qbittorrent", "inactive")
            if qb_status == "active":
                qb_payload = await get_qbittorrent_payload()
            else:
                qb_payload = {"active_torrents": 0, "dl_speed": "0 B/s", "ul_speed": "0 B/s"}
            qbittorrent_cache = {"status": qb_status, **qb_payload}

            # --- Jellyfin --- (not tied to a monitored systemd unit — Jellyfin
            # may run remotely or outside systemd, so this stays unconditional,
            # matching the original per-request behavior)
            jf_version = "v--"
            jf_playing = []
            headers = {"Authorization": f'MediaBrowser Token="{JELLYFIN_API_KEY}"', "Accept": "application/json"}
            async with httpx.AsyncClient(timeout=1.5) as client:
                try:
                    system_info_res = await client.get(f"{JELLYFIN_URL}/System/Info", headers=headers)
                    if system_info_res.status_code == 200:
                        jf_version = system_info_res.json().get("Version", "Unknown")

                    sessions_res = await client.get(f"{JELLYFIN_URL}/Sessions", headers=headers)
                    if sessions_res.status_code == 200:
                        for session in sessions_res.json():
                            if "NowPlayingItem" in session:
                                item = session["NowPlayingItem"]
                                title_string = item.get("Name", "Unknown Content")
                                if item.get("Type") == "Episode":
                                    title_string = f"{item.get('SeriesName', '')} - S{item.get('ParentIndexNumber', 0):02d}E{item.get('IndexNumber', 0):02d} - {title_string}"
                                jf_playing.append({
                                    "session_id": session.get("Id"),
                                    "now_playing_id": item.get("Id"),
                                    "title": title_string,
                                    "client": session.get("Client", "Player"),
                                    "user": session.get("UserName", "User"),
                                    "is_paused": session.get("PlayState", {}).get("IsPaused", False)
                                })
                except Exception:
                    pass
            jellyfin_cache = {"version": jf_version, "playing": jf_playing}

        except Exception as e:
            print(f"[Service Telemetry Loop Exception]: {str(e)}")

        await asyncio.sleep(TELEMETRY_POLL_INTERVAL)

async def update_process_metrics_loop():
    """Samples /proc every PROCESS_POLL_INTERVAL seconds, computing per-process
    CPU% from tick deltas (same approach as the overall/per-core CPU calc) and
    flagging processes that are sustained-hot or stuck in uninterruptible sleep."""
    global process_cache
    global _service_pid_cache, _service_pid_cycle_count
    while True:
        try:
            now = time.time()
            # Only re-resolve service->PID mappings every SERVICE_PID_REFRESH_CYCLES
            # cycles (main PIDs rarely change between restarts) instead of on
            # every single poll — cuts 5 subprocess spawns down to roughly 1/10th.
            if _service_pid_cycle_count % SERVICE_PID_REFRESH_CYCLES == 0:
                _service_pid_cache = await get_service_main_pids()
            _service_pid_cycle_count += 1
            service_pid_map = _service_pid_cache

            total_mem_kb = 0
            try:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            total_mem_kb = int(line.split()[1])
                            break
            except Exception:
                pass

            current_pids = set()
            rows: List[Dict[str, Any]] = []

            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                current_pids.add(pid)

                try:
                    comm, state, utime, stime = read_process_stat(pid)
                except Exception:
                    continue  # process likely exited mid-scan; skip it this cycle

                total_ticks = utime + stime
                prev = _process_prev_ticks.get(pid)
                cpu_percent = 0.0
                if prev:
                    tick_delta = total_ticks - prev["ticks"]
                    time_delta = now - prev["time"]
                    if time_delta > 0:
                        cpu_percent = max(0.0, round((tick_delta / _CLK_TCK) / time_delta * 100, 1))
                _process_prev_ticks[pid] = {"ticks": total_ticks, "time": now}

                mem_kb = get_process_rss_kb(pid)
                mem_percent = round((mem_kb / total_mem_kb) * 100, 1) if total_mem_kb > 0 else 0.0

                streak = _process_streaks.setdefault(pid, {"d_state": 0, "high_cpu": 0})
                streak["d_state"] = streak["d_state"] + 1 if state == HANG_STATE_CHAR else 0
                streak["high_cpu"] = streak["high_cpu"] + 1 if cpu_percent >= HIGH_CPU_THRESHOLD else 0

                is_hanging = streak["d_state"] >= HANG_SUSTAIN_CYCLES
                is_high_cpu = streak["high_cpu"] >= HIGH_CPU_SUSTAIN_CYCLES

                # Never surface the init process or this dashboard's own process as actionable
                if pid in (1, os.getpid()):
                    continue
                # Skip idle noise so the list stays focused on what matters
                if cpu_percent <= 0.1 and mem_percent < 0.5 and not is_hanging and not is_high_cpu:
                    continue

                rows.append({
                    "pid": pid,
                    "name": comm,
                    "cmd": get_process_cmdline(pid, comm),
                    "cpu_percent": cpu_percent,
                    "mem_percent": mem_percent,
                    "state": state,
                    "is_hanging": is_hanging,
                    "is_high_cpu": is_high_cpu,
                    "service": service_pid_map.get(pid)
                })

            # prune tracking state for processes that have since exited
            for stale_pid in list(_process_prev_ticks.keys()):
                if stale_pid not in current_pids:
                    _process_prev_ticks.pop(stale_pid, None)
                    _process_streaks.pop(stale_pid, None)

            rows.sort(key=lambda r: (r["is_hanging"], r["is_high_cpu"], r["cpu_percent"]), reverse=True)
            process_cache = rows[:PROCESS_LIST_LIMIT]
        except Exception as e:
            print(f"[Process Monitor Loop Exception]: {str(e)}")

        await asyncio.sleep(PROCESS_POLL_INTERVAL)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(update_smart_telemetry_loop())
    asyncio.create_task(update_process_metrics_loop())
    asyncio.create_task(update_network_speeds_loop())
    asyncio.create_task(update_disk_io_loop())
    asyncio.create_task(update_pihole_versions_loop())
    asyncio.create_task(update_service_telemetry_loop())
    asyncio.create_task(update_external_requests_map_loop())

# --- ENDPOINTS ---

@app.get("/api/pihole/updates")
async def get_pihole_updates():
    return pihole_update_cache

@app.post("/api/pihole/apply-update")
async def apply_pihole_update(background_tasks: BackgroundTasks):
    def run_update():
        subprocess.run(["sudo", "pihole", "-up"], check=False)
        
    # Executes the update as a background task so the API responds instantly
    background_tasks.add_task(run_update)
    return {"status": "Update initiated"}
    
@app.get("/api/jellyfin/poster/{item_id}")
async def jellyfin_poster(item_id: str):
    """Serves a Jellyfin item's poster through the dashboard so the browser
    never needs a direct route to Jellyfin (it only has to reach this app —
    which is what makes posters work over Tailscale/other networks) and the
    URL comes from JELLYFIN_URL instead of being hardcoded in the frontend.
    Behind the same login as every other route; the API key stays server-side."""
    # Jellyfin item IDs are GUIDs (32 hex chars, or dashed). Reject anything
    # else so the path segment can't be steered at other Jellyfin endpoints.
    if not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", item_id):
        raise HTTPException(status_code=400, detail="Invalid item id")
    headers = {"Authorization": f'MediaBrowser Token="{JELLYFIN_API_KEY}"'}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get(
                f"{JELLYFIN_URL}/Items/{item_id}/Images/Primary",
                params={"maxHeight": 120}, headers=headers,
            )
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Jellyfin unreachable")
    ctype = res.headers.get("content-type", "")
    if res.status_code == 404:
        raise HTTPException(status_code=404, detail="No poster")
    if res.status_code != 200 or not ctype.startswith("image/"):
        raise HTTPException(status_code=502, detail="Jellyfin returned no image")
    # The page re-renders its stream cards every 2s; let the browser cache the
    # image so it isn't re-fetched (and doesn't flicker) on every poll.
    return Response(content=res.content, media_type=ctype,
                    headers={"Cache-Control": "private, max-age=3600"})

@app.post("/api/jellyfin/subtitles/toggle")
async def toggle_active_subtitles(payload: SubtitleToggleRequest):
    headers = {
        "Authorization": f'MediaBrowser Token="{JELLYFIN_API_KEY}"',
        "Accept": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            # 1. Fetch active sessions
            sessions_resp = await client.get(f"{JELLYFIN_URL}/Sessions", headers=headers)
            if sessions_resp.status_code != 200:
                raise HTTPException(status_code=500, detail="Failed to connect to Jellyfin")
                
            sessions = sessions_resp.json()
            
            # 2. Find the specific session this request is for — not just
            # "whichever session happens to be playing first", which would
            # silently affect the wrong stream if more than one is active.
            active_session = next((s for s in sessions if s.get("Id") == payload.session_id and "NowPlayingItem" in s), None)
            if not active_session:
                return {"status": "error", "message": "That session is no longer playing anything."}

            session_id = active_session.get("Id")
            now_playing = active_session.get("NowPlayingItem", {})
            streams = now_playing.get("MediaStreams", [])

            # 3. Scan media streams for an English subtitle track ('eng' or 'en')
            eng_sub_index = None
            for stream in streams:
                if stream.get("Type") == "Subtitle" and stream.get("Language") in ["eng", "en"]:
                    eng_sub_index = stream.get("Index")
                    break
                    
            if eng_sub_index is None:
                return {"status": "error", "message": "No English subtitle track found for this media."}

            # 4. Check current playback state subtitle index (-1 means disabled)
            play_state = active_session.get("PlayState", {})
            current_sub_index = play_state.get("SubtitleStreamIndex", -1)
            
            new_index = -1 if current_sub_index == eng_sub_index else eng_sub_index

            # 5. Send the remote control command via a JSON payload
            command_url = f"{JELLYFIN_URL}/Sessions/{session_id}/Command"
            payload = {
                "Name": "SetSubtitleStreamIndex",
                "Arguments": {
                    "Index": new_index
                }
            }
            
            res = await client.post(command_url, json=payload, headers=headers)
            if res.status_code not in [200, 204]:
                return {"status": "error", "message": "Failed to apply subtitle command on Jellyfin."}
            
            state_msg = "Enabled" if new_index != -1 else "Disabled"
            return {"status": "success", "message": f"English subtitles {state_msg}."}
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Jellyfin subtitle toggle error: {str(e)}")

@app.get("/api/dashboard/metrics")
async def get_dashboard_metrics():
    cpu, ram, cpu_cores = await get_cpu_ram_payload()
    
    disks_payload = {}

    try:
        mounts = read_mounts()
    except Exception:
        mounts = [{"device": "/dev/sda1", "mount_point": "/", "fstype": ""}]

    for m in mounts:
        path, device = m["mount_point"], m["device"]
        if os.path.exists(path):
            try:
                total, used, free = get_fs_usage(path)
                if total <= 0:
                    continue
                denom = used + free
                percent = round((used / denom) * 100, 1) if denom > 0 else 0.0
                base_drive = resolve_parent_disk(device)
                # healthy=None means "we don't have SMART data for this drive" —
                # distinct from a confirmed-healthy True, so the frontend doesn't
                # show a false "OK" for a device we never actually queried.
                disks_payload[path] = {
                    "device": device,
                    "fstype": m["fstype"],
                    "percent": percent,
                    "total_bytes": total,
                    "used_bytes": used,
                    "free_bytes": free,
                    "disk_size_bytes": get_whole_disk_size_bytes(base_drive),
                    "can_unmount": path not in PROTECTED_MOUNTS,
                    "smart": lookup_smart(base_drive),
                }
            except Exception: pass

    try:
        unmounted_drives = read_unmounted_fstab_drives({m["mount_point"] for m in mounts})
    except Exception:
        unmounted_drives = []

# --- WireGuard / Tailscale / qBittorrent / Jellyfin telemetry ---
    # All of this now comes straight from the caches populated by
    # update_service_telemetry_loop() instead of spawning `wg`/`tailscale`
    # subprocesses or calling Jellyfin's API on every single poll — see the
    # comment above the cache declarations near the top of the file.
    wg_data = wireguard_cache
    ts_data = tailscale_cache
    qb_data = qbittorrent_cache
    jf_data = jellyfin_cache

    return {
        "uptime": get_system_uptime(),
        "download_speed": network_speed_cache["down"],
        "upload_speed": network_speed_cache["up"],
        "network_telemetry": {
            "down_kbps": network_speed_cache.get("down_kbps", 0.0),
            "up_kbps": network_speed_cache.get("up_kbps", 0.0)
        },
        "disk_io": disk_io_cache,
        "temperature": get_cpu_temperature(),
        "cpu_percent": cpu,
        "cpu_cores": cpu_cores,
        "ram_percent": ram,
        "disks": disks_payload,
        "unmounted_drives": unmounted_drives,
	"wireguard": wg_data,
        "tailscale": ts_data,
        "qbittorrent": qb_data,
        "jellyfin": jf_data
    }

class UnmountRequest(BaseModel):
    mount_point: str

@app.post("/api/control/unmount")
async def control_unmount(payload: UnmountRequest):
    # Never trust the client's path: it must exactly match a currently-mounted
    # block-device mount point from /proc/mounts, and must not be protected.
    try:
        current = {m["mount_point"]: m for m in read_mounts()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not read mounts: {e}")
    if payload.mount_point not in current:
        raise HTTPException(status_code=404, detail="That drive is not currently mounted")
    if payload.mount_point in PROTECTED_MOUNTS:
        raise HTTPException(status_code=403, detail="This is a system mount and can't be unmounted from the dashboard")

    # Plain umount only — no -f/-l. If something is using the drive (Jellyfin,
    # qBittorrent, Samba...) it fails with "target is busy" instead of risking
    # data loss. Exec list, no shell. `-n` makes sudo fail fast, not prompt.
    if _mount_lock.locked():
        raise HTTPException(status_code=409, detail="A mount or unmount is already running")
    async with _mount_lock:
        proc = await asyncio.create_subprocess_exec(
            "sudo", "-n", "umount", "--", payload.mount_point,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=UNMOUNT_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            raise HTTPException(status_code=504, detail="Unmount timed out — check the server directly")
    if proc.returncode != 0:
        msg = stderr.decode(errors="replace").strip() or f"umount exited with code {proc.returncode}"
        raise HTTPException(status_code=409, detail=msg)
    return {"status": "success", "mount_point": payload.mount_point}

@app.post("/api/control/mount-all")
async def control_mount_all():
    """Runs `mount -a`: mounts every /etc/fstab entry that isn't mounted yet
    (noauto entries are skipped by mount itself). Nothing from the client
    reaches the command, so there's nothing to inject; it's idempotent, so
    clicking it with everything already mounted is a harmless no-op."""
    if _mount_lock.locked():
        raise HTTPException(status_code=409, detail="A mount or unmount is already running")
    async with _mount_lock:
        proc = await asyncio.create_subprocess_exec(
            "sudo", "-n", "mount", "-a",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=MOUNT_ALL_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            raise HTTPException(status_code=504, detail="Mount timed out — check the server directly")
    msg = "\n".join(t for t in (out.decode(errors="replace").strip(), err.decode(errors="replace").strip()) if t)
    if proc.returncode == 0:
        return {"status": "success", "message": msg}
    if proc.returncode == 64:   # mount(8): some filesystems mounted, some failed
        return {"status": "partial", "message": msg or "Some drives failed to mount"}
    raise HTTPException(status_code=409, detail=msg or f"mount exited with code {proc.returncode}")

@app.get("/api/network/public-ip")
async def get_public_ip():
    """On-demand only — no background polling. Called when the user clicks
    Refresh in the Public IP widget."""
    ip = await fetch_public_ip()
    return {"public_ip": ip, "checked_at": time.strftime("%H:%M:%S")}

@app.get("/api/windscribe/locations")
async def get_windscribe_locations():
    try:
        _, output = await run_windscribe_switch("list", timeout=10.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="windscribe-switch list timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    locations = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("("):
            continue
        locations.append(line)
    return {"locations": locations}

@app.get("/api/windscribe/status")
async def get_windscribe_status():
    try:
        _, output = await run_windscribe_switch("status", timeout=10.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="windscribe-switch status timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    active_location = None
    interface_up = False
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Active location:"):
            loc = line.split(":", 1)[1].strip()
            active_location = None if loc == "(none)" else loc
        elif line.startswith("Interface state:"):
            interface_up = line.split(":", 1)[1].strip() == "up"
    return {"active_location": active_location, "interface_up": interface_up}

@app.post("/api/windscribe/switch")
async def switch_windscribe_location(payload: WindscribeSwitchRequest):
    # The script itself validates the location exists, but reject obviously
    # malformed input before it even reaches sudo. Note: create_subprocess_exec
    # never goes through a shell, so this isn't a command-injection concern —
    # it's just a fast, clear 400 instead of letting a typo hit the script.
    if not payload.location or not WINDSCRIBE_LOCATION_RE.match(payload.location):
        raise HTTPException(status_code=400, detail="Invalid location name")

    # Generous timeout: teardown + up + 4s handshake wait, and on failure the
    # script auto-reverts, which repeats most of that (teardown + up + another
    # 4s wait) before giving up. 30s covers that worst case with headroom.
    try:
        returncode, output = await run_windscribe_switch("up", payload.location, timeout=30.0)
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail="Switch timed out — the tunnel may be in an unknown state. Check the server directly."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    reverted = "Auto-reverting" in output or "Reverted." in output
    succeeded = returncode == 0 and "Handshake confirmed" in output and not reverted

    if succeeded:
        status = "success"
    elif reverted:
        status = "reverted"
    else:
        status = "failed"

    return {"status": status, "output": output, "returncode": returncode}

@app.get("/api/dashboard/services")
async def get_services():
    # Reads the cache update_service_telemetry_loop() already maintains, rather
    # than re-running `systemctl is-active` for every service again here — this
    # endpoint and /api/dashboard/metrics used to check the same services on
    # two separate overlapping timers.
    return {service: service_status_cache.get(service, "inactive") for service in SERVICES_TO_MONITOR}

@app.post("/api/control/service")
async def control_service(payload: ServiceAction):
    if payload.action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="action must be 'start', 'stop', or 'restart'")
    if payload.service in SERVICES_TO_MONITOR:
        try:
            await asyncio.create_subprocess_exec("sudo", "systemctl", payload.action, payload.service)
            return {"status": "success"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    raise HTTPException(status_code=404, detail="Service not found")

@app.get("/api/processes")
async def get_processes():
    return process_cache

@app.post("/api/control/process")
async def control_process(payload: ProcessAction):
    # Only act on PIDs the monitor itself surfaced this cycle — this prevents
    # a caller from targeting arbitrary PIDs on the box (sshd, the dashboard's
    # own supervisor, etc.) that were never shown on the dashboard.
    target = next((p for p in process_cache if p["pid"] == payload.pid), None)
    if not target:
        raise HTTPException(status_code=404, detail="PID not found in the current process monitor snapshot")

    if payload.action == "restart_service":
        if not target.get("service"):
            raise HTTPException(status_code=400, detail="This process isn't a monitored service — use terminate or kill instead")
        try:
            await asyncio.create_subprocess_exec("sudo", "systemctl", "restart", target["service"])
            return {"status": "success", "action": "restart_service", "service": target["service"]}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    if payload.action in ("terminate", "kill"):
        # Defense against PID reuse: process_cache can be up to
        # PROCESS_POLL_INTERVAL seconds stale. If the flagged process exited
        # and the kernel reassigned that exact PID to something new in the
        # meantime, re-checking the process name here (rather than trusting
        # the cached snapshot) stops us from signaling the wrong process.
        try:
            current_comm, _, _, _ = read_process_stat(payload.pid)
        except Exception:
            raise HTTPException(status_code=404, detail="Process no longer exists")
        if current_comm != target["name"]:
            raise HTTPException(
                status_code=409,
                detail="Process identity changed since the last scan (likely PID reuse) — refusing to act. Refresh and try again."
            )
        signal_flag = "-TERM" if payload.action == "terminate" else "-KILL"
        try:
            await asyncio.create_subprocess_exec("sudo", "kill", signal_flag, str(payload.pid))
            return {"status": "success", "action": payload.action, "pid": payload.pid}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    raise HTTPException(status_code=400, detail="Unsupported action")

@app.get("/api/packages/status")
async def get_package_status():
    return package_state

@app.post("/api/packages/check")
async def check_packages():
    if _apt_lock.locked():
        raise HTTPException(status_code=409, detail="Another package operation is in progress")
    async with _apt_lock:
        package_state["status"] = "checking"
        try:
            await refresh_package_lists(update_index=True)
        except Exception as e:
            print(f"[Package Check Exception]: {e}")
        finally:
            package_state["status"] = "idle"
    return {"status": "success"}

@app.post("/api/packages/run")
async def run_package_operation(payload: PackageOperation):
    if payload.operation not in ("upgrade", "full-upgrade", "autoremove"):
        raise HTTPException(status_code=400, detail="Unsupported operation")
    if _apt_lock.locked():
        raise HTTPException(status_code=409, detail="Another package operation is in progress")
    await _apt_lock.acquire()
    task = asyncio.create_task(_run_and_release(payload.operation))
    _background_tasks.add(task)                      # keep a reference so it isn't GC'd
    task.add_done_callback(_background_tasks.discard)
    return {"status": "started"}

@app.get("/api/telemetry/pihole/geomap")
async def get_external_requests_map():
    """Cached, geolocated points for the External Request Map widget — see
    update_external_requests_map_loop(). Never fetched live: geolocation and
    Pi-hole's stats API are both slow enough (and rate-limited enough, for
    ip-api.com) that per-request fetching would be a bad idea here."""
    return external_requests_cache

@app.get("/api/telemetry/pihole")
async def get_pihole_telemetry():
    async with httpx.AsyncClient(timeout=2.5) as client:
        sid = None
        try:
            sid = await get_pihole_sid(client)
            if not sid:
                return {
                    "status": "unauthorized",
                    "dns_queries_today": 0,
                    "ads_blocked_today": 0,
                    "ads_percentage_today": 0,
                    "top_sources": {}
                }

            headers = {"X-FTL-SID": sid}

            blocking_res = await client.get(f"{PIHOLE_URL}/dns/blocking", headers=headers)
            status_str = "offline"
            if blocking_res.status_code == 200:
                is_blocking = blocking_res.json().get("blocking")
                status_str = "active" if is_blocking in [True, "enabled"] else "disabled"

            stats_res = await client.get(f"{PIHOLE_URL}/stats/summary", headers=headers)
            stats_data = stats_res.json() if stats_res.status_code == 200 else {}
            
            queries = stats_data.get("queries", {})
            total_queries = queries.get("total", stats_data.get("dns_queries_today", 0))
            blocked_queries = queries.get("blocked", stats_data.get("ads_blocked_today", 0))
            blocked_pct = queries.get("percent_blocked", stats_data.get("ads_percentage_today", 0.0))

            top_sources = {}
            top_res = await client.get(f"{PIHOLE_URL}/stats/top_domains?blocked=true&count=5", headers=headers)
            if top_res.status_code == 200:
                top_sources = {
                    d["domain"]: d["count"]
                    for d in top_res.json().get("domains", [])
                }

            return {
                "status": status_str,
                "dns_queries_today": total_queries,
                "ads_blocked_today": blocked_queries,
                "ads_percentage_today": float(blocked_pct),
                "top_sources": top_sources
            }

        except Exception as e:
            print(f"[Pi-hole Telemetry Drop]: {str(e)}")

        finally:
            if sid:
                try:
                    await client.delete(f"{PIHOLE_URL}/auth", headers={"X-FTL-SID": sid})
                except Exception:
                    pass

    return {
        "status": "offline",
        "dns_queries_today": 0,
        "ads_blocked_today": 0,
        "ads_percentage_today": 0,
        "top_sources": {}
    }

@app.post("/api/control/pihole")
async def control_pihole(payload: PiholeAction):
    async with httpx.AsyncClient(timeout=2.5) as client:
        sid = await get_pihole_sid(client)
        if not sid:
            raise HTTPException(status_code=401, detail="Failed to authenticate with Pi-hole")

        headers = {"X-FTL-SID": sid, "Content-Type": "application/json"}
        
        if payload.action == "enable":
            body = {"blocking": True}
        else:
            body = {"blocking": False}
            if payload.duration > 0:
                body["timer"] = payload.duration

        try:
            res = await client.post(f"{PIHOLE_URL}/dns/blocking", headers=headers, json=body)
            if res.status_code == 200:
                return {"status": "success"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Pi-hole communication drop: {str(e)}")

    raise HTTPException(status_code=400, detail="Instruction routing failed")

@app.post("/api/control/power")
async def control_power(payload: PowerAction):
    if payload.action not in ("reboot", "shutdown"):
        raise HTTPException(status_code=400, detail="action must be 'reboot' or 'shutdown'")
    cmd = ["sudo", "shutdown", "-r", "now"] if payload.action == "reboot" else ["sudo", "shutdown", "now"]
    await asyncio.create_subprocess_exec(*cmd)
    return {"status": "signaled"}

@app.post("/api/control/jellyfin")
async def control_jellyfin(payload: JellyfinCommand):
    headers = {
        "accept": "*/*",
        "Authorization": f'MediaBrowser Token="{JELLYFIN_API_KEY}"'
    }
    action = "PlayPause" if payload.command == "PlayPause" else "Stop"
    url = f"{JELLYFIN_URL}/Sessions/{payload.session_id}/Playing/{action}"
    
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(url, headers=headers, content="")
            if res.status_code in [200, 204]: 
                return {"status": "success"}
        except Exception: pass
    raise HTTPException(status_code=400, detail="Command failed")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)