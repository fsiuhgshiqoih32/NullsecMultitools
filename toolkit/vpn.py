from __future__ import annotations

import base64
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests
from rich.prompt import Prompt
from rich.table import Table

from .utils import IS_WINDOWS, console, get_proxy, header, pause, report

try:  # VPNGate's cert is valid, but proxies/MITM can trip verification — quiet the noise
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# VPNGate — a public academic pool of volunteer-run free VPN relays worldwide.
# The iphone API returns a CSV, one row per server, with an embedded OpenVPN config.
_API = "https://www.vpngate.net/api/iphone/"
_MIRRORS = [
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
]

# Column indices in the VPNGate CSV.
_H, _IP, _SCORE, _PING, _SPEED, _CLONG, _CSHORT = 0, 1, 2, 3, 4, 5, 6
_SESS, _UPTIME, _CFG = 7, 8, 14


@dataclass
class VPNServer:
    host: str
    ip: str
    country: str          # long name, e.g. "Japan"
    cc: str               # 2-letter code, e.g. "JP"
    ping: str             # ms
    speed: int            # bits/sec
    sessions: str
    uptime_ms: str
    config_b64: str
    real_ping: float | None = None   # measured TCP latency from this machine (ms)

    @property
    def speed_mbps(self) -> float:
        try:
            return int(self.speed) / 1_000_000
        except (TypeError, ValueError):
            return 0.0

    @property
    def uptime_days(self) -> str:
        try:
            return f"{int(self.uptime_ms) / 86_400_000:.1f}d"
        except (TypeError, ValueError):
            return "-"


_servers: list[VPNServer] = []


# --- fetching ---------------------------------------------------------------

def fetch() -> int:
    """Download and parse the VPNGate server list. Returns count. Routes through
    the Proxy Manager if it's enabled."""
    global _servers
    text = ""
    for url in _MIRRORS:
        try:
            r = requests.get(url, timeout=25, proxies=get_proxy(), verify=False)
            if r.status_code == 200 and "HostName" in r.text:
                text = r.text
                break
        except requests.RequestException:
            continue
    if not text:
        return -1  # network failure (distinct from "0 servers")

    out: list[VPNServer] = []
    for line in text.splitlines():
        if not line or line[0] in "*#":
            continue
        c = line.split(",")
        if len(c) <= _CFG or not c[_H] or not c[_IP]:
            continue
        try:
            out.append(VPNServer(
                host=c[_H], ip=c[_IP], country=c[_CLONG], cc=c[_CSHORT].upper(),
                ping=c[_PING], speed=int(c[_SPEED] or 0), sessions=c[_SESS],
                uptime_ms=c[_UPTIME], config_b64=c[_CFG]))
        except (ValueError, IndexError):
            continue
    _servers = out
    return len(out)


def _ensure() -> bool:
    """Make sure we have a server list; offer to fetch if not."""
    if _servers:
        return True
    console.print("[dim]No server list yet — fetching from VPNGate…[/]")
    return _do_fetch()


def _do_fetch() -> bool:
    with console.status("[grey50]downloading free VPN list…[/]", spinner="dots"):
        n = fetch()
    if n < 0:
        console.print("[red]Couldn't reach VPNGate.[/] Check your connection (or "
                      "route through the Proxy Manager) and try again.")
        return False
    if n == 0:
        console.print("[yellow]No servers returned.[/]")
        return False
    console.print(f"[green]Fetched {n} free VPN servers[/] across "
                  f"{len({s.cc for s in _servers})} countries.")
    report("VPN", f"Fetched {n} VPNGate servers")
    return True


# --- config parsing + real latency -----------------------------------------

def _config_info(s: VPNServer) -> dict:
    """Pull proto/port and the encryption (cipher/auth) out of the OpenVPN config."""
    info = {"proto": "", "port": "", "cipher": "", "auth": ""}
    try:
        cfg = base64.b64decode(s.config_b64).decode("utf-8", "ignore")
    except Exception:
        return info
    for line in cfg.splitlines():
        line = line.strip()
        if line.startswith("remote ") and not info["port"]:
            parts = line.split()
            if len(parts) >= 3:
                info["port"] = parts[2]
        elif line.startswith("proto ") and not info["proto"]:
            info["proto"] = line.split()[1]
        elif line.startswith("cipher ") and not info["cipher"]:
            info["cipher"] = line.split()[1]
        elif line.startswith("auth ") and not info["auth"]:
            info["auth"] = line.split()[1]
    return info


def _tcp_ping(ip: str, ports: list[str], timeout: float = 2.5) -> float | None:
    """Round-trip time (ms) of a TCP handshake to the server — the real latency
    you'll see. Tries each port, returns the first that answers."""
    for port in ports:
        try:
            start = time.monotonic()
            with socket.create_connection((ip, int(port)), timeout=timeout):
                return round((time.monotonic() - start) * 1000, 1)
        except (OSError, ValueError):
            continue
    return None


def measure_all(servers: list[VPNServer]) -> None:
    """Measure real TCP latency to each server concurrently, filling real_ping."""
    def _m(s: VPNServer) -> None:
        ports = [p for p in (_config_info(s).get("port"), "443", "1194", "992") if p]
        s.real_ping = _tcp_ping(s.ip, list(dict.fromkeys(ports)))
    with ThreadPoolExecutor(max_workers=40) as pool:
        list(pool.map(_m, servers))


# --- display helpers --------------------------------------------------------

def _ordered(servers: list[VPNServer]) -> list[VPNServer]:
    """Sort by real ping (lowest first) once measured, otherwise by speed."""
    if any(s.real_ping is not None for s in servers):
        return sorted(servers, key=lambda s: (s.real_ping is None, s.real_ping or 1e9))
    return sorted(servers, key=lambda s: s.speed, reverse=True)


def _render(servers: list[VPNServer], title: str, limit: int = 40) -> None:
    servers = _ordered(servers)
    t = Table(title=f"{title} ({len(servers)})"
              + (f" — showing top {limit}" if len(servers) > limit else ""))
    t.add_column("#", justify="right", style="dim")
    t.add_column("Country", style="cyan")
    t.add_column("Host / IP", overflow="fold")
    t.add_column("Your ping", justify="right", style="bold")
    t.add_column("Speed", justify="right", style="green")
    t.add_column("Sessions", justify="right")
    t.add_column("Uptime", justify="right", style="dim")
    for i, s in enumerate(servers[:limit]):
        yours = f"{s.real_ping:.0f}ms" if s.real_ping is not None else "[dim]?[/]"
        t.add_row(str(i), f"{s.country} ({s.cc})", f"{s.host}  [dim]{s.ip}[/]",
                  yours, f"{s.speed_mbps:.1f} Mbps", s.sessions, s.uptime_days)
    console.print(t)
    if not any(s.real_ping is not None for s in servers):
        console.print("[dim]Tip: run 'Measure real ping' to see the latency you'll "
                      "actually get, sorted fastest-first.[/]")


def _pick(servers: list[VPNServer], prompt: str = "Server #") -> VPNServer | None:
    servers = _ordered(servers)
    idx = Prompt.ask(prompt, default="0").strip()
    if not idx.isdigit() or not (0 <= int(idx) < len(servers)):
        console.print("[red]Invalid selection.[/]")
        return None
    return servers[int(idx)]


# --- OpenVPN: locate / auto-install -----------------------------------------

_WIN_OPENVPN_PATHS = [
    r"C:\Program Files\OpenVPN\bin\openvpn.exe",
    r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
]


def _openvpn_path() -> str | None:
    """Resolve the openvpn binary from PATH or the usual install location."""
    p = shutil.which("openvpn")
    if p:
        return p
    if IS_WINDOWS:
        for c in _WIN_OPENVPN_PATHS:
            if Path(c).is_file():
                return c
    return None


def _run_live(cmd: list, note: str) -> int:
    console.print(f"[dim]$ {' '.join(cmd)}[/]  [bright_black]({note})[/]")
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        console.print(f"[yellow]'{cmd[0]}' isn't available on this system.[/]")
        return 127
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]failed: {e}[/]")
        return 1


def _install_openvpn() -> str | None:
    console.print("[bold]Installing OpenVPN…[/] [dim](this may take a minute)[/]")
    if IS_WINDOWS:
        if shutil.which("winget"):
            _run_live(["winget", "install", "--id", "OpenVPNTechnologies.OpenVPN",
                       "-e", "--silent", "--accept-package-agreements",
                       "--accept-source-agreements"], "winget")
        else:
            console.print("[yellow]winget not found.[/] Get the installer from "
                          "[cyan]https://openvpn.net/community-downloads/[/]")
            return None
    elif sys.platform == "darwin" and shutil.which("brew"):
        _run_live(["brew", "install", "openvpn"], "homebrew")
    elif shutil.which("apt"):
        _run_live(["sudo", "apt", "install", "-y", "openvpn"], "apt")
    elif shutil.which("dnf"):
        _run_live(["sudo", "dnf", "install", "-y", "openvpn"], "dnf")
    elif shutil.which("pacman"):
        _run_live(["sudo", "pacman", "-S", "--noconfirm", "openvpn"], "pacman")
    else:
        console.print("[yellow]Install 'openvpn' with your package manager.[/]")
        return None
    return _openvpn_path()


def ensure_openvpn() -> str | None:
    """Return the openvpn path, offering to auto-install it if it's missing."""
    p = _openvpn_path()
    if p:
        return p
    console.print("[yellow]OpenVPN isn't installed.[/]")
    if Prompt.ask("Auto-install OpenVPN now?", choices=["y", "n"], default="y") != "y":
        return None
    ovpn = _install_openvpn()
    if ovpn:
        console.print(f"[green]OpenVPN installed:[/] {ovpn}")
    else:
        console.print("[yellow]Couldn't confirm the OpenVPN install.[/] It may need a "
                      "new terminal for PATH — reopen nullsec and try again.")
    return ovpn


# --- menu actions -----------------------------------------------------------

def refresh() -> None:
    header("Fetch VPN servers", "Download the latest free VPNGate list")
    _do_fetch()
    pause()


def list_all() -> None:
    header("Free VPN servers", "Fastest first")
    if not _ensure():
        return pause()
    _render(_servers, "All servers")
    pause()


def by_country() -> None:
    header("VPNs by country", "Filter the free list to one country")
    if not _ensure():
        return pause()
    q = Prompt.ask("Country name or 2-letter code (e.g. Japan or JP)").strip().lower()
    hits = [s for s in _servers
            if q == s.cc.lower() or q in s.country.lower()]
    if not hits:
        avail = ", ".join(sorted({f"{s.cc}" for s in _servers}))
        console.print(f"[yellow]No servers for '{q}'.[/] Available: [dim]{avail}[/]")
        return pause()
    _render(hits, f"{hits[0].country}")
    report("VPN", f"Filtered to {q}: {len(hits)} servers")
    pause()


def countries() -> None:
    header("Countries", "How many free servers per country")
    if not _ensure():
        return pause()
    counts: dict[str, tuple[str, int]] = {}
    for s in _servers:
        name, n = counts.get(s.cc, (s.country, 0))
        counts[s.cc] = (name, n + 1)
    t = Table(title=f"{len(counts)} countries")
    t.add_column("CC", style="cyan")
    t.add_column("Country")
    t.add_column("Servers", justify="right", style="green")
    for cc, (name, n) in sorted(counts.items(), key=lambda x: -x[1][1]):
        t.add_row(cc, name, str(n))
    console.print(t)
    pause()


def measure_ping() -> None:
    header("Measure real ping", "Actual latency from YOU to each server (TCP handshake)")
    if not _ensure():
        return pause()
    scope = _ordered(_servers)[:60]  # cap the probe to the 60 best by speed
    console.print(f"[dim]Pinging {len(scope)} servers from your connection…[/]")
    with console.status("[grey50]measuring latency…[/]", spinner="dots"):
        measure_all(scope)
    reachable = [s for s in scope if s.real_ping is not None]
    if not reachable:
        console.print("[yellow]None answered — your network may block outbound "
                      "VPN ports. Try again or use a different server set.[/]")
        return pause()
    _render(reachable, "By real ping — lowest first")
    best = min(reachable, key=lambda s: s.real_ping)
    console.print(f"[green]Best:[/] {best.country} ({best.cc}) {best.host} — "
                  f"[bold]{best.real_ping:.0f} ms[/], {best.speed_mbps:.0f} Mbps")
    report("VPN", f"Measured ping; best {best.cc} {best.real_ping:.0f}ms")
    pause()


def details() -> None:
    header("Server details")
    if not _ensure():
        return pause()
    _render(_servers, "Servers", limit=20)
    s = _pick(_servers)
    if not s:
        return pause()
    info = _config_info(s)
    if s.real_ping is None:
        ports = [p for p in (info.get("port"), "443", "1194", "992") if p]
        s.real_ping = _tcp_ping(s.ip, list(dict.fromkeys(ports)))
    console.print(f"\n[bold cyan]{s.host}[/]  [dim]{s.ip}[/]")
    console.print(f"  Country    : {s.country} ({s.cc})")
    console.print("  Your ping  : " + (f"{s.real_ping:.0f} ms" if s.real_ping is not None
                                       else "[red]unreachable[/]")
                  + f"   [dim](server-reported {s.ping} ms)[/]")
    console.print(f"  Speed      : {s.speed_mbps:.1f} Mbps")
    console.print(f"  Sessions   : {s.sessions}   Uptime: {s.uptime_days}")
    console.print(f"  Encryption : {info.get('cipher') or 'AES-256-CBC (default)'} / "
                  f"{info.get('auth') or 'SHA1'}")
    console.print(f"  Transport  : {(info.get('proto') or 'udp').upper()} "
                  f":{info.get('port') or '?'}")
    pause()


def _write_config(s: VPNServer) -> Path | None:
    try:
        data = base64.b64decode(s.config_b64)
    except Exception:
        console.print("[red]This server has no valid OpenVPN config.[/]")
        return None
    out = Path.cwd() / f"vpngate_{s.cc}_{s.ip.replace('.', '-')}.ovpn"
    out.write_bytes(data)
    return out


def export_config() -> None:
    header("Export OpenVPN config", "Save a server's .ovpn file")
    if not _ensure():
        return pause()
    _render(_servers, "Pick a server", limit=25)
    s = _pick(_servers)
    if not s:
        return pause()
    path = _write_config(s)
    if not path:
        return pause()
    console.print(f"[green]Saved:[/] {path}")
    console.print(f"[dim]Connect with:[/] [cyan]openvpn --config \"{path}\"[/]  "
                  "[dim](needs OpenVPN + admin/root)[/]")
    report("VPN", f"Exported config {s.country} {s.ip}")
    pause()


def connect() -> None:
    header("Encrypt & connect (VPN tunnel)",
           "Establish an encrypted OpenVPN tunnel through a chosen server")
    if not _ensure():
        return pause()
    _render(_servers, "Pick a server", limit=25)
    s = _pick(_servers)
    if not s:
        return pause()

    # Surface the real ping and the actual tunnel encryption BEFORE committing.
    info = _config_info(s)
    if s.real_ping is None:
        ports = [p for p in (info.get("port"), "443", "1194", "992") if p]
        with console.status("[grey50]measuring latency…[/]", spinner="dots"):
            s.real_ping = _tcp_ping(s.ip, list(dict.fromkeys(ports)))
    cipher = info.get("cipher") or "AES-256-CBC (OpenVPN default)"
    auth = info.get("auth") or "SHA1"
    proto = (info.get("proto") or "udp").upper()
    console.print(f"\n[bold cyan]{s.country} ({s.cc})[/]  {s.host}  [dim]{s.ip}[/]")
    console.print("  Your ping  : " + (f"[bold]{s.real_ping:.0f} ms[/]"
                  if s.real_ping is not None else "[red]unreachable[/]"))
    console.print(f"  Encryption : [green]{cipher}[/] / {auth}  "
                  "[dim](encrypted tunnel)[/]")
    console.print(f"  Transport  : {proto} :{info.get('port') or '?'}   "
                  f"Speed: {s.speed_mbps:.0f} Mbps")

    path = _write_config(s)
    if not path:
        return pause()

    ovpn = ensure_openvpn()  # auto-installs if missing
    if ovpn is None:
        console.print(f"\n[dim]Config saved at [cyan]{path}[/]. Once OpenVPN is "
                      f"installed:[/]  [cyan]openvpn --config \"{path}\"[/]")
        return pause()

    console.print(f"\n[yellow]Connecting routes ALL your traffic through this "
                  f"volunteer relay in {s.country}. Needs admin; Ctrl+C to "
                  "disconnect.[/]")
    if Prompt.ask("Encrypt & connect now?", choices=["y", "n"], default="n") != "y":
        console.print(f"[dim]Config kept at {path}.[/]")
        return pause()
    report("VPN", f"Tunnel {s.country} {s.ip} cipher={cipher}")
    try:
        subprocess.run([ovpn, "--config", str(path)])
    except KeyboardInterrupt:
        console.print("\n[dim]Tunnel closed.[/]")
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]OpenVPN failed: {e}[/]")
    pause()


MENU = {
    "1": ("Fetch / refresh free VPN list", refresh),
    "2": ("List servers (fastest first)", list_all),
    "3": ("Filter by country", by_country),
    "4": ("Measure real ping (your latency)", measure_ping),
    "5": ("Countries + server counts", countries),
    "6": ("Server details + encryption", details),
    "7": ("Export OpenVPN config (.ovpn)", export_config),
    "8": ("Encrypt & connect (VPN tunnel)", connect),
}
