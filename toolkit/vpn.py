from __future__ import annotations

import base64
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import requests
from rich.prompt import Prompt
from rich.table import Table

from .utils import console, get_proxy, header, pause, report

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


# --- display helpers --------------------------------------------------------

def _render(servers: list[VPNServer], title: str, limit: int = 40) -> None:
    servers = sorted(servers, key=lambda s: s.speed, reverse=True)
    t = Table(title=f"{title} ({len(servers)})"
              + (f" — showing top {limit}" if len(servers) > limit else ""))
    t.add_column("#", justify="right", style="dim")
    t.add_column("Country", style="cyan")
    t.add_column("Host / IP", overflow="fold")
    t.add_column("Ping", justify="right")
    t.add_column("Speed", justify="right", style="green")
    t.add_column("Sessions", justify="right")
    t.add_column("Uptime", justify="right", style="dim")
    for i, s in enumerate(servers[:limit]):
        t.add_row(str(i), f"{s.country} ({s.cc})", f"{s.host}  [dim]{s.ip}[/]",
                  f"{s.ping}ms", f"{s.speed_mbps:.1f} Mbps", s.sessions, s.uptime_days)
    console.print(t)


def _pick(servers: list[VPNServer], prompt: str = "Server #") -> VPNServer | None:
    servers = sorted(servers, key=lambda s: s.speed, reverse=True)
    idx = Prompt.ask(prompt, default="0").strip()
    if not idx.isdigit() or not (0 <= int(idx) < len(servers)):
        console.print("[red]Invalid selection.[/]")
        return None
    return servers[int(idx)]


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


def details() -> None:
    header("Server details")
    if not _ensure():
        return pause()
    _render(_servers, "Servers", limit=20)
    s = _pick(_servers)
    if not s:
        return pause()
    console.print(f"\n[bold cyan]{s.host}[/]  [dim]{s.ip}[/]")
    console.print(f"  Country : {s.country} ({s.cc})")
    console.print(f"  Ping    : {s.ping} ms")
    console.print(f"  Speed   : {s.speed_mbps:.1f} Mbps")
    console.print(f"  Sessions: {s.sessions}   Uptime: {s.uptime_days}")
    console.print(f"  Config  : {'yes' if s.config_b64 else 'no'} (OpenVPN)")
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
    header("Connect via OpenVPN", "Launch OpenVPN with a server's config")
    if shutil.which("openvpn") is None:
        console.print("[yellow]OpenVPN isn't installed / on PATH.[/] Install it "
                      "(openvpn.net) or use 'Export config' and connect manually.")
        return pause()
    if not _ensure():
        return pause()
    _render(_servers, "Pick a server", limit=25)
    s = _pick(_servers)
    if not s:
        return pause()
    path = _write_config(s)
    if not path:
        return pause()
    console.print(f"[yellow]This routes ALL your traffic through {s.country} "
                  f"({s.ip}) — a volunteer relay. Ctrl+C to disconnect.[/]")
    if Prompt.ask("Connect now?", choices=["y", "n"], default="n") != "y":
        return pause()
    report("VPN", f"Connect {s.country} {s.ip}")
    try:
        subprocess.run(["openvpn", "--config", str(path)])
    except KeyboardInterrupt:
        console.print("\n[dim]Disconnected.[/]")
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]OpenVPN failed: {e}[/]")
    pause()


MENU = {
    "1": ("Fetch / refresh free VPN list", refresh),
    "2": ("List servers (fastest first)", list_all),
    "3": ("Filter by country", by_country),
    "4": ("Countries + server counts", countries),
    "5": ("Server details", details),
    "6": ("Export OpenVPN config (.ovpn)", export_config),
    "7": ("Connect via OpenVPN", connect),
}
