from __future__ import annotations

import importlib.util
import random
import time
from dataclasses import dataclass
from pathlib import Path

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report, resource_path

# Test URL used to verify a proxy actually forwards traffic.
_TEST_URL = "https://httpbin.org/ip"
_TEST_TIMEOUT = 8  # seconds


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ProxyEntry:
    """A single proxy with its parsed components and test status."""
    raw: str           # original user input
    url: str           # normalized URL for requests (e.g. http://1.2.3.4:8080)
    scheme: str        # http, https, socks5, socks4
    host: str
    port: int
    username: str = ""
    password: str = ""
    latency: float | None = None    # seconds, None = untested
    working: bool | None = None     # None = untested, True/False after test
    last_tested: str = ""           # timestamp

    @property
    def label(self) -> str:
        """Short display label."""
        auth = f"{self.username}@{self.host}" if self.username else self.host
        return f"{self.scheme}://{auth}:{self.port}"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_proxy(raw: str) -> ProxyEntry | None:
    """Parse a proxy string into a ProxyEntry.

    Supported formats:
      ip:port                      -> http://ip:port
      ip:port:user:pass            -> http://user:pass@ip:port
      http://ip:port               -> http://ip:port
      https://ip:port              -> https://ip:port
      socks5://ip:port             -> socks5://ip:port
      socks5://user:pass@ip:port   -> socks5://user:pass@ip:port
      socks4://ip:port             -> socks4://ip:port
    """
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None

    scheme = "http"
    rest = raw

    # Extract scheme if present
    if "://" in raw:
        scheme, rest = raw.split("://", 1)
        scheme = scheme.lower()

    # Extract auth (user:pass@) if present
    username = password = ""
    if "@" in rest:
        auth_part, rest = rest.rsplit("@", 1)
        if ":" in auth_part:
            username, password = auth_part.split(":", 1)
        else:
            username = auth_part

    # Now rest should be ip:port
    parts = rest.split(":")
    if len(parts) == 4 and not scheme:
        # ip:port:user:pass format (no scheme)
        host, port, username, password = parts
        scheme = "http"
    elif len(parts) == 2:
        host, port = parts
    elif len(parts) == 4 and scheme:
        # scheme://ip:port:user:pass — unusual but handle it
        host, port, username, password = parts
    else:
        return None

    try:
        port = int(port)
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None

    # Build normalized URL
    if username:
        url = f"{scheme}://{username}:{password}@{host}:{port}"
    else:
        url = f"{scheme}://{host}:{port}"

    return ProxyEntry(
        raw=raw, url=url, scheme=scheme,
        host=host, port=port,
        username=username, password=password,
    )


# ---------------------------------------------------------------------------
# Proxy Manager
# ---------------------------------------------------------------------------

class ProxyManager:
    """Manages a list of proxies with testing, rotation, and export."""

    def __init__(self) -> None:
        self.proxies: list[ProxyEntry] = []
        self.enabled: bool = False
        self.rotation: str = "round-robin"  # or "random"
        self._rr_index: int = 0

    # -- loading / adding / removing ----------------------------------------

    def load_from_file(self, path: str | Path) -> int:
        """Load proxies from a text file. Returns count loaded."""
        p = Path(path)
        if not p.is_file():
            return 0
        count = 0
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            entry = parse_proxy(line)
            if entry is not None:
                self.proxies.append(entry)
                count += 1
        return count

    def add(self, raw: str) -> bool:
        """Add a single proxy. Returns True if parsed successfully."""
        entry = parse_proxy(raw)
        if entry is None:
            return False
        self.proxies.append(entry)
        return True

    def remove(self, index: int) -> bool:
        """Remove proxy at 0-based index."""
        if 0 <= index < len(self.proxies):
            self.proxies.pop(index)
            return True
        return False

    def clear(self) -> None:
        self.proxies.clear()
        self._rr_index = 0

    def keep_working_only(self) -> int:
        """Remove all proxies that failed testing. Returns count removed."""
        before = len(self.proxies)
        self.proxies = [p for p in self.proxies if p.working is not False]
        return before - len(self.proxies)

    # -- rotation -----------------------------------------------------------

    def get_next(self) -> ProxyEntry | None:
        """Get the next proxy based on rotation mode."""
        usable = [p for p in self.proxies if p.working is not False]
        if not usable:
            return None
        if self.rotation == "random":
            return random.choice(usable)
        # round-robin
        entry = usable[self._rr_index % len(usable)]
        self._rr_index = (self._rr_index + 1) % len(usable)
        return entry

    def get_requests_proxies(self) -> dict | None:
        """Return a dict suitable for requests(proxies=...), or None."""
        if not self.enabled:
            return None
        entry = self.get_next()
        if entry is None:
            return None
        return {"http": entry.url, "https": entry.url}

    # -- testing ------------------------------------------------------------

    def test_all(self, timeout: float = _TEST_TIMEOUT,
                 test_url: str = _TEST_URL) -> None:
        """Test all proxies concurrently, updating latency and working status."""
        import requests
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # SOCKS proxies need PySocks (the `socks` module) installed.
        has_socks = importlib.util.find_spec("socks") is not None

        def _test_one(entry: ProxyEntry) -> None:
            if entry.scheme.startswith("socks") and not has_socks:
                entry.working = False
                entry.latency = None
                entry.last_tested = time.strftime("%H:%M:%S")
                return
            proxies = {"http": entry.url, "https": entry.url}
            start = time.monotonic()
            try:
                r = requests.get(test_url, proxies=proxies,
                                 timeout=timeout, verify=False)
                entry.latency = round(time.monotonic() - start, 2)
                entry.working = r.status_code == 200
            except Exception:
                entry.latency = None
                entry.working = False
            entry.last_tested = time.strftime("%H:%M:%S")

        # Suppress InsecureRequestWarning
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeRemainingColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("Testing proxies", total=len(self.proxies))
            with ThreadPoolExecutor(max_workers=20) as pool:
                futs = {pool.submit(_test_one, p): p for p in self.proxies}
                for fut in as_completed(futs):
                    fut.result()
                    prog.advance(task)

    # -- export -------------------------------------------------------------

    def export_working(self, path: str | Path) -> int:
        """Save working proxies to a file. Returns count saved."""
        working = [p for p in self.proxies if p.working is True]
        lines = [p.url for p in working]
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return len(working)

    # -- stats --------------------------------------------------------------

    def stats(self) -> tuple[int, int, int]:
        """Return (total, working, failed)."""
        total = len(self.proxies)
        working = sum(1 for p in self.proxies if p.working is True)
        failed = sum(1 for p in self.proxies if p.working is False)
        return total, working, failed


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_manager: ProxyManager | None = None


def get_manager() -> ProxyManager:
    global _manager
    if _manager is None:
        _manager = ProxyManager()
    return _manager


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def load_proxies() -> None:
    header("Load proxies", "Load from a file or the built-in list")
    choice = Prompt.ask("Source", choices=["built-in", "file"], default="built-in")
    if choice == "built-in":
        path = resource_path("data", "proxies.txt")
        if not path.is_file():
            console.print("[red]Built-in proxy list not found.[/]")
            return pause()
    else:
        path = Prompt.ask("File path").strip().strip('"')
        if not Path(path).is_file():
            console.print("[red]File not found.[/]")
            return pause()
    mgr = get_manager()
    count = mgr.load_from_file(path)
    if count == 0:
        console.print("[yellow]No valid proxies found in file.[/]")
        return pause()
    console.print(f"[green]Loaded {count} proxy(ies).[/]")
    report("proxy", f"Loaded {count} proxies from {path.name}")
    pause()


def add_proxy() -> None:
    header("Add proxy", "Enter a proxy in any supported format")
    raw = Prompt.ask("Proxy (e.g. 1.2.3.4:8080 or socks5://1.2.3.4:1080)")
    mgr = get_manager()
    if mgr.add(raw):
        console.print(f"[green]Added:[/] {mgr.proxies[-1].label}")
    else:
        console.print("[red]Invalid proxy format.[/]")
    pause()


def list_proxies() -> None:
    header("Proxy list")
    mgr = get_manager()
    if not mgr.proxies:
        console.print("[yellow]No proxies loaded. Use 'Load proxies' first.[/]")
        return pause()
    tbl = Table(title=f"{len(mgr.proxies)} proxy(ies)")
    tbl.add_column("#", justify="right", style="dim")
    tbl.add_column("Proxy", style="cyan")
    tbl.add_column("Scheme", style="magenta")
    tbl.add_column("Status")
    tbl.add_column("Latency", justify="right")
    for i, p in enumerate(mgr.proxies):
        if p.working is True:
            status = "[green]working[/]"
        elif p.working is False:
            status = "[red]failed[/]"
        else:
            status = "[dim]untested[/]"
        latency = f"{p.latency}s" if p.latency is not None else "-"
        tbl.add_row(str(i), p.label, p.scheme, status, latency)
    console.print(tbl)
    pause()


def remove_proxy() -> None:
    header("Remove proxy")
    mgr = get_manager()
    if not mgr.proxies:
        console.print("[yellow]No proxies loaded.[/]")
        return pause()
    console.print(f"[dim]{len(mgr.proxies)} proxies loaded (0–{len(mgr.proxies) - 1})[/]")
    idx = Prompt.ask("Index to remove (or 'all')", default="0").strip()
    if idx.lower() == "all":
        mgr.clear()
        console.print("[green]Cleared all proxies.[/]")
        return pause()
    try:
        i = int(idx)
    except ValueError:
        console.print("[red]Invalid index.[/]")
        return pause()
    if mgr.remove(i):
        console.print(f"[green]Removed proxy at index {i}.[/]")
    else:
        console.print(f"[red]Index {i} out of range.[/]")
    pause()


def test_proxies() -> None:
    header("Test proxies", "Check connectivity and measure latency")
    mgr = get_manager()
    if not mgr.proxies:
        console.print("[yellow]No proxies loaded.[/]")
        return pause()
    timeout = float(Prompt.ask("Timeout per proxy (s)", default="8"))
    mgr.test_all(timeout=timeout)
    total, working, failed = mgr.stats()
    console.print(f"\n[green]Working:[/] {working}  [red]Failed:[/] {failed}"
                  f"  [dim]Total:[/] {total}")
    report.log("proxy", "Proxy test complete",
               [f"- Working: {working}", f"- Failed: {failed}",
                f"- Total: {total}"])
    keep = Prompt.ask("\nKeep only working proxies?", choices=["y", "n"], default="n")
    if keep == "y":
        removed = mgr.keep_working_only()
        console.print(f"[green]Kept {len(mgr.proxies)} working proxy(ies), "
                      f"removed {removed}.[/]")
    pause()


def show_stats() -> None:
    header("Proxy statistics")
    mgr = get_manager()
    total, working, failed = mgr.stats()
    untested = total - working - failed
    console.print(f"  [bold]Total:[/]     {total}")
    console.print(f"  [green]Working:[/]   {working}")
    console.print(f"  [red]Failed:[/]    {failed}")
    console.print(f"  [dim]Untested:[/]  {untested}")
    console.print(f"  [bold]Enabled:[/]   {'[green]yes[/]' if mgr.enabled else '[red]no[/]'}")
    console.print(f"  [bold]Rotation:[/]  {mgr.rotation}")
    pause()


def export_working() -> None:
    header("Export working proxies")
    mgr = get_manager()
    working = [p for p in mgr.proxies if p.working is True]
    if not working:
        console.print("[yellow]No working proxies to export. Test first.[/]")
        return pause()
    path = Prompt.ask("Output file", default="working_proxies.txt")
    count = mgr.export_working(path)
    console.print(f"[green]Exported {count} working proxy(ies) to {path}[/]")
    pause()


def clear_proxies() -> None:
    header("Clear all proxies")
    mgr = get_manager()
    if not mgr.proxies:
        console.print("[yellow]Already empty.[/]")
        return pause()
    confirm = Prompt.ask("Remove all proxies?", choices=["y", "n"], default="n")
    if confirm == "y":
        mgr.clear()
        console.print("[green]Cleared.[/]")
    else:
        console.print("[yellow]Cancelled.[/]")
    pause()


def toggle_proxy() -> None:
    header("Toggle proxy on/off")
    mgr = get_manager()
    if mgr.enabled:
        mgr.enabled = False
        console.print("[yellow]Proxy disabled.[/] Requests will go direct.")
    else:
        if not mgr.proxies:
            console.print("[yellow]No proxies loaded. Load some first.[/]")
            return pause()
        mgr.enabled = True
        console.print("[green]Proxy enabled.[/] Requests will use the proxy manager.")
    report("proxy", f"Proxy {'enabled' if mgr.enabled else 'disabled'}")
    pause()


def set_rotation() -> None:
    header("Set rotation mode")
    mgr = get_manager()
    mode = Prompt.ask("Rotation mode", choices=["round-robin", "random"],
                      default=mgr.rotation)
    mgr.rotation = mode
    console.print(f"[green]Rotation set to:[/] {mode}")
    pause()


MENU = {
    "1": ("Load proxies (built-in or file)", load_proxies),
    "2": ("Add proxy manually", add_proxy),
    "3": ("List all proxies", list_proxies),
    "4": ("Remove proxy", remove_proxy),
    "5": ("Test all proxies", test_proxies),
    "6": ("Show statistics", show_stats),
    "7": ("Export working proxies", export_working),
    "8": ("Clear all proxies", clear_proxies),
    "9": ("Toggle proxy on/off", toggle_proxy),
    "10": ("Set rotation mode", set_rotation),
}
