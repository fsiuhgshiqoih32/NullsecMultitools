from __future__ import annotations

import subprocess

from rich.prompt import Prompt
from rich.table import Table

from .utils import IS_WINDOWS, console, get_wsl_distro, header, pause

ROOTS = ["/usr/share/seclists", "/usr/share/wordlists"]


def _sh(args: list[str], timeout: int = 60) -> str:
    """Run a command list natively, or through WSL on Windows (no shell => no
    $-expansion or glob surprises)."""
    if IS_WINDOWS and get_wsl_distro():
        args = ["wsl", "-d", get_wsl_distro(), "--"] + args
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]command failed: {e}[/]")
        return ""


def _available_roots() -> list[str]:
    out = []
    for r in ROOTS:
        if _sh(["test", "-d", r, "&&", "echo", "y"]).strip() == "y" or \
           _sh(["ls", r]).strip():
            out.append(r)
    return out


def browse() -> None:
    header("Wordlists: browse", "Top-level collections and their file counts")
    roots = _available_roots()
    if not roots:
        console.print("[yellow]No wordlist collections found.[/] Install seclists "
                      "(Install Arsenal) or run nullsec where /usr/share/seclists exists.")
        return pause()
    for root in roots:
        listing = _sh(["find", root, "-maxdepth", "1", "-type", "d"])
        dirs = [d for d in listing.splitlines() if d and d != root]
        console.print(f"\n[bold cyan]{root}[/]  ({len(dirs)} categories)")
        for d in sorted(dirs)[:25]:
            console.print(f"  {d.rsplit('/', 1)[-1]}")
    console.print("\n[bright_black]use 'search' to find a specific list.[/]")
    pause()


def search() -> None:
    header("Wordlists: search", "Find lists by name across every collection")
    kw = Prompt.ask("Keyword (e.g. rockyou, admin, subdomains)").strip()
    hits = []
    for root in _available_roots():
        out = _sh(["find", root, "-iname", f"*{kw}*", "-type", "f"])
        hits += [h for h in out.splitlines() if h.strip()]
    if not hits:
        console.print("[yellow]No matching lists.[/]")
        return pause()
    t = Table(title=f"{len(hits)} matches for '{kw}'")
    t.add_column("Lines", justify="right", style="green")
    t.add_column("Path", overflow="fold")
    for path in sorted(hits)[:40]:
        lines = _sh(["wc", "-l", path]).split()
        count = lines[0] if lines else "?"
        t.add_row(count, path)
    console.print(t)
    console.print("\n[bright_black]feed one to a tool, e.g. Brute-force (9) or "
                  "hashes -> John.[/]")
    pause()


def preview() -> None:
    header("Wordlists: preview", "Line count + first entries of a list")
    path = Prompt.ask("Wordlist path").strip('"')
    wc = _sh(["wc", "-l", path]).split()
    if not wc:
        console.print("[red]Not found or unreadable.[/]")
        return pause()
    console.print(f"[bold]{wc[0]}[/] lines\n")
    head = _sh(["head", "-n", "20", path])
    console.print("[dim]" + head + "[/]")
    pause()


def rockyou() -> None:
    header("Wordlists: locate rockyou", "The classic password list")
    for root in ROOTS:
        out = _sh(["find", root, "-iname", "rockyou*", "-type", "f"])
        for path in out.splitlines():
            if path.strip():
                wc = _sh(["wc", "-l", path]).split()
                console.print(f"[green]{path}[/]  ({wc[0] if wc else '?'} lines)")
    console.print("\n[bright_black]if it's rockyou.txt.gz, gunzip it first.[/]")
    pause()


MENU = {
    "1": ("Browse collections", browse),
    "2": ("Search wordlists", search),
    "3": ("Preview a list", preview),
    "4": ("Locate rockyou", rockyou),
}
