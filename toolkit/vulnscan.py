from __future__ import annotations

import subprocess

from rich.prompt import Prompt
from rich.table import Table

from .utils import (IS_WINDOWS, console, get_wsl_distro, header, pause,
                    resolve_tool, run_tool)


def _capture(args: list[str], timeout: int = 120) -> str:
    if IS_WINDOWS and get_wsl_distro():
        args = ["wsl", "-d", get_wsl_distro(), "--"] + args
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]command failed: {e}[/]")
        return ""


def _have_nuclei() -> bool:
    if resolve_tool("nuclei") is None:
        console.print("[yellow]nuclei not installed[/] (native or WSL). "
                      "Install via the Install Arsenal menu.")
        return False
    return True


def stats() -> None:
    header("Nuclei: template stats", "How many detections are available")
    if not _have_nuclei():
        return pause()
    total = _capture(["nuclei", "-tl", "-silent"])
    lines = [l for l in total.splitlines() if l.strip()]
    t = Table(show_header=False, box=None)
    t.add_row("Templates available", str(len(lines)))
    for sev in ("critical", "high", "medium", "low", "info"):
        out = _capture(["nuclei", "-tl", "-silent", "-severity", sev])
        n = len([l for l in out.splitlines() if l.strip()])
        t.add_row(f"  {sev}", str(n))
    console.print(t)
    pause()


def search() -> None:
    header("Nuclei: search templates", "Find detections by keyword (CVE, tech, tag)")
    if not _have_nuclei():
        return pause()
    kw = Prompt.ask("Keyword (e.g. wordpress, log4j, CVE-2023)").lower().strip()
    out = _capture(["nuclei", "-tl", "-silent"])
    hits = [l for l in out.splitlines() if kw in l.lower()]
    if not hits:
        console.print("[yellow]no templates matched.[/]")
        return pause()
    console.print(f"[bold]{len(hits)}[/] matching templates (showing 40):\n")
    for h in hits[:40]:
        console.print(f"  [green]{h.rsplit('/', 1)[-1]}[/]  [dim]{h}[/]")
    pause()


def scan() -> None:
    header("Nuclei: scan a target", "Authorized targets only — this actively probes")
    if not _have_nuclei():
        return pause()
    target = Prompt.ask("Target URL/host")
    mode = Prompt.ask("Filter by", choices=["severity", "tags", "all"], default="severity")
    args = ["nuclei", "-u", target]
    if mode == "severity":
        sev = Prompt.ask("Severity", default="critical,high,medium")
        args += ["-severity", sev]
    elif mode == "tags":
        tags = Prompt.ask("Tags (e.g. cve,rce,exposure)", default="cve")
        args += ["-tags", tags]

    console.print(f"\n[bold]About to scan[/] {target}. Only proceed if you're authorized.")
    if Prompt.ask("Proceed?", choices=["y", "n"], default="n") != "y":
        return pause()
    run_tool("nuclei", args[1:])
    pause()


MENU = {
    "1": ("Template stats (by severity)", stats),
    "2": ("Search templates", search),
    "3": ("Scan a target", scan),
}
