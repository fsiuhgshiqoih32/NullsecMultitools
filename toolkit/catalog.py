from __future__ import annotations

import json
import shutil
import subprocess

from rich.prompt import Prompt
from rich.table import Table

from .catalog_data import SEED_TOOLS
from .utils import console, header, pause, run_external, resource_path

_DATA_FILE = resource_path("data", "tools.json")

# Honest estimates of what the big external DBs expose once installed.
EXTERNAL_DBS = {
    "Exploit-DB (searchsploit)": 46636,  # actual count installed on this box
    "Nuclei templates": 9000,
    "Metasploit modules": 2300,
}


def _load_imported() -> list[tuple]:
    if not _DATA_FILE.is_file():
        return []
    try:
        raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
        return [tuple(x) for x in raw]
    except Exception:
        return []


def all_tools() -> list[tuple]:
    seen = {t[0].lower() for t in SEED_TOOLS}
    extra = [t for t in _load_imported() if t[0].lower() not in seen]
    return SEED_TOOLS + extra


def local_count() -> int:
    return len(all_tools())


def indexed_total() -> int:
    """Everything reachable: curated tools + external DB modules."""
    return local_count() + sum(EXTERNAL_DBS.values())


def _categories() -> dict[str, int]:
    counts: dict[str, int] = {}
    for _n, cat, *_ in all_tools():
        counts[cat] = counts.get(cat, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def _render(tools: list[tuple], title: str) -> None:
    t = Table(title=title)
    t.add_column("Tool", style="bold cyan")
    t.add_column("Cat", style="magenta")
    t.add_column("Description", style="dim", overflow="fold")
    t.add_column("Installed", justify="center")
    for name, cat, desc, _install, binary in tools:
        installed = "[green]yes[/]" if binary and shutil.which(binary) else "[dim]-[/]"
        t.add_row(name, cat, desc, installed)
    console.print(t)


def browse() -> None:
    header("Tool catalog · browse", "By category")
    cats = _categories()
    t = Table()
    t.add_column("#", justify="right", style="cyan")
    t.add_column("Category", style="bold")
    t.add_column("Tools", justify="right")
    keys = list(cats)
    for i, k in enumerate(keys, 1):
        t.add_row(str(i), k, str(cats[k]))
    console.print(t)
    sel = Prompt.ask("Category number (or blank for all)", default="").strip()
    if sel.isdigit() and 1 <= int(sel) <= len(keys):
        cat = keys[int(sel) - 1]
        _render([x for x in all_tools() if x[1] == cat], f"{cat} tools")
    else:
        _render(all_tools(), "All catalog tools")
    _detail_prompt()


def search() -> None:
    header("Tool catalog · search", "Match name, category, or description")
    q = Prompt.ask("Keyword").lower().strip()
    hits = [x for x in all_tools()
            if q in x[0].lower() or q in x[1].lower() or q in x[2].lower()]
    if not hits:
        console.print("[yellow]No matches in the local catalog.[/] "
                      "Try the Exploit-DB/Nuclei/Metasploit search for live modules.")
        return pause()
    _render(hits, f"{len(hits)} matches for '{q}'")
    _detail_prompt()


def _detail_prompt() -> None:
    name = Prompt.ask("\nTool name for details/launch (blank = back)", default="").strip()
    if not name:
        return
    match = next((x for x in all_tools() if x[0].lower() == name.lower()), None)
    if not match:
        console.print("[red]Not in catalog.[/]")
        return pause()
    _detail(match)


def _detail(tool: tuple) -> None:
    name, cat, desc, install, binary = tool
    console.print(f"\n[bold cyan]{name}[/]  [magenta]({cat})[/]")
    console.print(f"{desc}")
    console.print(f"[dim]Install:[/] {install}")
    path = shutil.which(binary) if binary else None
    if path:
        console.print(f"[green]Installed at:[/] {path}")
        if Prompt.ask(f"Run '{binary} --help'?", choices=["y", "n"], default="n") == "y":
            _safe_help(binary)
    else:
        console.print("[yellow]Not installed on this machine.[/] "
                      f"Install with: [cyan]{install}[/]")
    pause()


def _safe_help(binary: str) -> None:
    for flag in ("--help", "-h"):
        try:
            r = subprocess.run([binary, flag], text=True, capture_output=True, timeout=8)
            out = (r.stdout or r.stderr).strip()
            if out:
                console.print("[dim]" + "\n".join(out.splitlines()[:30]) + "[/]")
                return
        except Exception:
            continue
    console.print("[dim](no help output)[/]")


# --- external DB front-ends (the 10,000+ real modules) ----------------------

def exploitdb_search() -> None:
    header("Exploit-DB", "Search ~45,000 exploits via searchsploit")
    if not require_tool_generic("searchsploit", "apt install exploitdb"):
        return pause()
    q = Prompt.ask("Search terms (e.g. wordpress 5.0)")
    run_external(["searchsploit", *q.split()])
    pause()


def nuclei_scan() -> None:
    header("Nuclei", "Run ~9,000 community vuln templates against a target")
    if not require_tool_generic("nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"):
        return pause()
    target = Prompt.ask("Target URL")
    sev = Prompt.ask("Severity filter", default="low,medium,high,critical")
    run_external(["nuclei", "-u", target, "-severity", sev])
    pause()


def metasploit_search() -> None:
    header("Metasploit", "Search ~2,300 exploit/aux modules")
    if not require_tool_generic("msfconsole", "apt install metasploit-framework"):
        return pause()
    q = Prompt.ask("Search terms (e.g. type:exploit eternalblue)")
    run_external(["msfconsole", "-q", "-x", f"search {q}; exit"])
    pause()


def require_tool_generic(binary: str, install: str) -> bool:
    if shutil.which(binary):
        return True
    console.print(f"[yellow]{binary}[/] not installed. Get it with: [cyan]{install}[/]")
    return False


def import_blackarch() -> None:
    header("Expand catalog", "Pull the real BlackArch tool inventory (~2,800 tools)")
    console.print("[dim]This fetches the public BlackArch tools list over HTTPS and "
                  "merges the names into your catalog. Network required.[/]")
    if Prompt.ask("Proceed?", choices=["y", "n"], default="n") != "y":
        return
    try:
        import re
        import requests

        r = requests.get("https://blackarch.org/tools.html", timeout=20)
        r.raise_for_status()
        # Tool rows look like: <td>name</td><td>version</td><td>description</td>
        rows = re.findall(r"<tr[^>]*>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>.*?</td>\s*<td[^>]*>(.*?)</td>",
                          r.text, re.S)
        cleaned = []
        for name, desc in rows:
            name = re.sub(r"<[^>]+>", "", name).strip()
            desc = re.sub(r"<[^>]+>", "", desc).strip()[:120]
            if name:
                cleaned.append([name, "blackarch", desc or "BlackArch tool",
                                "pacman -S " + name, name])
        if not cleaned:
            console.print("[yellow]Couldn't parse the tool list (site format may have "
                          "changed). Catalog unchanged.[/]")
            return pause()
        _DATA_FILE.parent.mkdir(exist_ok=True)
        existing = _load_imported()
        have = {t[0].lower() for t in existing} | {t[0].lower() for t in SEED_TOOLS}
        merged = existing + [t for t in cleaned if t[0].lower() not in have]
        _DATA_FILE.write_text(json.dumps(merged, indent=1), encoding="utf-8")
        console.print(f"[green]Imported {len(merged)} tools.[/] "
                      f"Catalog now lists [bold]{local_count()}[/] local tools.")
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Import failed: {e}[/]")
        console.print("[dim]No problem — the curated catalog and external DBs still work.[/]")
    pause()


MENU = {
    "1": ("Browse tools by category", browse),
    "2": ("Search the catalog", search),
    "3": ("Exploit-DB search (~45,000)", exploitdb_search),
    "4": ("Nuclei templates (~9,000)", nuclei_scan),
    "5": ("Metasploit modules (~2,300)", metasploit_search),
    "6": ("Expand catalog (import BlackArch ~2,800)", import_blackarch),
}
