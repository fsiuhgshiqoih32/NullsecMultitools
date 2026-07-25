from __future__ import annotations

import re
from pathlib import Path

from rich.prompt import Prompt

from .utils import console, header, pause, report

# Ordered so the more specific patterns are shown first.
PATTERNS = {
    "URL": re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I),
    "Email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "IPv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "IPv6": re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.I),
    "Domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I),
    "SHA256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "SHA1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "MD5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "AWS Key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Bitcoin addr": re.compile(r"\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b"),
    "CVE": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "Credit-card-like": re.compile(r"\b(?:\d[ -]?){15,16}\b"),
}


def _get_text() -> str | None:
    src = Prompt.ask("[t]ext paste or [f]ile", choices=["t", "f"], default="t")
    if src == "f":
        p = Path(Prompt.ask("File path").strip('"'))
        if not p.is_file():
            console.print("[red]File not found.[/]")
            return None
        return p.read_text(encoding="utf-8", errors="ignore")
    console.print("[dim]Paste text, then finish with an empty line:[/]")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)


def _extract(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for name, rx in PATTERNS.items():
        vals = sorted({m.group(0) for m in rx.finditer(text)})
        if vals:
            found[name] = vals
    return found


def extract_all() -> None:
    header("IOC extractor", "Pull indicators (IPs, URLs, hashes, keys...) from text/files")
    text = _get_text()
    if text is None:
        return pause()
    found = _extract(text)
    if not found:
        console.print("[yellow]No indicators found.[/]")
        return pause()
    for name, vals in found.items():
        console.print(f"\n[bold magenta]{name}[/] ([green]{len(vals)}[/])")
        for v in vals[:30]:
            console.print(f"  {v}")
        if len(vals) > 30:
            console.print(f"  [dim]... +{len(vals) - 30} more[/]")
    total = sum(len(v) for v in found.values())
    report.log("extractor", "IOC extraction",
               [f"- {name}: {len(v)}" for name, v in found.items()])
    if Prompt.ask("\nSave all to iocs.txt?", choices=["y", "n"], default="n") == "y":
        out = Path.cwd() / "iocs.txt"
        with out.open("w", encoding="utf-8") as f:
            for name, vals in found.items():
                f.write(f"# {name}\n" + "\n".join(vals) + "\n\n")
        console.print(f"[green]Saved {total} indicators -> {out}[/]")
    pause()


def extract_one() -> None:
    header("Extract one type", "Harvest a single indicator type")
    names = list(PATTERNS)
    for i, n in enumerate(names, 1):
        console.print(f"  [cyan]{i:>2}[/] {n}")
    sel = Prompt.ask("Type number").strip()
    if not sel.isdigit() or not (1 <= int(sel) <= len(names)):
        console.print("[red]Invalid selection.[/]")
        return pause()
    name = names[int(sel) - 1]
    text = _get_text()
    if text is None:
        return pause()
    vals = sorted({m.group(0) for m in PATTERNS[name].finditer(text)})
    if not vals:
        console.print(f"[yellow]No {name} found.[/]")
        return pause()
    console.print(f"\n[bold]{len(vals)} {name}:[/]")
    for v in vals:
        console.print(f"  {v}")
    pause()


MENU = {
    "1": ("Extract ALL indicators", extract_all),
    "2": ("Extract one indicator type", extract_one),
}
