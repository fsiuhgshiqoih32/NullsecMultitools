from __future__ import annotations

import email
import email.policy
import hashlib
import re
from email.utils import parsedate_to_datetime
from pathlib import Path

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)

DANGEROUS_EXT = (".exe", ".scr", ".js", ".vbs", ".jar", ".docm", ".xlsm",
                 ".zip", ".iso", ".lnk", ".hta", ".cmd", ".bat")


def _load_eml():
    p = Path(Prompt.ask("Path to .eml file").strip('"'))
    if not p.is_file():
        console.print("[red]File not found.[/]")
        return None
    try:
        return email.message_from_bytes(p.read_bytes(), policy=email.policy.default)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Couldn't parse email: {e}[/]")
        return None


def _defang(s: str) -> str:
    return (s.replace("http://", "hxxp://").replace("https://", "hxxps://")
             .replace(".", "[.]").replace("@", "[at]"))


def _refang(s: str) -> str:
    return (s.replace("hxxps://", "https://").replace("hxxp://", "http://")
             .replace("[.]", ".").replace("(.)", ".").replace("[at]", "@")
             .replace("[:]", ":"))


def analyze_eml() -> None:
    header("Email (.eml) analyzer", "Headers, auth results, URLs, and attachments")
    msg = _load_eml()
    if msg is None:
        return pause()
    t = Table(show_header=False, box=None)
    for h in ("From", "To", "Subject", "Date", "Return-Path", "Reply-To", "Message-ID"):
        if msg[h]:
            t.add_row(h, str(msg[h])[:100])
    console.print(t)

    auth = (msg["Authentication-Results"] or "").lower()

    def verdict(kind: str) -> str:
        if f"{kind}=pass" in auth:
            return "[green]pass[/]"
        if f"{kind}=" in auth:
            return "[red]fail[/]"
        return "[yellow]?[/]"

    console.print(f"\n[bold]SPF:[/] {verdict('spf')}   [bold]DKIM:[/] {verdict('dkim')}"
                  f"   [bold]DMARC:[/] {verdict('dmarc')}")
    # Header From vs Return-Path mismatch is a classic spoof tell.
    frm = str(msg["From"] or "")
    rp = str(msg["Return-Path"] or "")
    if frm and rp and "@" in frm and "@" in rp:
        if frm.rsplit("@", 1)[-1].strip(">") != rp.rsplit("@", 1)[-1].strip(">"):
            console.print("[yellow][!] From domain != Return-Path domain (possible spoof)[/]")

    body = ""
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        if part.get_content_type() == "text/plain":
            try:
                body += part.get_content()
            except Exception:  # noqa: BLE001
                pass
    urls = sorted(set(URL_RE.findall(body)))
    if urls:
        console.print(f"\n[bold]{len(urls)} URL(s) (defanged):[/]")
        for u in urls[:25]:
            console.print(f"  [cyan]{_defang(u)}[/]")

    atts = []
    for part in msg.walk():
        fn = part.get_filename()
        if fn:
            payload = part.get_payload(decode=True) or b""
            atts.append((fn, len(payload), hashlib.sha256(payload).hexdigest()[:16]))
    if atts:
        console.print(f"\n[bold]{len(atts)} attachment(s):[/]")
        at = Table()
        at.add_column("Name", style="bold")
        at.add_column("Size", justify="right")
        at.add_column("SHA256 (short)", style="dim")
        for fn, sz, h in atts:
            danger = fn.lower().endswith(DANGEROUS_EXT)
            at.add_row(f"[red]{fn}[/]" if danger else fn, str(sz), h)
        console.print(at)
    report.log("email", f"Analyzed: {msg['Subject']}",
               ["- SPF/DKIM/DMARC from Authentication-Results",
                f"- {len(urls)} URLs, {len(atts)} attachments"])
    pause()


def header_hops() -> None:
    header("Received-hop analysis", "Trace the path an email took, with timestamps")
    msg = _load_eml()
    if msg is None:
        return pause()
    received = msg.get_all("Received", [])
    if not received:
        console.print("[yellow]No Received headers.[/]")
        return pause()
    hops = list(reversed(received))  # newest-first in the file -> oldest-first here
    t = Table(title=f"{len(hops)} hops (oldest first)")
    t.add_column("#", justify="right")
    t.add_column("from -> by", overflow="fold")
    t.add_column("time", style="dim")
    for i, h in enumerate(hops, 1):
        flat = " ".join(h.split())
        when = ""
        if ";" in flat:
            try:
                when = parsedate_to_datetime(flat.rsplit(";", 1)[1].strip()).strftime("%H:%M:%S")
            except Exception:  # noqa: BLE001
                pass
        frm = re.search(r"from\s+(\S+)", flat)
        by = re.search(r"by\s+(\S+)", flat)
        t.add_row(str(i), f"{frm.group(1) if frm else '?'} -> {by.group(1) if by else '?'}", when)
    console.print(t)
    pause()


def defang_tool() -> None:
    header("Defang / refang", "Make IOCs safe to share, or restore them")
    mode = Prompt.ask("[d]efang or [r]efang", choices=["d", "r"], default="d")
    s = Prompt.ask("URL / IP / text")
    console.print(f"[green]{_defang(s) if mode == 'd' else _refang(s)}[/]")
    pause()


# A small confusables map (Cyrillic/fullwidth -> ASCII lookalikes).
CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u051b": "q",
    "\uff10": "0", "\uff11": "1",
}


def homograph() -> None:
    header("Homograph / IDN detector", "Spot lookalike + punycode domains")
    d = Prompt.ask("Domain").strip()
    issues = []
    if d.startswith("xn--") or ".xn--" in d:
        issues.append("Contains a punycode (xn--) label -- decode it to compare visually.")
    try:
        as_idna = d.encode("idna").decode()
        if "xn--" in as_idna and as_idna != d.lower():
            issues.append(f"Encodes to punycode: {as_idna}")
    except Exception:  # noqa: BLE001
        pass
    non_ascii = [c for c in d if ord(c) > 127]
    if non_ascii:
        issues.append("Non-ASCII characters: " + " ".join(f"U+{ord(c):04X}" for c in non_ascii))
        mapped = "".join(CONFUSABLES.get(c, c) for c in d)
        if mapped != d:
            issues.append(f"Looks like: [bold]{mapped}[/] (confusable characters)")
    if issues:
        for i in issues:
            console.print(f"[yellow][!] {i}[/]")
    else:
        console.print("[green]Pure ASCII, no obvious homograph tricks.[/]")
    pause()


def typosquat() -> None:
    header("Typosquat generator", "Permutations attackers register to impersonate a domain")
    d = Prompt.ask("Domain (e.g. example.com)").strip().lower()
    if "." not in d:
        console.print("[red]Enter a full domain with a TLD.[/]")
        return pause()
    name, tld = d.split(".", 1)
    variants: set[str] = set()
    for i in range(len(name)):                       # omission
        variants.add(name[:i] + name[i + 1:] + "." + tld)
    for i in range(len(name) - 1):                   # transposition
        variants.add(name[:i] + name[i + 1] + name[i] + name[i + 2:] + "." + tld)
    for i in range(len(name)):                       # repetition
        variants.add(name[:i] + name[i] + name[i:] + "." + tld)
    homo = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "@", "s": "5"}
    for i, c in enumerate(name):                     # homoglyph
        if c in homo:
            variants.add(name[:i] + homo[c] + name[i + 1:] + "." + tld)
    for t in ("com", "net", "org", "co", "io", "info", "biz"):  # TLD swap
        if t != tld:
            variants.add(name + "." + t)
    variants.add(name + "-secure." + tld)
    variants.add("secure-" + name + "." + tld)
    variants.discard(d)
    out = sorted(v for v in variants if len(v.split(".")[0]) >= 2)
    console.print(f"[bold]{len(out)}[/] candidate typosquats:\n")
    for v in out[:60]:
        console.print(f"  {v}")
    p = Path.cwd() / f"typosquat_{name}.txt"
    p.write_text("\n".join(out) + "\n", encoding="utf-8")
    console.print(f"\n[dim]Saved to {p}. Check DNS/registration to find active ones.[/]")
    pause()


MENU = {
    "1": ("Analyze a .eml (headers/auth/URLs/attachments)", analyze_eml),
    "2": ("Received-hop path analysis", header_hops),
    "3": ("Defang / refang IOCs", defang_tool),
    "4": ("Homograph / IDN detector", homograph),
    "5": ("Typosquat generator", typosquat),
}
