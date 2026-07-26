from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path

# Enable ANSI colors on legacy Windows terminals, and make output UTF-8 so
# box glyphs / symbols don't crash on a cp1252 console.
os.system("")
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# Auto-install any missing Python dependencies before we import them (no-op in
# the frozen exe, where everything is bundled).
from toolkit import bootstrap  # noqa: E402  (must precede the rich/toolkit imports)
bootstrap.ensure()

from rich import box
from rich.columns import Columns
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from toolkit import (__version__, adattacks, ai, arsenal, bruteforce, catalog,
                     cloud, crypto, cryptotools, database, detect,
                     email_analyzer, evasion, offense, extractor, forensics,
                     generators, hardware, hashes, installer, interceptor, iot,
                     lolbins, metadata, mobile, network, osint, passwords,
                     payloadenc, postex, recipe, recon, reversing, smb, stego,
                     proxy, shodan, chainrecon, attacksurface, toolbox, vpn,
                     vulnscan, web, wireless, wordlists, workspace)
from toolkit.utils import (IS_WINDOWS, console, detect_tools, get_wsl_distro,
                           probe_tools, render_banner, report, resource_path,
                           wsl_available)

BANNER = render_banner("nullsec")
BANNER_STYLE = "grey70"  # calm grey wordmark; renders cleanly on any terminal

CATEGORIES = {
    "1": ("Reconnaissance", recon.MENU, "Resolve hosts, scan ports, hand off to nmap"),
    "2": ("Hashes & Cracking", hashes.MENU, "Identify, compute, crack (John/hashcat)"),
    "3": ("Crypto & Encoding", crypto.MENU, "Decode blobs, break Caesar/XOR ciphers"),
    "4": ("Passwords", passwords.MENU, "Strength checks and targeted wordlists"),
    "5": ("Web", web.MENU, "Headers/TLS/CORS/methods, dir brute, fingerprint"),
    "6": ("Network", network.MENU, "Host discovery, rDNS, ARP, local info"),
    "7": ("Payload Arsenal", arsenal.MENU, "Reverse/bind/web shells, msfvenom, listeners"),
    "8": ("Tool Catalog", catalog.MENU, "Index + launch 10,000+ real tools/exploits"),
    "9": ("Brute-force", bruteforce.MENU, "hydra login brute (native or via WSL)"),
    "v": ("Vuln Scan", vulnscan.MENU, "Nuclei ~9,000 templates: browse/search/scan"),
    "a": ("AD Attacks", adattacks.MENU, "Kerberoast / AS-REP roast (Impacket)"),
    "l": ("LOLBins", lolbins.MENU, "GTFOBins / LOLBAS abuse lookup"),
    "k": ("Wireless", wireless.MENU, "WPA/PMKID crack + capture guides"),
    "n": ("SMB / Shares", smb.MENU, "Enumerate SMB shares/users (netexec/smbmap)"),
    "x": ("Post-Exploitation", postex.MENU, "Privesc enum, NTLM relay, spray, pivot"),
    "b": ("Databases", database.MENU, "Exposed DB scan, MSSQL xp_cmdshell, brute"),
    "u": ("Cloud", cloud.MENU, "Metadata SSRF, prowler/pacu, trivy, k8s"),
    "y": ("Mobile", mobile.MENU, "APK decode/decompile, secret hunt, Frida"),
    "e": ("Reversing", reversing.MENU, "radare2/rabin2, ROP, RE cheat sheet"),
    "c": ("Cipher Lab", cryptotools.MENU, "XOR/Vigenere breakers, Morse, JWT crack"),
    "f": ("Forensics", forensics.MENU, "strings, carver, entropy, secret scanner"),
    "o": ("OSINT & DNS", osint.MENU, "Raw DNS, WHOIS, CIDR, favicon hash, dorks"),
    "m": ("Metadata", metadata.MENU, "Harvest author/software/paths from documents"),
    "g": ("Generators", generators.MENU, "Passphrases, wordlists, markov, HIBP check"),
    "w": ("Wordlists", wordlists.MENU, "Browse/search SecLists & wordlists"),
    "s": ("Steganography", stego.MENU, "Hide/extract data in text & images"),
    "p": ("Payload Forge", payloadenc.MENU, "Encoders, XSS/SQLi, shell stabilization"),
    "h": ("HTTP Interceptor", interceptor.MENU, "Catch-all listener, file server, repeater"),
    "d": ("Detection", detect.MENU, "Sigma/YARA rules, scan, detection matrix"),
    "i": ("Install Arsenal", installer.MENU, "Install the real tools (WSL BlackArch)"),
    "j": ("Email / Phishing", email_analyzer.MENU, "Parse .eml, SPF/DKIM/DMARC, defang, typosquat"),
    "z": ("Data Extractor", extractor.MENU, "Harvest IOCs (IPs/URLs/hashes/keys) from text"),
    "0": ("Encoding Recipe", recipe.MENU, "Chain transforms CyberChef-style"),
    "E": ("Evasion & Bypass", evasion.MENU, "AMSI/UAC/AV bypass, anti-debug/VM, WAF bypass"),
    "X": ("Exploit Toolkit", offense.MENU, "C2 listener, webshell gen, token impersonation, worm sim"),
    "I": ("IoT / ICS / SCADA", iot.MENU, "BACnet, ZigBee, Z-Wave, WiFi deauth, VLAN hop, VoIP"),
    "H": ("Hardware / Physical", hardware.MENU, "BadUSB, Bluetooth, ATM, camera hijack, vishing"),
    "A": ("AI Assistant", ai.MENU, "LLM help: chat, explain, suggest, analyze (Ollama/OpenAI)"),
    "U": ("Utilities", toolbox.MENU, "Base/subnet/epoch/UUID/passgen/URL/entropy/JSON"),
    "W": ("Workspace", workspace.MENU, "Named engagements: persist findings, notes, reports"),
    "P": ("Proxy Manager", proxy.MENU, "Load, test, rotate, and export proxies"),
    "V": ("Free VPN", vpn.MENU, "Fetch free VPNGate servers by country, export OpenVPN configs"),
    "S": ("Shodan Recon", shodan.MENU, "Host lookup, search, CVE scan, API key management"),
    "C": ("Chained Recon", chainrecon.MENU, "Auto pipeline: subdomains → DNS → Shodan → CVE → report"),
    "T": ("Attack Surface", attacksurface.MENU, "Hidden file crawl, tech fingerprint, cred leak check"),
}

# System pseudo-entries (handled specially, not real categories).
SYSTEM_ITEMS = {"r": "Session Report", "t": "Tool Status", "q": "Quit"}

# External tools each category can drive. Categories not listed are pure built-in
# (always ready). Used for the live installed-tools indicator.
CATEGORY_DEPS = {
    "1": ["nmap", "masscan"],
    "2": ["john", "hashcat"],
    "5": ["ffuf", "gobuster", "sqlmap", "nikto"],
    "8": ["searchsploit", "nuclei", "msfconsole"],
    "9": ["hydra"],
    "o": ["subfinder"],
}

_probe_cache: dict | None = None


def _probe() -> dict:
    global _probe_cache
    if _probe_cache is None:
        alltools = sorted({t for lst in CATEGORY_DEPS.values() for t in lst})
        _probe_cache = probe_tools(alltools)
    return _probe_cache


def _cat_dot(key: str) -> str:
    """Indicator: green=ready, yellow=some tools present, red=needs install."""
    if key not in CATEGORY_DEPS:
        return "[green]●[/]"          # built-in, always usable
    probe = _probe()
    have = sum(1 for t in CATEGORY_DEPS[key] if probe.get(t))
    total = len(CATEGORY_DEPS[key])
    if have == 0:
        return "[red]○[/]"
    return "[green]●[/]" if have == total else "[yellow]◐[/]"

# Home layout: (section title, colour, [category keys]).
GROUPS = [
    ("RECON / OSINT", "cyan", ["1", "6", "o", "m", "8", "j", "S", "C", "T"]),
    ("WEB / EXPLOIT", "red", ["5", "p", "h", "7", "9", "v", "l", "X"]),
    ("AD / NETWORK", "red", ["a", "n", "x", "k"]),
    ("DATA / CLOUD", "bright_blue", ["b", "u", "y"]),
    ("CRYPTO / STEGO", "magenta", ["3", "c", "2", "s", "0"]),
    ("WORDLISTS", "yellow", ["4", "g", "w"]),
    ("FORENSICS / DFIR", "green", ["f", "e", "z"]),
    ("IOT / HARDWARE", "bright_magenta", ["I", "H"]),
    ("EVASION / DEFENSE", "green", ["E", "d"]),
    ("AI / UTILITIES", "bright_cyan", ["A", "U", "W", "P", "V"]),
    ("SYSTEM", "blue", ["i", "r", "t", "q"]),
]

_wsl_status_cache: str | None = None


def _wsl_status() -> str:
    global _wsl_status_cache
    if _wsl_status_cache is None:
        if not IS_WINDOWS:
            _wsl_status_cache = "[green]native linux[/]"
        elif wsl_available():
            _wsl_status_cache = f"{get_wsl_distro()} [green]online[/]"
        else:
            _wsl_status_cache = "[red]offline[/]"
    return _wsl_status_cache


def _total_tools() -> int:
    return sum(len(c[1]) for c in CATEGORIES.values())


def _banner_block() -> str:
    reachable = catalog.indexed_total() + arsenal.payload_count()
    ws_name = workspace.get_active().name if workspace.is_active() else "none"
    return "\n".join([
        f"       =[ [bold green]nullsec[/] [green]v{__version__}[/] · offensive security framework ]",
        f"+ -- --=[ {len(CATEGORIES)} modules · {_total_tools()} tools ]",
        f"+ -- --=[ {catalog.local_count():,} cataloged · [bold]{reachable:,}[/] modules reachable ]",
        f"+ -- --=[ wsl: {_wsl_status()} · log: {len(report.entries)} · ws: {ws_name} ]",
    ])


def _group_block(title: str, colour: str, keys: list[str]) -> Table:
    tbl = Table(show_header=False, box=None, padding=(0, 1, 0, 0))
    tbl.add_column(justify="right", style=f"bold {colour}", no_wrap=True)
    tbl.add_column(no_wrap=True)
    tbl.add_row("", f"[bold {colour}]{title}[/]")
    for k in keys:
        label = CATEGORIES[k][0] if k in CATEGORIES else SYSTEM_ITEMS[k]
        tbl.add_row(k, label)
    return tbl


_STATE_FILE = Path("data", "state.json") if hasattr(sys, "_MEIPASS") else resource_path("data", "state.json")


def _load_recent() -> list[str]:
    try:
        return json.loads(_STATE_FILE.read_text(encoding="utf-8")).get("recent", [])
    except Exception:
        return []


def _push_recent(key: str) -> None:
    recent = [k for k in _load_recent() if k != key]
    recent.insert(0, key)
    try:
        _STATE_FILE.parent.mkdir(exist_ok=True)
        _STATE_FILE.write_text(json.dumps({"recent": recent[:6]}), encoding="utf-8")
    except Exception:
        pass


def _module_matches(term: str) -> list[tuple[str, str, str, str]]:
    """Search module menu labels -> (cat_key, cat_name, sub_key, label)."""
    term = term.lower()
    out = []
    for ckey, (cname, menu, _d) in CATEGORIES.items():
        for skey, (label, _fn) in menu.items():
            if term in label.lower() or term in cname.lower():
                out.append((ckey, cname, skey, label))
    return out


def show_home() -> None:
    console.clear()
    console.print(Text(BANNER.rstrip("\n"), style=BANNER_STYLE))
    console.print(f"  [white]Ø[/] [bold grey85]nullsec[/] [grey50]v{__version__}[/]"
                  f"  [grey42]·[/]  [grey62]{len(CATEGORIES)} modules · "
                  f"{_total_tools()} tools[/]  [grey42]·[/]  [grey50]authorized use only[/]")
    if workspace.is_active():
        ws = workspace.get_active()
        console.print(f"  [grey42]ws:[/] [bold green]{ws.name}[/]"
                      f"  [grey42]·[/]  [grey62]{len(ws.findings)} findings · "
                      f"{len(ws.notes)} notes[/]")
    console.print()
    console.print(Columns([_group_block(*g) for g in GROUPS], padding=(1, 4)))
    recent = [k for k in _load_recent() if k in CATEGORIES]
    if recent:
        console.print("\n[bright_black]  recent:[/] "
                      + "   ".join(f"[cyan]{k}[/] {CATEGORIES[k][0]}" for k in recent))
    console.print("\n  [grey42]key[/] [grey54]open[/]   [grey42]·[/]   [grey42]search <term>[/]"
                  "   [grey42]·[/]   [grey42]help[/]   [grey42]·[/]   [grey42]q[/] [grey54]quit[/]")


def cmd_help() -> None:
    console.print(Panel(
        "[bold]commands[/]\n"
        "  [cyan]<key>[/]           open a module by its key (e.g. 1, c, o, w)\n"
        "  [cyan]search <term>[/]   search catalog + module tools, then jump\n"
        "  [cyan]use <tool>[/]      show a catalogued tool's install/details\n"
        "  [cyan]banner[/]          redraw the banner\n"
        "  [cyan]version[/]         framework version\n"
        "  [cyan]r[/] / [cyan]t[/]             session report / external tool status\n"
        "  [cyan]help[/], [cyan]?[/]          this screen\n"
        "  [cyan]q[/]               quit",
        border_style="bright_black", box=box.SQUARE, padding=(1, 2), expand=False))
    console.input("[bright_black][enter][/] ")


def cmd_version() -> None:
    reachable = catalog.indexed_total() + arsenal.payload_count()
    console.print(f"[bold green]nullsec[/] v{__version__}  ·  {_total_tools()} tools / "
                  f"{len(CATEGORIES)} modules  ·  {catalog.local_count():,} cataloged  ·  "
                  f"{reachable:,} reachable  ·  by anonymous")
    console.input("[bright_black][enter][/] ")


def cmd_search(term: str) -> None:
    term = term.strip()
    if not term:
        console.print("[yellow]usage: search <term>[/]")
        return console.input("[bright_black][enter][/] ")
    mod_hits = _module_matches(term)
    if mod_hits:
        tbl = Table(title=f"{len(mod_hits)} module tool(s) for '{term}'"
                    + (" (showing 30)" if len(mod_hits) > 30 else ""))
        tbl.add_column("open", style="bold green")
        tbl.add_column("module", style="magenta")
        tbl.add_column("tool")
        for ckey, cname, skey, label in mod_hits[:30]:
            tbl.add_row(f"{ckey} -> {skey}", cname, label)
        console.print(tbl)
    hits = [t for t in catalog.all_tools()
            if term.lower() in t[0].lower() or term.lower() in t[1].lower()
            or term.lower() in t[2].lower()]
    if hits:
        tbl = Table(title=f"{len(hits)} catalog tool(s)"
                    + (" (showing 40)" if len(hits) > 40 else ""))
        tbl.add_column("tool", style="bold cyan")
        tbl.add_column("cat", style="magenta")
        tbl.add_column("install", style="dim", overflow="fold")
        for name, cat, _desc, install, _binary in hits[:40]:
            tbl.add_row(name, cat, install)
        console.print(tbl)
    if not mod_hits and not hits:
        console.print(f"[yellow]no matches for '{term}'[/]")
        return console.input("[bright_black][enter][/] ")
    if mod_hits:
        sel = console.input("\n[bright_black]open which module key? (e.g. "
                            + mod_hits[0][0] + ", enter = back) [/]").strip()
        key = resolve_category(sel)
        if key is not None:
            _push_recent(key)
            run_category(key, CATEGORIES[key][0], CATEGORIES[key][1])
            return
    else:
        console.input("[bright_black][enter][/] ")


def cmd_use(name: str) -> None:
    name = name.strip()
    match = next((t for t in catalog.all_tools() if t[0].lower() == name.lower()), None)
    if not match:
        console.print(f"[yellow]'{name}' not in catalog. try: search {name}[/]")
        return console.input("[bright_black][enter][/] ")
    n, cat, desc, install, _binary = match
    console.print(f"\n[bold cyan]{n}[/] [magenta]({cat})[/]\n{desc}\n"
                  f"[dim]install:[/] {install}")
    console.input("[bright_black][enter][/] ")


def show_report() -> None:
    console.clear()
    console.print(Panel("[bold]Session report[/]", border_style="cyan", expand=False))
    if not report.entries:
        console.print("[dim]No findings logged yet. Recon/web/network modules add "
                      "entries here as you use them.[/]")
        return console.input("\n[dim]Press Enter…[/]")
    from rich.markdown import Markdown

    console.print(Markdown(report.as_markdown()))
    choice = Prompt.ask("\nsave as [m]arkdown, save as [h]tml, [c]lear, or [b]ack",
                        choices=["m", "h", "c", "b"], default="b")
    if choice == "m":
        console.print(f"[green]Saved:[/] {report.save()}")
        console.input("\n[dim]Press Enter…[/]")
    elif choice == "h":
        console.print(f"[green]Saved:[/] {report.save_html()}")
        console.input("\n[dim]Press Enter…[/]")
    elif choice == "c":
        report.clear()
        console.print("[yellow]Cleared.[/]")
        console.input("\n[dim]Press Enter…[/]")


def show_tool_status() -> None:
    console.clear()
    console.print(Panel("[bold]External tool status[/]", border_style="cyan", expand=False))
    table = Table()
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Description", style="dim")
    for t in detect_tools():
        mark = "[green][+] installed[/]" if t.installed else "[red][-] missing[/]"
        table.add_row(t.key, mark, t.description)
    console.print(table)
    console.print("\n[dim]Missing tools just disable their module — the built-in "
                  "scanners/crackers work without them.[/]")
    console.input("\n[dim]Press Enter…[/]")


def _module_error(module: str, key: str, menu: dict, exc: BaseException) -> None:
    """A module raised an unexpected error — show it, log it, keep running.

    This is the last-resort guard: no single tool should be able to crash the
    whole framework. The user gets a clear message (and can opt into the full
    traceback), and the failure is recorded in the session report.
    """
    label = menu[key][0] if key in menu else key
    console.print(Panel(
        f"[bold red]{type(exc).__name__}[/]: {exc}\n\n"
        f"[bright_black]The [bold]{module}[/] action '[cyan]{label}[/]' hit an "
        f"error, but nullsec kept running.[/]",
        title="module error", border_style="red", box=box.SQUARE,
        padding=(1, 2), expand=False))
    report.log("error", f"{module} · {label}", [f"- {type(exc).__name__}: {exc}"])
    if console.input("[bright_black]show traceback? [y/N] [/]").strip().lower() == "y":
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        console.print(f"[dim]{tb.rstrip()}[/]")
    console.input("[bright_black][enter][/] ")


def run_category(key: str, name: str, menu: dict) -> str | None:
    modid = name.split()[0].lower()
    desc = CATEGORIES.get(key, ("", "", ""))[2]
    while True:
        console.clear()
        console.print(Text(BANNER.rstrip("\n"), style=BANNER_STYLE))
        console.print(f"\n  [white]Ø[/] [bold grey85]{name}[/]")
        if desc:
            console.print(f"  [grey42]{desc}[/]")
        console.print()
        for k, (label, _fn) in menu.items():
            console.print(f"     [bold cyan]{k:>2}[/]  [grey85]{label}[/]")
        console.print("\n     [grey42]b[/] [grey54]back[/]   [grey42]/[/] [grey54]home[/]"
                      "   [grey42]q[/] [grey54]quit[/]")
        choice = Prompt.ask(f"\n  [grey50]nullsec[/][grey42]([/][cyan]{modid}[/]"
                            f"[grey42])[/] [grey42]›[/]").strip().lower()
        if choice in ("b", "/"):
            return None
        if choice in ("q", "quit", "exit"):
            return "quit"
        if choice in ("?", "help"):
            cmd_help()
            continue
        if choice in menu:
            console.clear()
            try:
                menu[choice][1]()
            except KeyboardInterrupt:
                console.print("\n[yellow]Cancelled.[/]")
            except EOFError:
                raise  # exhausted stdin — let the app exit cleanly at top level
            except Exception as exc:  # noqa: BLE001 — last-resort guard
                _module_error(name, choice, menu, exc)
        else:
            console.print("[red]Unknown option.[/]")


def resolve_category(raw: str) -> str | None:
    """Map raw home input to a category key, honoring case.

    Category keys are case-sensitive: 'E' (Evasion) and 'e' (Reversing) are
    different modules, as are X/x, I/i, H/h. Exact case wins; for a key with no
    upper/lower twin we also accept the opposite case so 'V' still opens 'v'.
    """
    if raw in CATEGORIES:
        return raw
    if len(raw) == 1 and raw not in CATEGORIES and raw.swapcase() in CATEGORIES:
        return raw.swapcase()
    return None


def main() -> None:
    while True:
        show_home()
        raw = Prompt.ask("\n  [grey50]nullsec[/] [grey42]›[/]").strip()
        low = raw.lower()
        verb = low.split(None, 1)[0] if low else ""
        arg = raw.split(None, 1)[1] if " " in raw else ""
        # Category keys are matched first, by exact case, so uppercase modules
        # (E/X/I/H and 'h') aren't shadowed by a lowercased command or twin key.
        cat_key = resolve_category(raw)
        if cat_key is not None:
            name, menu, _desc = CATEGORIES[cat_key]
            _push_recent(cat_key)
            if run_category(cat_key, name, menu) == "quit":
                return
        elif low in ("q", "quit", "exit"):
            return
        elif low in ("help", "?"):
            cmd_help()
        elif low in ("banner", "clear"):
            continue
        elif low in ("version", "-v", "--version"):
            cmd_version()
        elif verb == "search":
            cmd_search(arg)
        elif verb == "use":
            cmd_use(arg)
        elif low == "r":
            show_report()
        elif low == "t":
            show_tool_status()
        else:
            console.print(f"[red]unknown command:[/] {raw}   "
                          "[bright_black](type 'help')[/]")
            console.input("[bright_black][enter][/] ")


if __name__ == "__main__":
    # Auto-elevate on Windows (one UAC prompt), then repair the environment
    # (Defender exclusion so payload data stops being quarantined). Kept out of
    # module scope so importing `main` for tests/CI never triggers a UAC prompt.
    from toolkit import elevate
    if elevate.maybe_elevate():
        sys.exit(0)  # a new elevated instance took over; this one is done
    elevate.auto_fix()
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Interrupted. Bye.[/]")
        sys.exit(0)
