from __future__ import annotations

from pathlib import Path

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report

# --- Sigma rules (generic SIEM detection format) ----------------------------
SIGMA = {
    "kerberoasting": """title: Potential Kerberoasting (RC4 Service Ticket Requests)
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    TicketOptions: '0x40810000'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
level: high
tags: [attack.credential_access, attack.t1558.003]""",

    "asrep_roasting": """title: AS-REP Roasting (Kerberos Pre-Auth Disabled)
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
  condition: selection
level: high
tags: [attack.credential_access, attack.t1558.004]""",

    "password_spray": """title: Password Spraying (many accounts from one source)
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 5m
  condition: selection | count(TargetUserName) by IpAddress > 10
level: high
tags: [attack.credential_access, attack.t1110.003]""",

    "dcsync": """title: DCSync Replication Requested by Non-DC
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
  condition: selection
level: critical
tags: [attack.credential_access, attack.t1003.006]""",

    "certutil_download": """title: Certutil Used to Download a File
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains|all: ['urlcache', 'http']
  condition: selection
level: high
tags: [attack.command_and_control, attack.t1105]""",

    "powershell_cradle": """title: PowerShell Download Cradle
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains:
      - 'DownloadString'
      - 'New-Object Net.WebClient'
      - 'IEX('
  condition: selection
level: high
tags: [attack.execution, attack.t1059.001]""",

    "new_service": """title: New Windows Service Created (persistence)
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
  condition: selection
level: medium
tags: [attack.persistence, attack.t1543.003]""",
}

# --- YARA rules -------------------------------------------------------------
YARA = {
    "Webshell_Generic": {
        "desc": "PHP/JSP/ASP web shells",
        "strings": ["system($_GET", "shell_exec($_", "eval($_POST", "passthru($_REQUEST",
                    "Runtime.getRuntime().exec", "WScript.Shell"],
        "yara": """rule Webshell_Generic {
  strings:
    $a = "system($_GET" $b = "shell_exec($_" $c = "eval($_POST"
    $d = "passthru($_REQUEST" $e = "Runtime.getRuntime().exec"
  condition: any of them
}""",
    },
    "ReverseShell_Unix": {
        "desc": "Unix reverse-shell one-liners",
        "strings": ["/dev/tcp/", "nc -e", "mkfifo /tmp", "bash -i >&", "socat ", "sh -i >&"],
        "yara": """rule ReverseShell_Unix {
  strings:
    $a = "/dev/tcp/" $b = "nc -e" $c = "mkfifo /tmp"
    $d = "bash -i >&" $e = "sh -i >&"
  condition: any of them
}""",
    },
    "Mimikatz": {
        "desc": "Mimikatz credential-dumping strings",
        "strings": ["sekurlsa::logonpasswords", "gentilkiwi", "privilege::debug",
                    "lsadump::", "kerberos::golden"],
        "yara": """rule Mimikatz {
  strings:
    $a = "sekurlsa::logonpasswords" $b = "gentilkiwi"
    $c = "privilege::debug" $d = "lsadump::" $e = "kerberos::golden"
  condition: any of them
}""",
    },
    "PowerShell_Encoded": {
        "desc": "Obfuscated / encoded PowerShell execution",
        "strings": ["-enc ", "-EncodedCommand", "FromBase64String", "-nop -w hidden",
                    "IEX(New-Object"],
        "yara": """rule PowerShell_Encoded {
  strings:
    $a = "-EncodedCommand" $b = "FromBase64String"
    $c = "-nop -w hidden" $d = "IEX(New-Object"
  condition: 2 of them
}""",
    },
}


def sigma_rules() -> None:
    header("Sigma rules", "Generic SIEM detections for common techniques")
    names = list(SIGMA)
    for i, n in enumerate(names, 1):
        title = SIGMA[n].splitlines()[0].replace("title: ", "")
        console.print(f"  [cyan]{i}[/]  {title}")
    sel = Prompt.ask("\nNumber to view, 'e' to export all, or enter to skip", default="").strip()
    if sel == "e":
        out = Path.cwd() / "sigma"
        out.mkdir(exist_ok=True)
        for n, rule in SIGMA.items():
            (out / f"{n}.yml").write_text(rule, encoding="utf-8")
        console.print(f"[green]Exported {len(SIGMA)} rules -> {out}[/]")
    elif sel.isdigit() and 1 <= int(sel) <= len(names):
        console.print("\n[dim]" + SIGMA[names[int(sel) - 1]] + "[/]")
    pause()


def yara_rules() -> None:
    header("YARA rules", "Pattern-matching rules for malicious artifacts")
    for name, r in YARA.items():
        console.print(f"  [cyan]{name}[/] — {r['desc']} ({len(r['strings'])} patterns)")
    if Prompt.ask("\nExport to nullsec.yar?", choices=["y", "n"], default="n") == "y":
        out = Path.cwd() / "nullsec.yar"
        out.write_text("\n\n".join(r["yara"] for r in YARA.values()), encoding="utf-8")
        console.print(f"[green]Exported -> {out}[/]  (scan: yara nullsec.yar <target>)")
    pause()


def yara_scan() -> None:
    header("YARA scan", "Scan a file/folder against the built-in rules")
    target = Path(Prompt.ask("File or folder").strip('"'))
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = [p for p in target.rglob("*") if p.is_file() and p.stat().st_size < 5_000_000]
    else:
        console.print("[red]Not found.[/]")
        return pause()

    hits = []
    for f in files[:3000]:
        try:
            data = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for name, r in YARA.items():
            matched = [s for s in r["strings"] if s in data]
            if matched:
                hits.append((name, str(f), matched[0]))
    if not hits:
        console.print("[green]No rule matches.[/]")
        return pause()
    t = Table(title=f"{len(hits)} match(es)")
    t.add_column("Rule", style="red bold")
    t.add_column("File", style="dim", overflow="fold")
    t.add_column("Matched", style="yellow")
    for name, path, m in hits[:100]:
        t.add_row(name, path, m)
    console.print(t)
    report.log("detect", "YARA scan", [f"- {len(hits)} matches in {target}"])
    pause()


def matrix() -> None:
    header("Detection matrix", "Each nullsec technique -> how a defender catches it")
    rows = [
        ("Port scan", "Firewall / Zeek conn.log", "SYN floods, many ports/host, fast"),
        ("Kerberoast", "Win Security 4769", "RC4 (0x17) service tickets, burst"),
        ("AS-REP roast", "Win Security 4768", "PreAuthType 0, RC4"),
        ("Password spray", "Win Security 4625", ">10 accounts fail from one IP / 5m"),
        ("NTLM relay", "Win Security 4624 t3", "auth chains; enforce SMB/LDAP signing"),
        ("DCSync", "Win Security 4662", "DS-Replication-Get-Changes by non-DC"),
        ("Reverse shell", "EDR / proxy / netflow", "egress to odd ports; /dev/tcp in cmdline"),
        ("Payload download", "Sysmon 1 / ps_script", "certutil/bitsadmin/IEX cradles"),
        ("Web dir brute", "Web access logs", "404 spikes, high req rate one IP"),
        ("Persistence", "Win System 7045 / Sysmon 13", "new service, Run-key writes"),
        ("SMB enum", "Win Security 5140/4624", "many share accesses, RID cycling"),
    ]
    t = Table()
    t.add_column("Technique", style="bold red")
    t.add_column("Log source", style="cyan")
    t.add_column("What to alert on", style="green")
    for a, b, c in rows:
        t.add_row(a, b, c)
    console.print(t)
    pause()


def hunt_queries() -> None:
    header("Hunt queries", "Ready-made SIEM searches")
    console.print("[bold]Kerberoasting (Splunk):[/]")
    console.print('  [green]index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17\n'
                  '    | stats count by Account_Name,Service_Name | where count > 5[/]')
    console.print("\n[bold]Password spray (Elastic KQL):[/]")
    console.print('  [green]event.code:"4625" | stats dc(user.name) by source.ip '
                  '| where cardinality > 10[/]')
    console.print("\n[bold]DCSync (Splunk):[/]")
    console.print('  [green]index=wineventlog EventCode=4662 Properties="*1131f6aa*"\n'
                  '    NOT (Account_Name IN (dc_accounts))[/]')
    console.print("\n[bold]Suspicious download cradle (Sysmon):[/]")
    console.print('  [green]EventCode=1 (Image="*certutil.exe" OR CommandLine="*DownloadString*"\n'
                  '    OR CommandLine="*FromBase64String*")[/]')
    pause()


MENU = {
    "1": ("Sigma rules (view/export)", sigma_rules),
    "2": ("YARA rules (view/export)", yara_rules),
    "3": ("YARA scan a file/folder", yara_scan),
    "4": ("Detection matrix", matrix),
    "5": ("SIEM hunt queries", hunt_queries),
}
