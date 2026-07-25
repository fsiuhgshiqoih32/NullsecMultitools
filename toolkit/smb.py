from __future__ import annotations

from rich.prompt import Prompt

from .utils import console, header, pause, resolve_tool, run_tool


def _cme() -> str | None:
    for name in ("nxc", "netexec", "crackmapexec", "cme"):
        if resolve_tool(name):
            return name
    return None


def shares_null() -> None:
    header("SMB shares (null session)", "List shares with no creds (smbclient -N)")
    if not resolve_tool("smbclient"):
        console.print("[yellow]smbclient not installed[/] — [cyan]pacman -S smbclient[/]")
        return pause()
    target = Prompt.ask("Target IP/host")
    run_tool("smbclient", ["-N", "-L", f"//{target}"])
    pause()


def cme_enum() -> None:
    header("SMB enumeration", "Shares, users, sessions, password policy (netexec/CME)")
    tool = _cme()
    if not tool:
        console.print("[yellow]netexec/crackmapexec not installed[/] — "
                      "[cyan]pipx install netexec[/]")
        return pause()
    target = Prompt.ask("Target (IP/CIDR)")
    mode = Prompt.ask("Auth", choices=["null", "creds"], default="null")
    args = ["smb", target]
    if mode == "creds":
        args += ["-u", Prompt.ask("Username"), "-p", Prompt.ask("Password")]
    else:
        args += ["-u", "", "-p", ""]
    what = Prompt.ask("Enumerate", choices=["shares", "users", "pass-pol", "sessions"],
                      default="shares")
    args.append("--" + {"pass-pol": "pass-pol"}.get(what, what))
    run_tool(tool, args)
    pause()


def smbmap_enum() -> None:
    header("smbmap", "Share access + permissions")
    if not resolve_tool("smbmap"):
        console.print("[yellow]smbmap not installed[/] — [cyan]pipx install smbmap[/]")
        return pause()
    target = Prompt.ask("Target IP")
    args = ["-H", target]
    if Prompt.ask("Use creds?", choices=["y", "n"], default="n") == "y":
        args += ["-u", Prompt.ask("Username"), "-p", Prompt.ask("Password")]
    else:
        args += ["-u", "guest", "-p", ""]
    run_tool("smbmap", args)
    pause()


def rid_cycle() -> None:
    header("RID cycling", "Enumerate domain users via SID brute (netexec --rid-brute)")
    tool = _cme()
    if not tool:
        console.print("[yellow]netexec/crackmapexec required.[/]")
        return pause()
    target = Prompt.ask("DC IP")
    run_tool(tool, ["smb", target, "-u", "guest", "-p", "", "--rid-brute"])
    pause()


MENU = {
    "1": ("List shares (null session)", shares_null),
    "2": ("Enumerate (netexec/CME)", cme_enum),
    "3": ("Share permissions (smbmap)", smbmap_enum),
    "4": ("RID cycling (user enum)", rid_cycle),
}
