from __future__ import annotations

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, resolve_tool, run_tool

# service -> whether it needs extra module arguments (e.g. http form)
SERVICES = {
    "ssh": "SSH login",
    "ftp": "FTP login",
    "smb": "Windows SMB",
    "rdp": "Windows RDP",
    "mysql": "MySQL",
    "postgres": "PostgreSQL",
    "vnc": "VNC",
    "telnet": "Telnet",
    "http-get": "HTTP Basic auth (GET)",
    "http-post-form": "HTTP login form (POST)",
}


def _tool_banner() -> bool:
    loc = resolve_tool("hydra")
    if loc is None:
        console.print("[yellow]hydra is not installed (native or WSL).[/] "
                      "Use the home menu → [bold]i[/] to install the arsenal, then retry.")
        return False
    kind = loc[0]
    console.print(f"[dim]hydra found ({kind}). File paths you give will be "
                  f"{'translated for WSL' if kind == 'wsl' else 'used as-is'}.[/]")
    return True


def hydra_brute() -> None:
    header("hydra · login brute-force", "Authorized targets only — this is loud and logged")
    if not _tool_banner():
        return pause()

    t = Table(show_header=False, box=None)
    for k, v in SERVICES.items():
        t.add_row(f"[cyan]{k}[/]", v)
    console.print(t)
    service = Prompt.ask("Service", choices=list(SERVICES), default="ssh")
    target = Prompt.ask("Target host/IP")

    # username: single or list
    user_mode = Prompt.ask("Username: [s]ingle or [l]ist", choices=["s", "l"], default="s")
    if user_mode == "s":
        user_flag = ["-l", Prompt.ask("Username", default="root")]
    else:
        user_flag = ["-L", Prompt.ask("Path to user list")]

    pass_path = Prompt.ask("Path to password list")
    port = Prompt.ask("Port (blank = default)", default="").strip()
    tasks = Prompt.ask("Parallel tasks (-t)", default="16")

    args: list[str] = [*user_flag, "-P", pass_path, "-t", tasks]
    # track which arg positions are file paths for WSL translation
    file_positions = set()
    # recompute positions after assembling
    if user_mode == "l":
        file_positions.add(args.index(user_flag[1]))
    args_pass_idx = args.index(pass_path)
    file_positions.add(args_pass_idx)

    if port:
        args += ["-s", port]

    if service == "http-post-form":
        console.print("[dim]Form string format: \"/login:user=^USER^&pass=^PASS^:F=Invalid\"[/]")
        form = Prompt.ask("Form string")
        args += [target, "http-post-form", form]
    else:
        args += [target, service]

    console.print("\n[bold]About to run hydra. This attempts real logins against the "
                  "target — only proceed if you're authorized.[/]")
    if Prompt.ask("Proceed?", choices=["y", "n"], default="n") != "y":
        return pause()

    run_tool("hydra", args, wsl_pathify=file_positions)
    pause()


MENU = {
    "1": ("hydra login brute-force", hydra_brute),
}
