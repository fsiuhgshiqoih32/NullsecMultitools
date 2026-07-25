from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.prompt import Prompt
from rich.table import Table

from .utils import (console, header, pause, require_tool, run_external, run_tool,
                    soft_require)

# A small map so results are readable without a full /etc/services parse.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}
TOP_PORTS = sorted(COMMON_PORTS)


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _scan_one(ip: str, port: int, timeout: float) -> tuple[int, bool]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return port, s.connect_ex((ip, port)) == 0


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Best-effort banner: read what the service says, nudge HTTP with a HEAD."""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        sock = raw
        if port in (443, 8443, 993, 995):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        sock.settimeout(timeout)
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        except OSError:
            pass
        data = sock.recv(256)
        sock.close()
        return data.decode(errors="replace").strip().splitlines()[0] if data else "(no banner)"
    except Exception:
        return "(no banner)"


def port_scan() -> None:
    header("Port Scanner", "Threaded TCP connect scan — stdlib sockets, no nmap required")
    host = Prompt.ask("Target host/IP", default="127.0.0.1")
    ip = _resolve(host)
    if not ip:
        console.print(f"[red]Could not resolve {host}[/]")
        return pause()
    console.print(f"Resolved [bold]{host}[/] -> [cyan]{ip}[/]")

    mode = Prompt.ask("Ports", choices=["top", "1-1024", "custom"], default="top")
    if mode == "top":
        ports = TOP_PORTS
    elif mode == "1-1024":
        ports = range(1, 1025)
    else:
        spec = Prompt.ask("Range or list (e.g. 20-25,80,443)", default="1-1000")
        ports = _parse_ports(spec)

    timeout = float(Prompt.ask("Per-port timeout (s)", default="0.5"))
    ports = list(ports)
    open_ports: list[int] = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}"),
                  TimeRemainingColumn(), console=console) as prog:
        task = prog.add_task(f"Scanning {len(ports)} ports", total=len(ports))
        with ThreadPoolExecutor(max_workers=200) as pool:
            futs = [pool.submit(_scan_one, ip, p, timeout) for p in ports]
            for fut in as_completed(futs):
                port, is_open = fut.result()
                if is_open:
                    open_ports.append(port)
                prog.advance(task)

    if not open_ports:
        console.print("[yellow]No open ports found.[/]")
        return pause()

    table = Table(title=f"Open ports on {ip}")
    table.add_column("Port", justify="right", style="green bold")
    table.add_column("Service")
    table.add_column("Banner", style="dim")
    for port in sorted(open_ports):
        banner = _grab_banner(ip, port) if port in COMMON_PORTS or len(open_ports) <= 30 else "(skipped)"
        table.add_row(str(port), COMMON_PORTS.get(port, "unknown"), banner)
    console.print(table)
    pause()


def _parse_ports(spec: str):
    result: set[int] = set()
    for part in spec.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-")
            result.update(range(int(a), int(b) + 1))
        elif part:
            result.add(int(part))
    return sorted(p for p in result if 0 < p < 65536)


def nmap_handoff() -> None:
    header("Nmap", "Hand off to the real Nmap for OS/version/script scanning")
    path = require_tool("nmap")
    if not path:
        return pause()
    target = Prompt.ask("Target")
    profile = Prompt.ask(
        "Profile",
        choices=["quick", "version", "aggressive", "custom"],
        default="version",
    )
    flags = {
        "quick": ["-T4", "-F"],
        "version": ["-T4", "-sV"],
        "aggressive": ["-T4", "-A"],
    }.get(profile)
    if profile == "custom":
        flags = Prompt.ask("Nmap flags", default="-sV -T4").split()
    run_external(["nmap", *flags, target])
    pause()


def masscan_scan() -> None:
    header("masscan", "Internet-scale async port scanner (native or WSL; needs root)")
    if not soft_require("masscan", "apt install masscan"):
        return pause()
    target = Prompt.ask("Target (IP or CIDR)")
    ports = Prompt.ask("Ports", default="1-1000")
    rate = Prompt.ask("Packets/sec", default="1000")
    run_tool("masscan", [target, "-p", ports, "--rate", rate])
    pause()


MENU = {
    "1": ("Port scan (built-in, no deps)", port_scan),
    "2": ("Nmap hand-off (needs nmap)", nmap_handoff),
    "3": ("masscan (fast async scan)", masscan_scan),
}
