from __future__ import annotations

import shutil
import subprocess

from rich.prompt import Prompt
from rich.table import Table

from .utils import WSL_DISTRO, console, header, pause, wsl_available

# Curated pacman targets — the tools people actually reach for, matching the
# nullsec catalog. Installed one-by-one so an unknown name never aborts the batch.
CURATED_PACMAN = [
    # scanning / recon
    "nmap", "masscan", "rustscan", "amass", "subfinder", "dnsenum", "dnsrecon",
    "theharvester", "recon-ng", "whatweb", "wafw00f",
    # web
    "nikto", "gobuster", "ffuf", "feroxbuster", "wfuzz", "sqlmap", "wpscan",
    "nuclei", "dirb", "commix",
    # exploitation
    "metasploit", "exploitdb", "impacket", "crackmapexec", "beef",
    "routersploit", "set",
    # passwords
    "john", "hashcat", "hydra", "medusa", "ncrack", "hashid", "crunch", "cewl",
    # network / mitm
    "wireshark-cli", "tcpdump", "bettercap", "responder", "socat",
    "openbsd-netcat", "proxychains-ng",
    # wireless
    "aircrack-ng", "reaver", "hcxdumptool",
    # reversing / forensics / stego
    "radare2", "gdb", "binwalk", "foremost", "perl-image-exiftool", "steghide",
    # wordlists
    "seclists", "wordlists",
]

# Windows-native lane: (package, manager, binary-to-check)
WINDOWS_NATIVE = [
    ("Nmap.Nmap", "winget", "nmap"),
    ("WiresharkFoundation.Wireshark", "winget", "wireshark"),
    ("sqlmap", "pip", "sqlmap"),
    ("impacket", "pip", None),
    ("shodan", "pip", "shodan"),
    ("wafw00f", "pip", "wafw00f"),
    ("rustscan", "cargo", "rustscan"),
    ("feroxbuster", "cargo", "feroxbuster"),
]


def _wsl(cmd: str, timeout: int = 3600) -> subprocess.CompletedProcess:
    return subprocess.run(["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "bash", "-lc", cmd],
                          text=True, timeout=timeout)


def plan() -> None:
    header("Install plan", "What nullsec will install and how")
    t = Table()
    t.add_column("Lane", style="bold cyan")
    t.add_column("Method")
    t.add_column("Count", justify="right")
    t.add_row("WSL Arch curated", "BlackArch + pacman", str(len(CURATED_PACMAN)))
    t.add_row("WSL Arch FULL", "pacman -S blackarch", "~2,800")
    t.add_row("Windows native", "winget / pip / cargo", str(len(WINDOWS_NATIVE)))
    console.print(t)
    console.print("[dim]WSL is where the heavy tools live. After install you can run "
                  "nullsec from inside WSL for seamless access, or keep using it on "
                  "Windows — it drives WSL tools automatically.[/]")
    pause()


def bootstrap_blackarch() -> None:
    header("Bootstrap BlackArch", "Adds the BlackArch repo + keyring to your Arch WSL")
    if not wsl_available():
        console.print("[red]Arch WSL not reachable.[/]")
        return pause()
    console.print("[dim]Downloading and running strap.sh as root (one-time)…[/]")
    r = _wsl("cd /tmp && curl -fsSL https://blackarch.org/strap.sh -o strap.sh && "
             "chmod +x strap.sh && ./strap.sh && pacman -Sy --noconfirm", timeout=1800)
    if r.returncode == 0:
        console.print("[green]BlackArch repo ready.[/]")
    else:
        console.print("[yellow]strap.sh returned non-zero — it may already be set up.[/]")
    pause()


def install_curated() -> None:
    header("Install curated arsenal", f"{len(CURATED_PACMAN)} top tools into WSL Arch")
    if not wsl_available():
        console.print("[red]Arch WSL not reachable.[/]")
        return pause()
    if Prompt.ask("This downloads a few GB and can take a while. Proceed?",
                  choices=["y", "n"], default="n") != "y":
        return
    pkgs = " ".join(CURATED_PACMAN)
    # per-package so a bad name never aborts the run
    script = (f'for p in {pkgs}; do echo "== $p =="; '
              f'pacman -S --noconfirm --needed "$p" || echo "SKIP $p"; done')
    _wsl(script, timeout=7200)
    verify()


def install_full() -> None:
    header("Install FULL BlackArch", "~2,800 tools — many GB, can take a long time")
    if not wsl_available():
        console.print("[red]Arch WSL not reachable.[/]")
        return pause()
    if Prompt.ask("Install the ENTIRE BlackArch toolset? This is huge.",
                  choices=["y", "n"], default="n") != "y":
        return
    _wsl("pacman -S --noconfirm --needed blackarch", timeout=21600)
    verify()


def install_windows_native() -> None:
    header("Windows-native subset", "Tools that run without WSL")
    for pkg, mgr, _binary in WINDOWS_NATIVE:
        if mgr == "winget" and shutil.which("winget"):
            subprocess.run(["winget", "install", "-e", "--id", pkg,
                            "--accept-package-agreements", "--accept-source-agreements"])
        elif mgr == "pip" and shutil.which("pip"):
            subprocess.run(["pip", "install", "--user", pkg])
        elif mgr == "cargo" and shutil.which("cargo"):
            subprocess.run(["cargo", "install", pkg])
        else:
            console.print(f"[dim]Skipping {pkg}: {mgr} not available.[/]")
    pause()


def verify() -> None:
    header("Verify install", "What's reachable now (native or WSL)")
    from .utils import resolve_tool
    checks = ["nmap", "sqlmap", "hydra", "john", "hashcat", "nuclei", "searchsploit",
              "msfconsole", "gobuster", "ffuf", "nikto", "aircrack-ng", "radare2"]
    t = Table()
    t.add_column("Tool", style="bold")
    t.add_column("Status")
    for c in checks:
        loc = resolve_tool(c)
        if loc:
            t.add_row(c, f"[green]{loc[0]}[/]")
        else:
            t.add_row(c, "[red]missing[/]")
    console.print(t)
    pause()


MENU = {
    "1": ("Show install plan", plan),
    "2": ("Bootstrap BlackArch (one-time)", bootstrap_blackarch),
    "3": ("Install curated arsenal (~50 tools)", install_curated),
    "4": ("Install FULL BlackArch (~2,800)", install_full),
    "5": ("Install Windows-native subset", install_windows_native),
    "6": ("Verify what's installed", verify),
}
