from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()


def resource_path(*parts: str) -> Path:
    """Return a project data path, aware of PyInstaller's onefile freeze."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base.joinpath(*parts)


def bundled_wordlist() -> Path | None:
    """Path to the bundled top-1,000,000 password list, or None if absent."""
    p = resource_path("wordlists", "top-1million-passwords.txt")
    return p if p.is_file() else None

# --- platform detection -----------------------------------------------------
IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"


# --- ASCII banner -----------------------------------------------------------

# Hardcoded fallback if pyfiglet is missing. Pure ASCII (no Unicode block/box
# glyphs), so it renders identically on any terminal font or code page.
_FALLBACK_BANNER = r"""
                ____
   ____  __  __/ / /_______  _____
  / __ \/ / / / / / ___/ _ \/ ___/
 / / / / /_/ / / (__  )  __/ /__
/_/ /_/\__,_/_/_/____/\___/\___/
"""


def render_banner(text: str = "nullsec") -> str:
    """Big ASCII banner via pyfiglet; degrade gracefully if it's unavailable.

    Uses the pure-ASCII 'slant' font — the Unicode-block fonts (ansi_shadow)
    look broken on terminals whose font lacks those box-drawing glyphs.
    """
    try:
        import pyfiglet

        try:
            return pyfiglet.figlet_format(text, font="slant")
        except Exception:
            return pyfiglet.figlet_format(text, font="standard")
    except Exception:
        return _FALLBACK_BANNER


# --- external tool detection ------------------------------------------------

# Tools the multitool can drive if they are installed on this machine.
# name -> (executable, human description, where to get it)
EXTERNAL_TOOLS = {
    "john": ("john", "John the Ripper – password hash cracker", "https://www.openwall.com/john/"),
    "hashcat": ("hashcat", "hashcat – GPU hash cracker", "https://hashcat.net/hashcat/"),
    "nmap": ("nmap", "Nmap – network/port scanner", "https://nmap.org/"),
    "masscan": ("masscan", "masscan – internet-scale port scanner", "https://github.com/robertdavidgraham/masscan"),
    "ffuf": ("ffuf", "ffuf – web fuzzer / dir brute", "https://github.com/ffuf/ffuf"),
    "gobuster": ("gobuster", "gobuster – dir/dns brute", "https://github.com/OJ/gobuster"),
    "hydra": ("hydra", "hydra – network login brute", "https://github.com/vanhauser-thc/thc-hydra"),
    "sqlmap": ("sqlmap", "sqlmap – automatic SQL injection", "https://sqlmap.org/"),
    "nikto": ("nikto", "Nikto – web server scanner", "https://github.com/sullo/nikto"),
    "whatweb": ("whatweb", "WhatWeb – web tech fingerprinter", "https://github.com/urbanadventurer/WhatWeb"),
    "subfinder": ("subfinder", "subfinder – passive subdomain enum", "https://github.com/projectdiscovery/subfinder"),
    "nuclei": ("nuclei", "nuclei – template vuln scanner", "https://github.com/projectdiscovery/nuclei"),
    "httpx": ("httpx", "httpx – fast HTTP probing", "https://github.com/projectdiscovery/httpx"),
    "searchsploit": ("searchsploit", "searchsploit – offline Exploit-DB", "https://www.exploit-db.com/searchsploit"),
}


@dataclass
class ToolStatus:
    key: str
    path: str | None
    description: str
    url: str

    @property
    def installed(self) -> bool:
        return self.path is not None


def detect_tools() -> list[ToolStatus]:
    out = []
    for key, (exe, desc, url) in EXTERNAL_TOOLS.items():
        out.append(ToolStatus(key, shutil.which(exe), desc, url))
    return out


def require_tool(key: str) -> str | None:
    """Return the resolved path for an external tool, or None (with a message)."""
    exe = EXTERNAL_TOOLS[key][0]
    path = shutil.which(exe)
    if not path:
        console.print(
            f"[yellow]{exe}[/] is not on your PATH. "
            f"Install it from [cyan]{EXTERNAL_TOOLS[key][2]}[/] to use this module."
        )
    return path


def run_external(cmd: list[str], capture: bool = False) -> subprocess.CompletedProcess:
    """Run an external command, echoing it first so the user sees exactly what ran."""
    console.print(f"[dim]$ {' '.join(cmd)}[/]")
    return subprocess.run(cmd, text=True, capture_output=capture)


# --- optional python libraries ---------------------------------------------
# Some tools use extras (cryptography, pillow, dnspython). They're optional so
# nullsec keeps running with just rich + requests; missing libs degrade to a
# one-line install hint instead of crashing.

def optional_import(module: str):
    """Import an optional dependency, returning the module or None."""
    import importlib
    try:
        return importlib.import_module(module)
    except Exception:
        return None


def need_lib(module: str, pip_name: str | None = None):
    """Return an imported optional lib, or None after printing an install hint."""
    mod = optional_import(module)
    if mod is None:
        console.print(f"[yellow]This tool needs the optional '{module}' library.[/] "
                      f"Install it with [cyan]pip install {pip_name or module}[/]")
    return mod


def soft_require(binary: str, install_hint: str = "") -> tuple[str, str] | None:
    """Resolve an external tool (native or WSL) for a wrapper, or print a hint.

    Returns the resolve_tool() location tuple ('native'|'wsl', where), or None."""
    loc = resolve_tool(binary)
    if loc is None:
        msg = f"[yellow]{binary}[/] not found natively or in WSL."
        msg += f" Install: [cyan]{install_hint}[/]" if install_hint else \
               " Install it (home menu -> i)."
        console.print(msg)
    return loc


# --- WSL bridge -------------------------------------------------------------
# Many Linux-only tools install into WSL. On Windows these helpers let nullsec
# detect and drive them, so 'hydra', 'searchsploit', etc. still work. On real
# Linux/macOS there is no WSL and everything resolves natively instead.

# Distros we prefer to bridge into if several are installed.
_PREFERRED_DISTROS = ("archlinux", "kali-linux", "kali", "ubuntu", "debian")
_wsl_distro_cache: str | None = "__unset__"  # sentinel = not yet detected


def _detect_wsl_distro() -> str | None:
    """Pick an installed WSL distro (preferring pentest ones). Windows only."""
    if not IS_WINDOWS or shutil.which("wsl") is None:
        return None
    try:
        r = subprocess.run(["wsl", "-l", "-q"], capture_output=True, timeout=15)
        # wsl.exe emits UTF-16LE with NULs; decode and clean.
        text = r.stdout.decode("utf-16-le", errors="ignore")
        distros = [d.strip() for d in text.replace("\x00", "").splitlines() if d.strip()]
        if not distros:
            return None
        for pref in _PREFERRED_DISTROS:
            for d in distros:
                if d.lower() == pref:
                    return d
        return distros[0]
    except Exception:
        return None


def get_wsl_distro() -> str | None:
    global _wsl_distro_cache
    if _wsl_distro_cache == "__unset__":
        _wsl_distro_cache = _detect_wsl_distro()
    return _wsl_distro_cache


# Back-compat: modules importing WSL_DISTRO get the detected value.
WSL_DISTRO = get_wsl_distro() or "archlinux"


def wsl_available() -> bool:
    distro = get_wsl_distro()
    if not distro:
        return False
    try:
        r = subprocess.run(["wsl", "-d", distro, "-u", "root", "--", "true"],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def wsl_which(binary: str) -> bool:
    """True if `binary` exists inside the WSL distro."""
    distro = get_wsl_distro()
    if not distro:
        return False
    try:
        r = subprocess.run(
            ["wsl", "-d", distro, "-u", "root", "--", "bash", "-lc",
             f"command -v {binary}"],
            capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def to_wsl_path(win_path: str) -> str:
    """C:\\Users\\x -> /mnt/c/Users/x so WSL tools can read Windows files."""
    p = win_path.strip().strip('"').replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def resolve_tool(binary: str) -> tuple[str, str] | None:
    """Where a tool lives: ('native', path) | ('wsl', distro) | None."""
    native = shutil.which(binary)
    if native:
        return ("native", native)
    if IS_WINDOWS and wsl_available() and wsl_which(binary):
        return ("wsl", get_wsl_distro())
    return None


def probe_tools(binaries: list[str]) -> dict[str, tuple[str, str] | None]:
    """Resolve many tools at once. Native check per tool, then a SINGLE batched
    WSL call for the rest — so the home-screen indicator stays fast."""
    result: dict[str, tuple[str, str] | None] = {}
    remaining = []
    for b in binaries:
        p = shutil.which(b)
        if p:
            result[b] = ("native", p)
        else:
            remaining.append(b)
    if remaining and IS_WINDOWS and wsl_available():
        distro = get_wsl_distro()
        # NOTE: the wsl.exe invocation layer pre-expands $VARs before bash runs,
        # so a shell for-loop with $t yields empty. Bake each name into the script
        # literally (names come from our own code, so no injection risk).
        script = "; ".join(f"command -v {b} >/dev/null 2>&1 && echo {b}"
                           for b in remaining)
        try:
            r = subprocess.run(["wsl", "-d", distro, "-u", "root", "--", "bash", "-lc", script],
                               capture_output=True, timeout=30)
            found = set(r.stdout.decode("utf-8", "ignore").replace("\x00", "").split())
        except Exception:
            found = set()
        for b in remaining:
            result[b] = ("wsl", distro) if b in found else None
    else:
        for b in remaining:
            result.setdefault(b, None)
    return result


def run_tool(binary: str, args: list[str], wsl_pathify: set[int] | None = None):
    """Run a tool natively if present, else through WSL. Indices in wsl_pathify
    are argument positions that are file paths needing Windows->WSL translation."""
    loc = resolve_tool(binary)
    if loc is None:
        console.print(f"[yellow]{binary}[/] not found natively or in WSL. "
                      f"Install it (home menu → i) first.")
        return None
    kind, where = loc
    if kind == "native":
        return run_external([binary, *args])
    # WSL path
    conv = list(args)
    if wsl_pathify:
        for i in wsl_pathify:
            if 0 <= i < len(conv):
                conv[i] = to_wsl_path(conv[i])
    return run_external(["wsl", "-d", where, "--", binary, *conv])


# --- small UI helpers -------------------------------------------------------

def header(title: str, subtitle: str = "") -> None:
    console.print(f"\n[bold green]::[/] [bold]{title}[/]")
    if subtitle:
        console.print(f"[bright_black]   {subtitle}[/]")
    console.print()


def pause() -> None:
    console.input("\n[bright_black][enter][/] ")


def kv_table(title: str, rows: list[tuple[str, str]]) -> Table:
    t = Table(title=title, show_header=False, box=None, pad_edge=False)
    t.add_column(style="bold")
    t.add_column()
    for k, v in rows:
        t.add_row(k, v)
    return t


# --- proxy helper -----------------------------------------------------------
# Lazy import avoids a circular dependency: toolkit.proxy imports from utils.

def get_proxy() -> dict | None:
    """Return a proxies dict for ``requests`` (e.g. ``{"http": url, ...}``),
    or ``None`` if the proxy manager is disabled or empty.

    Any module can do::

        from .utils import get_proxy
        r = requests.get(url, proxies=get_proxy(), timeout=10)
    """
    try:
        from toolkit import proxy as _proxy_mod
        mgr = _proxy_mod.get_manager()
        return mgr.get_requests_proxies()
    except Exception:
        return None


# --- session reporting ------------------------------------------------------

@dataclass
class ReportEntry:
    category: str
    title: str
    lines: list[str]
    when: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


class SessionReport:
    """Collects findings during a run so they can be saved to Markdown.

    When ``active_workspace`` is set (by the Workspace module), every ``log()``
    call is also forwarded into that workspace's persistent findings list.
    """

    def __init__(self) -> None:
        self.entries: list[ReportEntry] = []
        self.started = datetime.now()
        self.active_workspace = None  # set by toolkit.workspace.set_active

    def log(self, category: str, title: str, lines: list[str]) -> None:
        entry = ReportEntry(category, title, [str(x) for x in lines])
        self.entries.append(entry)
        if self.active_workspace is not None:
            try:
                self.active_workspace.add_finding(
                    category, title, [str(x) for x in lines], entry.when)
            except Exception:
                pass  # never let workspace persistence crash a tool

    def __call__(self, category: str, detail: str = "", *lines: str) -> None:
        """Shorthand logger: ``report("Category", "one-line detail")``.

        Complements :meth:`log` (which takes multi-line evidence). Modules use
        this quick form to record that an action ran; the detail becomes the
        entry title so the report reads ``[Category] detail``. Extra positional
        args are appended as body lines.
        """
        self.log(category, detail or "(logged)", list(lines))

    def clear(self) -> None:
        self.entries.clear()

    def as_markdown(self) -> str:
        out = [
            "# nullsec session report",
            f"\n_Started {self.started:%Y-%m-%d %H:%M:%S} · "
            f"{len(self.entries)} finding(s)_\n",
        ]
        for e in self.entries:
            out.append(f"## [{e.category}] {e.title}  \n_{e.when}_\n")
            out.extend(e.lines)
            out.append("")
        return "\n".join(out)

    def save(self, directory: str | Path = ".") -> Path:
        name = f"nullsec_report_{self.started:%Y%m%d_%H%M%S}.md"
        path = Path(directory) / name
        path.write_text(self.as_markdown(), encoding="utf-8")
        return path

    def save_html(self, directory: str | Path = ".") -> Path:
        rows = []
        for e in self.entries:
            body = "<br>".join(x.replace("`", "") for x in e.lines)
            rows.append(
                f'<div class="card"><span class="cat">{e.category}</span>'
                f'<span class="time">{e.when}</span><h3>{e.title}</h3>'
                f'<pre>{body}</pre></div>')
        html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>nullsec report</title><style>
body{{background:#0d1117;color:#c9d1d9;font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:2rem}}
h1{{color:#39d353;font-family:monospace;letter-spacing:2px}}
.meta{{color:#8b949e;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #30363d;border-left:3px solid #39d353;
border-radius:6px;padding:1rem 1.2rem;margin:.8rem 0}}
.cat{{background:#1f6feb;color:#fff;border-radius:4px;padding:1px 8px;font-size:.75rem;text-transform:uppercase}}
.time{{color:#8b949e;float:right;font-family:monospace}}
h3{{margin:.5rem 0}}pre{{color:#8b949e;white-space:pre-wrap;margin:0}}
</style></head><body>
<h1>&#9608; nullsec SESSION REPORT</h1>
<div class="meta">Started {self.started:%Y-%m-%d %H:%M:%S} &middot; {len(self.entries)} finding(s)</div>
{''.join(rows) or '<p>No findings.</p>'}
</body></html>"""
        name = f"nullsec_report_{self.started:%Y%m%d_%H%M%S}.html"
        path = Path(directory) / name
        path.write_text(html, encoding="utf-8")
        return path


# One shared reporter every module can append to.
report = SessionReport()
