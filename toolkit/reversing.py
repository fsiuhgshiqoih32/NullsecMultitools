from __future__ import annotations

from rich.prompt import Prompt

from .utils import console, header, pause, resolve_tool, run_tool


def _need(binary: str, install: str) -> bool:
    if resolve_tool(binary):
        return True
    console.print(f"[yellow]{binary} not installed[/] (native or WSL). "
                  f"Install: [cyan]{install}[/]")
    return False


def bin_info() -> None:
    header("Binary info", "Headers, arch, libraries (rabin2)")
    if not _need("rabin2", "pacman -S radare2"):
        return pause()
    f = Prompt.ask("Binary path").strip('"')
    run_tool("rabin2", ["-I", f], wsl_pathify={1})
    console.print("\n[dim]imports:[/]")
    run_tool("rabin2", ["-i", f], wsl_pathify={1})
    pause()


def functions() -> None:
    header("Function list", "Auto-analyze and list functions (radare2)")
    if not _need("r2", "pacman -S radare2"):
        return pause()
    f = Prompt.ask("Binary path").strip('"')
    run_tool("r2", ["-qc", "aaa;afl", f], wsl_pathify={2})
    pause()


def bin_strings() -> None:
    header("Binary strings", "Extract strings with offsets (rabin2 -z)")
    if not _need("rabin2", "pacman -S radare2"):
        return pause()
    f = Prompt.ask("Binary path").strip('"')
    run_tool("rabin2", ["-z", f], wsl_pathify={1})
    pause()


def rop_gadgets() -> None:
    header("ROP gadgets", "Find gadgets for exploit development")
    tool = "ROPgadget" if resolve_tool("ROPgadget") else ("ropper" if resolve_tool("ropper") else None)
    if not tool:
        console.print("[yellow]No ROP tool[/] — install: [cyan]pip install ropgadget[/] "
                      "or [cyan]pip install ropper[/]")
        return pause()
    f = Prompt.ask("Binary path").strip('"')
    if tool == "ROPgadget":
        run_tool("ROPgadget", ["--binary", f], wsl_pathify={1})
    else:
        run_tool("ropper", ["-f", f], wsl_pathify={1})
    pause()


def cheatsheet() -> None:
    header("RE cheat sheet", "Common commands")
    for line in [
        "[bold]radare2[/]  r2 -A bin   (aaa, afl, pdf @main, VV for graph)",
        "[bold]gdb+pwndbg[/]  gdb ./bin  (break main, run, info functions, x/20i $pc)",
        "[bold]objdump[/]  objdump -d -M intel bin",
        "[bold]binwalk[/]  binwalk -e firmware.bin   (extract embedded)",
        "[bold]ltrace/strace[/]  strace ./bin   ltrace ./bin",
        "[bold]checksec[/]  checksec --file=bin   (NX/PIE/canary/RELRO)",
        "[bold]one_gadget[/]  one_gadget libc.so.6   (magic RCE offsets)",
        "[bold]patchelf[/]  patchelf --set-interpreter ... --replace-needed ...",
    ]:
        console.print("  " + line)
    console.print("\n[dim]nullsec also parses PE/ELF headers offline: Forensics -> 10.[/]")
    pause()


MENU = {
    "1": ("Binary info (rabin2)", bin_info),
    "2": ("Function list (radare2)", functions),
    "3": ("Strings with offsets", bin_strings),
    "4": ("ROP gadgets", rop_gadgets),
    "5": ("RE cheat sheet", cheatsheet),
}
