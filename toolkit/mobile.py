from __future__ import annotations

from rich.prompt import Prompt

from .utils import console, header, pause, resolve_tool, run_tool


def _hand(binary: str, install: str) -> bool:
    if resolve_tool(binary):
        return True
    console.print(f"[yellow]{binary} not installed[/] — [cyan]{install}[/]")
    return False


def apk_decode() -> None:
    header("APK decode (apktool)", "Unpack resources + smali")
    if not _hand("apktool", "apt install apktool"):
        return pause()
    apk = Prompt.ask("APK path").strip('"')
    run_tool("apktool", ["d", apk, "-o", "apk_out", "-f"], wsl_pathify={1})
    console.print("[green]Decoded to apk_out/[/] — read AndroidManifest.xml + smali/.")
    pause()


def apk_decompile() -> None:
    header("APK decompile (jadx)", "Dex -> readable Java")
    if not _hand("jadx", "apt install jadx"):
        return pause()
    apk = Prompt.ask("APK path").strip('"')
    run_tool("jadx", ["-d", "jadx_out", apk], wsl_pathify={2})
    console.print("[green]Java in jadx_out/[/] — grep for keys, URLs, secrets.")
    pause()


def apk_secrets() -> None:
    header("APK secret hunt", "What to grep for after decompiling")
    for line in [
        "grep -rniE 'api[_-]?key|secret|password|token' jadx_out/",
        "grep -rniE 'https?://' jadx_out/           # endpoints",
        "grep -rn 'AKIA' jadx_out/                  # AWS keys",
        "cat apk_out/AndroidManifest.xml            # exported components, permissions",
        "grep -rn 'android:exported=\"true\"' apk_out/   # attackable components",
        "find apk_out -name '*.js' -o -name 'strings.xml'  # config",
    ]:
        console.print(f"  [green]{line}[/]")
    console.print("\n[bright_black]nullsec's Forensics secret scanner (f -> 8) works on the "
                  "decompiled folder too.[/]")
    pause()


def frida_ref() -> None:
    header("Dynamic analysis (Frida/objection)", "Runtime hooking on a rooted device/emulator")
    for line in [
        "frida-ps -U                         # list processes on USB device",
        "objection -g <package> explore      # interactive runtime toolkit",
        "android sslpinning disable          # (in objection) bypass cert pinning",
        "android hooking watch class <cls>   # hook methods",
        "frida -U -f <package> -l hook.js    # spawn with a script",
    ]:
        console.print(f"  [green]{line}[/]")
    if resolve_tool("frida"):
        console.print("\n[green]frida is installed.[/]")
    pause()


MENU = {
    "1": ("Decode APK (apktool)", apk_decode),
    "2": ("Decompile to Java (jadx)", apk_decompile),
    "3": ("Secret-hunt grep recipes", apk_secrets),
    "4": ("Frida/objection reference", frida_ref),
}
