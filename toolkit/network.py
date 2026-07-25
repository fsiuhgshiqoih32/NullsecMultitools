from __future__ import annotations

import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from .utils import IS_WINDOWS, console, header, pause, report

# Ports we knock on to decide "is this host alive" without needing ICMP/admin.
PROBE_PORTS = (445, 139, 135, 80, 443, 22, 3389)


def local_info() -> None:
    header("Local network info", "Who am I on the network")
    hostname = socket.gethostname()
    local_ip = _primary_ip()
    t = Table(show_header=False, box=None)
    t.add_row("Hostname", hostname)
    t.add_row("Primary IP", local_ip)
    t.add_row("Likely subnet", _subnet_of(local_ip) + ".0/24" if local_ip else "?")
    try:
        _, _, addrs = socket.gethostbyname_ex(hostname)
        t.add_row("All addresses", ", ".join(addrs))
    except socket.gaierror:
        pass
    console.print(t)
    pause()


def _primary_ip() -> str:
    """Trick: open a UDP socket 'to' a public IP; the OS picks our outbound iface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _subnet_of(ip: str) -> str:
    return ".".join(ip.split(".")[:3]) if ip else ""


def _host_alive(ip: str, timeout: float) -> tuple[str, bool, list[int]]:
    open_ports = []
    for port in PROBE_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return ip, bool(open_ports), open_ports


def ping_sweep() -> None:
    header("Host discovery", "TCP ping-sweep of your /24 — finds live hosts, no admin")
    default_subnet = _subnet_of(_primary_ip())
    subnet = console.input(f"Subnet first three octets [[cyan]{default_subnet}[/]]: ").strip() or default_subnet
    timeout = float(console.input("Per-probe timeout (s) [0.3]: ").strip() or "0.3")
    ips = [f"{subnet}.{i}" for i in range(1, 255)]

    alive: list[tuple[str, list[int]]] = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}"), console=console) as prog:
        task = prog.add_task(f"Sweeping {subnet}.0/24", total=len(ips))
        with ThreadPoolExecutor(max_workers=256) as pool:
            futs = [pool.submit(_host_alive, ip, timeout) for ip in ips]
            for fut in as_completed(futs):
                ip, up, ports = fut.result()
                if up:
                    alive.append((ip, ports))
                prog.advance(task)

    if not alive:
        console.print("[yellow]No hosts responded on the probe ports. "
                      "They may still be up but firewalled.[/]")
        return pause()

    t = Table(title=f"Live hosts on {subnet}.0/24")
    t.add_column("IP", style="green bold")
    t.add_column("Hostname", style="cyan")
    t.add_column("Open probe ports")
    lines = []
    for ip, ports in sorted(alive, key=lambda x: int(x[0].split(".")[-1])):
        name = _reverse_dns(ip)
        t.add_row(ip, name, ", ".join(map(str, ports)))
        lines.append(f"- {ip} ({name}) ports {ports}")
    console.print(t)
    report.log("network", f"Host discovery {subnet}.0/24", [f"{len(alive)} live hosts:"] + lines)
    pause()


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return "-"


def reverse_lookup() -> None:
    header("Reverse DNS", "IP -> hostname")
    ip = console.input("IP: ").strip()
    console.print(f"{ip} -> [cyan]{_reverse_dns(ip)}[/]")
    pause()


def arp_cache() -> None:
    header("ARP cache", "Devices your machine has recently talked to (arp -a)")
    try:
        out = subprocess.run(["arp", "-a"], text=True, capture_output=True, timeout=10)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Couldn't run arp: {e}[/]")
        return pause()
    console.print("[dim]" + out.stdout.strip() + "[/]")
    pause()


def sniff() -> None:
    header("Packet capture", "tcpdump filter builder (root/admin required)")
    from .utils import resolve_tool, run_tool
    if not resolve_tool("tcpdump"):
        console.print("[yellow]tcpdump not installed[/] — [cyan]apt install tcpdump[/]")
        return pause()
    iface = Prompt.ask("Interface", default="any")
    filt = Prompt.ask("BPF filter (e.g. 'port 80 or port 443', 'host 10.0.0.5')",
                      default="tcp")
    count = Prompt.ask("Packet count (0 = until Ctrl-C)", default="50")
    args = ["-i", iface, "-nn", "-A", filt]
    if count != "0":
        args = ["-c", count] + args
    console.print("[bright_black]Capturing creds in cleartext protocols (FTP/HTTP/telnet) "
                  "is a classic MITM finding. Authorized networks only.[/]")
    run_tool("tcpdump", args)
    pause()


def traceroute() -> None:
    header("Traceroute", "Trace the hops to a host (uses the OS tool)")
    target = Prompt.ask("Host/IP", default="8.8.8.8").strip()
    cmd = (["tracert", "-d", "-h", "20", target] if IS_WINDOWS
           else ["traceroute", "-n", "-m", "20", target])
    try:
        subprocess.run(cmd, timeout=120)
    except FileNotFoundError:
        console.print("[red]traceroute/tracert not found on PATH.[/]")
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]{e}[/]")
    pause()


def public_ip() -> None:
    header("Public IP", "Your internet-facing address + ISP/geo")
    try:
        d = requests.get("http://ip-api.com/json/", timeout=8).json()
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Lookup failed: {e}[/]")
        return pause()
    t = Table(show_header=False, box=None)
    for label, key in (("Public IP", "query"), ("ISP", "isp"), ("Org", "org"),
                       ("AS", "as"), ("City", "city"), ("Country", "country")):
        t.add_row(label, str(d.get(key, "?")))
    console.print(t)
    report.log("network", "Public IP", [f"- {d.get('query')} ({d.get('isp')})"])
    pause()


def mac_vendor() -> None:
    header("MAC vendor lookup", "Resolve an OUI (first 3 bytes) to a manufacturer")
    mac = Prompt.ask("MAC address (e.g. 00:1A:2B:3C:4D:5E)").strip()
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=8)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Lookup failed: {e}[/]")
        return pause()
    if r.status_code == 200 and r.text.strip():
        console.print(f"[bold green]{r.text.strip()}[/]")
    else:
        console.print("[yellow]No vendor found for that OUI.[/]")
    pause()


# ---------------------------------------------------------------------------
# DDoS test tool (stress test for authorized targets)
# ---------------------------------------------------------------------------
def ddos_test() -> None:
    header("DDoS Stress Test (Authorized Only)")
    console.print("Flood a target with UDP/TCP packets for load testing.\n")
    target = Prompt.ask("Target IP/hostname")
    port = int(Prompt.ask("Port", default="80"))
    count = int(Prompt.ask("Packet count", default="100"))
    proto = Prompt.ask("Protocol (udp/tcp)", choices=["udp", "tcp"], default="udp")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
    payload = b"\x00" * 1024
    sent = 0
    try:
        if proto == "tcp":
            sock.connect((target, port))
        for _ in range(count):
            try:
                if proto == "udp":
                    sock.sendto(payload, (target, port))
                else:
                    sock.send(payload)
                sent += 1
            except Exception:
                break
    finally:
        sock.close()
    console.print(f"[green]Sent {sent}/{count} {proto.upper()} packets to {target}:{port}[/]")
    report("DDoS test", f"target={target}:{port} proto={proto} sent={sent}/{count}")
    pause()


# ---------------------------------------------------------------------------
# Tor service guide
# ---------------------------------------------------------------------------
def tor_guide() -> None:
    header("Tor Service Guide")
    console.print("Tor setup and operational security for authorized testing.\n")
    steps = [
        ("Install", "apt install tor (Linux) or Tor Expert Bundle (Windows)"),
        ("Start", "service tor start / tor --runasclient"),
        ("SOCKS proxy", "Route traffic through 127.0.0.1:9050 (SOCKS5)"),
        ("Python proxy", "pip install pysocks; requests with proxies={'socks5':'127.0.0.1:9050'}"),
        ("Hidden service", "Configure HiddenServiceDir + HiddenServicePort in torrc"),
        ("OpSec", "Rotate circuits, avoid JS, use Tails/Whonix for isolation"),
        ("Tools", "torsocks, nyx (monitor), onionbalance, stem (Python controller)"),
    ]
    for label, desc in steps:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Tor guide", f"{len(steps)} steps")
    pause()


# ---------------------------------------------------------------------------
# VPN tunnel attack guide
# ---------------------------------------------------------------------------
def vpn_tunnel_guide() -> None:
    header("VPN Tunnel Attack Guide")
    console.print("VPN tunneling attack methodology for authorized testing.\n")
    attacks = [
        ("IKE scan", "ike-scan to discover VPN endpoints and vendor fingerprints"),
        ("Aggressive mode", "ike-scan --aggressive to grab PSK hash → crack with hashcat -m 500"),
        ("VPN fingerprint", "Identify Cisco/Fortinet/PaloAlto/StrongSwan by IKE response"),
        ("Split tunneling", "Test for split-tunnel misconfig allowing bypass"),
        ("Cert-based", "Steal/mimic client certificates for IKEv2/EAP-TLS"),
        ("Downgrade", "Force weak cipher suites / IKEv1 aggressive mode"),
        ("Tools", "ike-scan, strongSwan, nmap ike-* scripts, vpnc, hashcat"),
    ]
    for label, desc in attacks:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("VPN tunnel guide", f"{len(attacks)} techniques")
    pause()


# ---------------------------------------------------------------------------
# Cisco ASA exploit guide
# ---------------------------------------------------------------------------
def cisco_exploit() -> None:
    header("Cisco ASA / IOS Exploit Guide")
    console.print("Cisco network device exploitation for authorized testing.\n")
    attacks = [
        ("CVE-2018-0101", "Cisco ASA FXS DNS heap overflow (RCE via crafted DNS packet)"),
        ("CVE-2019-15271", "CVE-2019-15271 ASA path traversal (read arbitrary files)"),
        ("Smart Install", "Smart Install exploitation (cisco-smi-install / cisco-sma)"),
        ("SNMP", "RW community strings → config push, password extraction"),
        ("HTTP/ASDM", "Default creds on ASDM web interface, path traversal"),
        ("IKE / VPN", "Aggressive mode PSK hash grab (ike-scan)"),
        ("Tools", "cisco-config-extractor, ike-scan, metasploit cisco modules"),
    ]
    for label, desc in attacks:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Cisco exploit", f"{len(attacks)} techniques")
    pause()


# ---------------------------------------------------------------------------
# Checkpoint exploit guide
# ---------------------------------------------------------------------------
def checkpoint_exploit() -> None:
    header("Check Point Firewall Exploit Guide")
    console.print("Check Point exploitation for authorized testing.\n")
    attacks = [
        ("CVE-2024-24919", "Info disclosure via path traversal in Gaia portal"),
        ("CVE-2020-6025", "SQL injection in Mobile Access blade"),
        ("Default creds", "admin:admin on Gaia portal, cptwn:password on CLI"),
        ("IPSO/Splat", "Legacy OS file disclosure, command injection"),
        ("VPN", "IKE aggressive mode PSK grab, mode-config leaks"),
        ("Tools", "nmap cisco/checkpoint NSE, ike-scan, metasploit"),
    ]
    for label, desc in attacks:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Checkpoint exploit", f"{len(attacks)} techniques")
    pause()


MENU = {
    "1": ("Local network info", local_info),
    "2": ("Host discovery (ping-sweep /24)", ping_sweep),
    "3": ("Reverse DNS lookup", reverse_lookup),
    "4": ("ARP cache (local devices)", arp_cache),
    "5": ("Packet capture (tcpdump)", sniff),
    "6": ("Traceroute", traceroute),
    "7": ("Public IP + geo", public_ip),
    "8": ("MAC vendor (OUI) lookup", mac_vendor),
    "9": ("DDoS stress test (authorized)", ddos_test),
    "10": ("Tor service guide", tor_guide),
    "11": ("VPN tunnel attack guide", vpn_tunnel_guide),
    "12": ("Cisco ASA exploit guide", cisco_exploit),
    "13": ("Check Point exploit guide", checkpoint_exploit),
}
