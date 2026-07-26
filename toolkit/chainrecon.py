from __future__ import annotations

import socket
import struct
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                           TimeRemainingColumn)
from rich.prompt import Prompt
from rich.table import Table

from .utils import (console, header, pause, report,
                    save_json_report, save_md_report, get_proxy)

# Import shodan module for API key sharing
from . import shodan as _shodan


# ---------------------------------------------------------------------------
# DNS helpers (reuse raw-packet approach from osint.py)
# ---------------------------------------------------------------------------

def _dns_a(host: str, server: str = "8.8.8.8") -> list[str]:
    """Resolve A records via raw UDP DNS packet."""
    qname = b""
    for label in host.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    pkt = (struct.pack(">HHHHHH", 0x2021, 0x0100, 1, 0, 0, 0)
           + qname + struct.pack(">HH", 1, 1))  # A record
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
        s.close()
    except Exception:
        return []
    if len(data) < 12:
        return []
    _id, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    # Skip question
    for _ in range(qd):
        while data[off] != 0:
            if data[off] & 0xC0 == 0xC0:
                off += 2
                break
            off += 1 + data[off]
        else:
            off += 1
        off += 4
    # Parse answers
    ips = []
    for _ in range(an):
        try:
            # Skip name (possibly compressed)
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while data[off] != 0:
                    off += 1 + data[off]
                off += 1
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4:
                ips.append(".".join(str(b) for b in data[off:off + 4]))
            off += rdlen
        except Exception:
            break
    return ips


def _crtsh_subdomains(domain: str) -> list[str]:
    """Fetch subdomains from crt.sh certificate transparency logs."""
    import requests
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20, proxies=get_proxy(), verify=False)
        if r.status_code != 200:
            return []
        entries = r.json()
    except Exception:
        return []
    subs = set()
    for e in entries:
        for name in e.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*") and domain in name:
                subs.add(name)
    return sorted(subs)


def _shodan_host(ip: str, api_key: str) -> dict | None:
    """Query Shodan for a single IP. Returns dict or None on error."""
    import requests
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=15, proxies=get_proxy(), verify=False)
        d = r.json()
        if isinstance(d, dict) and "error" in d:
            return None
        return d
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(domain: str, do_shodan: bool = True,
                 do_resolve: bool = True, max_shodan: int = 20) -> dict:
    """Run the full chained recon pipeline on a domain.

    Returns a structured dict with all results.
    """
    results: dict = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "subdomains": [],
        "resolved": {},
        "shodan": {},
        "vulns": [],
        "errors": [],
    }

    # Step 1: Subdomain enumeration via crt.sh
    console.print("\n[bold cyan]Step 1:[/] Subdomain enumeration (crt.sh)")
    subs = _crtsh_subdomains(domain)
    results["subdomains"] = subs
    console.print(f"  Found [green]{len(subs)}[/] subdomain(s)")
    if not subs:
        results["errors"].append("No subdomains found via crt.sh")
        return results

    # Step 2: DNS resolution
    if do_resolve:
        console.print("\n[bold cyan]Step 2:[/] DNS resolution")
        for sub in subs:
            ips = _dns_a(sub)
            if ips:
                results["resolved"][sub] = ips
                console.print(f"  [green]{sub}[/] -> {', '.join(ips)}")
        console.print(f"  Resolved [green]{len(results['resolved'])}[/] / {len(subs)}")

    # Step 3: Shodan lookups for unique IPs
    unique_ips = set()
    for ip_list in results["resolved"].values():
        unique_ips.update(ip_list)

    if do_shodan and unique_ips:
        api_key = _shodan._load_key()
        if not api_key:
            console.print("\n[yellow]No Shodan API key — skipping Shodan step.[/]")
            console.print("[dim]Set SHODAN_API_KEY or use Shodan module to configure.[/]")
            results["errors"].append("No Shodan API key configured")
        else:
            console.print(f"\n[bold cyan]Step 3:[/] Shodan lookup "
                          f"({min(len(unique_ips), max_shodan)} / {len(unique_ips)} IPs)")
            ip_list = sorted(unique_ips)[:max_shodan]
            with Progress(
                SpinnerColumn(), BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeRemainingColumn(), console=console,
            ) as prog:
                task = prog.add_task("Shodan", total=len(ip_list))
                with ThreadPoolExecutor(max_workers=5) as pool:
                    futs = {pool.submit(_shodan_host, ip, api_key): ip
                            for ip in ip_list}
                    for fut in as_completed(futs):
                        ip = futs[fut]
                        d = fut.result()
                        if d:
                            results["shodan"][ip] = {
                                "org": d.get("org"),
                                "os": d.get("os"),
                                "ports": sorted(d.get("ports", [])),
                                "vulns": sorted(d.get("vulns", [])),
                                "country": d.get("country_name"),
                                "hostnames": d.get("hostnames", []),
                            }
                            if d.get("vulns"):
                                for v in d["vulns"]:
                                    results["vulns"].append({"ip": ip, "cve": v})
                        prog.advance(task)
            console.print(f"  Shodan data for [green]{len(results['shodan'])}[/] IP(s)")
            if results["vulns"]:
                console.print(f"  [red bold]{len(results['vulns'])}[/] [red]vulnerabilit(y/ies) found[/]")

    return results


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _display_results(results: dict) -> None:
    """Display pipeline results in rich tables."""
    # Subdomains
    subs = results.get("subdomains", [])
    if subs:
        tbl = Table(title=f"Subdomains ({len(subs)})")
        tbl.add_column("#", justify="right", style="dim")
        tbl.add_column("Subdomain", style="cyan")
        tbl.add_column("IP(s)", style="green")
        for i, s in enumerate(subs, 1):
            ips = ", ".join(results.get("resolved", {}).get(s, []))
            tbl.add_row(str(i), s, ips or "-")
        console.print(tbl)

    # Shodan summary
    shodan_data = results.get("shodan", {})
    if shodan_data:
        tbl = Table(title=f"Shodan summary ({len(shodan_data)} IPs)")
        tbl.add_column("IP", style="green")
        tbl.add_column("Org", style="dim")
        tbl.add_column("Country")
        tbl.add_column("Ports", style="cyan")
        tbl.add_column("OS", style="magenta")
        tbl.add_column("Vulns", style="red")
        for ip, d in sorted(shodan_data.items()):
            tbl.add_row(
                ip,
                str(d.get("org", "?")),
                str(d.get("country", "?")),
                ", ".join(map(str, d.get("ports", [])))[:40],
                str(d.get("os", "?")),
                str(len(d.get("vulns", []))),
            )
        console.print(tbl)

    # Vulnerabilities
    vulns = results.get("vulns", [])
    if vulns:
        console.print(f"\n[red bold]Vulnerabilities ({len(vulns)}):[/]")
        for v in vulns:
            console.print(f"  [red]{v['cve']}[/] on [green]{v['ip']}[/]")


def _results_to_markdown(results: dict) -> str:
    lines = [
        f"# Chained Recon Report: {results['domain']}",
        f"\n_Generated: {results['timestamp']}_\n",
        "## Summary\n",
        f"- Subdomains found: {len(results.get('subdomains', []))}",
        f"- Resolved: {len(results.get('resolved', {}))}",
        f"- Shodan results: {len(results.get('shodan', {}))}",
        f"- Vulnerabilities: {len(results.get('vulns', []))}",
    ]
    subs = results.get("subdomains", [])
    if subs:
        lines.append(f"\n## Subdomains ({len(subs)})\n")
        for s in subs:
            ips = ", ".join(results.get("resolved", {}).get(s, []))
            lines.append(f"- {s}" + (f" ({ips})" if ips else ""))
    shodan_data = results.get("shodan", {})
    if shodan_data:
        lines.append(f"\n## Shodan Results ({len(shodan_data)} IPs)\n")
        for ip, d in sorted(shodan_data.items()):
            lines.append(f"### {ip}")
            lines.append(f"- Org: {d.get('org', '?')}")
            lines.append(f"- Country: {d.get('country', '?')}")
            lines.append(f"- OS: {d.get('os', '?')}")
            lines.append(f"- Ports: {', '.join(map(str, d.get('ports', [])))}")
            if d.get("vulns"):
                lines.append(f"- Vulns: {', '.join(d['vulns'])}")
            lines.append("")
    vulns = results.get("vulns", [])
    if vulns:
        lines.append(f"\n## Vulnerabilities ({len(vulns)})\n")
        for v in vulns:
            lines.append(f"- **{v['cve']}** on {v['ip']}")
    errors = results.get("errors", [])
    if errors:
        lines.append("\n## Errors\n")
        for e in errors:
            lines.append(f"- {e}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def full_pipeline() -> None:
    header("Chained Recon", "Subdomain enum → DNS → Shodan → CVE → report")
    domain = Prompt.ask("Target domain (e.g. example.com)").strip()
    if not domain:
        return pause()
    do_shodan = Prompt.ask("Include Shodan lookups?", choices=["y", "n"],
                           default="y") == "y"
    results = run_pipeline(domain, do_shodan=do_shodan)
    console.print()
    _display_results(results)
    total_subs = len(results.get("subdomains", []))
    total_resolved = len(results.get("resolved", {}))
    total_shodan = len(results.get("shodan", {}))
    total_vulns = len(results.get("vulns", []))
    report.log("chainrecon", f"Pipeline {domain}",
               [f"- Subdomains: {total_subs}",
                f"- Resolved: {total_resolved}",
                f"- Shodan: {total_shodan}",
                f"- Vulns: {total_vulns}"])
    choice = Prompt.ask("\nExport? [j]son, [m]arkdown, [b]oth, [n]o", default="n")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if choice in ("j", "b"):
        path = save_json_report(results, f"chainrecon_{domain}_{ts}.json")
        console.print(f"[green]JSON saved:[/] {path}")
    if choice in ("m", "b"):
        path = save_md_report(_results_to_markdown(results),
                              f"chainrecon_{domain}_{ts}.md")
        console.print(f"[green]Markdown saved:[/] {path}")
    pause()


def subdomain_only() -> None:
    header("Subdomain enumeration", "crt.sh certificate transparency logs")
    domain = Prompt.ask("Domain").strip()
    if not domain:
        return pause()
    subs = _crtsh_subdomains(domain)
    if not subs:
        console.print("[yellow]No subdomains found.[/]")
        return pause()
    console.print(f"\n[bold]{len(subs)}[/] subdomain(s):\n")
    for s in subs:
        console.print(f"  [cyan]{s}[/]")
    report.log("chainrecon", f"Subdomains {domain}", [f"- {len(subs)} found"])
    choice = Prompt.ask("\nFeed into Shodan pipeline?", choices=["y", "n"], default="n")
    if choice == "y":
        results = run_pipeline(domain, do_shodan=True)
        _display_results(results)
    pause()


def resolve_only() -> None:
    header("Bulk DNS resolution", "Resolve a list of hostnames to IPs")
    raw = Prompt.ask("Hostnames (comma-separated)").strip()
    if not raw:
        return pause()
    hosts = [h.strip() for h in raw.split(",") if h.strip()]
    tbl = Table(title=f"DNS resolution ({len(hosts)} hosts)")
    tbl.add_column("Hostname", style="cyan")
    tbl.add_column("IP(s)", style="green")
    resolved = {}
    for h in hosts:
        ips = _dns_a(h)
        resolved[h] = ips
        tbl.add_row(h, ", ".join(ips) if ips else "[red]no A record[/]")
    console.print(tbl)
    report.log("chainrecon", "Bulk DNS resolve",
               [f"- {len(resolved)} hosts, "
                f"{sum(1 for v in resolved.values() if v)} resolved"])
    pause()


def shodan_batch() -> None:
    header("Batch Shodan lookup", "Run Shodan on a list of IPs")
    raw = Prompt.ask("IPs (comma-separated)").strip()
    if not raw:
        return pause()
    ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
    api_key = _shodan._load_key()
    if not api_key:
        console.print("[yellow]No Shodan API key configured.[/]")
        console.print("[dim]Use Shodan module → Set API key, or set SHODAN_API_KEY env var.[/]")
        return pause()
    results = {}
    with Progress(
        SpinnerColumn(), BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as prog:
        task = prog.add_task("Shodan", total=len(ips))
        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = {pool.submit(_shodan_host, ip, api_key): ip for ip in ips}
            for fut in as_completed(futs):
                ip = futs[fut]
                d = fut.result()
                if d:
                    results[ip] = {
                        "org": d.get("org"),
                        "ports": sorted(d.get("ports", [])),
                        "vulns": sorted(d.get("vulns", [])),
                        "country": d.get("country_name"),
                    }
                prog.advance(task)
    if not results:
        console.print("[yellow]No Shodan data returned.[/]")
        return pause()
    tbl = Table(title=f"Shodan batch ({len(results)} IPs)")
    tbl.add_column("IP", style="green")
    tbl.add_column("Org", style="dim")
    tbl.add_column("Ports", style="cyan")
    tbl.add_column("Vulns", style="red")
    for ip, d in sorted(results.items()):
        tbl.add_row(ip, str(d.get("org", "?")),
                    ", ".join(map(str, d.get("ports", [])))[:40],
                    str(len(d.get("vulns", []))))
    console.print(tbl)
    report.log("chainrecon", "Batch Shodan",
               [f"- {len(results)} IPs looked up"])
    pause()


MENU = {
    "1": ("Full pipeline (subdomains → DNS → Shodan → CVE)", full_pipeline),
    "2": ("Subdomain enumeration only (crt.sh)", subdomain_only),
    "3": ("Bulk DNS resolution", resolve_only),
    "4": ("Batch Shodan lookup (IP list)", shodan_batch),
}
