from __future__ import annotations

import json
import os
from datetime import datetime

from rich.prompt import Prompt
from rich.table import Table

from .utils import (console, header, pause, report, resource_path,
                    save_json_report, save_md_report, get_proxy)

_API_BASE = "https://api.shodan.io"
_CONFIG_FILE = resource_path("data", "shodan_config.json")


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------

def _load_key() -> str | None:
    """Load API key from env var or config file."""
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if key:
        return key
    if _CONFIG_FILE.is_file():
        try:
            data = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
            return data.get("api_key", "").strip() or None
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _save_key(key: str) -> None:
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(
        json.dumps({"api_key": key}, indent=2), encoding="utf-8")


def get_api_key() -> str | None:
    """Return the stored API key, or prompt the user to enter one."""
    key = _load_key()
    if key:
        return key
    header("Shodan API key", "No key found in env or config")
    console.print("[dim]Get a free key at https://www.shodan.io/[/]")
    key = Prompt.ask("Enter your Shodan API key (or blank to cancel)").strip()
    if not key:
        return None
    save = Prompt.ask("Save for next time?", choices=["y", "n"], default="y")
    if save == "y":
        _save_key(key)
    return key


def set_api_key() -> None:
    header("Set Shodan API key")
    key = Prompt.ask("API key").strip()
    if not key:
        console.print("[yellow]Empty key, not saved.[/]")
        return pause()
    _save_key(key)
    console.print(f"[green]Saved to:[/] {_CONFIG_FILE}")
    pause()


def clear_api_key() -> None:
    header("Clear Shodan API key")
    if _CONFIG_FILE.is_file():
        _CONFIG_FILE.unlink()
    console.print("[green]Key cleared.[/]")
    pause()


def show_key_info() -> None:
    header("Shodan API key status")
    key = _load_key()
    if key:
        masked = key[:4] + "..." + key[-4:] if len(key) > 8 else "***"
        console.print(f"  [green]Key set:[/] {masked}")
        console.print("  [dim]Source:[/] "
                      + ("env var" if os.environ.get("SHODAN_API_KEY") else "config file"))
    else:
        console.print("  [red]No API key configured.[/]")
        console.print("  [dim]Set SHODAN_API_KEY env var or use 'Set API key' menu option.[/]")
    pause()


# ---------------------------------------------------------------------------
# API calls (pure requests, no shodan library needed)
# ---------------------------------------------------------------------------

def _api_get(endpoint: str, params: dict | None = None,
             timeout: int = 20) -> dict:
    """Make a Shodan API GET request. Raises on network errors."""
    import requests
    key = get_api_key()
    if not key:
        raise RuntimeError("No Shodan API key configured")
    params = params or {}
    params["key"] = key
    url = f"{_API_BASE}/{endpoint}"
    r = requests.get(url, params=params, timeout=timeout,
                     proxies=get_proxy(), verify=False)
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass
    data = r.json()
    if isinstance(data, dict) and "error" in data:
        raise RuntimeError(data["error"])
    return data


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _display_host(d: dict) -> None:
    """Rich colorized display of a Shodan host lookup result."""
    # Top-level info
    info = Table(show_header=False, box=None, pad_edge=False)
    info.add_column(style="bold cyan")
    info.add_column()
    info.add_row("IP", str(d.get("ip_str", d.get("ip", "?"))))
    info.add_row("Org", str(d.get("org", "?")))
    info.add_row("OS", str(d.get("os", "?")))
    info.add_row("Country", f"{d.get('country_name', '?')} ({d.get('country_code', '?')})")
    info.add_row("City", str(d.get("city", "?")))
    info.add_row("ASN", str(d.get("asn", "?")))
    info.add_row("Hostnames", ", ".join(d.get("hostnames", [])[:10]))
    info.add_row("Last update", str(d.get("last_update", "?")))
    console.print(info)

    # Ports / services table
    services = d.get("data", [])
    if services:
        tbl = Table(title=f"Open services ({len(services)})")
        tbl.add_column("Port", justify="right", style="green")
        tbl.add_column("Transport", style="dim")
        tbl.add_column("Product", style="cyan")
        tbl.add_column("Version", style="magenta")
        tbl.add_column("Banner", overflow="fold", max_width=60)
        for svc in services:
            banner = (svc.get("data", "") or "")[:120].replace("\n", " ")
            tbl.add_row(
                str(svc.get("port", "")),
                str(svc.get("transport", "")),
                str(svc.get("product", "")),
                str(svc.get("version", "")),
                banner,
            )
        console.print(tbl)

    # Vulnerabilities
    vulns = d.get("vulns", [])
    if vulns:
        console.print(f"\n[red bold]Vulnerabilities ({len(vulns)}):[/]")
        for v in sorted(vulns):
            console.print(f"  [red]{v}[/]")

    # Geolocation
    lat = d.get("latitude")
    lon = d.get("longitude")
    if lat and lon:
        console.print(f"\n[dim]Geo: {lat}, {lon}[/]")


def _display_search(d: dict, limit: int = 25) -> None:
    """Rich colorized display of Shodan search results."""
    total = d.get("total", 0)
    matches = d.get("matches", [])[:limit]
    console.print(f"[bold]{total:,}[/] total results (showing {len(matches)}):\n")
    tbl = Table()
    tbl.add_column("IP", style="green")
    tbl.add_column("Port", justify="right")
    tbl.add_column("Country", style="dim")
    tbl.add_column("Org", style="dim", overflow="fold", max_width=30)
    tbl.add_column("Product", style="cyan")
    tbl.add_column("OS", style="magenta")
    for m in matches:
        tbl.add_row(
            str(m.get("ip_str", "?")),
            str(m.get("port", "")),
            str(m.get("country_code", "")),
            str(m.get("org", "")),
            str(m.get("product", "")),
            str(m.get("os", "")),
        )
    console.print(tbl)


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def _host_to_markdown(d: dict) -> str:
    lines = [
        f"# Shodan Host: {d.get('ip_str', d.get('ip', '?'))}",
        f"\n_Query: {datetime.now().isoformat(timespec='seconds')}_\n",
        f"- **Org:** {d.get('org', '?')}",
        f"- **OS:** {d.get('os', '?')}",
        f"- **Country:** {d.get('country_name', '?')}",
        f"- **ASN:** {d.get('asn', '?')}",
        f"- **Hostnames:** {', '.join(d.get('hostnames', []))}",
        f"- **Ports:** {', '.join(map(str, sorted(d.get('ports', []))))}",
    ]
    vulns = d.get("vulns", [])
    if vulns:
        lines.append(f"\n## Vulnerabilities ({len(vulns)})\n")
        for v in sorted(vulns):
            lines.append(f"- {v}")
    services = d.get("data", [])
    if services:
        lines.append(f"\n## Services ({len(services)})\n")
        lines.append("| Port | Transport | Product | Version |")
        lines.append("|------|-----------|---------|---------|")
        for svc in services:
            lines.append(
                f"| {svc.get('port', '')} | {svc.get('transport', '')} "
                f"| {svc.get('product', '')} | {svc.get('version', '')} |")
    return "\n".join(lines) + "\n"


def _search_to_markdown(d: dict, query: str) -> str:
    lines = [
        f"# Shodan Search: {query}",
        f"\n_Results: {d.get('total', 0):,} · "
        f"{datetime.now().isoformat(timespec='seconds')}_\n",
        "| IP | Port | Country | Org | Product | OS |",
        "|----|------|---------|-----|---------|----|",
    ]
    for m in d.get("matches", [])[:100]:
        lines.append(
            f"| {m.get('ip_str', '?')} | {m.get('port', '')} "
            f"| {m.get('country_code', '')} | {m.get('org', '')} "
            f"| {m.get('product', '')} | {m.get('os', '')} |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def host_lookup() -> None:
    header("Shodan: host lookup", "Ports, banners, vulns, OS, geo for an IP")
    ip = Prompt.ask("IP address").strip()
    if not ip:
        return pause()
    try:
        d = _api_get(f"shodan/host/{ip}")
    except RuntimeError as e:
        console.print(f"[red]API error: {e}[/]")
        return pause()
    except Exception as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    _display_host(d)
    report.log("shodan", f"Host lookup {ip}",
               [f"- Org: {d.get('org', '?')}",
                f"- Ports: {sorted(d.get('ports', []))}",
                f"- Vulns: {len(d.get('vulns', []))}"])
    choice = Prompt.ask("\nExport? [j]son, [m]arkdown, [n]o", default="n")
    if choice == "j":
        path = save_json_report(d, f"shodan_host_{ip}_{datetime.now():%Y%m%d_%H%M%S}.json")
        console.print(f"[green]Saved:[/] {path}")
    elif choice == "m":
        path = save_md_report(_host_to_markdown(d),
                              f"shodan_host_{ip}_{datetime.now():%Y%m%d_%H%M%S}.md")
        console.print(f"[green]Saved:[/] {path}")
    pause()


def search() -> None:
    header("Shodan: search", "Query the exposed-device index")
    query = Prompt.ask("Query (e.g. apache country:US, product:MongoDB)")
    if not query.strip():
        return pause()
    try:
        d = _api_get("shodan/host/search", {"query": query})
    except RuntimeError as e:
        console.print(f"[red]API error: {e}[/]")
        return pause()
    except Exception as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    _display_search(d)
    report.log("shodan", f"Search '{query}'",
               [f"- Total: {d.get('total', 0):,}"])
    choice = Prompt.ask("\nExport? [j]son, [m]arkdown, [n]o", default="n")
    if choice == "j":
        path = save_json_report(d, f"shodan_search_{datetime.now():%Y%m%d_%H%M%S}.json")
        console.print(f"[green]Saved:[/] {path}")
    elif choice == "m":
        path = save_md_report(_search_to_markdown(d, query),
                              f"shodan_search_{datetime.now():%Y%m%d_%H%M%S}.md")
        console.print(f"[green]Saved:[/] {path}")
    pause()


def search_count() -> None:
    header("Shodan: result count", "How many results match a query (no credits used)")
    query = Prompt.ask("Query")
    if not query.strip():
        return pause()
    try:
        d = _api_get("shodan/host/count", {"query": query})
    except RuntimeError as e:
        console.print(f"[red]API error: {e}[/]")
        return pause()
    except Exception as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    total = d.get("total", 0)
    console.print(f"\n[bold green]{total:,}[/] results for '{query}'")
    facets = d.get("facets", {})
    if facets:
        console.print("\n[dim]Top facets:[/]")
        for facet, values in list(facets.items())[:5]:
            console.print(f"  [cyan]{facet}:[/]")
            for v in values[:5]:
                console.print(f"    {v.get('value', '?')}: {v.get('count', 0):,}")
    report.log("shodan", f"Count '{query}'", [f"- Total: {total:,}"])
    pause()


def cve_search() -> None:
    header("Shodan: CVE search", "Find hosts vulnerable to a specific CVE")
    cve = Prompt.ask("CVE (e.g. CVE-2021-44228)").strip().upper()
    if not cve:
        return pause()
    query = f"vuln:{cve}"
    try:
        d = _api_get("shodan/host/search", {"query": query})
    except RuntimeError as e:
        console.print(f"[red]API error: {e}[/]")
        return pause()
    except Exception as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    total = d.get("total", 0)
    console.print(f"\n[bold]{total:,}[/] hosts vulnerable to [red]{cve}[/]\n")
    _display_search(d, limit=50)
    report.log("shodan", f"CVE search {cve}", [f"- Vulnerable hosts: {total:,}"])
    choice = Prompt.ask("\nExport? [j]son, [m]arkdown, [n]o", default="n")
    if choice == "j":
        path = save_json_report(d, f"shodan_cve_{cve}_{datetime.now():%Y%m%d_%H%M%S}.json")
        console.print(f"[green]Saved:[/] {path}")
    elif choice == "m":
        path = save_md_report(_search_to_markdown(d, query),
                              f"shodan_cve_{cve}_{datetime.now():%Y%m%d_%H%M%S}.md")
        console.print(f"[green]Saved:[/] {path}")
    pause()


def profile() -> None:
    header("Shodan: account profile", "Check API credits and plan info")
    try:
        d = _api_get("account/profile")
    except RuntimeError as e:
        console.print(f"[red]API error: {e}[/]")
        return pause()
    except Exception as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    info = Table(show_header=False, box=None, pad_edge=False)
    info.add_column(style="bold cyan")
    info.add_column()
    info.add_row("Member", str(d.get("member", False)))
    info.add_row("Credits", str(d.get("credits", "?")))
    info.add_row("Plan", str(d.get("plan", "?")))
    info.add_row("Scan credits", str(d.get("scan_credits", "?")))
    info.add_row("Unlocked left", str(d.get("unlocked_left", "?")))
    info.add_row("Query credits", str(d.get("query_credits", "?")))
    console.print(info)
    pause()


def export_last_result() -> None:
    header("Export", "This option is integrated into each query — use [j]/[m] after a search.")
    pause()


MENU = {
    "1": ("Host lookup (IP)", host_lookup),
    "2": ("Search (query)", search),
    "3": ("Result count (free)", search_count),
    "4": ("CVE search (vuln:CVE)", cve_search),
    "5": ("Account profile / credits", profile),
    "6": ("Set API key", set_api_key),
    "7": ("Clear API key", clear_api_key),
    "8": ("Show API key status", show_key_info),
}
