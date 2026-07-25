from __future__ import annotations

import base64
import ipaddress
import socket
import struct

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report

DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
             "TXT": 16, "AAAA": 28}
DNS_TYPE_NAMES = {v: k for k, v in DNS_TYPES.items()}


def _encode_qname(host: str) -> bytes:
    out = b""
    for label in host.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    """Parse a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels, jumped, orig = [], False, off
    while True:
        length = data[off]
        if length & 0xC0 == 0xC0:  # pointer
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                orig = off + 2
            off, jumped = ptr, True
            continue
        off += 1
        if length == 0:
            break
        labels.append(data[off:off + length].decode(errors="replace"))
        off += length
    return ".".join(labels), (orig if jumped else off)


def dns_query() -> None:
    header("DNS resolver", "Raw DNS packets built and parsed by hand (no dig needed)")
    host = Prompt.ask("Domain", default="example.com")
    qtype = Prompt.ask("Record type", choices=list(DNS_TYPES), default="A")
    server = Prompt.ask("DNS server", default="8.8.8.8")

    txid = 0x1337
    header_b = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(host) + struct.pack(">HH", DNS_TYPES[qtype], 1)
    packet = header_b + question

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(4096)
        s.close()
    except Exception as e:
        console.print(f"[red]Query failed: {e}[/]")
        return pause()

    _id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):  # skip question section
        _, off = _read_name(data, off)
        off += 4

    t = Table(title=f"{qtype} records for {host}")
    t.add_column("Name", style="cyan")
    t.add_column("Type", style="magenta")
    t.add_column("TTL", justify="right")
    t.add_column("Data", style="green")
    results = []
    for _ in range(an):
        name, off = _read_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        val = _parse_rdata(rtype, rdata, data, off)
        off += rdlen
        t.add_row(name, DNS_TYPE_NAMES.get(rtype, str(rtype)), str(ttl), val)
        results.append(val)
    console.print(t if an else "[yellow]No answer records.[/]")
    if results:
        report.log("osint", f"DNS {qtype} {host}", [f"- {r}" for r in results])
    pause()


def _parse_rdata(rtype, rdata, full, off) -> str:
    if rtype == 1 and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if rtype == 28 and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5, 12):  # NS, CNAME, PTR
        return _read_name(full, off)[0]
    if rtype == 15:  # MX
        pref = struct.unpack(">H", rdata[:2])[0]
        return f"{pref} {_read_name(full, off + 2)[0]}"
    if rtype == 16:  # TXT
        return rdata[1:].decode(errors="replace")
    return rdata.hex()


def whois_lookup() -> None:
    header("WHOIS", "Socket WHOIS client that follows the IANA referral chain")
    domain = Prompt.ask("Domain or IP")

    def ask(server, query):
        s = socket.create_connection((server, 43), timeout=8)
        s.sendall((query + "\r\n").encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()
        return buf.decode(errors="replace")

    try:
        first = ask("whois.iana.org", domain)
    except Exception as e:
        console.print(f"[red]WHOIS failed: {e}[/]")
        return pause()

    refer = None
    for line in first.splitlines():
        if line.lower().startswith("refer:") or line.lower().startswith("whois:"):
            refer = line.split(":", 1)[1].strip()
            break
    text = first
    if refer:
        console.print(f"[dim]Referred to {refer}…[/]")
        try:
            text = ask(refer, domain)
        except Exception:
            pass
    # show the interesting lines
    keep = ("registrar", "creation", "created", "expir", "updated", "name server",
            "status", "org", "country", "netname", "cidr", "inetnum")
    shown = 0
    for line in text.splitlines():
        low = line.lower().strip()
        if any(low.startswith(k) for k in keep) and shown < 30:
            console.print(f"  {line.strip()}")
            shown += 1
    if not shown:
        console.print("[dim]" + "\n".join(text.splitlines()[:25]) + "[/]")
    pause()


def cidr_calc() -> None:
    header("CIDR / subnet calculator", "Everything about a network range")
    spec = Prompt.ask("Network (e.g. 192.168.1.0/24)", default="192.168.1.0/24")
    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        return pause()
    hosts = list(net.hosts())
    t = Table(show_header=False, box=None)
    t.add_row("Network", str(net.network_address))
    t.add_row("Netmask", str(net.netmask))
    t.add_row("Wildcard", str(net.hostmask))
    if net.version == 4:
        t.add_row("Broadcast", str(net.broadcast_address))
    t.add_row("Total addresses", f"{net.num_addresses:,}")
    t.add_row("Usable hosts", f"{len(hosts):,}")
    if hosts:
        t.add_row("First host", str(hosts[0]))
        t.add_row("Last host", str(hosts[-1]))
    t.add_row("Is private", str(net.is_private))
    console.print(t)
    pause()


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 — the hash Shodan uses for favicons."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h = seed & 0xffffffff
    rounded = (length // 4) * 4
    for i in range(0, rounded, 4):
        k = struct.unpack("<I", data[i:i + 4])[0]
        k = (k * c1) & 0xffffffff
        k = ((k << 15) | (k >> 17)) & 0xffffffff
        k = (k * c2) & 0xffffffff
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xffffffff
        h = (h * 5 + 0xe6546b64) & 0xffffffff
    k = 0
    tail = data[rounded:]
    for j, b in enumerate(tail):
        k ^= b << (8 * j)
    if tail:
        k = (k * c1) & 0xffffffff
        k = ((k << 15) | (k >> 17)) & 0xffffffff
        k = (k * c2) & 0xffffffff
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xffffffff
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xffffffff
    h ^= h >> 16
    # to signed 32-bit (Shodan reports signed)
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_hash() -> None:
    header("Favicon hash", "Shodan-style favicon fingerprint (MurmurHash3)")
    import requests
    url = Prompt.ask("Site URL (favicon fetched from /favicon.ico if no path)")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not url.rstrip("/").endswith(".ico"):
        url = url.rstrip("/") + "/favicon.ico"
    try:
        r = requests.get(url, timeout=8, verify=False)
        r.raise_for_status()
    except Exception as e:
        console.print(f"[red]Couldn't fetch favicon: {e}[/]")
        return pause()
    b64 = base64.encodebytes(r.content)  # Shodan hashes the newline-wrapped b64
    h = _murmur3_32(b64)
    console.print(f"favicon bytes: {len(r.content)}")
    console.print(f"[bold green]favicon hash: {h}[/]")
    console.print(f"[cyan]Shodan search:[/] http.favicon.hash:{h}")
    console.print("[cyan]Censys/other:[/] find other hosts serving the same favicon")
    report.log("osint", "Favicon hash", [f"- hash {h}", f"- shodan: http.favicon.hash:{h}"])
    pause()


def email_permutator() -> None:
    header("Email permutator", "Generate likely email formats from a name")
    first = Prompt.ask("First name").lower().strip()
    last = Prompt.ask("Last name").lower().strip()
    domain = Prompt.ask("Domain (e.g. corp.com)").lower().strip()
    f, l = first[0] if first else "", last[0] if last else ""
    patterns = [
        f"{first}.{last}", f"{first}{last}", f"{first}_{last}", f"{first}-{last}",
        f"{f}{last}", f"{f}.{last}", f"{first}{l}", f"{first}", f"{last}",
        f"{last}.{first}", f"{last}{first}", f"{f}{l}", f"{first}.{l}",
    ]
    emails = sorted({f"{p}@{domain}" for p in patterns if p})
    for e in emails:
        console.print(f"  {e}")
    console.print(f"\n[dim]{len(emails)} candidates. Verify with an SMTP/OSINT check "
                  "(e.g. holehe) before trusting any.[/]")
    pause()


def dork_generator() -> None:
    header("Google dork generator", "Recon search queries for a target")
    domain = Prompt.ask("Target domain (e.g. example.com)")
    dorks = [
        f'site:{domain}',
        f'site:{domain} ext:pdf OR ext:docx OR ext:xlsx',
        f'site:{domain} inurl:admin OR inurl:login',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} ext:sql OR ext:env OR ext:log OR ext:bak',
        f'site:{domain} inurl:wp-content',
        f'site:pastebin.com "{domain}"',
        f'site:github.com "{domain}"',
        f'"{domain}" filetype:xls OR filetype:csv password',
        f'site:{domain} intext:"api_key" OR intext:"apikey"',
        f'site:trello.com "{domain}"',
        f'site:{domain} -www',
    ]
    for d in dorks:
        console.print(f"  [green]{d}[/]")
    pause()


COMMON_SUBS = ("www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
               "admin", "portal", "vpn", "api", "dev", "staging", "test", "app",
               "beta", "gitlab", "git", "jenkins", "jira", "cpanel", "autodiscover",
               "m", "mobile", "shop", "store", "blog", "cdn", "static", "assets",
               "internal", "intranet", "remote", "cloud", "docs", "status", "monitor")


def subdomain_permutator() -> None:
    header("Subdomain permutator", "Generate a candidate list (feed to a resolver)")
    domain = Prompt.ask("Base domain (e.g. example.com)")
    resolve = Prompt.ask("Try resolving each? (slow)", choices=["y", "n"], default="n") == "y"
    live = []
    for sub in COMMON_SUBS:
        fqdn = f"{sub}.{domain}"
        if resolve:
            try:
                ip = socket.gethostbyname(fqdn)
                console.print(f"  [green]{fqdn}[/] -> {ip}")
                live.append(fqdn)
            except socket.gaierror:
                pass
        else:
            console.print(f"  {fqdn}")
    if resolve:
        console.print(f"\n[bold]{len(live)}[/] resolved.")
        report.log("osint", f"Subdomain scan {domain}", [f"- {s}" for s in live])
    pause()


def ip_geolocate() -> None:
    header("IP geolocation", "Public IP + geo/ISP (yours or a given IP)")
    import requests
    target = Prompt.ask("IP to look up (blank = your public IP)", default="").strip()
    url = f"http://ip-api.com/json/{target}" if target else "http://ip-api.com/json/"
    try:
        r = requests.get(url, timeout=8)
        d = r.json()
    except Exception as e:
        console.print(f"[red]Lookup failed: {e}[/]")
        return pause()
    if d.get("status") != "success":
        console.print(f"[yellow]{d.get('message', 'lookup failed')}[/]")
        return pause()
    t = Table(show_header=False, box=None)
    for label, key in [("IP", "query"), ("Country", "country"), ("Region", "regionName"),
                       ("City", "city"), ("ZIP", "zip"), ("Lat/Lon", None),
                       ("ISP", "isp"), ("Org", "org"), ("AS", "as"), ("Timezone", "timezone")]:
        if label == "Lat/Lon":
            t.add_row("Lat/Lon", f"{d.get('lat')}, {d.get('lon')}")
        else:
            t.add_row(label, str(d.get(key, "?")))
    console.print(t)
    report.log("osint", f"IP geolocation {d.get('query')}",
               [f"- {d.get('city')}, {d.get('country')} — {d.get('isp')}"])
    pause()


def crtsh_subdomains() -> None:
    header("Cert-transparency subdomains", "Passive subdomain discovery via crt.sh logs")
    import requests
    domain = Prompt.ask("Domain (e.g. example.com)").strip()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        rows = r.json()
    except Exception as e:
        console.print(f"[red]crt.sh query failed: {e}[/]")
        return pause()
    subs = set()
    for row in rows:
        for nm in str(row.get("name_value", "")).splitlines():
            nm = nm.strip().lstrip("*.").lower()
            if nm.endswith(domain):
                subs.add(nm)
    if not subs:
        console.print("[yellow]No certificates found for that domain.[/]")
        return pause()
    resolve = Prompt.ask(f"Found {len(subs)} unique names. Resolve them?",
                         choices=["y", "n"], default="n") == "y"
    live = []
    for s in sorted(subs):
        if resolve:
            try:
                ip = socket.gethostbyname(s)
                console.print(f"  [green]{s}[/] -> {ip}")
                live.append(s)
            except socket.gaierror:
                console.print(f"  [dim]{s} (no A record)[/]")
        else:
            console.print(f"  {s}")
    console.print(f"\n[bold]{len(subs)}[/] subdomains from certificate transparency"
                  + (f", [green]{len(live)}[/] resolved" if resolve else ""))
    report.log("osint", f"crt.sh subdomains {domain}",
               [f"- {len(subs)} names; {len(live)} resolved" if resolve else f"- {len(subs)} names"])
    pause()


def shodan_host() -> None:
    header("Shodan: host lookup", "Exposed ports/services/vulns for an IP (needs API key)")
    import requests
    key = Prompt.ask("Shodan API key").strip()
    ip = Prompt.ask("IP address").strip()
    try:
        d = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}", timeout=15).json()
    except Exception as e:
        console.print(f"[red]Lookup failed: {e}[/]")
        return pause()
    if "error" in d:
        console.print(f"[yellow]{d['error']}[/]")
        return pause()
    t = Table(show_header=False, box=None)
    t.add_row("Org", str(d.get("org", "?")))
    t.add_row("OS", str(d.get("os", "?")))
    t.add_row("Hostnames", ", ".join(d.get("hostnames", [])[:5]))
    t.add_row("Ports", ", ".join(map(str, sorted(d.get("ports", [])))))
    if d.get("vulns"):
        t.add_row("[red]Vulns[/]", ", ".join(sorted(d["vulns"])[:15]))
    console.print(t)
    report.log("osint", f"Shodan host {ip}",
               [f"- org: {d.get('org')}", f"- ports: {sorted(d.get('ports', []))}",
                f"- vulns: {', '.join(sorted(d.get('vulns', {}))) or 'none'}"])
    pause()


def shodan_search() -> None:
    header("Shodan: search", "Query the exposed-device index (needs API key)")
    import requests
    import urllib.parse
    key = Prompt.ask("Shodan API key").strip()
    query = Prompt.ask("Query (e.g. apache country:US, product:MongoDB)")
    url = (f"https://api.shodan.io/shodan/host/search?key={key}"
           f"&query={urllib.parse.quote(query)}")
    try:
        d = requests.get(url, timeout=20).json()
    except Exception as e:
        console.print(f"[red]Search failed: {e}[/]")
        return pause()
    if "error" in d:
        console.print(f"[yellow]{d['error']}[/]")
        return pause()
    console.print(f"[bold]{d.get('total', 0):,}[/] total results (showing 25):\n")
    t = Table()
    t.add_column("IP", style="green")
    t.add_column("Port", justify="right")
    t.add_column("Org", style="dim", overflow="fold")
    t.add_column("Product")
    for m in d.get("matches", [])[:25]:
        t.add_row(m.get("ip_str", "?"), str(m.get("port", "")),
                  str(m.get("org", "")), str(m.get("product", "")))
    console.print(t)
    console.print("[bright_black]Censys equivalent: search.censys.io (API needs id+secret).[/]")
    pause()


def zone_transfer() -> None:
    header("DNS zone transfer", "Attempt AXFR — dumps every record if the NS is misconfigured")
    domain = Prompt.ask("Domain (e.g. zonetransfer.me)")
    ns = Prompt.ask("Nameserver (IP or hostname)")
    try:
        ns_ip = ns if ns.replace(".", "").isdigit() else socket.gethostbyname(ns)
    except socket.gaierror:
        console.print("[red]Could not resolve nameserver.[/]")
        return pause()
    msg = struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0) + _encode_qname(domain) + \
        struct.pack(">HH", 252, 1)  # QTYPE 252 = AXFR
    try:
        s = socket.create_connection((ns_ip, 53), timeout=10)
        s.sendall(struct.pack(">H", len(msg)) + msg)
        s.settimeout(10)
        data = b""
        while len(data) < 2_000_000:
            chunk = s.recv(65535)
            if not chunk:
                break
            data += chunk
        s.close()
    except Exception as e:
        console.print(f"[yellow]AXFR refused/failed: {e}[/] "
                      "(refusing transfers is the secure default).")
        return pause()

    records, off = [], 0
    while off + 2 <= len(data):
        mlen = struct.unpack(">H", data[off:off + 2])[0]
        off += 2
        m = data[off:off + mlen]
        off += mlen
        if len(m) < 12:
            continue
        _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", m[:12])
        p = 12
        for _ in range(qd):
            _, p = _read_name(m, p)
            p += 4
        for _ in range(an):
            try:
                name, p = _read_name(m, p)
                rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", m[p:p + 10])
                p += 10
                records.append((name, DNS_TYPE_NAMES.get(rtype, str(rtype)),
                                _parse_rdata(rtype, m[p:p + rdlen], m, p)))
                p += rdlen
            except Exception:
                break
    if not records:
        console.print("[green]Transfer refused — no records returned (good; AXFR is "
                      "locked down).[/]")
        return pause()
    t = Table(title=f"AXFR {domain} ({len(records)} records)")
    t.add_column("Name", style="cyan", overflow="fold")
    t.add_column("Type", style="magenta")
    t.add_column("Data", style="green", overflow="fold")
    for name, typ, val in records[:200]:
        t.add_row(name, typ, val)
    console.print(t)
    console.print("[red][!] Zone transfer succeeded — this leaks the entire DNS zone.[/]")
    report.log("osint", f"AXFR {domain}", [f"- {len(records)} records leaked from {ns}"])
    pause()


def s3_check() -> None:
    header("S3 bucket check", "Probe common bucket-name guesses for public exposure")
    import requests
    base = Prompt.ask("Base name (e.g. company)").strip().lower()
    names = [base, f"{base}-backup", f"{base}-backups", f"{base}-dev", f"{base}-prod",
             f"{base}-assets", f"{base}-static", f"{base}-uploads", f"{base}-data",
             f"{base}-logs", f"{base}-media", f"{base}-files", f"backup-{base}",
             f"{base}-public", f"{base}-private"]
    t = Table(title="S3 buckets")
    t.add_column("Bucket", style="bold")
    t.add_column("Status")
    for n in names:
        try:
            r = requests.get(f"https://{n}.s3.amazonaws.com", timeout=6)
            if r.status_code == 200:
                status = "[red]PUBLIC — listable![/]"
            elif r.status_code == 403:
                status = "[yellow]exists (access denied)[/]"
            elif "NoSuchBucket" in r.text or r.status_code == 404:
                status = "[dim]no bucket[/]"
            else:
                status = str(r.status_code)
        except Exception:
            status = "[dim]error[/]"
        t.add_row(n, status)
    console.print(t)
    report.log("osint", f"S3 check {base}", ["- probed 15 bucket-name permutations"])
    pause()


def _dns_values(host: str, qtype: int, server: str = "8.8.8.8") -> list[str]:
    """Query one record type via raw UDP DNS; return list of rdata strings."""
    pkt = (struct.pack(">HHHHHH", 0x2020, 0x0100, 1, 0, 0, 0)
           + _encode_qname(host) + struct.pack(">HH", qtype, 1))
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
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    out = []
    for _ in range(an):
        try:
            _name, off = _read_name(data, off)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            out.append(_parse_rdata(rtype, data[off:off + rdlen], data, off))
            off += rdlen
        except Exception:
            break
    return out


def mail_records() -> None:
    header("Mail security records", "MX + SPF / DMARC / DKIM posture for a domain")
    domain = Prompt.ask("Domain (e.g. example.com)").strip()
    mx = _dns_values(domain, 15)
    txt = _dns_values(domain, 16)
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    dmarc = [t for t in _dns_values("_dmarc." + domain, 16) if "v=dmarc1" in t.lower()]
    console.print("\n[bold]MX:[/]    " + (", ".join(mx) if mx else "[yellow]none[/]"))
    console.print("[bold]SPF:[/]   " + (spf[0] if spf else "[red]MISSING[/]"))
    if spf and "~all" not in spf[0] and "-all" not in spf[0]:
        console.print("  [yellow][!] SPF has no ~all/-all -- weak enforcement[/]")
    console.print("[bold]DMARC:[/] " + (dmarc[0] if dmarc else "[red]MISSING[/]"))
    if dmarc and "p=none" in dmarc[0].lower():
        console.print("  [yellow][!] DMARC p=none -- monitoring only, not enforcing[/]")
    selector = Prompt.ask("DKIM selector to check (blank to skip, e.g. google, default)",
                          default="").strip()
    if selector:
        dkim = _dns_values(f"{selector}._domainkey.{domain}", 16)
        console.print(f"[bold]DKIM ({selector}):[/] "
                      + ("[green]present[/]" if dkim else "[yellow]not found[/]"))
    report.log("osint", f"Mail records {domain}",
               [f"- MX: {len(mx)}", f"- SPF: {'yes' if spf else 'no'}",
                f"- DMARC: {'yes' if dmarc else 'no'}"])
    pause()


def reverse_ip_lookup() -> None:
    header("Reverse IP", "Other domains sharing an IP (HackerTarget API)")
    import requests
    target = Prompt.ask("IP or domain").strip()
    try:
        text = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={target}",
            timeout=15).text.strip()
    except Exception as e:
        console.print(f"[red]Lookup failed: {e}[/]")
        return pause()
    if not text or "error" in text.lower() or "exceeded" in text.lower():
        console.print(f"[yellow]{text or 'no results'}[/]")
        return pause()
    hosts = [h for h in text.splitlines() if h.strip()]
    console.print(f"[bold]{len(hosts)}[/] host(s) on that IP:\n")
    for h in hosts[:60]:
        console.print(f"  [green]{h}[/]")
    report.log("osint", f"Reverse IP {target}", [f"- {len(hosts)} co-hosted domains"])
    pause()


def subfinder_enum() -> None:
    header("subfinder", "Passive subdomain enumeration (native or WSL)")
    from .utils import run_tool, soft_require
    if not soft_require("subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"):
        return pause()
    domain = Prompt.ask("Domain")
    run_tool("subfinder", ["-d", domain, "-silent"])
    pause()


MENU = {
    "1": ("DNS resolver (raw packets)", dns_query),
    "2": ("DNS zone transfer (AXFR)", zone_transfer),
    "3": ("WHOIS lookup", whois_lookup),
    "4": ("CIDR / subnet calculator", cidr_calc),
    "5": ("Favicon hash (Shodan pivot)", favicon_hash),
    "6": ("IP geolocation", ip_geolocate),
    "7": ("Subdomains via crt.sh (CT logs)", crtsh_subdomains),
    "8": ("S3 bucket check", s3_check),
    "9": ("Shodan host lookup", shodan_host),
    "10": ("Shodan search", shodan_search),
    "11": ("Email permutator", email_permutator),
    "12": ("Google dork generator", dork_generator),
    "13": ("Subdomain permutator", subdomain_permutator),
    "14": ("Mail records (SPF/DMARC/DKIM)", mail_records),
    "15": ("Reverse IP (co-hosted domains)", reverse_ip_lookup),
    "16": ("subfinder (passive subdomains)", subfinder_enum),
}
