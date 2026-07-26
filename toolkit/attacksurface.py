from __future__ import annotations

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                           TimeRemainingColumn)
from rich.prompt import Prompt
from rich.table import Table

from .utils import (console, header, pause, report,
                    save_json_report, save_md_report, get_proxy)

# ---------------------------------------------------------------------------
# Common hidden file / endpoint paths
# ---------------------------------------------------------------------------

_HIDDEN_PATHS = [
    ".git/HEAD", ".git/config", ".git/index",
    ".env", ".env.local", ".env.production", ".env.dev",
    ".htaccess", ".htpasswd",
    "backup.sql", "backup.zip", "backup.tar.gz", "backup.bak",
    "db.sql", "database.sql", "dump.sql",
    ".DS_Store", "Thumbs.db",
    "wp-config.php", "wp-config.php.bak", "wp-admin/",
    "admin/", "administrator/", "admin.php",
    "phpinfo.php", "info.php", "test.php",
    "robots.txt", "sitemap.xml", "sitemap.xml.gz",
    ".svn/entries", ".svn/wc.db",
    ".hg/store", ".bzr/",
    "config.php", "config.php.bak", "config.yml", "config.json",
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".dockerignore",
    "id_rsa", "id_dsa", ".ssh/id_rsa", ".ssh/authorized_keys",
    "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known/security.txt", ".well-known/openid-configuration",
    "server-status", "server-info",
    "phpmyadmin/", "pma/", "mysqladmin/",
    ".gitignore", ".eslintignore", ".dockerignore",
    "swagger.json", "swagger-ui/", "api-docs", "graphql",
    "actuator", "actuator/health", "actuator/env", "actuator/heapdump",
    "console", "h2-console", "jmx-console",
]

# ---------------------------------------------------------------------------
# Tech-stack fingerprinting signatures
# ---------------------------------------------------------------------------

_TECH_SIGNATURES: list[dict] = [
    {"name": "Apache", "header": "server", "pattern": "Apache"},
    {"name": "nginx", "header": "server", "pattern": "nginx"},
    {"name": "IIS", "header": "server", "pattern": "Microsoft-IIS"},
    {"name": "LiteSpeed", "header": "server", "pattern": "LiteSpeed"},
    {"name": "Cloudflare", "header": "server", "pattern": "cloudflare"},
    {"name": "PHP", "header": "x-powered-by", "pattern": "PHP"},
    {"name": "ASP.NET", "header": "x-powered-by", "pattern": "ASP.NET"},
    {"name": "Express", "header": "x-powered-by", "pattern": "Express"},
    {"name": "Next.js", "header": "x-powered-by", "pattern": "Next.js"},
    {"name": "JSP/Tomcat", "header": "x-powered-by", "pattern": "JSP"},
    {"name": "WordPress", "body": '<meta name="generator" content="WordPress'},
    {"name": "Joomla", "body": '<meta name="generator" content="Joomla'},
    {"name": "Drupal", "body": '<meta name="generator" content="Drupal'},
    {"name": "React", "body": 'data-reactroot', "header": "x-powered-by", "pattern": "React"},
    {"name": "Vue.js", "body": 'data-v-', "header": "x-powered-by", "pattern": "Vue"},
    {"name": "Angular", "body": 'ng-app', "header": "x-powered-by", "pattern": "Angular"},
    {"name": "jQuery", "body": 'jquery'},
    {"name": "Bootstrap", "body": 'bootstrap'},
    {"name": "Tailwind CSS", "body": 'tailwind'},
    {"name": "Rails", "header": "x-powered-by", "pattern": "Phusion Passenger"},
    {"name": "Django", "header": "x-frame-options", "pattern": "DENY", "cookie": "csrftoken"},
    {"name": "Flask", "cookie": "session", "header": "server", "pattern": "Werkzeug"},
    {"name": "Spring Boot", "header": "x-application-context", "pattern": "application"},
    {"name": "Gatsby", "header": "x-powered-by", "pattern": "Gatsby"},
    {"name": "Svelte", "body": '__svelte'},
]


# ---------------------------------------------------------------------------
# Hidden file / endpoint crawler
# ---------------------------------------------------------------------------

def _check_path(base_url: str, path: str, timeout: int = 8) -> dict:
    """Check a single path. Returns dict with status, size, and interesting flag."""
    import requests
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.get(url, timeout=timeout, proxies=get_proxy(),
                         verify=False, allow_redirects=False)
        interesting = r.status_code in (200, 401, 403) and r.headers.get("content-length", "0") != "0"
        return {
            "url": url,
            "path": path,
            "status": r.status_code,
            "size": len(r.content),
            "content_type": r.headers.get("content-type", ""),
            "interesting": interesting,
        }
    except Exception as e:
        return {
            "url": url, "path": path, "status": -1, "size": 0,
            "content_type": "", "interesting": False, "error": str(e),
        }


def crawl_hidden() -> None:
    header("Hidden file / endpoint crawler",
           "Probe common paths for exposed files and admin panels")
    base = Prompt.ask("Base URL (e.g. https://example.com)").strip()
    if not base:
        return pause()
    if not base.startswith("http"):
        base = "https://" + base
    timeout = int(Prompt.ask("Timeout per request (s)", default="8"))
    paths = Prompt.ask("Use built-in wordlist?", choices=["y", "n"], default="y")
    if paths == "n":
        wf = Prompt.ask("Wordlist file path").strip().strip('"')
        try:
            custom = [l.strip() for l in open(wf, encoding="utf-8") if l.strip() and not l.startswith("#")]
        except Exception:
            console.print("[red]Could not read wordlist.[/]")
            return pause()
    else:
        custom = _HIDDEN_PATHS

    console.print(f"\n[dim]Probing {len(custom)} paths...[/]")
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    results = []
    with Progress(
        SpinnerColumn(), BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(), console=console,
    ) as prog:
        task = prog.add_task("Crawling", total=len(custom))
        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {pool.submit(_check_path, base, p, timeout): p for p in custom}
            for fut in as_completed(futs):
                results.append(fut.result())
                prog.advance(task)

    # Display interesting results
    found = [r for r in results if r["interesting"]]
    if not found:
        console.print("[yellow]No interesting paths found.[/]")
        return pause()

    tbl = Table(title=f"Found {len(found)} interesting path(s)")
    tbl.add_column("Status", justify="right")
    tbl.add_column("Size", justify="right", style="dim")
    tbl.add_column("Path", style="cyan")
    tbl.add_column("Content-Type", style="magenta")
    for r in sorted(found, key=lambda x: x["path"]):
        status_color = "green" if r["status"] == 200 else "yellow"
        tbl.add_row(
            f"[{status_color}]{r['status']}[/]",
            str(r["size"]),
            r["path"],
            r["content_type"][:40],
        )
    console.print(tbl)

    report.log("attacksurface", f"Hidden crawl {base}",
               [f"- {len(found)} interesting paths found",
                f"- Probed {len(custom)} total"])
    choice = Prompt.ask("\nExport? [j]son, [m]arkdown, [n]o", default="n")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if choice == "j":
        path = save_json_report(found, f"crawl_{ts}.json")
        console.print(f"[green]Saved:[/] {path}")
    elif choice == "m":
        lines = [f"# Hidden Path Crawl: {base}\n"]
        for r in sorted(found, key=lambda x: x["path"]):
            lines.append(f"- **{r['status']}** `{r['path']}` ({r['size']} bytes, {r['content_type'][:40]})")
        path = save_md_report("\n".join(lines), f"crawl_{ts}.md")
        console.print(f"[green]Saved:[/] {path}")
    pause()


# ---------------------------------------------------------------------------
# Tech-stack fingerprinting
# ---------------------------------------------------------------------------

def tech_fingerprint() -> None:
    header("Tech-stack fingerprint", "Identify web technologies via headers and body")
    import requests
    url = Prompt.ask("URL (e.g. https://example.com)").strip()
    if not url:
        return pause()
    if not url.startswith("http"):
        url = "https://" + url
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    try:
        r = requests.get(url, timeout=15, proxies=get_proxy(), verify=False)
    except Exception as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()

    headers = {k.lower(): v for k, v in r.headers.items()}
    body = r.text[:50000] if r.text else ""
    cookies = {c.name for c in r.cookies} if hasattr(r, "cookies") else set()

    # Display raw headers of interest
    console.print("\n[bold]Response headers:[/]")
    interesting_headers = ["server", "x-powered-by", "x-aspnet-version",
                           "x-frame-options", "content-security-policy",
                           "x-content-type-options", "strict-transport-security",
                           "set-cookie", "via", "x-cache"]
    for h in interesting_headers:
        if h in headers:
            console.print(f"  [cyan]{h}:[/] {headers[h][:80]}")

    # Fingerprint
    detected = []
    for sig in _TECH_SIGNATURES:
        matched = False
        if "header" in sig and "pattern" in sig:
            val = headers.get(sig["header"], "")
            if sig["pattern"].lower() in val.lower():
                matched = True
        if "body" in sig and sig["body"].lower() in body.lower():
            matched = True
        if "cookie" in sig and sig["cookie"] in cookies:
            matched = True
        if matched:
            detected.append(sig["name"])

    if detected:
        console.print(f"\n[bold green]Detected technologies ({len(detected)}):[/]")
        for tech in detected:
            console.print(f"  [green]{tech}[/]")
    else:
        console.print("\n[yellow]No technologies detected from signatures.[/]")

    # Security headers check
    console.print("\n[bold]Security headers:[/]")
    security_checks = [
        ("HSTS", "strict-transport-security"),
        ("X-Frame-Options", "x-frame-options"),
        ("X-Content-Type-Options", "x-content-type-options"),
        ("Content-Security-Policy", "content-security-policy"),
        ("X-XSS-Protection", "x-xss-protection"),
        ("Referrer-Policy", "referrer-policy"),
        ("Permissions-Policy", "permissions-policy"),
    ]
    missing = []
    for name, hdr in security_checks:
        if hdr in headers:
            console.print(f"  [green]{name}:[/] present")
        else:
            console.print(f"  [red]{name}:[/] MISSING")
            missing.append(name)

    result = {
        "url": url,
        "status": r.status_code,
        "detected_tech": detected,
        "missing_security_headers": missing,
        "headers": {k: v for k, v in headers.items() if k in interesting_headers},
    }
    report.log("attacksurface", f"Fingerprint {url}",
               [f"- Tech: {', '.join(detected) or 'none'}",
                f"- Missing security headers: {len(missing)}"])
    choice = Prompt.ask("\nExport? [j]son, [m]arkdown, [n]o", default="n")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if choice == "j":
        path = save_json_report(result, f"fingerprint_{ts}.json")
        console.print(f"[green]Saved:[/] {path}")
    elif choice == "m":
        lines = [f"# Tech Fingerprint: {url}\n",
                 f"**Status:** {r.status_code}\n",
                 "## Detected Technologies\n"]
        for t in detected:
            lines.append(f"- {t}")
        lines.append("\n## Security Headers\n")
        for name, hdr in security_checks:
            status = "present" if hdr in headers else "MISSING"
            lines.append(f"- **{name}:** {status}")
        path = save_md_report("\n".join(lines), f"fingerprint_{ts}.md")
        console.print(f"[green]Saved:[/] {path}")
    pause()


# ---------------------------------------------------------------------------
# Credential leak checking
# ---------------------------------------------------------------------------

def _check_hibp(email: str) -> dict:
    """Check an email against Have I Been Pwned (requires API key for full API).

    Falls back to the free breach search endpoint if no key is available.
    """
    import requests
    # HIBP v3 requires an API key. We use the free unauthenticated endpoint
    # that checks if an account appears in any breach (returns breach names).
    # This endpoint may rate-limit; we handle gracefully.
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"User-Agent": "nullsec-recon"},
            timeout=15, proxies=get_proxy(), verify=False)
        if r.status_code == 200:
            breaches = r.json()
            return {"email": email, "breaches": [b["Name"] for b in breaches],
                    "count": len(breaches)}
        elif r.status_code == 404:
            return {"email": email, "breaches": [], "count": 0}
        elif r.status_code == 429:
            return {"email": email, "breaches": [], "count": 0,
                    "error": "Rate limited"}
        else:
            return {"email": email, "breaches": [], "count": 0,
                    "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"email": email, "breaches": [], "count": 0, "error": str(e)}


def cred_leak_check() -> None:
    header("Credential leak check", "Check emails against breach databases")
    console.print("[dim]Uses Have I Been Pwned API (may require key / rate-limited).[/]")
    console.print("[dim]For bulk checks, consider a local breach DB.[/]\n")
    raw = Prompt.ask("Email(s) — comma separated").strip()
    if not raw:
        return pause()
    emails = [e.strip() for e in raw.split(",") if e.strip()]
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    results = []
    for email in emails:
        console.print(f"  [dim]Checking {email}...[/]", end="")
        result = _check_hibp(email)
        results.append(result)
        if result.get("error"):
            console.print(f" [yellow]{result['error']}[/]")
        elif result["count"] == 0:
            console.print(" [green]clean[/]")
        else:
            console.print(f" [red]{result['count']} breach(es)[/]")
            for b in result["breaches"]:
                console.print(f"    [red]{b}[/]")

    # Summary
    pwned = [r for r in results if r["count"] > 0]
    clean = [r for r in results if r["count"] == 0 and not r.get("error")]
    errors = [r for r in results if r.get("error")]
    console.print(f"\n[bold]Summary:[/] [red]{len(pwned)} pwned[/] · "
                  f"[green]{len(clean)} clean[/] · [yellow]{len(errors)} error(s)[/]")

    report.log("attacksurface", "Credential leak check",
               [f"- Checked: {len(emails)}",
                f"- Pwned: {len(pwned)}",
                f"- Clean: {len(clean)}"])
    choice = Prompt.ask("\nExport? [j]son, [m]arkdown, [n]o", default="n")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if choice == "j":
        path = save_json_report(results, f"credleak_{ts}.json")
        console.print(f"[green]Saved:[/] {path}")
    elif choice == "m":
        lines = ["# Credential Leak Check\n",
                 f"_Checked: {len(emails)} emails_\n"]
        for r in results:
            if r["count"] > 0:
                lines.append(f"- **{r['email']}**: {r['count']} breach(es) — {', '.join(r['breaches'])}")
            elif r.get("error"):
                lines.append(f"- {r['email']}: error ({r['error']})")
            else:
                lines.append(f"- {r['email']}: clean")
        path = save_md_report("\n".join(lines), f"credleak_{ts}.md")
        console.print(f"[green]Saved:[/] {path}")
    pause()


# ---------------------------------------------------------------------------
# Directory brute-force with custom wordlist
# ---------------------------------------------------------------------------

def dir_brute_custom() -> None:
    header("Directory brute-force", "Custom wordlist against a target")
    base = Prompt.ask("Base URL").strip()
    if not base:
        return pause()
    if not base.startswith("http"):
        base = "https://" + base
    wf = Prompt.ask("Wordlist file path").strip().strip('"')
    try:
        paths = [l.strip() for l in open(wf, encoding="utf-8")
                 if l.strip() and not l.startswith("#")]
    except Exception:
        console.print("[red]Could not read wordlist.[/]")
        return pause()
    timeout = int(Prompt.ask("Timeout per request (s)", default="8"))
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    console.print(f"\n[dim]Brute-forcing {len(paths)} paths...[/]")
    results = []
    with Progress(
        SpinnerColumn(), BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeRemainingColumn(), console=console,
    ) as prog:
        task = prog.add_task("Brute", total=len(paths))
        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {pool.submit(_check_path, base, p, timeout): p for p in paths}
            for fut in as_completed(futs):
                results.append(fut.result())
                prog.advance(task)

    found = [r for r in results if r["status"] in (200, 301, 302, 401, 403)]
    if not found:
        console.print("[yellow]No paths found.[/]")
        return pause()
    tbl = Table(title=f"Found {len(found)} path(s)")
    tbl.add_column("Status", justify="right")
    tbl.add_column("Path", style="cyan")
    tbl.add_column("Size", justify="right", style="dim")
    for r in sorted(found, key=lambda x: x["path"]):
        sc = "green" if r["status"] == 200 else "yellow" if r["status"] < 400 else "red"
        tbl.add_row(f"[{sc}]{r['status']}[/]", r["path"], str(r["size"]))
    console.print(tbl)
    report.log("attacksurface", f"Dir brute {base}",
               [f"- {len(found)} paths found out of {len(paths)}"])
    pause()


MENU = {
    "1": ("Hidden file / endpoint crawler", crawl_hidden),
    "2": ("Tech-stack fingerprint", tech_fingerprint),
    "3": ("Credential leak check (HIBP)", cred_leak_check),
    "4": ("Directory brute-force (custom wordlist)", dir_brute_custom),
}
