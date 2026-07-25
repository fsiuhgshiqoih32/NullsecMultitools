from __future__ import annotations

import ipaddress
import json
import math
import secrets
import string
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, kv_table, pause, report


def base_convert() -> None:
    header("Base converter", "Decimal / hex / octal / binary / ASCII")
    raw = Prompt.ask("Number (prefix 0x/0o/0b, or decimal)").strip()
    try:
        n = int(raw, 0) if raw.lower().startswith(("0x", "0o", "0b")) else int(raw)
    except ValueError:
        try:
            n = int(raw, 16)  # bare hex fallback
        except ValueError:
            console.print("[red]Not a valid number.[/]")
            return pause()
    rows = [("decimal", str(n)), ("hex", hex(n)), ("octal", oct(n)),
            ("binary", bin(n)), ("bytes", str(n.bit_length() + 7 >> 3))]
    if 0 <= n <= 0x10FFFF:
        try:
            rows.append(("chr", repr(chr(n))))
        except ValueError:
            pass
    console.print(kv_table("", rows))
    pause()


def subnet_calc() -> None:
    header("Subnet calculator", "CIDR -> network, mask, range, host count")
    cidr = Prompt.ask("Network (e.g. 10.0.0.0/24 or 2001:db8::/64)").strip()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        return pause()
    hosts = list(net.hosts())
    rows = [
        ("network", str(net.network_address)),
        ("netmask", str(net.netmask)),
        ("wildcard", str(net.hostmask)),
        ("broadcast", str(net.broadcast_address) if net.version == 4 else "-"),
        ("prefix", f"/{net.prefixlen}"),
        ("total addrs", f"{net.num_addresses:,}"),
        ("usable hosts", f"{len(hosts):,}"),
        ("first host", str(hosts[0]) if hosts else "-"),
        ("last host", str(hosts[-1]) if hosts else "-"),
    ]
    console.print(kv_table("", rows))
    report("Subnet calc", f"{cidr} -> {net.num_addresses} addrs")
    pause()


def epoch_convert() -> None:
    header("Timestamp converter", "Unix epoch <-> human (UTC + local)")
    raw = Prompt.ask("Epoch seconds, or blank for now", default="").strip()
    ts = time.time() if not raw else float(raw)
    try:
        utc = datetime.fromtimestamp(ts, tz=timezone.utc)
        loc = datetime.fromtimestamp(ts)
    except (ValueError, OSError, OverflowError):
        console.print("[red]Out-of-range timestamp.[/]")
        return pause()
    console.print(kv_table("", [
        ("epoch", f"{ts:.0f}"),
        ("epoch (ms)", f"{ts * 1000:.0f}"),
        ("UTC", utc.strftime("%Y-%m-%d %H:%M:%S UTC")),
        ("local", loc.strftime("%Y-%m-%d %H:%M:%S")),
        ("ISO 8601", utc.isoformat()),
    ]))
    pause()


def uuid_gen() -> None:
    header("UUID generator", "Random v4 UUIDs")
    n = Prompt.ask("How many", default="5").strip()
    count = int(n) if n.isdigit() and int(n) > 0 else 5
    for _ in range(min(count, 100)):
        console.print(f"[cyan]{uuid.uuid4()}[/]")
    pause()


def passgen() -> None:
    header("Password generator", "Cryptographically secure (secrets)")
    length = Prompt.ask("Length", default="20").strip()
    length = int(length) if length.isdigit() and int(length) > 0 else 20
    count = Prompt.ask("How many", default="5").strip()
    count = int(count) if count.isdigit() and int(count) > 0 else 5
    symbols = Prompt.ask("Include symbols?", choices=["y", "n"], default="y") == "y"
    alphabet = string.ascii_letters + string.digits + ("!@#$%^&*-_=+?" if symbols else "")
    for _ in range(min(count, 50)):
        pw = "".join(secrets.choice(alphabet) for _ in range(min(length, 256)))
        console.print(f"[green]{pw}[/]")
    report("Passgen", f"len={length} n={count} symbols={symbols}")
    pause()


def url_parse() -> None:
    header("URL dissector", "Split a URL into its parts and query params")
    u = Prompt.ask("URL").strip()
    p = urllib.parse.urlsplit(u)
    rows = [("scheme", p.scheme), ("host", p.hostname or ""),
            ("port", str(p.port) if p.port else ""), ("path", p.path),
            ("fragment", p.fragment)]
    console.print(kv_table("", [(k, v) for k, v in rows if v]))
    qs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    if qs:
        t = Table(title="query params")
        t.add_column("param", style="cyan")
        t.add_column("value", overflow="fold")
        for k, v in qs:
            t.add_row(k, v)
        console.print(t)
    pause()


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def text_stats() -> None:
    header("Text stats", "Counts + Shannon entropy (bits/char)")
    s = Prompt.ask("Text")
    ent = _entropy(s)
    console.print(kv_table("", [
        ("characters", str(len(s))),
        ("words", str(len(s.split()))),
        ("lines", str(len(s.splitlines()) or 1)),
        ("unique chars", str(len(set(s)))),
        ("entropy", f"{ent:.2f} bits/char  (~{ent * len(s):.0f} bits total)"),
    ]))
    pause()


def json_tool() -> None:
    header("JSON validate / pretty-print", "Check and format JSON")
    raw = Prompt.ask("Paste JSON")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON:[/] {e}")
        return pause()
    console.print("[green]Valid JSON.[/]\n")
    from rich.syntax import Syntax
    console.print(Syntax(json.dumps(obj, indent=2, ensure_ascii=False),
                         "json", theme="ansi_dark", word_wrap=True))
    pause()


MENU = {
    "1": ("Base converter (hex/oct/bin/ascii)", base_convert),
    "2": ("Subnet / CIDR calculator", subnet_calc),
    "3": ("Timestamp converter (epoch)", epoch_convert),
    "4": ("UUID generator", uuid_gen),
    "5": ("Secure password generator", passgen),
    "6": ("URL dissector", url_parse),
    "7": ("Text stats + entropy", text_stats),
    "8": ("JSON validate / pretty-print", json_tool),
}
