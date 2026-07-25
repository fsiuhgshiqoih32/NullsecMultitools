from __future__ import annotations

import base64
import codecs
import gzip
import urllib.parse
import zlib

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause

# CyberChef-lite: each op takes (bytes, arg) -> bytes so they chain cleanly.


def _b64d(d, a):  return base64.b64decode(d + b"===")
def _b64e(d, a):  return base64.b64encode(d)
def _b32d(d, a):  return base64.b32decode(d + b"=" * (-len(d) % 8))
def _hexd(d, a):  return bytes.fromhex(d.decode(errors="ignore").replace(" ", ""))
def _hexe(d, a):  return d.hex().encode()
def _urld(d, a):  return urllib.parse.unquote_to_bytes(d.decode(errors="ignore"))
def _urle(d, a):  return urllib.parse.quote_from_bytes(d).encode()
def _rot13(d, a): return codecs.encode(d.decode(errors="ignore"), "rot13").encode()
def _rev(d, a):   return d[::-1]
def _gunzip(d, a): return gzip.decompress(d)
def _inflate(d, a): return zlib.decompress(d)
def _rawinflate(d, a): return zlib.decompress(d, -15)


def _xor(d, a):
    key = a.encode()
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(d)) if key else d


OPS = {
    "from-base64": (False, _b64d),
    "to-base64": (False, _b64e),
    "from-base32": (False, _b32d),
    "from-hex": (False, _hexd),
    "to-hex": (False, _hexe),
    "url-decode": (False, _urld),
    "url-encode": (False, _urle),
    "rot13": (False, _rot13),
    "reverse": (False, _rev),
    "gunzip": (False, _gunzip),
    "zlib-inflate": (False, _inflate),
    "raw-inflate": (False, _rawinflate),
    "xor": (True, _xor),
}


def run_recipe() -> None:
    header("Encoding recipe", "Chain transforms like CyberChef; see the output at each step")
    console.print("[dim]Ops:[/] " + ", ".join(OPS))
    console.print("[dim]Give a comma-separated recipe. Ops that take an argument use op:arg "
                  "(e.g. xor:key).[/]")
    recipe_str = Prompt.ask("Recipe (e.g. from-base64, gunzip)")
    steps = [s.strip() for s in recipe_str.split(",") if s.strip()]
    data = Prompt.ask("Input").encode()
    t = Table()
    t.add_column("Step", style="bold cyan")
    t.add_column("Output", overflow="fold")
    t.add_row("input", data.decode(errors="replace")[:200])
    for step in steps:
        name, _, arg = step.partition(":")
        name = name.strip()
        if name not in OPS:
            t.add_row(step, "[red]unknown op[/]")
            break
        _needs_arg, fn = OPS[name]
        try:
            data = fn(data, arg)
        except Exception as e:  # noqa: BLE001
            t.add_row(step, f"[red]error: {e}[/]")
            break
        t.add_row(name + (f":{arg}" if arg else ""), data.decode(errors="replace")[:200])
    console.print(t)
    console.print(f"\n[dim]final hex:[/] {data.hex()[:200]}")
    pause()


def list_ops() -> None:
    header("Recipe operations", "Every transform you can chain")
    t = Table()
    t.add_column("Operation", style="bold cyan")
    t.add_column("Argument")
    for name, (needs, _fn) in OPS.items():
        t.add_row(name, "op:arg" if needs else "-")
    console.print(t)
    pause()


MENU = {
    "1": ("Run a recipe (chain transforms)", run_recipe),
    "2": ("List operations", list_ops),
}
