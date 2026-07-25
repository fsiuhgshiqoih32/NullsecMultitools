#!/usr/bin/env python3
"""Regenerate the terminal screenshots used in the README (docs/*.svg).

Renders the live nullsec views into rich recording consoles and exports them as
SVG — crisp on GitHub, no real terminal capture needed.

    python tools/gen_screenshots.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console          # noqa: E402
from rich.terminal_theme import MONOKAI   # noqa: E402
from rich.text import Text                # noqa: E402

DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)
WIDTH = 100


def new_console() -> Console:
    c = Console(record=True, width=WIDTH)
    c.clear = lambda *a, **k: None  # suppress screen-clear during capture
    return c


def save(rec: Console, name: str, title: str) -> None:
    rec.save_svg(str(DOCS / name), title=title, theme=MONOKAI)
    print("wrote", DOCS / name)


def render_menu(rec: Console, name: str, menu: dict) -> None:
    """Reproduce run_category's header + menu listing for a screenshot."""
    import main
    rec.print(Text(main.BANNER.rstrip("\n"), style=main.BANNER_STYLE))
    rec.print(f"\n  [white]Ø[/] [bold grey85]{name}[/]\n")
    for k, (label, _fn) in menu.items():
        rec.print(f"    [cyan]{k:>2}[/]  {label}")
    rec.print("    [cyan] b[/]  [bright_black]back[/]   "
              "[cyan]/[/] [bright_black]home[/]   [cyan]q[/] [bright_black]quit[/]")
    rec.print(f"\n  [grey42]nullsec[/]([cyan]{name.split()[0].lower()}[/]) >")


def main_gen() -> None:
    import main
    from toolkit import utils, arsenal

    # 1) Home screen ---------------------------------------------------------
    rec = new_console()
    utils.console = rec
    main.console = rec
    main.show_home()
    save(rec, "screenshot-home.svg", "nullsec — home")

    # 2) A module menu (Hashes & Cracking) -----------------------------------
    from toolkit import hashes
    rec = new_console()
    render_menu(rec, "Hashes & Cracking", hashes.MENU)
    save(rec, "screenshot-module.svg", "nullsec — module")

    # 3) A tool in action: Payload Arsenal building a reverse shell -----------
    rec = new_console()
    arsenal.console = rec
    with mock.patch.object(arsenal, "pause", lambda *a, **k: None), \
         mock.patch("rich.prompt.Prompt.ask",
                    side_effect=["1", "10.10.14.7", "4444"]):
        arsenal.browse_reverse()
    save(rec, "screenshot-arsenal.svg", "nullsec — payload arsenal")


if __name__ == "__main__":
    main_gen()
