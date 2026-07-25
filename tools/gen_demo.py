#!/usr/bin/env python3
"""Render docs/demo.gif — a looping animated terminal demo for the README.

Pure Pillow (no external recorder needed). Draws a scripted nullsec session as a
sequence of terminal 'scenes' and saves them as a looping GIF.

    python tools/gen_demo.py
"""
from __future__ import annotations

import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)

W, H = 900, 560
PAD_X, PAD_Y = 22, 44          # body offset (title bar is 30px)
LH = 21                        # line height
BG = (13, 17, 23)
BAR = (22, 27, 34)
DOTS = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]

C = {
    "fg": (201, 209, 217), "grey": (128, 137, 148), "green": (57, 211, 83),
    "cyan": (88, 166, 255), "red": (248, 81, 73), "yellow": (210, 153, 34),
    "mag": (188, 140, 255), "dim": (90, 99, 108),
}


def _font(size: int) -> ImageFont.FreeTypeFont:
    for p in (r"C:\Windows\Fonts\consola.ttf", r"C:\Windows\Fonts\lucon.ttf",
              r"C:\Windows\Fonts\cour.ttf"):
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


FONT = _font(15)
BANNER = [
    "                ____",
    "   ____  __  __/ / /_______  _____",
    "  / __ \\/ / / / / / ___/ _ \\/ ___/",
    " / / / / /_/ / / (__  )  __/ /__",
    "/_/ /_/\\__,_/_/_/____/\\___/\\___/",
]


def frame(rows: list) -> Image.Image:
    """rows: list of either str (default colour) or (text, colour_key)."""
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 30], fill=BAR)
    for i, col in enumerate(DOTS):
        d.ellipse([16 + i * 22, 10, 28 + i * 22, 22], fill=col)
    d.text((W // 2 - 60, 8), "nullsec — demo", font=FONT, fill=C["grey"])
    y = PAD_Y
    for row in rows:
        text, key = (row, "fg") if isinstance(row, str) else row
        d.text((PAD_X, y), text, font=FONT, fill=C.get(key, C["fg"]))
        y += LH
    return img


# --- scenes -----------------------------------------------------------------
def s_home(cursor: str = "") -> list:
    return [
        *[(b, "grey") for b in BANNER], "",
        ("  Ø nullsec v0.5.0  ·  39 modules · 287 tools  ·  authorized use only", "grey"),
        "",
        ("  RECON / OSINT      WEB / EXPLOIT      CRYPTO / STEGO      AI / UTILITIES", "cyan"),
        ("  1 Reconnaissance   5 Web              3 Crypto & Enc      A AI Assistant", "fg"),
        ("  6 Network          7 Payload Arsenal  2 Hashes & Crack    U Utilities", "fg"),
        ("  o OSINT & DNS      9 Brute-force      4 Passwords         i Install Arsenal", "fg"),
        "",
        (f"  nullsec › {cursor}", "grey"),
    ]


def s_passwords(cursor: str = "") -> list:
    return [
        ("  Ø Passwords", "fg"),
        ("  Strength checks, breach lookup, and targeted wordlists", "grey"),
        "",
        ("     1  Password strength / entropy", "fg"),
        ("     2  Breach check (top-1M list)", "fg"),
        ("     3  Targeted wordlist generator", "fg"),
        ("     4  Target profiler (CUPP-style wordlist)", "fg"),
        ("     5  Password policy checker", "fg"),
        "",
        (f"  nullsec(passwords) › {cursor}", "grey"),
    ]


def s_breach() -> list:
    return [
        ("  :: Breach check", "green"),
        ("     Is this password in the top 1,000,000 most-used list?", "grey"),
        "",
        ("  Password to check: 123456", "fg"),
        "",
        ("  FOUND — ranked #1 of 1,000,000  (more common than 99.99% of the list).", "red"),
        ("  This password is in public breach corpora — crackers try it in seconds.", "yellow"),
        "",
        ("  Password to check: Tr0ub4dor&3xK9zLm!", "fg"),
        ("  Not found in the top 1,000,000.", "green"),
    ]


def s_ai() -> list:
    return [
        ("  :: AI chat", "green"),
        ("  model: gemma3:12b   (local Ollama)", "grey"),
        "",
        ("  you: what does nmap -sV do?", "cyan"),
        "",
        ("  ai:  nmap -sV probes each open port to fingerprint the service and", "green"),
        ("       its version — the versions let you match known CVEs and pick", "green"),
        ("       the right exploit. Pair with -p- to cover all 65535 ports.", "green"),
    ]


def s_utils() -> list:
    return [
        ("  Ø Utilities", "fg"),
        ("  Subnet / CIDR calculator", "grey"),
        "",
        ("  Network: 10.0.0.0/24", "fg"),
        "",
        ("  network       10.0.0.0", "fg"),
        ("  netmask       255.255.255.0", "fg"),
        ("  broadcast     10.0.0.255", "fg"),
        ("  usable hosts  254", "green"),
    ]


def s_end() -> list:
    return [
        *[(b, "grey") for b in BANNER], "",
        ("  39 modules · 287 built-in tools · 1,000,000 passwords · authorized use only", "cyan"),
        "",
        ("  github.com/fsiuhgshiqoih32/NullsecMultitools", "green"),
    ]


def main() -> None:
    # (scene rows, hold milliseconds)
    timeline = [
        (s_home(""), 500), (s_home("4"), 700), (s_home("4_"), 500),
        (s_passwords(""), 700), (s_passwords("2_"), 700),
        (s_breach(), 2600),
        (s_ai(), 2800),
        (s_utils(), 2200),
        (s_end(), 2200),
    ]
    frames = [frame(rows) for rows, _ in timeline]
    durations = [ms for _, ms in timeline]
    out = DOCS / "demo.gif"
    frames[0].save(out, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print(f"wrote {out}  ({out.stat().st_size // 1024} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
