from __future__ import annotations

import hashlib
import hmac
import re
import tempfile
import zlib
from pathlib import Path

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, require_tool, run_external

# (name, John --format hint, regex). Identification is heuristic — length + charset.
HASH_SIGNATURES = [
    ("MD5",          "raw-md5",    re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("NTLM",         "nt",         re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("SHA-1",        "raw-sha1",   re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("SHA-224",      "raw-sha224", re.compile(r"^[a-f0-9]{56}$", re.I)),
    ("SHA-256",      "raw-sha256", re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("SHA-384",      "raw-sha384", re.compile(r"^[a-f0-9]{96}$", re.I)),
    ("SHA-512",      "raw-sha512", re.compile(r"^[a-f0-9]{128}$", re.I)),
    ("bcrypt",       "bcrypt",     re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$")),
    ("MD5-crypt",    "md5crypt",   re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$")),
    ("SHA-256-crypt","sha256crypt",re.compile(r"^\$5\$")),
    ("SHA-512-crypt","sha512crypt",re.compile(r"^\$6\$")),
    ("MySQL 4.1+",   "mysql-sha1", re.compile(r"^\*[A-F0-9]{40}$")),
    ("Argon2",       "argon2",     re.compile(r"^\$argon2(?:id|i|d)\$")),
    ("PBKDF2 (Django)", "django",  re.compile(r"^pbkdf2_sha256\$\d+\$")),
    ("phpass (WP/phpBB)", "phpass", re.compile(r"^\$[PH]\$[./A-Za-z0-9]{31}$")),
    ("Drupal 7",     "drupal7",    re.compile(r"^\$S\$[./A-Za-z0-9]{52}$")),
]


def identify() -> None:
    header("Hash Identifier", "Guess the algorithm from length and format")
    h = Prompt.ask("Paste a hash").strip()
    matches = [(name, fmt) for name, fmt, rx in HASH_SIGNATURES if rx.match(h)]
    if not matches:
        console.print("[yellow]No confident match. Length =[/] "
                      f"[bold]{len(h)}[/] chars.")
        return pause()
    table = Table(title="Possible matches (most likely first)")
    table.add_column("Algorithm", style="green bold")
    table.add_column("John --format")
    for name, fmt in matches:
        table.add_row(name, fmt)
    console.print(table)
    if len(matches) > 1:
        console.print("[dim]Same-length hashes are ambiguous (e.g. MD5 vs NTLM) — "
                      "context decides which one it is.[/]")
    pause()


def calculate() -> None:
    header("Hash Calculator", "Compute digests of text or a file")
    src = Prompt.ask("Hash [t]ext or [f]ile?", choices=["t", "f"], default="t")
    if src == "t":
        data = Prompt.ask("Text").encode()
        label = "text"
    else:
        p = Path(Prompt.ask("File path").strip('"'))
        if not p.is_file():
            console.print(f"[red]No such file: {p}[/]")
            return pause()
        data = p.read_bytes()
        label = p.name

    table = Table(title=f"Digests of {label}")
    table.add_column("Algorithm", style="bold")
    table.add_column("Digest", style="green")
    for algo in ("md5", "sha1", "sha256", "sha512"):
        table.add_row(algo, hashlib.new(algo, data).hexdigest())
    console.print(table)
    pause()


def john_crack() -> None:
    header("John the Ripper", "Dictionary attack against a hash file")
    path = require_tool("john")
    if not path:
        console.print("[dim]On Windows, install the 'jumbo' build and add its /run "
                      "folder to PATH so 'john' is callable.[/]")
        return pause()

    hash_file = Prompt.ask("Path to file containing the hash(es)").strip('"')
    if not Path(hash_file).is_file():
        console.print("[red]Hash file not found.[/]")
        return pause()

    fmt = Prompt.ask("John --format (blank = let John autodetect)", default="").strip()
    wl = Prompt.ask("Wordlist path (blank = John default rules)", default="").strip('"')

    cmd = ["john"]
    if fmt:
        cmd.append(f"--format={fmt}")
    if wl:
        cmd += [f"--wordlist={wl}", "--rules"]
    cmd.append(hash_file)

    console.print("[dim]Running John. It writes cracked passwords to its pot file; "
                  "we'll show them after.[/]")
    run_external(cmd)
    console.print("\n[bold]Cracked so far:[/]")
    run_external(["john", "--show"] + ([f"--format={fmt}"] if fmt else []) + [hash_file])
    pause()


def hashcat_crack() -> None:
    header("hashcat", "GPU dictionary attack (needs an installed hashcat)")
    path = require_tool("hashcat")
    if not path:
        return pause()
    hash_file = Prompt.ask("Path to hash file").strip('"')
    if not Path(hash_file).is_file():
        console.print("[red]Hash file not found.[/]")
        return pause()
    # A few common hashcat mode numbers so the user doesn't have to memorize them.
    console.print("[dim]Common modes: 0=MD5  100=SHA1  1400=SHA256  1700=SHA512  "
                  "3200=bcrypt  1000=NTLM[/]")
    mode = Prompt.ask("hash-mode (-m)", default="0").strip()
    wl = Prompt.ask("Wordlist path").strip('"')
    if not Path(wl).is_file():
        console.print("[red]Wordlist not found.[/]")
        return pause()
    run_external(["hashcat", "-m", mode, "-a", "0", hash_file, wl])
    console.print("\n[bold]Cracked:[/]")
    run_external(["hashcat", "-m", mode, hash_file, "--show"])
    pause()


def make_demo_hashes() -> None:
    """Generate a safe practice file so the user can try John on their own data."""
    header("Make practice hashes", "Creates a local file of MD5 hashes to crack for practice")
    words = ["password", "letmein", "dragon", "hunter2", "qwerty123"]
    lines = [hashlib.md5(w.encode()).hexdigest() for w in words]
    out = Path(tempfile.gettempdir()) / "practice_md5.txt"
    out.write_text("\n".join(lines) + "\n")
    console.print(f"Wrote [cyan]{out}[/] with {len(words)} MD5 hashes of common words.")
    console.print("[dim]Point John (option above) at it with --format=raw-md5 and a "
                  "wordlist like rockyou.txt to see cracking work end to end.[/]")
    pause()


def checksum_verify() -> None:
    header("Checksum verify", "Compute a file's hash and compare to an expected value")
    p = Path(Prompt.ask("File path").strip('"'))
    if not p.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    data = p.read_bytes()
    digests = {a: hashlib.new(a, data).hexdigest() for a in ("md5", "sha1", "sha256")}
    for a, d in digests.items():
        console.print(f"  [bold]{a}[/]  {d}")
    expected = Prompt.ask("\nExpected hash to compare (blank to skip)", default="").strip().lower()
    if expected:
        match = next((a for a, d in digests.items() if d == expected), None)
        if match:
            console.print(f"[bold green]MATCH[/] — file integrity confirmed ({match}).")
        else:
            console.print("[bold red]NO MATCH[/] — file differs from the expected hash!")
    pause()


def _md4(msg: bytes) -> bytes:
    """MD4 from scratch (OpenSSL 3 disables it, so we don't rely on hashlib)."""
    import struct
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def rol(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    ml = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack("<Q", ml)
    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[off:off + 64])
        A, B, C, D = h
        for k in range(0, 16, 4):
            for a, b, c, d, i, s in ((0, 1, 2, 3, k, 3), (3, 0, 1, 2, k + 1, 7),
                                     (2, 3, 0, 1, k + 2, 11), (1, 2, 3, 0, k + 3, 19)):
                r = [A, B, C, D]
                r[a] = rol((r[a] + ((r[b] & r[c]) | (~r[b] & r[d])) + X[i]) & 0xFFFFFFFF, s)
                A, B, C, D = r
        for k in range(4):
            for a, b, c, d, i, s in ((0, 1, 2, 3, k, 3), (3, 0, 1, 2, k + 4, 5),
                                     (2, 3, 0, 1, k + 8, 9), (1, 2, 3, 0, k + 12, 13)):
                r = [A, B, C, D]
                r[a] = rol((r[a] + ((r[b] & r[c]) | (r[b] & r[d]) | (r[c] & r[d]))
                            + X[i] + 0x5A827999) & 0xFFFFFFFF, s)
                A, B, C, D = r
        for k in (0, 2, 1, 3):
            for a, b, c, d, i, s in ((0, 1, 2, 3, k, 3), (3, 0, 1, 2, k + 8, 9),
                                     (2, 3, 0, 1, k + 4, 11), (1, 2, 3, 0, k + 12, 15)):
                r = [A, B, C, D]
                r[a] = rol((r[a] + (r[b] ^ r[c] ^ r[d]) + X[i] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
                A, B, C, D = r
        h = [(h[0] + A) & 0xFFFFFFFF, (h[1] + B) & 0xFFFFFFFF,
             (h[2] + C) & 0xFFFFFFFF, (h[3] + D) & 0xFFFFFFFF]
    return struct.pack("<4I", *h)


def ntlm_gen() -> None:
    header("NTLM hash", "MD4(UTF-16LE) — the Windows/AD password hash (for PtH testing)")
    pw = Prompt.ask("Password")
    h = _md4(pw.encode("utf-16-le")).hex()
    console.print(f"[bold green]{h}[/]")
    console.print("[dim]Crack it: hashcat -m 1000  ·  john --format=nt[/]")
    pause()


def crc_calc() -> None:
    header("CRC32 / Adler32", "Fast non-cryptographic integrity checksums")
    src = Prompt.ask("[t]ext or [f]ile", choices=["t", "f"], default="t")
    if src == "t":
        data = Prompt.ask("Text").encode()
    else:
        p = Path(Prompt.ask("File path").strip('"'))
        if not p.is_file():
            console.print("[red]File not found.[/]")
            return pause()
        data = p.read_bytes()
    t = Table(show_header=False, box=None)
    t.add_row("CRC32", f"{zlib.crc32(data) & 0xffffffff:08x}")
    t.add_row("Adler32", f"{zlib.adler32(data) & 0xffffffff:08x}")
    console.print(t)
    pause()


def hmac_calc() -> None:
    header("HMAC calculator", "Keyed hash for message authentication")
    algo = Prompt.ask("Algorithm", choices=["md5", "sha1", "sha256", "sha512"],
                      default="sha256")
    key = Prompt.ask("Key").encode()
    msg = Prompt.ask("Message").encode()
    console.print(f"[bold green]{hmac.new(key, msg, algo).hexdigest()}[/]")
    pause()


MENU = {
    "1": ("Identify a hash", identify),
    "2": ("Calculate hashes (text/file)", calculate),
    "3": ("NTLM hash generator", ntlm_gen),
    "4": ("Checksum verify / compare", checksum_verify),
    "5": ("Crack with John the Ripper", john_crack),
    "6": ("Crack with hashcat (GPU)", hashcat_crack),
    "7": ("Generate practice hashes", make_demo_hashes),
    "8": ("CRC32 / Adler32 checksums", crc_calc),
    "9": ("HMAC calculator", hmac_calc),
}
