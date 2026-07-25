from __future__ import annotations

import math
import re
import struct
import uuid as uuidlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report

# magic signature -> (label, extension)
MAGIC = {
    b"\xff\xd8\xff": ("JPEG image", "jpg"),
    b"\x89PNG\r\n\x1a\n": ("PNG image", "png"),
    b"GIF87a": ("GIF image", "gif"),
    b"GIF89a": ("GIF image", "gif"),
    b"%PDF": ("PDF document", "pdf"),
    b"PK\x03\x04": ("ZIP/Office/JAR", "zip"),
    b"\x1f\x8b": ("GZIP archive", "gz"),
    b"Rar!\x1a\x07": ("RAR archive", "rar"),
    b"7z\xbc\xaf\x27\x1c": ("7-Zip archive", "7z"),
    b"\x7fELF": ("ELF executable", "elf"),
    b"MZ": ("Windows PE/EXE", "exe"),
    b"\xca\xfe\xba\xbe": ("Java class / Mach-O fat", "class"),
    b"ID3": ("MP3 audio", "mp3"),
    b"OggS": ("OGG media", "ogg"),
    b"\x00\x00\x01\xba": ("MPEG video", "mpg"),
    b"SQLite format 3\x00": ("SQLite database", "db"),
    b"-----BEGIN": ("PEM key/cert", "pem"),
}

# carver signatures with optional footers
CARVE = [
    ("jpg", b"\xff\xd8\xff", b"\xff\xd9"),
    ("png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    ("gif", b"GIF89a", b"\x00\x3b"),
    ("pdf", b"%PDF", b"%%EOF"),
    ("zip", b"PK\x03\x04", None),
    ("gz", b"\x1f\x8b\x08", None),
]


def _read_file(prompt="File path") -> bytes | None:
    p = Path(Prompt.ask(prompt).strip('"'))
    if not p.is_file():
        console.print(f"[red]No such file: {p}[/]")
        return None
    return p.read_bytes()


def strings_tool() -> None:
    header("strings", "Extract printable ASCII/UTF-16 sequences")
    data = _read_file()
    if data is None:
        return pause()
    minlen = int(Prompt.ask("Minimum length", default="4"))
    found = re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)
    # also catch wide (UTF-16LE) strings
    wide = re.findall((rb"(?:[\x20-\x7e]\x00){%d,}" % minlen), data)
    console.print(f"[dim]{len(found)} ascii + {len(wide)} wide strings; showing first 60[/]")
    for s in (found + wide)[:60]:
        console.print(s.decode("utf-8", "replace").replace("\x00", ""))
    pause()


def hexdump_tool() -> None:
    header("hexdump", "Classic hex + ASCII view")
    data = _read_file()
    if data is None:
        return pause()
    n = int(Prompt.ask("Bytes to show", default="256"))
    data = data[:n]
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        asc = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        console.print(f"[cyan]{off:08x}[/]  {hexs}  [green]{asc}[/]")
    pause()


def magic_identify() -> None:
    header("Magic-byte identifier", "What is this file, really?")
    data = _read_file()
    if data is None:
        return pause()
    head = data[:32]
    for sig, (label, ext) in MAGIC.items():
        if head.startswith(sig):
            console.print(f"[bold green]{label}[/]  (.{ext})  — magic {sig[:8].hex()}")
            report.log("forensics", "File identified", [f"- {label} (.{ext})"])
            return pause()
    console.print(f"[yellow]Unknown signature.[/] First bytes: {head[:12].hex()}")
    pause()


def carve_tool() -> None:
    header("File carver", "Find embedded files by magic bytes (binwalk-lite)")
    data = _read_file("File to carve")
    if data is None:
        return pause()
    outdir = Path(Prompt.ask("Output folder", default="carved"))
    outdir.mkdir(exist_ok=True)
    found = 0
    for ext, sig, footer in CARVE:
        start = 0
        while True:
            i = data.find(sig, start)
            if i == -1:
                break
            if footer:
                j = data.find(footer, i)
                end = j + len(footer) if j != -1 else min(i + 5_000_000, len(data))
            else:
                end = min(i + 5_000_000, len(data))
            blob = data[i:end]
            if len(blob) > 20:
                out = outdir / f"carved_{found:03d}_{i:08x}.{ext}"
                out.write_bytes(blob)
                console.print(f"[green]carved[/] {ext} @ 0x{i:x} ({len(blob)} bytes) -> {out.name}")
                found += 1
            start = i + len(sig)
    console.print(f"\n[bold]{found}[/] embedded file(s) carved into [cyan]{outdir}[/]")
    report.log("forensics", "File carve", [f"- {found} embedded files from input"])
    pause()


def entropy_scan() -> None:
    header("Entropy scan", "Spot encrypted/packed regions (8.0 = random)")
    data = _read_file()
    if data is None:
        return pause()
    window = max(256, len(data) // 40)
    console.print(f"[dim]window {window} bytes; ▁▂▃▄▅▆▇█ = 0..8 bits/byte[/]\n")
    blocks = "▁▂▃▄▅▆▇█"
    line = ""
    for off in range(0, len(data), window):
        e = _entropy(data[off:off + window])
        line += blocks[min(7, int(e / 8 * 8))]
    console.print(line)
    console.print(f"\nOverall entropy: [bold]{_entropy(data):.2f}[/] bits/byte "
                  f"({'likely encrypted/compressed' if _entropy(data) > 7.2 else 'structured'})")
    pause()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def uuid_analyze() -> None:
    header("UUID analyzer", "Version, and the timestamp/MAC hidden in v1 UUIDs")
    s = Prompt.ask("UUID").strip()
    try:
        u = uuidlib.UUID(s)
    except ValueError:
        console.print("[red]Not a valid UUID.[/]")
        return pause()
    t = Table(show_header=False, box=None)
    t.add_row("Version", str(u.version))
    t.add_row("Variant", str(u.variant))
    if u.version == 1:
        # 100ns intervals since 1582-10-15
        ts = (u.time - 0x01b21dd213814000) / 1e7
        dt = datetime.fromtimestamp(ts, timezone.utc)
        t.add_row("Timestamp", f"{dt:%Y-%m-%d %H:%M:%S} UTC")
        mac = ":".join(f"{(u.node >> (40 - 8 * i)) & 0xff:02x}" for i in range(6))
        t.add_row("Node (MAC)", mac)
        t.add_row("[yellow]Note[/]", "v1 leaks creation time + the generating host's MAC")
    console.print(t)
    pause()


def timestamp_convert() -> None:
    header("Timestamp converter", "Epoch <-> human, auto-detecting seconds/ms")
    s = Prompt.ask("Unix epoch (s or ms) or leave blank for 'now'", default="").strip()
    if not s:
        now = datetime.now(timezone.utc)
        console.print(f"now = [green]{int(now.timestamp())}[/] (s)  ·  {now:%Y-%m-%d %H:%M:%S} UTC")
        return pause()
    try:
        val = int(s)
    except ValueError:
        console.print("[red]Not an integer epoch.[/]")
        return pause()
    if val > 1e12:  # milliseconds
        val //= 1000
    dt = datetime.fromtimestamp(val, timezone.utc)
    local = datetime.fromtimestamp(val)
    console.print(f"UTC:   [green]{dt:%Y-%m-%d %H:%M:%S}[/]")
    console.print(f"Local: [green]{local:%Y-%m-%d %H:%M:%S}[/]")
    console.print(f"ISO:   {dt.isoformat()}")
    pause()


SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws.{0,20}[:=]\s*['\"]?([A-Za-z0-9/+]{40})"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "GitHub Token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "Generic secret": re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]([^'\"]{6,})"),
    "Stripe Key": re.compile(r"[sr]k_(?:live|test)_[0-9A-Za-z]{24}"),
}


def secret_scan() -> None:
    header("Secret scanner", "Grep files/folders for leaked keys & tokens")
    target = Path(Prompt.ask("File or folder").strip('"'))
    files = []
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = [p for p in target.rglob("*") if p.is_file() and p.stat().st_size < 2_000_000]
    else:
        console.print("[red]Not found.[/]")
        return pause()

    hits = []
    for f in files[:2000]:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for name, rx in SECRET_PATTERNS.items():
            for m in rx.finditer(text):
                snippet = m.group(0)[:60]
                hits.append((name, str(f), snippet))

    if not hits:
        console.print("[green]No secrets matched.[/]")
        return pause()
    t = Table(title=f"{len(hits)} potential secret(s)")
    t.add_column("Type", style="red bold")
    t.add_column("File", style="dim", overflow="fold")
    t.add_column("Match", style="yellow", overflow="fold")
    for name, path, snip in hits[:100]:
        t.add_row(name, path, snip)
    console.print(t)
    report.log("forensics", "Secret scan", [f"- {len(hits)} potential secrets in {target}"])
    pause()


PE_MACHINES = {0x14c: "x86 (i386)", 0x8664: "x64 (AMD64)", 0x1c0: "ARM",
               0xaa64: "ARM64", 0x1c4: "ARMv7"}
ELF_MACHINES = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64",
                0xf3: "RISC-V", 0x08: "MIPS"}


def binary_headers() -> None:
    header("Executable header parser", "Read PE (.exe/.dll) or ELF headers from scratch")
    data = _read_file("Binary path")
    if data is None:
        return pause()
    t = Table(show_header=False, box=None)
    if data[:2] == b"MZ":
        pe = struct.unpack("<I", data[0x3c:0x40])[0]
        if data[pe:pe + 4] != b"PE\x00\x00":
            console.print("[yellow]MZ stub but no PE header (DOS executable?).[/]")
            return pause()
        machine, nsec, tds = struct.unpack("<HHI", data[pe + 4:pe + 12])
        opt_magic = struct.unpack("<H", data[pe + 24:pe + 26])[0]
        bits = "PE32+ (64-bit)" if opt_magic == 0x20b else "PE32 (32-bit)"
        t.add_row("Format", "Windows PE")
        t.add_row("Machine", PE_MACHINES.get(machine, hex(machine)))
        t.add_row("Bitness", bits)
        t.add_row("Sections", str(nsec))
        t.add_row("Compiled", f"{datetime.fromtimestamp(tds, timezone.utc):%Y-%m-%d %H:%M:%S} UTC"
                  if tds else "0 (stripped)")
        # section names
        so = pe + 24 + struct.unpack("<H", data[pe + 20:pe + 22])[0]
        names = []
        for i in range(min(nsec, 12)):
            nm = data[so + i * 40:so + i * 40 + 8].rstrip(b"\x00").decode(errors="replace")
            names.append(nm)
        t.add_row("Section names", ", ".join(names))
        report.log("forensics", "PE header", [f"- {bits}, {machine:#x}, {nsec} sections"])
    elif data[:4] == b"\x7fELF":
        ei_class = "64-bit" if data[4] == 2 else "32-bit"
        endian = "little" if data[5] == 1 else "big"
        e_type, e_machine = struct.unpack("<HH", data[16:20])
        types = {1: "relocatable", 2: "executable", 3: "shared object (PIE/.so)", 4: "core"}
        t.add_row("Format", "ELF")
        t.add_row("Class", ei_class)
        t.add_row("Endian", endian)
        t.add_row("Type", types.get(e_type, str(e_type)))
        t.add_row("Machine", ELF_MACHINES.get(e_machine, hex(e_machine)))
        entry = struct.unpack("<Q" if data[4] == 2 else "<I",
                              data[24:32] if data[4] == 2 else data[24:28])[0]
        t.add_row("Entry point", hex(entry))
        report.log("forensics", "ELF header", [f"- {ei_class} {ELF_MACHINES.get(e_machine)}"])
    else:
        console.print(f"[yellow]Not a PE or ELF binary.[/] First bytes: {data[:4].hex()}")
        return pause()
    console.print(t)
    pause()


def appended_data_detect() -> None:
    header("Trailing-data detector", "Flag images hiding a file after their end marker")
    data = _read_file("Image path")
    if data is None:
        return pause()
    end = None
    if data[:3] == b"\xff\xd8\xff":              # JPEG -> last FFD9
        i = data.rfind(b"\xff\xd9")
        end = i + 2 if i != -1 else None
        fmt = "JPEG"
    elif data[:8] == b"\x89PNG\r\n\x1a\n":        # PNG -> IEND + CRC
        i = data.rfind(b"IEND")
        end = i + 8 if i != -1 else None
        fmt = "PNG"
    elif data[:3] == b"GIF":                       # GIF -> trailer 0x3B
        i = data.rfind(b"\x3b")
        end = i + 1 if i != -1 else None
        fmt = "GIF"
    elif data[:2] == b"BM":                        # BMP -> size in header
        end = struct.unpack("<I", data[2:6])[0]
        fmt = "BMP"
    else:
        console.print("[yellow]Not a recognized image format.[/]")
        return pause()

    if end is None or end >= len(data):
        console.print(f"[green]{fmt}: no trailing data. Clean.[/]")
        return pause()

    trailing = data[end:]
    console.print(f"[bold red][!] {fmt} has {len(trailing):,} bytes AFTER its end marker[/] "
                  f"(image ends at 0x{end:x}).")
    if _BINDMAGIC in trailing:
        console.print("[red]Contains an nullsec-bound payload[/] — extract it with "
                      "Steganography → 8.")
    # identify what the trailing blob is
    for sig, (label, ext) in MAGIC.items():
        if trailing[:16].lstrip(b"FFLKBIND1")[:len(sig)] == sig or trailing.startswith(sig):
            console.print(f"Trailing data looks like: [bold]{label}[/] (.{ext})")
            break
    console.print(f"[dim]First bytes: {trailing[:16].hex()}[/]")
    report.log("forensics", "Trailing data in image",
               [f"- {fmt} carries {len(trailing)} appended bytes"])
    pause()


_BINDMAGIC = b"FFLKBIND1"


def _exif_gps(gps: dict):
    from PIL.ExifTags import GPSTAGS
    data = {GPSTAGS.get(k, k): v for k, v in gps.items()}
    try:
        def dms(v):
            return float(v[0]) + float(v[1]) / 60 + float(v[2]) / 3600
        lat = dms(data["GPSLatitude"])
        lon = dms(data["GPSLongitude"])
        if data.get("GPSLatitudeRef") == "S":
            lat = -lat
        if data.get("GPSLongitudeRef") == "W":
            lon = -lon
        return lat, lon
    except Exception:
        return None


def exif_read() -> None:
    header("EXIF / GPS reader", "Pull camera + GPS metadata from a photo (needs pillow)")
    from .utils import need_lib
    if not need_lib("PIL", "pillow"):
        return pause()
    from PIL import ExifTags, Image
    p = Path(Prompt.ask("Image path").strip('"'))
    if not p.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    try:
        img = Image.open(p)
        exif = img._getexif() or {}
    except Exception as e:
        console.print(f"[red]Couldn't read EXIF: {e}[/]")
        return pause()
    if not exif:
        console.print("[yellow]No EXIF metadata (it may have been stripped).[/]")
        return pause()
    tagmap = {v: k for k, v in ExifTags.TAGS.items()}
    t = Table(show_header=False, box=None)
    for tag_id, val in exif.items():
        name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if name in ("Make", "Model", "Software", "DateTime", "DateTimeOriginal",
                    "LensModel", "Artist", "Copyright"):
            t.add_row(name, str(val)[:80])
    console.print(t)
    gps_id = tagmap.get("GPSInfo")
    if gps_id and gps_id in exif:
        coords = _exif_gps(exif[gps_id])
        if coords:
            lat, lon = coords
            console.print(f"[bold red][!] GPS:[/] {lat:.6f}, {lon:.6f}  "
                          f"[cyan]https://maps.google.com/?q={lat},{lon}[/]")
            report.log("forensics", f"EXIF GPS {p.name}", [f"- {lat}, {lon}"])
    pause()


def file_diff() -> None:
    header("File diff", "Compare two files byte-for-byte and line-by-line")
    a = Path(Prompt.ask("File A").strip('"'))
    b = Path(Prompt.ask("File B").strip('"'))
    if not a.is_file() or not b.is_file():
        console.print("[red]Both files must exist.[/]")
        return pause()
    da, db = a.read_bytes(), b.read_bytes()
    if da == db:
        console.print("[green]Files are identical.[/]")
        return pause()
    console.print(f"Sizes: A={len(da):,}  B={len(db):,}  (diff {len(db) - len(da):+,} bytes)")
    first = next((i for i in range(min(len(da), len(db))) if da[i] != db[i]),
                 min(len(da), len(db)))
    console.print(f"First differing byte at offset [bold]0x{first:x}[/] ({first})")
    import difflib
    la = da.decode("utf-8", "ignore").splitlines()
    lb = db.decode("utf-8", "ignore").splitlines()
    diff = list(difflib.unified_diff(la, lb, a.name, b.name, lineterm=""))
    if diff:
        console.print("\n[bold]Unified text diff (first 40 lines):[/]")
        for line in diff[:40]:
            color = "green" if line.startswith("+") else "red" if line.startswith("-") else "dim"
            console.print(f"[{color}]{line}[/]")
    pause()


MENU = {
    "1": ("strings (extract text)", strings_tool),
    "2": ("hexdump", hexdump_tool),
    "3": ("Identify file type (magic bytes)", magic_identify),
    "4": ("Carve embedded files", carve_tool),
    "5": ("Entropy scan (find encryption)", entropy_scan),
    "6": ("UUID analyzer", uuid_analyze),
    "7": ("Timestamp converter", timestamp_convert),
    "8": ("Secret scanner (keys/tokens)", secret_scan),
    "9": ("Detect hidden file in image", appended_data_detect),
    "10": ("PE/ELF header parser", binary_headers),
    "11": ("EXIF / GPS reader", exif_read),
    "12": ("File diff (byte + text)", file_diff),
}
