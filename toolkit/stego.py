from __future__ import annotations

import struct
from pathlib import Path

from rich.prompt import Prompt

from .utils import console, header, pause, report

# zero-width characters used as 0/1 and a terminator
ZW0 = "​"   # zero-width space
ZW1 = "‌"   # zero-width non-joiner
ZW_END = "‍"  # zero-width joiner (terminator)


def _bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bytes_from_bits(bits) -> bytes:
    out = bytearray()
    acc = cur = 0
    for b in bits:
        cur = (cur << 1) | b
        acc += 1
        if acc == 8:
            out.append(cur)
            acc = cur = 0
    return bytes(out)


def zw_hide() -> None:
    header("Zero-width steg · hide", "Embed a secret invisibly inside cover text")
    cover = Prompt.ask("Cover text (visible)")
    secret = Prompt.ask("Secret message").encode()
    payload = "".join(ZW1 if b else ZW0 for b in _bits(secret)) + ZW_END
    # tuck the invisible payload after the first character
    stego = cover[:1] + payload + cover[1:] if cover else payload
    console.print("\n[bold]Stego text (copy the whole line — the secret is invisible):[/]")
    console.print(stego)
    console.print(f"\n[dim]Visible length {len(cover)}, actual length {len(stego)} "
                  f"({len(stego) - len(cover)} hidden chars).[/]")
    report.log("stego", "Zero-width hide", [f"- hid {len(secret)} bytes in cover text"])
    pause()


def zw_extract() -> None:
    header("Zero-width steg · extract", "Pull a hidden secret out of text")
    s = Prompt.ask("Paste suspicious text")
    bits = []
    for ch in s:
        if ch == ZW0:
            bits.append(0)
        elif ch == ZW1:
            bits.append(1)
        elif ch == ZW_END:
            break
    if not bits:
        console.print("[yellow]No zero-width payload found.[/]")
        return pause()
    msg = _bytes_from_bits(bits)
    console.print(f"[bold green]Hidden message:[/] {msg.decode(errors='replace')}")
    pause()


def ws_hide() -> None:
    header("Whitespace steg · hide", "Encode a secret as trailing spaces/tabs")
    cover = Prompt.ask("Cover line")
    secret = Prompt.ask("Secret").encode()
    trailer = "".join("\t" if b else " " for b in _bits(secret))
    console.print("\n[bold]Stego line (trailing whitespace carries the secret):[/]")
    console.print(repr(cover + trailer))
    out = Path.cwd() / "stego_whitespace.txt"
    out.write_text(cover + trailer + "\n", encoding="utf-8")
    console.print(f"[dim]Saved to {out} (whitespace preserved).[/]")
    pause()


def ws_extract() -> None:
    header("Whitespace steg · extract", "Decode trailing spaces/tabs")
    line = Prompt.ask("Paste line (or path to file)")
    p = Path(line.strip('"'))
    if p.is_file():
        line = p.read_text(encoding="utf-8").splitlines()[0]
    stripped = line.rstrip(" \t")
    trailer = line[len(stripped):]
    bits = [1 if c == "\t" else 0 for c in trailer]
    msg = _bytes_from_bits(bits)
    console.print(f"[bold green]Hidden message:[/] {msg.decode(errors='replace')}")
    pause()


def _bmp_pixel_offset(data: bytes) -> int:
    if data[:2] != b"BM":
        raise ValueError("Not a BMP file")
    return struct.unpack("<I", data[10:14])[0]


def bmp_hide() -> None:
    header("BMP LSB steg · hide", "Embed a message in image pixel low-bits")
    src = Prompt.ask("Cover BMP path").strip('"')
    p = Path(src)
    if not p.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    data = bytearray(p.read_bytes())
    try:
        off = _bmp_pixel_offset(data)
    except ValueError as e:
        console.print(f"[red]{e} — needs an uncompressed .bmp[/]")
        return pause()
    secret = Prompt.ask("Secret message").encode()
    payload = struct.pack(">I", len(secret)) + secret  # 4-byte length prefix
    capacity = len(data) - off
    need = len(payload) * 8
    if need > capacity:
        console.print(f"[red]Too big: need {need} pixel-bytes, have {capacity}.[/]")
        return pause()
    for i, bit in enumerate(_bits(payload)):
        data[off + i] = (data[off + i] & 0xFE) | bit
    out = p.with_name(p.stem + "_stego.bmp")
    out.write_bytes(data)
    console.print(f"[green]Hidden {len(secret)} bytes -> {out}[/]  "
                  f"[dim](used {need}/{capacity} pixel-bytes)[/]")
    report.log("stego", "BMP LSB hide", [f"- {len(secret)} bytes into {out.name}"])
    pause()


def bmp_extract() -> None:
    header("BMP LSB steg · extract", "Recover a message from pixel low-bits")
    src = Prompt.ask("Stego BMP path").strip('"')
    p = Path(src)
    if not p.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    data = p.read_bytes()
    try:
        off = _bmp_pixel_offset(data)
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        return pause()
    pixels = data[off:]
    length = int.from_bytes(_bytes_from_bits(pixels[i] & 1 for i in range(32)), "big")
    if length <= 0 or length > (len(pixels) - 32) // 8:
        console.print("[yellow]No valid hidden length — probably no message here.[/]")
        return pause()
    bits = (pixels[32 + i] & 1 for i in range(length * 8))
    msg = _bytes_from_bits(bits)
    console.print(f"[bold green]Hidden message ({length} bytes):[/] {msg.decode(errors='replace')}")
    pause()


# --- file-in-image binder ---------------------------------------------------
# Appends an arbitrary file after the image's data. Decoders stop at the image's
# end marker, so the picture still displays; the payload is recovered by extract.
# This is a stego CONTAINER (like steghide) — it does NOT auto-run the payload and
# does NOT disguise it. Extraction and execution are deliberate, separate steps.
_BIND_MAGIC = b"FFLKBIND1"


def file_embed() -> None:
    header("Hide a file in an image", "Carry any file (e.g. .exe) inside a PNG/JPEG/BMP/GIF")
    console.print("[dim]The image still displays normally. The payload is recovered with "
                  "'extract' — it is NOT auto-run and NOT disguised. Authorized/CTF use.[/]\n")
    cover_p = Path(Prompt.ask("Cover image path").strip('"'))
    payload_p = Path(Prompt.ask("File to hide (any type)").strip('"'))
    if not cover_p.is_file() or not payload_p.is_file():
        console.print("[red]Cover or payload not found.[/]")
        return pause()

    cover = cover_p.read_bytes()
    payload = payload_p.read_bytes()
    if cover[:3] not in (b"\xff\xd8\xff", b"\x89PN", b"GIF", b"BM"):
        console.print("[yellow]Cover doesn't look like a common image — continuing anyway.[/]")

    name = payload_p.name.encode()
    blob = (cover + _BIND_MAGIC +
            struct.pack(">HQ", len(name), len(payload)) + name + payload)
    out = cover_p.with_name(cover_p.stem + "_bound" + cover_p.suffix)
    out.write_bytes(blob)
    console.print(f"[green]Embedded[/] {payload_p.name} ({len(payload):,} bytes) into "
                  f"[cyan]{out.name}[/] ({len(blob):,} bytes total).")
    console.print(f"[dim]The image opens/displays as normal. To recover the file, run "
                  f"'extract' on {out.name}.[/]")
    report.log("stego", "File embedded in image",
               [f"- hid {payload_p.name} ({len(payload)} bytes) in {out.name}"])
    pause()


def file_extract() -> None:
    header("Extract a hidden file", "Recover a file carried inside an image")
    carrier_p = Path(Prompt.ask("Carrier image path").strip('"'))
    if not carrier_p.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    data = carrier_p.read_bytes()
    idx = data.rfind(_BIND_MAGIC)
    if idx == -1:
        console.print("[yellow]No nullsec-embedded payload found in this image.[/] "
                      "[dim](Only files hidden by this tool are detected here; try the "
                      "Forensics carver for other embedded data.)[/]")
        return pause()
    p = idx + len(_BIND_MAGIC)
    name_len, payload_len = struct.unpack(">HQ", data[p:p + 10])
    p += 10
    name = data[p:p + name_len].decode(errors="replace")
    payload = data[p + name_len:p + name_len + payload_len]
    outdir = Path(Prompt.ask("Save extracted file to folder", default="extracted").strip('"'))
    outdir.mkdir(exist_ok=True)
    out = outdir / name
    out.write_bytes(payload)
    console.print(f"[green]Recovered[/] {name} ({len(payload):,} bytes) -> [cyan]{out}[/]")
    if name.lower().endswith((".exe", ".dll", ".msi", ".bat", ".ps1", ".sh", ".elf")):
        console.print("[yellow]This is an executable — only run it if it's yours / you "
                      "trust it and you're authorized on the target.[/]")
    report.log("stego", "File extracted from image", [f"- recovered {name} ({len(payload)} bytes)"])
    pause()


def png_hide() -> None:
    header("PNG LSB steg - hide", "Embed a message in PNG pixel low-bits (needs pillow)")
    from .utils import need_lib
    if not need_lib("PIL", "pillow"):
        return pause()
    from PIL import Image
    src = Path(Prompt.ask("Cover PNG path").strip('"'))
    if not src.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    secret = Prompt.ask("Secret message").encode()
    payload = struct.pack(">I", len(secret)) + secret
    bits = [(byte >> i) & 1 for byte in payload for i in range(7, -1, -1)]
    try:
        img = Image.open(src).convert("RGB")
    except Exception as e:
        console.print(f"[red]Couldn't open image: {e}[/]")
        return pause()
    flat = [c for pixel in img.getdata() for c in pixel]
    if len(bits) > len(flat):
        console.print(f"[red]Too big: need {len(bits)} bits, capacity {len(flat)}.[/]")
        return pause()
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | bit
    img.putdata([tuple(flat[i:i + 3]) for i in range(0, len(flat), 3)])
    out = src.with_name(src.stem + "_stego.png")
    img.save(out, "PNG")
    console.print(f"[green]Hid {len(secret)} bytes -> {out}[/]")
    report.log("stego", "PNG LSB hide", [f"- {len(secret)} bytes into {out.name}"])
    pause()


def png_extract() -> None:
    header("PNG LSB steg - extract", "Recover a message from PNG pixel low-bits")
    from .utils import need_lib
    if not need_lib("PIL", "pillow"):
        return pause()
    from PIL import Image
    src = Path(Prompt.ask("Stego PNG path").strip('"'))
    if not src.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    try:
        img = Image.open(src).convert("RGB")
    except Exception as e:
        console.print(f"[red]Couldn't open image: {e}[/]")
        return pause()
    lsb = [c & 1 for pixel in img.getdata() for c in pixel]
    length = int.from_bytes(_bytes_from_bits(lsb[:32]), "big")
    if length <= 0 or length * 8 > len(lsb) - 32:
        console.print("[yellow]No valid hidden length -- probably no message here.[/]")
        return pause()
    msg = _bytes_from_bits(lsb[32:32 + length * 8])
    console.print(f"[bold green]Hidden message ({length} bytes):[/] "
                  f"{msg.decode(errors='replace')}")
    pause()


def img_strip() -> None:
    header("Strip image metadata", "Re-save an image with no EXIF/metadata (needs pillow)")
    from .utils import need_lib
    if not need_lib("PIL", "pillow"):
        return pause()
    from PIL import Image
    src = Path(Prompt.ask("Image path").strip('"'))
    if not src.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    try:
        img = Image.open(src)
        clean = Image.new(img.mode, img.size)
        clean.putdata(list(img.getdata()))
        out = src.with_name(src.stem + "_clean" + src.suffix)
        clean.save(out)
    except Exception as e:
        console.print(f"[red]Failed: {e}[/]")
        return pause()
    console.print(f"[green]Saved metadata-free copy -> {out}[/]")
    pause()


MENU = {
    "1": ("Zero-width text: hide", zw_hide),
    "2": ("Zero-width text: extract", zw_extract),
    "3": ("Whitespace: hide", ws_hide),
    "4": ("Whitespace: extract", ws_extract),
    "5": ("Image (BMP LSB): hide", bmp_hide),
    "6": ("Image (BMP LSB): extract", bmp_extract),
    "7": ("Hide a FILE in an image (exe/any)", file_embed),
    "8": ("Extract a hidden file", file_extract),
    "9": ("Image (PNG LSB): hide", png_hide),
    "10": ("Image (PNG LSB): extract", png_extract),
    "11": ("Strip image metadata", img_strip),
}
