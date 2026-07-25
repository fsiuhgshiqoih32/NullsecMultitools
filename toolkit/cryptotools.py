from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
from collections import Counter

from rich.prompt import Prompt

from .utils import console, header, need_lib, pause, report

# English letter frequencies (%) for chi-squared / scoring.
ENGLISH_FREQ = {
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2, 'g': 2.0,
    'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7,
    'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8,
    'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074,
}


def _english_score(data: bytes) -> float:
    """Higher = more English-like. Rewards letters/space, punishes control bytes."""
    score = 0.0
    for b in data:
        c = chr(b).lower()
        if c in ENGLISH_FREQ:
            score += ENGLISH_FREQ[c]
        elif b == 0x20:
            score += 7.0
        elif b in (0x0a, 0x0d, 0x09):
            score += 1.0
        elif 0x21 <= b <= 0x7e:
            score += 0.2
        else:
            score -= 15.0
    return score


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


_PUNCT = set(b".,'\"!?;:-()")


def _text_quality(data: bytes) -> float:
    """English *cleanliness* per char — rewards letters/space uniformly and
    punishes control bytes hard. Unlike frequency-sum scoring this can't be
    inflated by a few lucky high-frequency letters, so it correctly ranks a
    perfect decode above a slightly-garbled one when comparing key sizes."""
    if not data:
        return -1e9
    score = 0.0
    for b in data:
        if b == 0x20 or 0x41 <= b <= 0x5a or 0x61 <= b <= 0x7a:
            score += 1.0
        elif b in (0x0a, 0x0d, 0x09):
            score += 0.3
        elif b in _PUNCT:
            score += 0.5
        elif 0x30 <= b <= 0x39:
            score += 0.4
        elif 0x21 <= b <= 0x7e:
            score += 0.1
        else:
            score -= 5.0
    return score / len(data)


def _read_bytes(prompt: str) -> bytes | None:
    raw = Prompt.ask(prompt + " [b]ase64/[h]ex/[r]aw", default="b")
    data_str = Prompt.ask("Ciphertext")
    try:
        if raw == "b":
            return base64.b64decode(data_str + "===")
        if raw == "h":
            return bytes.fromhex(data_str.replace(" ", ""))
        return data_str.encode()
    except (binascii.Error, ValueError) as e:
        console.print(f"[red]Decode error: {e}[/]")
        return None


def _solve_xor_keysize(data: bytes, ks: int) -> tuple[bytes, bytes]:
    """Solve each column as single-byte XOR; return (key, plaintext)."""
    if ks < 1:
        return b"", data
    key = bytearray()
    for col in range(ks):
        column = data[col::ks]
        best_b, best_s = 0, -1e9
        for b in range(256):
            s = _english_score(bytes(c ^ b for c in column))
            if s > best_s:
                best_s, best_b = s, b
        key.append(best_b)
    plain = bytes(c ^ key[i % ks] for i, c in enumerate(data))
    return bytes(key), plain


def crack_repeating_xor(data: bytes) -> tuple[int, bytes, bytes]:
    """Return (keysize, key, plaintext). Hamming distance can produce noisy false
    minima on short inputs, so we solve every plausible key size and rank by the
    plaintext *cleanliness* score — preferring the smallest size on a tie, so the
    true key wins over its repeated multiples."""
    best = None
    max_ks = min(41, max(2, len(data) // 4))
    for ks in range(1, max_ks):
        key, plain = _solve_xor_keysize(data, ks)
        score = _text_quality(plain)
        if best is None or score > best[0] + 1e-9:  # strict => smallest ks wins ties
            best = (score, ks, key, plain)
    _score, ks, key, plain = best
    return ks, key, plain


def xor_repeating_break() -> None:
    header("Repeating-key XOR breaker", "Hamming keysize detection + per-column analysis")
    data = _read_bytes("Encoding")
    if not data or len(data) < 4:
        console.print("[red]Need more ciphertext.[/]")
        return pause()
    ks, key, plain = crack_repeating_xor(data)
    console.print(f"[bold]Best key size:[/] {ks}")
    printable_key = key.decode(errors="replace")
    console.print(f"[bold]Recovered key:[/] [green]{printable_key}[/]  "
                  f"[dim](hex {key.hex()})[/]")
    console.print(f"\n[bold]Plaintext:[/]\n{plain.decode(errors='replace')[:1000]}")
    report.log("cipher", "Repeating-key XOR break", [f"- key: `{printable_key}`",
               f"- keysize: {ks}"])
    pause()


def crack_vigenere(text: str) -> tuple[str, str]:
    """Pure core: return (key, plaintext) for a Vigenere ciphertext."""
    letters = [c for c in text.upper() if c.isalpha()]

    def ioc(seq):
        n = len(seq)
        if n < 2:
            return 0
        counts = Counter(seq)
        return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))

    # Score every key length by average column IoC, then pick the SMALLEST length
    # that already looks English-like — this avoids latching onto 2x/3x multiples
    # of the true key length (which also score high).
    scored = []
    for klen in range(1, min(21, len(letters) // 3)):
        cols = [letters[i::klen] for i in range(klen)]
        avg = sum(ioc(c) for c in cols) / klen
        scored.append((klen, avg))
    good = [k for k, a in scored if a >= 0.06]
    # scored is empty for very short ciphertext (< 6 letters); fall back to a
    # single-shift (Caesar-like) key rather than crashing on max([]).
    best_len = min(good) if good else (
        max(scored, key=lambda x: x[1])[0] if scored else 1)

    key = []
    for i in range(best_len):
        col = letters[i::best_len]
        best_shift, best_chi = 0, 1e18
        for shift in range(26):
            dec = [chr((ord(c) - 65 - shift) % 26 + 65) for c in col]
            counts = Counter(dec)
            chi = 0.0
            for ltr, freq in ENGLISH_FREQ.items():
                observed = counts.get(ltr.upper(), 0)
                expected = freq / 100 * len(col)
                if expected:
                    chi += (observed - expected) ** 2 / expected
            if chi < best_chi:
                best_chi, best_shift = chi, shift
        key.append(chr(best_shift + 65))
    keystr = "".join(key)

    out, ki = [], 0
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            shift = ord(key[ki % best_len]) - 65
            out.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return keystr, "".join(out)


def vigenere_break() -> None:
    header("Vigenere breaker", "Index-of-coincidence key length + chi-squared columns")
    text = Prompt.ask("Ciphertext (letters)")
    letters = [c for c in text.upper() if c.isalpha()]
    if len(letters) < 20:
        console.print("[red]Need more text for statistical analysis.[/]")
        return pause()
    keystr, plain = crack_vigenere(text)
    best_len = len(keystr)
    console.print(f"[bold]Likely key:[/] [green]{keystr}[/]  (length {best_len})")
    console.print(f"\n[bold]Plaintext:[/]\n{plain[:1000]}")
    report.log("cipher", "Vigenere break", [f"- key: `{keystr}`"])
    return pause()


MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
    '/': '-..-.', '@': '.--.-.', ' ': '/',
}
MORSE_REV = {v: k for k, v in MORSE.items()}


def morse_tool() -> None:
    header("Morse code", "Encode or decode")
    mode = Prompt.ask("[e]ncode or [d]ecode", choices=["e", "d"], default="d")
    s = Prompt.ask("Input")
    if mode == "e":
        out = " ".join(MORSE.get(c.upper(), "?") for c in s)
    else:
        out = "".join(MORSE_REV.get(tok, "?") for tok in s.split(" "))
    console.print(f"[green]{out}[/]")
    pause()


def rail_fence() -> None:
    header("Rail fence cipher", "Zig-zag transposition")
    mode = Prompt.ask("[e]ncode or [d]ecode", choices=["e", "d"], default="e")
    s = Prompt.ask("Text")
    try:
        rails = int(Prompt.ask("Rails", default="3"))
    except ValueError:
        rails = 3
    if rails < 2:
        console.print("[yellow]Rails must be 2 or more.[/]")
        return pause()
    if mode == "e":
        console.print(f"[green]{_rail_encode(s, rails)}[/]")
    else:
        console.print(f"[green]{_rail_decode(s, rails)}[/]")
    pause()


def _rail_pattern(n, rails):
    pat, r, d = [], 0, 1
    for _ in range(n):
        pat.append(r)
        if r == 0:
            d = 1
        elif r == rails - 1:
            d = -1
        r += d
    return pat


def _rail_encode(s, rails):
    if rails < 2 or not s:
        return s  # 0/1 rails (or empty) is the identity — nothing to zig-zag
    rows = [""] * rails
    for ch, r in zip(s, _rail_pattern(len(s), rails)):
        rows[r] += ch
    return "".join(rows)


def _rail_decode(s, rails):
    if rails < 2 or not s:
        return s
    pat = _rail_pattern(len(s), rails)
    counts = Counter(pat)
    idx, rows = 0, {}
    for r in range(rails):
        rows[r] = list(s[idx:idx + counts[r]])
        idx += counts[r]
    ptr = {r: 0 for r in range(rails)}
    out = []
    for r in pat:
        out.append(rows[r][ptr[r]])
        ptr[r] += 1
    return "".join(out)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_tool() -> None:
    header("Base58", "Bitcoin-style base58 encode/decode")
    mode = Prompt.ask("[e]ncode or [d]ecode", choices=["e", "d"], default="e")
    s = Prompt.ask("Input")
    if mode == "e":
        num = int.from_bytes(s.encode(), "big")
        out = ""
        while num:
            num, rem = divmod(num, 58)
            out = B58[rem] + out
        console.print(f"[green]{out or '1'}[/]")
    else:
        num = 0
        for ch in s:
            num = num * 58 + B58.index(ch)
        out = num.to_bytes((num.bit_length() + 7) // 8, "big")
        console.print(f"[green]{out.decode(errors='replace')}[/]")
    pause()


def cipher_identify() -> None:
    header("Cipher identifier", "Heuristic guess of what you're looking at")
    s = Prompt.ask("Ciphertext").strip()
    guesses = []
    if set(s) <= set(".-/ "):
        guesses.append("Morse code")
    if all(c in "0123456789abcdefABCDEF " for c in s) and len(s.replace(" ", "")) % 2 == 0:
        guesses.append("Hex-encoded")
    if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in s) and len(s) % 4 == 0:
        guesses.append("Base64")
    if all(c in B58 for c in s):
        guesses.append("Base58")
    letters = [c for c in s.upper() if c.isalpha()]
    if letters and all(c.isalpha() or c.isspace() for c in s):
        counts = Counter(letters)
        n = len(letters)
        ic = sum(v * (v - 1) for v in counts.values()) / (n * (n - 1)) if n > 1 else 0
        if ic > 0.06:
            guesses.append("Substitution/Caesar (monoalphabetic — IoC high)")
        else:
            guesses.append("Vigenere/polyalphabetic (IoC low)")
    ent = _entropy(s.encode())
    guesses.append(f"Shannon entropy: {ent:.2f} bits/byte "
                   f"({'looks encrypted/compressed' if ent > 7.2 else 'structured text'})")
    for g in guesses:
        console.print(f"  • {g}")
    pause()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def jwt_tool() -> None:
    header("JWT decoder / analyzer", "Decode and audit a JSON Web Token")
    tok = Prompt.ask("Paste JWT").strip()
    parts = tok.split(".")
    if len(parts) != 3:
        console.print("[red]Not a 3-part JWT.[/]")
        return pause()

    def b64u(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    try:
        head = json.loads(b64u(parts[0]))
        payload = json.loads(b64u(parts[1]))
    except Exception as e:
        console.print(f"[red]Decode failed: {e}[/]")
        return pause()

    console.print("[bold]Header:[/]", json.dumps(head, indent=2))
    console.print("[bold]Payload:[/]", json.dumps(payload, indent=2))

    warns = []
    if str(head.get("alg", "")).lower() == "none":
        warns.append("alg=none — signature not verified! Forgeable.")
    if head.get("alg", "").startswith("HS"):
        warns.append("HMAC (HS*) — crackable if the secret is weak (try the cracker).")
    if "exp" in payload:
        from datetime import datetime, timezone
        exp = datetime.fromtimestamp(payload["exp"], timezone.utc)
        if exp < datetime.now(timezone.utc):
            warns.append(f"Token expired {exp:%Y-%m-%d %H:%M} UTC.")
    for w in warns:
        console.print(f"[yellow][!] {w}[/]")
    pause()


def jwt_crack() -> None:
    header("JWT HMAC cracker", "Brute the HS256 secret with a wordlist")
    tok = Prompt.ask("JWT (HS256)").strip()
    parts = tok.split(".")
    if len(parts) != 3:
        console.print("[red]Not a valid JWT.[/]")
        return pause()
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    want = parts[2]
    wl = Prompt.ask("Wordlist path").strip('"')
    try:
        with open(wl, encoding="utf-8", errors="ignore") as f:
            for line in f:
                secret = line.strip()
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                ).rstrip(b"=").decode()
                if sig == want:
                    console.print(f"[bold green]FOUND secret:[/] {secret}")
                    report.log("cipher", "JWT secret cracked", [f"- secret: `{secret}`"])
                    return pause()
    except FileNotFoundError:
        console.print("[red]Wordlist not found.[/]")
        return pause()
    console.print("[yellow]Secret not in wordlist.[/]")
    pause()


def jwt_forge() -> None:
    header("JWT forge", "Craft an alg:none token / tamper claims (tests weak validation)")

    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    tok = Prompt.ask("Original JWT (blank to build a fresh one)", default="").strip()
    payload = {"user": "admin"}
    if tok.count(".") == 2:
        try:
            payload = json.loads(base64.urlsafe_b64decode(
                tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)))
        except Exception:
            pass
    console.print(f"[dim]payload: {json.dumps(payload)}[/]")
    if Prompt.ask("Edit a claim?", choices=["y", "n"], default="y") == "y":
        k = Prompt.ask("Claim key", default="role")
        v = Prompt.ask("Claim value", default="admin")
        payload[k] = v
    head = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64u(json.dumps(payload).encode())
    forged = f"{head}.{body}."
    console.print(f"\n[bold green]{forged}[/]")
    console.print("[dim]Works only where the server accepts alg:none (unsigned). "
                  "For HS256 targets, crack the secret (option 8) and re-sign.[/]")
    report.log("cipher", "JWT forge (alg:none)", [f"- payload: {json.dumps(payload)}"])
    pause()


def _factor_n(n: int):
    """Factor a weak RSA modulus: trial division then Fermat. Returns (p,q)|None."""
    if n % 2 == 0:
        return 2, n // 2
    i = 3
    while i * i <= n and i < 5_000_000:
        if n % i == 0:
            return i, n // i
        i += 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(200_000):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def rsa_lab() -> None:
    header("RSA lab", "Factor a weak modulus, derive d, optionally decrypt")
    try:
        n = int(Prompt.ask("Modulus n").strip())
        e = int(Prompt.ask("Public exponent e", default="65537").strip())
    except ValueError:
        console.print("[red]n and e must be integers.[/]")
        return pause()
    console.print("[dim]Trying trial division + Fermat (works on small/close primes)...[/]")
    fac = _factor_n(n)
    if not fac:
        console.print("[yellow]Couldn't factor n -- it's not obviously weak. "
                      "For real attacks try RsaCtfTool.[/]")
        return pause()
    p, q = fac
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        console.print("[red]e is not invertible mod phi(n) -- bad key.[/]")
        return pause()
    console.print(f"[green]p =[/] {p}")
    console.print(f"[green]q =[/] {q}")
    console.print(f"[green]d =[/] {d}")
    report.log("cipher", "RSA weak-modulus factored", [f"- n={n}", f"- d={d}"])
    c = Prompt.ask("Ciphertext integer c (blank to skip)", default="").strip()
    if c:
        try:
            m = pow(int(c), d, n)
        except ValueError:
            console.print("[red]c must be an integer.[/]")
            return pause()
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        console.print(f"[bold green]m (int)  =[/] {m}")
        console.print(f"[bold green]m (bytes)=[/] {raw.decode(errors='replace')}")
    pause()


def _key_bytes(s: str) -> bytes:
    s = s.strip()
    if s.startswith("hex:"):
        return bytes.fromhex(s[4:].replace(" ", ""))
    return s.encode()


def aes_tool() -> None:
    header("AES", "ECB/CBC encrypt or decrypt (needs the 'cryptography' library)")
    if not need_lib("cryptography", "cryptography"):
        return pause()
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    action = Prompt.ask("[e]ncrypt or [d]ecrypt", choices=["e", "d"], default="d")
    mode_name = Prompt.ask("Mode", choices=["ecb", "cbc"], default="cbc")
    key = _key_bytes(Prompt.ask("Key (text, or 'hex:...')"))
    if len(key) not in (16, 24, 32):
        console.print(f"[red]AES key must be 16/24/32 bytes (got {len(key)}).[/]")
        return pause()
    iv = b"\x00" * 16
    if mode_name == "cbc":
        iv = _key_bytes(Prompt.ask("IV (text or 'hex:...')", default="hex:" + "00" * 16))
        if len(iv) != 16:
            console.print("[red]IV must be exactly 16 bytes.[/]")
            return pause()
    mode = modes.ECB() if mode_name == "ecb" else modes.CBC(iv)
    cipher = Cipher(algorithms.AES(key), mode)
    if action == "d":
        blob = _read_bytes("Ciphertext")
        if blob is None:
            return pause()
        dec = cipher.decryptor()
        try:
            padded = dec.update(blob) + dec.finalize()
        except Exception as ex:
            console.print(f"[red]Decrypt failed: {ex}[/]")
            return pause()
        try:
            unpad = padding.PKCS7(128).unpadder()
            out = unpad.update(padded) + unpad.finalize()
        except Exception:
            out = padded  # not PKCS7-padded; show raw
        console.print(f"[bold green]{out.decode(errors='replace')}[/]")
        console.print(f"[dim]hex: {out.hex()}[/]")
    else:
        pt = Prompt.ask("Plaintext").encode()
        pad = padding.PKCS7(128).padder()
        padded = pad.update(pt) + pad.finalize()
        enc = cipher.encryptor()
        out = enc.update(padded) + enc.finalize()
        console.print(f"[bold green]b64:[/] {base64.b64encode(out).decode()}")
        console.print(f"[green]hex:[/] {out.hex()}")
    pause()


MENU = {
    "1": ("Repeating-key XOR breaker", xor_repeating_break),
    "2": ("Vigenere breaker", vigenere_break),
    "3": ("Cipher identifier", cipher_identify),
    "4": ("Morse encode/decode", morse_tool),
    "5": ("Rail-fence cipher", rail_fence),
    "6": ("Base58 encode/decode", base58_tool),
    "7": ("JWT decode + analyze", jwt_tool),
    "8": ("JWT HMAC secret cracker", jwt_crack),
    "9": ("JWT forge (alg:none)", jwt_forge),
    "10": ("RSA lab (factor weak n, decrypt)", rsa_lab),
    "11": ("AES encrypt/decrypt (ECB/CBC)", aes_tool),
}
