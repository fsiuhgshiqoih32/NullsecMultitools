from __future__ import annotations

import math
from pathlib import Path

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause

# A tiny sample of the most-common passwords, for an offline "is this awful?" check.
COMMON = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "1234567", "111111", "1234567890", "123123", "abc123", "password1",
    "iloveyou", "admin", "welcome", "monkey", "letmein", "dragon", "hunter2",
}


def _charset_size(pw: str) -> int:
    size = 0
    if any(c.islower() for c in pw):
        size += 26
    if any(c.isupper() for c in pw):
        size += 26
    if any(c.isdigit() for c in pw):
        size += 10
    if any(not c.isalnum() for c in pw):
        size += 33
    return size or 1


def strength() -> None:
    header("Password strength", "Rough entropy estimate — not a guarantee")
    pw = Prompt.ask("Password (typed in the clear here — use throwaways)")
    size = _charset_size(pw)
    entropy = len(pw) * math.log2(size)

    if pw.lower() in COMMON:
        verdict, color = "TRIVIAL – it's on every wordlist", "red"
    elif entropy < 28:
        verdict, color = "Very weak", "red"
    elif entropy < 36:
        verdict, color = "Weak", "yellow"
    elif entropy < 60:
        verdict, color = "Reasonable", "green"
    else:
        verdict, color = "Strong", "bold green"

    # ~10 billion guesses/sec is a realistic offline GPU number for a fast hash.
    seconds = (size ** len(pw)) / 1e10
    table = Table(show_header=False, box=None)
    table.add_row("Length", str(len(pw)))
    table.add_row("Charset size", str(size))
    table.add_row("Entropy", f"{entropy:.1f} bits")
    table.add_row("Offline crack time*", _human_time(seconds))
    table.add_row("Verdict", f"[{color}]{verdict}[/]")
    console.print(table)
    console.print("[dim]*brute force at ~1e10 guesses/s vs a fast hash. A slow hash "
                  "(bcrypt) or a wordlist changes this enormously.[/]")
    pause()


def _human_time(seconds: float) -> str:
    if seconds < 1:
        return "instant"
    units = [("years", 3.15e7), ("days", 86400), ("hours", 3600),
             ("minutes", 60), ("seconds", 1)]
    for name, size in units:
        if seconds >= size:
            val = seconds / size
            if name == "years" and val > 1e6:
                return f"{val:.0e} years"
            return f"{val:.1f} {name}"
    return "instant"


def wordlist_gen() -> None:
    header("Wordlist generator", "Build a targeted list from base words + mutations")
    base = Prompt.ask("Base words (comma-separated, e.g. companyname,2024,admin)")
    words = [w.strip() for w in base.split(",") if w.strip()]
    if not words:
        console.print("[yellow]No words given.[/]")
        return pause()

    leet = Prompt.ask("Apply leetspeak (a->@, o->0, e->3, i->1)?", choices=["y", "n"], default="y") == "y"
    suffixes = Prompt.ask("Append suffixes (comma-sep, blank for a default set)",
                          default="!,1,123,2024,2025").split(",")

    results: set[str] = set()
    for w in words:
        variants = {w, w.lower(), w.upper(), w.capitalize()}
        if leet:
            variants |= {_leet(v) for v in list(variants)}
        for v in variants:
            results.add(v)
            for suf in suffixes:
                results.add(v + suf.strip())

    out = Path.cwd() / "generated_wordlist.txt"
    out.write_text("\n".join(sorted(results)) + "\n", encoding="utf-8")
    console.print(f"Generated [bold]{len(results)}[/] candidates -> [cyan]{out}[/]")
    console.print("[dim]Feed this to John/hashcat as a --wordlist for targeted cracking "
                  "of hashes you're authorized to test.[/]")
    pause()


def _leet(s: str) -> str:
    # leetspeak substitution — both args must be equal length for maketrans
    return s.translate(str.maketrans("aoeisAOEIS", "@0315@0315"))


def cupp_profiler() -> None:
    header("Target profiler", "Build a personalized wordlist from known details (CUPP-style)")
    info = {
        "name": Prompt.ask("First name", default="").lower().strip(),
        "surname": Prompt.ask("Surname", default="").lower().strip(),
        "nick": Prompt.ask("Nickname", default="").lower().strip(),
        "partner": Prompt.ask("Partner/child name", default="").lower().strip(),
        "pet": Prompt.ask("Pet name", default="").lower().strip(),
        "company": Prompt.ask("Company/keyword", default="").lower().strip(),
    }
    years = Prompt.ask("Important years (comma-sep, e.g. 1990,2015)", default="").strip()
    words = {v for v in info.values() if v}
    if not words:
        console.print("[yellow]Give at least one detail.[/]")
        return pause()
    yrs = [y.strip() for y in years.split(",") if y.strip()]
    suffixes = ["", "!", "@", "#", "1", "123", "1234", ".", "_"] + yrs + [y[-2:] for y in yrs]
    leet = str.maketrans("aoeis", "@0315")
    base = set(words) | {a + b for a in words for b in words if a != b}
    results = set()
    for w in base:
        for v in {w, w.capitalize(), w.upper(), w.translate(leet), w.capitalize().translate(leet)}:
            for suf in suffixes:
                results.add(v + suf)
    results = sorted(x for x in results if 3 <= len(x) <= 32)
    out = Path.cwd() / "profile_wordlist.txt"
    out.write_text("\n".join(results) + "\n", encoding="utf-8")
    console.print(f"Generated [bold]{len(results)}[/] candidates -> [cyan]{out}[/]")
    console.print("[dim]Authorized testing only. Feed to John/hashcat as a --wordlist.[/]")
    pause()


def policy_check() -> None:
    header("Password policy check", "Does a password meet a configurable policy?")
    pw = Prompt.ask("Password (throwaway)")
    try:
        minlen = int(Prompt.ask("Minimum length", default="12"))
    except ValueError:
        minlen = 12
    checks = [
        (f">= {minlen} characters", len(pw) >= minlen),
        ("has lowercase", any(c.islower() for c in pw)),
        ("has uppercase", any(c.isupper() for c in pw)),
        ("has a digit", any(c.isdigit() for c in pw)),
        ("has a symbol", any(not c.isalnum() for c in pw)),
        ("not a common password", pw.lower() not in COMMON),
    ]
    t = Table(show_header=False, box=None)
    for name, ok in checks:
        t.add_row("[green]PASS[/]" if ok else "[red]FAIL[/]", name)
    console.print(t)
    passed = sum(1 for _, ok in checks if ok)
    console.print(f"\n[bold]{passed}/{len(checks)}[/] requirements met.")
    pause()


MENU = {
    "1": ("Password strength / entropy", strength),
    "2": ("Targeted wordlist generator", wordlist_gen),
    "3": ("Target profiler (CUPP-style wordlist)", cupp_profiler),
    "4": ("Password policy checker", policy_check),
}
