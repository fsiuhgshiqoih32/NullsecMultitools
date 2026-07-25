from __future__ import annotations

import calendar
import hashlib
import secrets
from collections import defaultdict
from pathlib import Path

from rich.prompt import Prompt

from .utils import console, header, pause

# Compact word pool for diceware-style passphrases (memorable, unambiguous).
WORDS = ("apple anchor amber arrow autumn basil bacon badger ballot banjo beacon "
         "birch bison blaze bluff bramble bronze cabin cactus candle canyon cedar "
         "cinder clover cobalt comet copper coral cove crane crimson crystal dagger "
         "dawn delta denim diamond dolphin domino dune ember emerald falcon fable "
         "fern flint forest fossil garnet ginger glacier granite harbor hazel hollow "
         "ivory jade jasmine jungle kernel kettle lagoon lantern ledger lilac linen "
         "lotus lunar maple marble meadow mint mocha nectar nickel nomad oak ocean "
         "onyx opal orbit otter pebble pepper pewter pine pixel prairie quartz quiver "
         "raven ridge river rustic saffron sage salmon sapphire shadow silver slate "
         "spruce storm summit tango thistle timber topaz tundra umber velvet violet "
         "walnut willow winter zephyr zenith").split()


def passphrase() -> None:
    header("Passphrase generator", "Memorable, high-entropy (diceware style)")
    n = int(Prompt.ask("Number of words", default="4"))
    sep = Prompt.ask("Separator", default="-")
    cap = Prompt.ask("Capitalize each word?", choices=["y", "n"], default="y") == "y"
    digit = Prompt.ask("Append a random digit?", choices=["y", "n"], default="y") == "y"
    for _ in range(5):
        words = [secrets.choice(WORDS) for _ in range(n)]
        if cap:
            words = [w.capitalize() for w in words]
        phrase = sep.join(words)
        if digit:
            phrase += str(secrets.randbelow(100))
        console.print(f"  [green]{phrase}[/]")
    import math
    bits = n * math.log2(len(WORDS))
    console.print(f"\n[dim]~{bits:.0f} bits of entropy from the words alone "
                  f"(pool of {len(WORDS)}).[/]")
    pause()


def pin_list() -> None:
    header("PIN wordlist", "Common + date-based PINs for authorized testing")
    length = int(Prompt.ask("PIN length", choices=["4", "6"], default="4"))
    pins = set()
    # statistically common PINs
    common4 = ["1234", "1111", "0000", "1212", "7777", "1004", "2000", "4444",
               "2222", "6969", "9999", "3333", "5555", "6666", "1122", "1313",
               "8888", "4321", "2001", "1010"]
    if length == 4:
        pins.update(common4)
        for y in range(1940, 2026):  # birth years
            pins.add(str(y))
        for m in range(1, 13):       # MMDD-ish
            for d in range(1, 32):
                pins.add(f"{m:02d}{d:02d}")
    else:
        pins.update(p + p[:2] for p in common4)
        for y in range(1940, 2026):
            for pre in ("19", "20"):
                pins.add(f"{pre}{y % 100:02d}{secrets.randbelow(100):02d}")
        pins.update(["123456", "000000", "111111", "121212", "654321", "666666"])
    pins = sorted(p for p in pins if len(p) == length)
    out = Path.cwd() / f"pins_{length}.txt"
    out.write_text("\n".join(pins) + "\n")
    console.print(f"Wrote [bold]{len(pins)}[/] {length}-digit PINs -> [cyan]{out}[/]")
    pause()


def keyboard_walk() -> None:
    header("Keyboard-walk generator", "Passwords people make by sliding across keys")
    rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
    walks = set()
    for row in rows:
        for i in range(len(row) - 3):
            seg = row[i:i + 6]
            walks.add(seg)
            walks.add(seg.capitalize())
            walks.add(seg + "123")
            walks.add(seg[::-1])
    combos = ["qwerty", "qwerty123", "1qaz2wsx", "1q2w3e4r", "zaq12wsx",
              "qazwsx", "asdfghjkl", "1qazxsw2", "qweasdzxc", "poiuytrewq"]
    walks.update(combos)
    walks.update(c.capitalize() for c in combos)
    walks = sorted(walks)
    out = Path.cwd() / "keyboard_walks.txt"
    out.write_text("\n".join(walks) + "\n")
    console.print(f"Generated [bold]{len(walks)}[/] keyboard-walk candidates -> [cyan]{out}[/]")
    for w in walks[:12]:
        console.print(f"  {w}")
    pause()


def markov_gen() -> None:
    header("Markov password generator", "Learn the shape of a wordlist, invent similar")
    wl = Prompt.ask("Training wordlist path").strip('"')
    p = Path(wl)
    if not p.is_file():
        console.print("[red]Wordlist not found.[/]")
        return pause()
    order = 2
    model = defaultdict(list)
    starts = []
    count = 0
    with p.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if not (3 <= len(w) <= 16):
                continue
            starts.append(w[:order])
            for i in range(len(w) - order):
                model[w[i:i + order]].append(w[i + order])
            model[w[-order:]].append("\n")
            count += 1
            if count > 200000:
                break
    if not starts:
        console.print("[yellow]No usable training words.[/]")
        return pause()
    console.print(f"[dim]Trained on {count:,} words.[/]\n")
    generated = []
    for _ in range(15):
        cur = secrets.choice(starts)
        out = cur
        for _ in range(14):
            nxt = model.get(out[-order:])
            if not nxt:
                break
            ch = secrets.choice(nxt)
            if ch == "\n":
                break
            out += ch
        if 4 <= len(out) <= 16:
            generated.append(out)
    for g in generated:
        console.print(f"  [green]{g}[/]")
    pause()


def rule_mutator() -> None:
    header("Rule mutator", "Expand base words with hashcat-style transforms")
    base = Prompt.ask("Base words (comma-separated)")
    words = [w.strip() for w in base.split(",") if w.strip()]
    leet = str.maketrans("aoeisAOEIS", "@031$@031$")
    years = ["", "1", "12", "123", "!", "!!", "2024", "2025", "01", "69", "007"]
    out = set()
    for w in words:
        bases = {w, w.lower(), w.upper(), w.capitalize(), w[::-1],
                 w.translate(leet), w.capitalize().translate(leet)}
        for b in bases:
            for suf in years:
                out.add(b + suf)
                out.add(suf + b)
    result = sorted(out)
    path = Path.cwd() / "mutated_wordlist.txt"
    path.write_text("\n".join(result) + "\n", encoding="utf-8")
    console.print(f"Expanded {len(words)} base word(s) into [bold]{len(result)}[/] "
                  f"candidates -> [cyan]{path}[/]")
    pause()


def hibp_check() -> None:
    header("Have-I-Been-Pwned check", "k-anonymity: only a 5-char hash prefix leaves your machine")
    import requests
    pw = Prompt.ask("Password to check (throwaway!)")
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
        r.raise_for_status()
    except Exception as e:
        console.print(f"[red]Lookup failed: {e}[/]")
        return pause()
    count = 0
    for line in r.text.splitlines():
        h, _, c = line.partition(":")
        if h == suffix:
            count = int(c)
            break
    if count:
        console.print(f"[bold red]PWNED[/] — seen in [bold]{count:,}[/] breaches. "
                      "Never use this password.")
    else:
        console.print("[green]Not found in the Pwned Passwords set.[/] "
                      "(Absence isn't proof it's strong.)")
    console.print(f"[dim]Only prefix {prefix} was sent; the API never saw your full hash.[/]")
    pause()


def username_permutator() -> None:
    header("Username permutator", "Common corporate username formats from a name")
    first = Prompt.ask("First name").lower().strip()
    last = Prompt.ask("Last name").lower().strip()
    f, l = first[:1], last[:1]
    patterns = [
        first, last, f"{first}{last}", f"{first}.{last}", f"{first}_{last}",
        f"{f}{last}", f"{f}.{last}", f"{first}{l}", f"{last}{first}",
        f"{last}.{first}", f"{last}{f}", f"{f}{l}", f"{first}-{last}",
    ]
    names = sorted({p for p in patterns if p})
    for n in names:
        console.print(f"  {n}")
    out = Path.cwd() / "usernames.txt"
    out.write_text("\n".join(names) + "\n", encoding="utf-8")
    console.print(f"\n[bold]{len(names)}[/] usernames -> [cyan]{out}[/] "
                  f"[dim](feed to hydra/brute-force)[/]")
    pause()


def date_wordlist() -> None:
    header("Date wordlist", "Every date in a year range, in common password formats")
    try:
        start = int(Prompt.ask("Start year", default="1980"))
        end = int(Prompt.ask("End year", default="2025"))
    except ValueError:
        console.print("[red]Years must be numbers.[/]")
        return pause()
    if end < start or end - start > 200:
        console.print("[red]Bad range.[/]")
        return pause()
    out = set()
    for y in range(start, end + 1):
        out.add(str(y))
        for m in range(1, 13):
            for d in range(1, calendar.monthrange(y, m)[1] + 1):
                out.add(f"{d:02d}{m:02d}{y}")            # DDMMYYYY
                out.add(f"{m:02d}{d:02d}{y}")            # MMDDYYYY
                out.add(f"{y}{m:02d}{d:02d}")            # YYYYMMDD
                out.add(f"{d:02d}{m:02d}{y % 100:02d}")  # DDMMYY
    result = sorted(out)
    path = Path.cwd() / f"dates_{start}_{end}.txt"
    path.write_text("\n".join(result) + "\n", encoding="utf-8")
    console.print(f"Wrote [bold]{len(result):,}[/] date strings -> [cyan]{path}[/]")
    pause()


def combinator() -> None:
    header("Wordlist combinator", "Concatenate every word of A with every word of B")
    a = Path(Prompt.ask("Wordlist A path").strip('"'))
    b = Path(Prompt.ask("Wordlist B path").strip('"'))
    if not a.is_file() or not b.is_file():
        console.print("[red]Both wordlists must exist.[/]")
        return pause()
    sep = Prompt.ask("Separator between words", default="")
    wa = [x.strip() for x in a.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()][:5000]
    wb = [x.strip() for x in b.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()][:5000]
    cap = 5_000_000
    if len(wa) * len(wb) > cap:
        console.print(f"[yellow]{len(wa) * len(wb):,} combos -- capping at {cap:,}.[/]")
    out = Path.cwd() / "combined_wordlist.txt"
    count = 0
    with out.open("w", encoding="utf-8") as f:
        for x in wa:
            for y in wb:
                f.write(f"{x}{sep}{y}\n")
                count += 1
                if count >= cap:
                    break
            if count >= cap:
                break
    console.print(f"Wrote [bold]{count:,}[/] combinations -> [cyan]{out}[/]")
    pause()


MENU = {
    "1": ("Passphrase generator", passphrase),
    "2": ("PIN wordlist", pin_list),
    "3": ("Keyboard-walk wordlist", keyboard_walk),
    "4": ("Username permutator", username_permutator),
    "5": ("Markov password generator", markov_gen),
    "6": ("Rule mutator (hashcat-style)", rule_mutator),
    "7": ("Have-I-Been-Pwned check", hibp_check),
    "8": ("Date wordlist (year range)", date_wordlist),
    "9": ("Wordlist combinator (A x B)", combinator),
}
