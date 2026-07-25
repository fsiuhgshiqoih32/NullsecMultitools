# Running nullsec

A menu-driven security multitool. Most of it runs with just Python; the heavy
external tools (nmap, hydra, john, hashcat, nuclei, metasploit…) are optional and
light up automatically once installed.

> **Authorized use only** — your own machines, lab VMs, and CTF / training targets
> you have permission to test.

---

## 1. Requirements

- **Python 3.10+**
- Python packages (one command):
  ```bash
  pip install -r requirements.txt
  ```
  Core is just `rich` + `requests`; `pyfiglet` draws the banner. The optional extras
  `cryptography`, `pillow`, and `dnspython` unlock a few tools (AES/RSA lab, image
  stego + EXIF, richer DNS) and degrade gracefully with an install hint when absent.
- **Optional:** WSL (Windows) or a Linux box for the external command-line tools.

---

## 2. Quick start

Unzip the project, open a terminal **in the `nullsec` folder**, then:

### Windows (Command Prompt or PowerShell)
```bash
cd nullsec
```
```bash
pip install rich pyfiglet requests
```
```bash
python main.py
```
> On Windows the command is `python` — not `python3`. If typing `python` opens the
> Microsoft Store, use `py main.py` instead.

### Linux / macOS / WSL
```bash
cd nullsec
```
```bash
pip3 install rich pyfiglet requests
```
```bash
python3 main.py
```

You should see the **nullsec** banner and a grid of module panels.

---

## 3. Driving the interface

The home screen groups every module into panels (RECON/OSINT, ATTACK, CRYPTO/STEGO,
WORDLISTS, APPS/CLOUD, FORENSICS, DEFENSE, SYSTEM). Each entry has a status dot:

- **●** ready (built-in, or its external tool is installed)
- **◐** some of its tools are installed
- **○** needs an install

At the `nullsec >` prompt you can type:

| Input | Does |
|-------|------|
| a module key (`c`, `3`, `o`, `w`…) | opens that module |
| `search <term>` | search the catalog **and** module tools, then jump straight into one |
| `use <tool>` | shows a catalogued tool's install/details |
| `help` / `?` | command list |
| `version` | build info |
| `r` / `t` | session report / external-tool status |
| `q` | quit |

Inside a module you get numbered options; type the number, `b`/`/` to return to the
home grid, `q` to quit, or `?` for help. The home screen also shows a **recent** row
so you can jump back to what you last used. Findings from many modules auto-log to
the **session report** (`r`), which you can save as Markdown or HTML.

> Tip: don't paste menu lines (the ones with `│`) back into your shell — type the
> option key at nullsec's own prompt.

---

## 4. Try these first (zero installs needed)

- **Cipher Lab** → `c` → `1` — paste XOR ciphertext (base64/hex); it recovers the key.
- **Crypto** → `3` → `2` — magic decoder auto-peels nested base64/hex/rot layers.
- **Hashes** → `2` → `6` then `4` — make practice hashes, then crack them.
- **Forensics** → `f` → `8` — scan a folder for leaked API keys/tokens.
- **Generators** → `g` → `7` — check a password against Have-I-Been-Pwned (safely).
- **OSINT** → `o` → `1` — raw-packet DNS lookups.
- **Steganography** → `s` — hide/extract data (and files) in text and images.
- **Encoding Recipe** → `0` → `1` — chain transforms (from-base64, gunzip, xor:key…) CyberChef-style.
- **Data Extractor** → `z` — paste logs/text; harvest IPs, URLs, hashes, JWTs, and API keys.
- **Email / Phishing** → `j` → `5` — generate typosquat domains for a target.

---

## 4b. Workspaces (engagement management)

The **Workspace** module (`W` from the home screen) lets you create named
engagements that persist across sessions. Each workspace stores:

- **Findings** — automatically captured from the session report when a workspace
  is active. Every module that logs to `report("category", "detail")` will also
  save into the workspace.
- **Notes** — free-text notes you add manually (e.g. "confirmed SSRF on /api/proxy").
- **Metadata** — target, operator, creation timestamp.
- **Export** — Markdown or HTML report of all findings + notes.

### Quick workflow

1. `W` → `1` — **Create** a workspace (e.g. `pentest-acme-2026`), enter target/operator.
2. Run your normal modules (recon, web, network, etc.). Findings auto-persist.
3. `W` → `5` — **Add note** for manual observations.
4. `W` → `9` — **Export** the workspace as Markdown or HTML.
5. Next session: `W` → `2` — **Load** the workspace and continue where you left off.

The home screen shows the active workspace name and finding/note counts in the
status line. The banner line also shows `ws: <name>` when a workspace is active.

---

## 4c. Proxy Manager

The **Proxy Manager** module (`P` from the home screen) lets you load, test,
rotate, and export proxies. Other modules can automatically route their HTTP
requests through the active proxy.

### Supported formats

| Format | Example |
|--------|---------|
| `ip:port` | `1.2.3.4:8080` |
| `ip:port:user:pass` | `1.2.3.4:8080:admin:secret` |
| `http://ip:port` | `http://1.2.3.4:3128` |
| `socks5://ip:port` | `socks5://1.2.3.4:1080` |
| `socks5://user:pass@ip:port` | `socks5://admin:x@1.2.3.4:1080` |

### Quick workflow

1. `P` → `1` — **Load** the built-in list (~200 free proxies) or your own file.
2. `P` → `5` — **Test** all proxies (checks connectivity + measures latency).
3. Optionally keep only working proxies when prompted.
4. `P` → `9` — **Toggle** proxy on (enables routing for all modules).
5. `P` → `10` — Set rotation mode: **round-robin** or **random**.
6. `P` → `7` — **Export** working proxies to a file for later use.

### How modules use it

When the proxy is enabled, any module that calls `get_proxy()` from
`toolkit/utils.py` gets a `{"http": url, "https": url}` dict for `requests`:

```python
from .utils import get_proxy
r = requests.get(url, proxies=get_proxy(), timeout=10)
```

If the proxy is disabled or empty, `get_proxy()` returns `None` (direct connection).

> **Note:** Free public proxies are unreliable and short-lived. Always test
> before use, and replace them with paid/private proxies for real engagements.
> SOCKS5 support requires `pip install pysocks` (degrades gracefully if missing).

---

## 5. Turning on the external tools

Modules like Recon, Brute-force, Vuln Scan, and Tool Catalog drive real programs.
Install them and the status dots turn green.

### Easiest: run inside Linux / WSL
The full toolset is Linux-native. On Windows, install a WSL distro (Arch is ideal
because of the BlackArch repo), then use the in-app installer:

- Home menu → **`i` (Install Arsenal)** → bootstrap BlackArch → install the curated
  set. nullsec then drives those tools through WSL automatically.
- Or just run `python3 main.py` **inside** WSL, where everything resolves natively.

On Debian/Kali/Ubuntu you can also `sudo apt install nmap hydra john hashcat nuclei
sqlmap …` and they'll be detected.

### Windows Defender note (payload arsenal)
The Payload Arsenal stores reverse-shell templates in `arsenal.dat`. Antivirus
often **false-flags and quarantines** that file. If the arsenal shows *"payload data
isn't loaded,"* add a one-time exclusion in an **Administrator PowerShell**:
```powershell
Add-MpPreference -ExclusionPath "C:\full\path\to\nullsec"
```
Everything else in nullsec works without it.

---

## 6. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `can't open file 'main.py'` | You're not in the project folder — `cd` into `nullsec` first. |
| `python` opens the Microsoft Store | Use `py main.py` (Windows) or install Python from python.org. |
| `ModuleNotFoundError: rich` | `pip install rich pyfiglet requests` |
| Payload Arsenal is empty | Antivirus quarantined `arsenal.dat` — add the Defender exclusion above. |
| A module says a tool is "not installed" | Install it (menu `i`, or your package manager); the dot goes green. |
| Garbled boxes / colors | Use Windows Terminal, or a terminal that supports UTF-8 + ANSI. |

---

## 7. Layout

```
nullsec/
  main.py              # launcher + REPL
  requirements.txt     # core deps + optional extras
  toolkit/             # one module per capability
    arsenal.dat        # base64 payload data (loaded at runtime)
  data/tools.json      # the tool catalog
  data/state.json      # remembers your recent modules
  data/proxies.txt     # built-in free proxy list (replace with your own)
  workspaces/          # saved engagement workspaces (*.json)
  tests/test_smoke.py  # wiring checks (python tests/test_smoke.py)
```

Adding a tool = write one function and add a line to a module's `MENU` dict.
