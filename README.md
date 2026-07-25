<div align="center">

# nullsec

**A menu-driven offensive-security multitool — 37 modules and 271 built-in tools behind one prompt.**

Recon · password cracking · crypto & cipher breaking · web/API testing · forensics · steganography · OSINT · evasion · payload generation — most of it pure Python with no setup.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Modules](https://img.shields.io/badge/modules-37-red)
![Tools](https://img.shields.io/badge/built--in%20tools-271-orange)

</div>

```
 ███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗███████╗ ██████╗
████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔════╝██╔════╝
██╔██╗ ██║██║   ██║██║     ██║     ███████╗█████╗  ██║
██║╚██╗██║██║   ██║██║     ██║     ╚════██║██╔══╝  ██║
██║ ╚████║╚██████╔╝███████╗███████╗███████║███████╗╚██████╗
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝
        offensive security framework · authorized use only
```

Most of nullsec runs on **pure Python** (just `rich` + `requests`). Heavier external
tools — `nmap`, `sqlmap`, `hydra`, `nuclei`, `metasploit`, `john`, `hashcat` — light
up automatically once they're installed, **natively or through WSL**. Nothing is
required to start: missing tools simply grey out their module and the built-in
scanners/crackers keep working.

- **37 modules · 271 built-in tools**
- **2,964** curated tools in the searchable catalog
- **~60,900** exploit/template modules reachable once Exploit-DB, Nuclei, and Metasploit are installed
- **71** ready-to-fill reverse/bind/web-shell payloads + msfvenom builders
- Session reporting to Markdown/HTML, a CyberChef-style transform pipeline, and a WSL bridge for Linux-only tools

---

## Quick start

```bash
pip install -r requirements.txt
python main.py
```

Optional extras unlock a few more tools and **degrade gracefully** when absent
(`cryptography` → AES/RSA lab, `pillow` → PNG/EXIF stego, `pyfiglet` → the banner).

### Prebuilt Windows executable

Don't want Python? Build a standalone, self-contained `nullsec.exe` (bundles the
icon, catalog, and payloads — runs on any 64-bit Windows):

```bash
pyinstaller nullsec.spec --clean --noconfirm
# → dist/nullsec.exe
```

> The exe is unsigned, so Windows SmartScreen shows a warning on first run —
> **More info → Run anyway**, or right-click → Properties → **Unblock**.

---

## Usage

At the home prompt, press a module's key to open it, or use a command:

| Command | Does |
|---|---|
| `<key>` | open a module (e.g. `1`, `c`, `o`, `w`) — **keys are case-sensitive** (`E`=Evasion, `e`=Reversing) |
| `search <term>` | search the catalog + every module's tools, then jump straight in |
| `use <tool>` | show a catalogued tool's install command and details |
| `r` / `t` | session report · external-tool status |
| `help` / `?` | command help |
| `q` | quit |

Findings from recon/web/network modules collect in the **session report** (`r`),
which you can save as Markdown or a styled HTML page.

See **[USAGE.md](USAGE.md)** for a full walkthrough.

---

## Modules

| Group | Modules |
|---|---|
| **Recon / OSINT** | Reconnaissance · Network · OSINT & DNS · Metadata · Tool Catalog · Email / Phishing |
| **Web / Exploit** | Web · Payload Forge · HTTP Interceptor · Payload Arsenal · Brute-force · Vuln Scan · LOLBins · Exploit Toolkit |
| **AD / Network** | AD Attacks · SMB / Shares · Post-Exploitation · Wireless |
| **Data / Cloud** | Databases · Cloud · Mobile |
| **Crypto / Stego** | Crypto & Encoding · Cipher Lab · Hashes & Cracking · Steganography · Encoding Recipe |
| **Wordlists** | Passwords · Generators · Wordlists |
| **Forensics / DFIR** | Forensics · Reversing · Data Extractor |
| **IoT / Hardware** | IoT / ICS / SCADA · Hardware / Physical |
| **Evasion / Defense** | Evasion & Bypass · Detection |
| **System** | Install Arsenal |

---

## How it fits together

- **`main.py`** draws the home grid and dispatches to modules.
- **`toolkit/*.py`** — one file per module, each exposing a `MENU` dict of `(label, function)`.
- **`toolkit/utils.py`** — shared console, the WSL bridge, external-tool detection, and the session reporter.
- **`toolkit/arsenal.dat`** — the base64 payload dataset (regenerate with `python tools/gen_arsenal.py`).
- **`data/tools.json`** — the importable tool catalog.

Run the smoke tests after changes:

```bash
python tests/test_smoke.py
```

---

## ⚠️ Legal

nullsec is for **authorized use only** — your own machines, lab VMs, and
CTF / training targets, or systems you have **explicit written permission** to test.
Unauthorized access to computer systems is illegal. You are solely responsible for
how you use this software. The authors accept no liability for misuse.

## License

[MIT](LICENSE) © 2026 anonymous
