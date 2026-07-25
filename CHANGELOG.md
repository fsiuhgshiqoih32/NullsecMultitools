# Changelog

All notable changes to nullsec are documented here.
This project loosely follows [Semantic Versioning](https://semver.org/).

## [2.4.5] — 2026-07-25

### Fixed
- **OpenVPN connect failed on Windows** ("Bad backslash usage") — the injected
  `auth-user-pass` file path now uses forward slashes, which OpenVPN accepts.

### Added
- **Double-hop**: when the Proxy Manager is enabled, the VPN config is written with
  an `http-proxy`/`socks-proxy` directive so the encrypted tunnel is routed through
  the proxy first (you -> proxy -> VPN), hiding your IP from the VPN operator.

## [2.4.4] — 2026-07-25

### Added
- **VPNBook as a second source — real US & Canada servers.** The Free VPN module
  now also pulls VPNBook's curated free relays (US ×2, Canada ×2, UK, Germany,
  France) with working AES-256-GCM OpenVPN configs, filling the North-American gap
  VPNGate leaves. These are shown first, and export writes the shared credentials
  into an auth file so `openvpn` connects non-interactively.

### Fixed
- Config writer no longer crashes on Windows when injecting the auth-file path
  (the path's backslashes were mis-parsed as regex escapes).

## [2.4.3] — 2026-07-25

### Added
- **VPN server accumulation**: each VPNGate fetch now merges into a persistent
  cache instead of replacing the list. Because VPNGate rotates its ~100-server
  response over time, the pool and its country coverage grow with repeated fetches;
  servers unseen for 21 days are dropped, and "Measure real ping" prunes the ones
  that have gone offline. The fetch summary shows live-this-fetch vs. total.

## [2.4.2] — 2026-07-25

### Added
- **OpenVPN auto-install**: when you go to connect and OpenVPN isn't present, the
  Free VPN module offers to install it automatically (winget on Windows, apt/dnf/
  pacman on Linux, brew on macOS), then resolves the binary (including the standard
  `C:\Program Files\OpenVPN\bin` location) and connects — no manual step.

## [2.4.1] — 2026-07-25

### Added (Free VPN)
- **Real ping** — measures the actual TCP latency from your machine to each server
  (VPNGate's own figure is the server's internal ping, not yours), sorts the list
  fastest-first once measured, and shows it before you connect.
- **Encrypted-tunnel details** — the connect/details views now parse and show the
  tunnel's real cipher/auth and transport (e.g. AES-128-CBC / SHA1 over TCP:443)
  before establishing the encrypted OpenVPN tunnel.

## [2.4.0] — 2026-07-25

### Added
- **Free VPN module** (`V`): fetches the public **VPNGate** pool of volunteer VPN
  relays, filters by country, ranks by speed, exports an OpenVPN `.ovpn` config for
  any server, and can launch OpenVPN to connect. Routes its fetch through the Proxy
  Manager when enabled.

## [2.3.5] — 2026-07-25

Version renumbered to reflect the project's maturity (41 modules, 309 tools,
CI + automated releases). No functional changes from 2.3.3.

## [2.3.3] — 2026-07-25

### Fixed (found in a 5-pass code scan)
- **Vigenere breaker** crashed (`max() arg is an empty sequence`) on any ciphertext
  with fewer than 6 letters; now falls back to a single-shift key.
- **Rail fence** crashed (IndexError/KeyError) on fewer than 2 rails; the cores now
  treat 0/1 rails as identity, and the menu validates the input.
- Hardened `_solve_xor_keysize` against a `ks=0` divide-by-zero and corrected its
  return-type annotation (returns 2 values, not 3).
- API fuzzer read the *entire* parameter wordlist (and leaked the file handle) just
  to take 50 entries; now streams and closes properly.
- Added cipher edge-case regression tests.

## [2.3.2] — 2026-07-25

### Added
- **Proxy Manager** (`P`): load proxies (built-in list or file, 4 formats incl.
  SOCKS), concurrently test connectivity + latency, round-robin/random rotation,
  keep-working-only, export, and an on/off toggle. `utils.get_proxy()` gives any
  module a `requests`-ready proxies dict.
- **Workspace** (`W`): named engagements that persist findings, notes, target, and
  operator to disk as JSON, with Markdown/HTML export. When a workspace is active,
  the session reporter auto-forwards every finding into it; shown on the home screen.

### Fixed
- Proxy Manager's "Load" and "Toggle" called `report.log()` with a missing
  argument (would crash); now use the shorthand logger.
- Workspaces write to a persistent dir next to the exe instead of the read-only
  bundle, so engagements survive across runs of the packaged build.

## [2.3.1] — 2026-07-25

### Fixed
- **Hash calculator no longer truncates** SHA-256/SHA-512 — digests print as full,
  copy-pasteable lines instead of an ellipsised table cell.

### Added
- A correctness test (`test_builtin_tools_produce_correct_output`) that drives a
  sample of built-in tools with known inputs and asserts the output is right, not
  just crash-free. Backed by a 29-tool correctness sweep (hashes, decoders, ciphers,
  subnet/base/JSON utilities, breach lookup) — all passing.

## [2.3.0] — 2026-07-25

### Added
- **1,000,000 most-common passwords** bundled (`wordlists/top-1million-passwords.txt`,
  from SecLists/xato-net). Powers a new **Breach check** tool (is a password in the
  top-1M, and at what rank?), upgrades the strength/policy checks to use the full
  list, and is the default wordlist for the John and hashcat crackers.
- **Animated demo GIF** in the README (`docs/demo.gif`), generated by
  `tools/gen_demo.py`.
- A more descriptive README with a Highlights section.

## [2.2.0] — 2026-07-25

### Added
- **Auto-elevate to Administrator** on Windows (one UAC prompt), then **auto-add a
  Windows Defender exclusion** for the app folder so the payload data files
  (`arsenal.dat` / `gen_arsenal.py`) stop getting quarantined — the main reason the
  Payload Arsenal "didn't work" on Windows. Self-heals quarantined files afterwards.
  Opt out with `NULLSEC_NO_ELEVATE=1`; no-op on Linux/macOS.
- **Utilities module** (`U`): base converter, subnet/CIDR calculator, epoch
  timestamp converter, UUID generator, secure password generator, URL dissector,
  text stats + Shannon entropy, and JSON validate/pretty-print. 8 pure-Python tools.

## [2.1.1] — 2026-07-25

### Changed
- **AI is faster and clearer**: auto-picks the smallest (fastest) installed model
  instead of the first one; shows a "thinking" spinner until the first token so a
  cold model never looks hung; renders answers as Markdown (proper code blocks and
  lists). In-chat commands added: `/models`, `/model <name>`, `/clear`, `/help`.
- **UI polish**: module screens now show the module's description, cleaner item
  layout, and a consistent grey footer/prompt across home and every module.

## [2.1.0] — 2026-07-25

### Added
- **AI Assistant module** (`A` on the home menu): chat, explain a command/error,
  suggest next steps, and analyze pasted output — streamed from a local **Ollama**
  backend by default, or any OpenAI-compatible endpoint. The API key is read from
  `OPENAI_API_KEY` and never stored on disk.
- **Auto-install**: missing Python dependencies are installed automatically on
  first run (skipped in the bundled exe). The AI module can also auto-install
  Ollama and pull a small model on demand.
- **Auto-build release workflow**: pushing a `v*` tag builds the Windows exe on a
  runner and publishes it as a release automatically.

## [2.0.1] — 2026-07-25

### Added
- Logo and three live terminal screenshots in the README.
- `tools/gen_screenshots.py` to regenerate those screenshots.
- Continuous integration (GitHub Actions): pyflakes lint + smoke tests on 3.11 / 3.12.

### Changed
- Redesigned the banner: clean, pure-ASCII **slant** wordmark rendered in grey.
  The old `ansi_shadow` font used Unicode block/box glyphs that rendered broken
  on terminals whose font lacked them.

### Fixed
- Leetspeak wordlist generator crashed every run (`str.maketrans` was given
  arguments of unequal length). Now uses a correct map (`Password123` → `P@55w0rd123`).
- Reverse DNS lookup no longer crashes on a hostname or malformed input (catches
  `OSError`, not just `herror`/`gaierror`).

## [2.0.0] — 2026-07-24

### Fixed
- `report()` crash across ~10 modules: the shared `SessionReport` instance was
  called like a function at ~65 sites. Added `SessionReport.__call__` so the
  Evasion, Hardware, IoT, Cloud, Network, Web, and Exploit modules stop crashing.
- Home-menu keys are now case-sensitive as intended, so `E`/`X`/`I`/`H` and `h`
  open their own modules (Evasion, Exploit Toolkit, IoT, Hardware, HTTP Interceptor)
  instead of being shadowed by their lowercase twins.
- Restored the Payload Arsenal dataset (`toolkit/arsenal.dat`, 71 payloads) that
  was missing, which had left the whole module dead.

### Added
- Last-resort error guard in the module dispatcher so a single tool can never
  crash the whole framework.
- PyInstaller build (`nullsec.spec`) producing a standalone `nullsec.exe` with a
  bundled icon, catalog, and payloads.
