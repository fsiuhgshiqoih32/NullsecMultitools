# Changelog

All notable changes to nullsec are documented here.
This project loosely follows [Semantic Versioning](https://semver.org/).

## [0.2.2] — 2026-07-25

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

## [0.2.1] — 2026-07-24

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
