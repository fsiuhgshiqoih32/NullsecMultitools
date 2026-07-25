# Changelog

All notable changes to nullsec are documented here.
This project loosely follows [Semantic Versioning](https://semver.org/).

## [0.3.1] — 2026-07-25

### Changed
- **AI is faster and clearer**: auto-picks the smallest (fastest) installed model
  instead of the first one; shows a "thinking" spinner until the first token so a
  cold model never looks hung; renders answers as Markdown (proper code blocks and
  lists). In-chat commands added: `/models`, `/model <name>`, `/clear`, `/help`.
- **UI polish**: module screens now show the module's description, cleaner item
  layout, and a consistent grey footer/prompt across home and every module.

## [0.3.0] — 2026-07-25

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
