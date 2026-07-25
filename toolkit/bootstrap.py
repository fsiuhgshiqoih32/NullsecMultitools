"""Ensure nullsec's Python dependencies are present, installing any that are
missing on first run.

Pure standard library, so it can run *before* rich / requests are imported.
Skipped inside the frozen exe (PyInstaller already bundles everything).
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys

# import-name -> pip requirement
_REQUIRED = {
    "rich": "rich>=13.0",
    "requests": "requests>=2.28",
    "pyfiglet": "pyfiglet>=0.8",
}
_OPTIONAL = {
    "cryptography": "cryptography>=41.0",
    "PIL": "pillow>=10.0",
    "dns": "dnspython>=2.4",
}


def _missing(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is None
    except (ImportError, ValueError):
        return True


def ensure() -> None:
    """Install any missing dependencies. Exits if a *required* one can't be had."""
    if getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS"):
        return  # bundled exe already ships everything

    missing_req = {m: p for m, p in _REQUIRED.items() if _missing(m)}
    missing_opt = {m: p for m, p in _OPTIONAL.items() if _missing(m)}
    to_install = list(missing_req.values()) + list(missing_opt.values())
    if not to_install:
        return

    print("nullsec: first-run setup - installing "
          f"{len(to_install)} package(s): {', '.join(to_install)}")
    base = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"]
    try:
        subprocess.call(base + ["--quiet", *to_install])
    except Exception as e:  # noqa: BLE001
        print(f"  install error: {e}")

    # If a required package still won't import, retry it verbosely, then give up.
    still = [m for m in missing_req if _missing(m)]
    if still:
        print("  retrying required packages...")
        subprocess.call(base + [_REQUIRED[m] for m in still])
        still = [m for m in still if _missing(m)]
    if still:
        print(f"nullsec: could not install required package(s): {', '.join(still)}.\n"
              "Install them manually:  pip install -r requirements.txt")
        sys.exit(1)
