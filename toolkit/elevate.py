"""Auto-elevate to Administrator on Windows and self-heal the environment.

Running as admin lets nullsec add a Windows Defender exclusion for its own folder
so the payload data files (arsenal.dat / gen_arsenal.py, which contain reverse-shell
strings) stop getting quarantined — the #1 reason "tools don't work" on Windows.

All of this is a no-op on Linux/macOS and skippable with NULLSEC_NO_ELEVATE=1.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path


def is_admin() -> bool:
    if os.name != "nt":
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def app_dir() -> Path:
    """Folder the app lives in (exe dir when frozen, else the source root)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def maybe_elevate() -> bool:
    """If on Windows and not admin, relaunch elevated via UAC.

    Returns True if a new elevated process was launched (the caller should exit).
    Returns False when already admin, elevation was declined/failed, disabled, or
    not on Windows — in which case the app keeps running in the current process.
    """
    if os.name != "nt" or is_admin() or os.environ.get("NULLSEC_NO_ELEVATE"):
        return False
    try:
        if getattr(sys, "frozen", False):
            exe, args = sys.executable, sys.argv[1:]
        else:
            exe, args = sys.executable, [os.path.abspath(sys.argv[0]), *sys.argv[1:]]
        params = subprocess.list2cmdline(args)
        workdir = str(app_dir())
        # ShellExecuteW returns >32 on success. SW_SHOWNORMAL = 1.
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, workdir, 1)
        return int(rc) > 32
    except Exception:
        return False  # declined UAC or any error -> just continue unelevated


def add_defender_exclusions() -> list[str]:
    """When admin on Windows, exclude our folder (and exe) from Defender scans.

    Returns the paths excluded (empty list if not applicable / it failed)."""
    if os.name != "nt" or not is_admin():
        return []
    targets = {str(app_dir())}
    if getattr(sys, "frozen", False):
        targets.add(sys.executable)
    done = []
    for t in targets:
        # ExclusionPath for folders, ExclusionProcess for the exe itself.
        pref = "ExclusionProcess" if t.lower().endswith(".exe") else "ExclusionPath"
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"Add-MpPreference -{pref} '{t}'"],
                capture_output=True, text=True, timeout=25)
            if r.returncode == 0:
                done.append(t)
        except Exception:
            pass
    return done


def heal_payload_data() -> bool:
    """Restore arsenal.dat if AV removed it (source checkout only). Returns True
    if the arsenal data is present afterwards."""
    root = app_dir()
    dat = root / "toolkit" / "arsenal.dat"
    if dat.is_file():
        return True
    if (root / ".git").exists():
        try:
            subprocess.run(["git", "-C", str(root), "restore",
                            "toolkit/arsenal.dat", "tools/gen_arsenal.py"],
                           capture_output=True, timeout=25)
        except Exception:
            pass
    return dat.is_file()


def auto_fix() -> None:
    """Best-effort environment repair, run once at startup after elevation."""
    if os.name != "nt" or not is_admin():
        return
    excluded = add_defender_exclusions()
    if excluded:
        # now that AV won't re-quarantine, restore any files it already took
        heal_payload_data()
