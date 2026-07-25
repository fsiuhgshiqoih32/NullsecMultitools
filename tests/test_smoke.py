"""Smoke tests: verify every module imports and is wired correctly.

nullsec wires its whole UI by hand (per-module MENU dicts + a home grid in
main.py). These tests catch the easy mistakes as new tools are added:
a bad MENU entry, a duplicate home key, or a GROUPS key with no module.

Run from the project root:  python -m pytest -q tests/
"""
from __future__ import annotations

import os
import sys

# Make the project root importable no matter where pytest is invoked from.
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import main  # noqa: E402
import toolkit  # noqa: E402


def test_version_is_string():
    assert isinstance(toolkit.__version__, str) and toolkit.__version__


def test_every_category_menu_is_valid():
    for key, (name, menu, desc) in main.CATEGORIES.items():
        assert isinstance(menu, dict) and menu, f"{key} ({name}) has an empty MENU"
        assert isinstance(desc, str) and desc, f"{key} ({name}) missing description"
        for mk, entry in menu.items():
            assert isinstance(entry, tuple) and len(entry) == 2, \
                f"{name}:{mk} is not a (label, fn) tuple"
            label, fn = entry
            assert isinstance(label, str) and label, f"{name}:{mk} has no label"
            assert callable(fn), f"{name}:{mk} target is not callable"


def test_home_keys_are_unique():
    keys = list(main.CATEGORIES) + list(main.SYSTEM_ITEMS)
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, f"duplicate home keys: {dupes}"


def test_groups_reference_real_keys():
    valid = set(main.CATEGORIES) | set(main.SYSTEM_ITEMS)
    for title, _colour, keys in main.GROUPS:
        for k in keys:
            assert k in valid, f"GROUPS section {title!r} references unknown key {k!r}"


def test_category_deps_reference_real_categories():
    for key in main.CATEGORY_DEPS:
        assert key in main.CATEGORIES, f"CATEGORY_DEPS has unknown category {key!r}"


def test_report_shorthand_is_callable():
    """~60 module call sites use ``report("Category", "detail")`` as a quick
    logger. The shared reporter must support that call form (not just .log()),
    or those menu actions raise TypeError and crash the app mid-use.
    """
    from toolkit.utils import SessionReport

    r = SessionReport()
    assert callable(r), "report() shorthand missing — module call sites crash"
    r("Test category", "one-line detail")
    r("Multi", "title", "line 1", "line 2")
    assert len(r.entries) == 2
    assert r.entries[0].category == "Test category"
    assert r.entries[0].title == "one-line detail"
    assert r.entries[1].lines == ["line 1", "line 2"]


def test_every_category_is_reachable_by_its_key():
    """Every home key must open its OWN module. Regression guard for the
    case-folding bug where 'E' (Evasion) opened 'e' (Reversing), and the 'h'
    help alias shadowed the HTTP Interceptor module.
    """
    for key in main.CATEGORIES:
        assert main.resolve_category(key) == key, \
            f"key {key!r} does not resolve to itself (case collision?)"


def test_command_words_do_not_shadow_categories():
    """The reserved command words must not resolve to a category key."""
    for word in ("q", "quit", "exit", "help", "?", "r", "t", "version", "search", "use"):
        # multi-char words never match a single-char key; single-char r/t must
        # not be category keys (they're system items)
        assert word not in main.CATEGORIES, f"command word {word!r} collides with a category key"


def test_arsenal_payloads_are_loaded():
    """The Payload Arsenal loads its shells from toolkit/arsenal.dat. If that
    data file is missing the whole module goes dead (every submenu shows an
    'antivirus quarantined it' notice) and payload_count() drops to 0.
    """
    from toolkit import arsenal

    assert not arsenal._MISSING, "arsenal.dat failed to load — Payload Arsenal is dead"
    assert arsenal.payload_count() >= 25, \
        f"expected 25+ payloads, got {arsenal.payload_count()}"
    # reverse shells must carry the runtime placeholders
    assert "{LHOST}" in arsenal.REVERSE_SHELLS["bash -i"]
    # msfvenom entries must be (payload, fmt, outfile) tuples
    for name, entry in arsenal.MSFVENOM.items():
        assert isinstance(entry, tuple) and len(entry) == 3, f"bad msf entry: {name}"


def test_catalog_tools_are_well_formed():
    from toolkit import catalog
    tools = catalog.all_tools()
    assert len(tools) > 100
    for t in tools[:2000]:
        assert len(t) == 5, f"catalog entry not a 5-tuple: {t!r}"
        name, cat, desc, install, _binary = t
        assert name and cat and desc and install


if __name__ == "__main__":
    # Allow running without pytest:  python tests/test_smoke.py
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"[ok]   {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"[FAIL] {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} checks passed.")
    sys.exit(1 if failures else 0)
