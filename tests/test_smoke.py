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


def test_builtin_tools_produce_correct_output():
    """Drive a sample of pure-Python tools with known inputs and assert the
    output is actually correct — not merely crash-free. Guards against silent
    breakage (e.g. a hash column truncating, a decoder returning garbage).
    """
    from unittest import mock
    from toolkit import utils, hashes, crypto, cryptotools, toolbox, passwords

    def drive(fn, inputs):
        it = iter(inputs)
        ask = lambda *a, **k: (next(it, str(k.get("default", ""))))  # noqa: E731
        with mock.patch("rich.prompt.Prompt.ask", side_effect=ask), \
             mock.patch.object(utils.console, "input", side_effect=ask), \
             mock.patch("builtins.input", side_effect=ask):
            with utils.console.capture() as cap:
                fn()
        return cap.get().lower()

    checks = [
        (hashes.calculate, ["t", "abc"], "900150983cd24fb0d6963f7d28e17f72"),
        (hashes.calculate, ["t", "abc"],
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),  # full sha256
        (crypto.multi_decode, ["aGVsbG8="], "hello"),
        (crypto.rot_n, ["Uryyb", "13"], "hello"),
        (cryptotools.morse_tool, ["d", ".... . .-.. .-.. ---"], "hello"),
        (toolbox.subnet_calc, ["10.0.0.0/24"], "10.0.0.255"),
    ]
    for fn, inputs, expected in checks:
        out = drive(fn, inputs)
        assert expected.lower() in out, f"{fn.__name__}({inputs}) missing {expected!r}"

    # the bundled top-1M list powers the breach check (skip if not present)
    if passwords.bundled_wordlist():
        assert "#1" in drive(passwords.breach_check, ["123456"])


def test_cipher_cores_survive_edge_inputs():
    """Cipher breakers/transposers must not crash on short or degenerate input
    (regression: Vigenere < 6 letters, rail fence with < 2 rails)."""
    from toolkit import cryptotools as C

    for ct in ("", "A", "AB", "HELLO", "LXFOPVEFRNHR"):
        C.crack_vigenere(ct)  # must not raise
    for rails in (0, 1, 2, 3):
        C._rail_encode("HELLO", rails)
        C._rail_decode("HELLO", rails)
    # rail fence still round-trips for valid rails
    assert C._rail_decode(C._rail_encode("HELLOWORLD", 3), 3) == "HELLOWORLD"
    # repeating-key XOR recovers a known key
    key = b"KEY"
    pt = b"attack at dawn from the north ridge before sunrise today"
    ct = bytes(c ^ key[i % 3] for i, c in enumerate(pt))
    assert C.crack_repeating_xor(ct)[2] == pt


def test_vpn_write_config_handles_auth(tmp_path=None):
    """Writing a VPNBook config (auth-user-pass) must inject the auth-file path
    without choking on Windows backslashes in the regex replacement."""
    import os
    import tempfile
    from toolkit import vpn

    s = vpn.VPNServer(
        host="us16.vpnbook.com", ip="us16.vpnbook.com", country="United States",
        cc="US", ping="?", speed=0, sessions="-", uptime_ms="0",
        config_b64=__import__("base64").b64encode(
            b"client\nremote us16.vpnbook.com 443\nauth-user-pass\ncipher AES-256-GCM\n"
        ).decode(),
        source="vpnbook", username="vpnbook", password="secret123")
    cwd = os.getcwd()
    os.chdir(tempfile.mkdtemp())
    try:
        p = vpn._write_config(s)
        assert p is not None and p.exists()
        text = p.read_text(encoding="utf-8")
        assert 'auth-user-pass "' in text          # path was injected
        assert p.with_suffix(".auth").read_text().startswith("vpnbook\n")
    finally:
        os.chdir(cwd)


def test_catalog_tools_are_well_formed():
    from toolkit import catalog
    tools = catalog.all_tools()
    assert len(tools) > 100
    for t in tools[:2000]:
        assert len(t) == 5, f"catalog entry not a 5-tuple: {t!r}"
        name, cat, desc, install, _binary = t
        assert name and cat and desc and install


def test_workspace_menu_is_valid():
    from toolkit import workspace
    assert isinstance(workspace.MENU, dict) and workspace.MENU
    for k, (label, fn) in workspace.MENU.items():
        assert isinstance(label, str) and label, f"workspace:{k} has no label"
        assert callable(fn), f"workspace:{k} target is not callable"


def test_workspace_create_save_load_delete():
    from toolkit import workspace
    ws = workspace.Workspace(name="_test_ws", target="10.0.0.1", operator="tester")
    ws.add_note("test note")
    ws.add_finding("recon", "port scan", ["- 22 open", "- 80 open"], "12:00:00")
    path = ws.save()
    assert path.is_file(), "workspace file not created"

    loaded = workspace.Workspace.load("_test_ws")
    assert loaded is not None, "workspace failed to load"
    assert loaded.name == "_test_ws"
    assert loaded.target == "10.0.0.1"
    assert loaded.operator == "tester"
    assert len(loaded.notes) == 1
    assert loaded.notes[0].text == "test note"
    assert len(loaded.findings) == 1
    assert loaded.findings[0].category == "recon"

    md = loaded.as_markdown()
    assert "_test_ws" in md and "port scan" in md and "test note" in md

    assert loaded.delete(), "workspace file not deleted"
    assert not path.is_file(), "workspace file still exists after delete"


def test_report_forwards_to_active_workspace():
    from toolkit import workspace
    from toolkit.utils import SessionReport

    r = SessionReport()
    ws = workspace.Workspace(name="_test_fwd")
    r.active_workspace = ws
    r.log("recon", "test finding", ["- line 1"])
    r("web", "headers checked")
    assert len(ws.findings) == 2
    assert ws.findings[0].category == "recon"
    assert ws.findings[0].title == "test finding"
    assert ws.findings[1].category == "web"
    r.active_workspace = None


def test_proxy_menu_is_valid():
    from toolkit import proxy
    assert isinstance(proxy.MENU, dict) and proxy.MENU
    for k, (label, fn) in proxy.MENU.items():
        assert isinstance(label, str) and label, f"proxy:{k} has no label"
        assert callable(fn), f"proxy:{k} target is not callable"


def test_proxy_parsing_all_formats():
    from toolkit import proxy

    # ip:port -> http
    p = proxy.parse_proxy("1.2.3.4:8080")
    assert p is not None and p.scheme == "http" and p.host == "1.2.3.4" and p.port == 8080
    assert p.url == "http://1.2.3.4:8080"

    # ip:port:user:pass -> http with auth
    p = proxy.parse_proxy("1.2.3.4:8080:admin:secret")
    assert p is not None and p.username == "admin" and p.password == "secret"
    assert "admin:secret@" in p.url

    # http://ip:port
    p = proxy.parse_proxy("http://10.0.0.1:3128")
    assert p is not None and p.scheme == "http" and p.port == 3128

    # socks5://ip:port
    p = proxy.parse_proxy("socks5://10.0.0.2:1080")
    assert p is not None and p.scheme == "socks5" and p.port == 1080

    # socks5://user:pass@ip:port
    p = proxy.parse_proxy("socks5://user:pwd@10.0.0.3:1080")
    assert p is not None and p.username == "user" and p.password == "pwd"

    # invalid entries
    assert proxy.parse_proxy("") is None
    assert proxy.parse_proxy("# comment") is None
    assert proxy.parse_proxy("not_a_proxy") is None
    assert proxy.parse_proxy("1.2.3.4:99999") is None


def test_proxy_manager_add_remove_clear():
    from toolkit import proxy
    mgr = proxy.ProxyManager()
    assert mgr.add("1.2.3.4:8080")
    assert mgr.add("socks5://5.6.7.8:1080")
    assert len(mgr.proxies) == 2
    assert mgr.remove(0)
    assert len(mgr.proxies) == 1
    assert mgr.proxies[0].scheme == "socks5"
    mgr.clear()
    assert len(mgr.proxies) == 0


def test_proxy_rotation():
    from toolkit import proxy
    mgr = proxy.ProxyManager()
    for i in range(5):
        mgr.add(f"10.0.0.{i}:8080")
    # round-robin: should cycle through all 5
    seen = set()
    for _ in range(5):
        entry = mgr.get_next()
        assert entry is not None
        seen.add(entry.host)
    assert len(seen) == 5  # all unique = proper round-robin
    # random mode should still return a valid proxy
    mgr.rotation = "random"
    entry = mgr.get_next()
    assert entry is not None and entry.host.startswith("10.0.0.")


def test_proxy_stats_and_get_proxy_helper():
    from toolkit import proxy
    from toolkit.utils import get_proxy

    # get_proxy returns None when disabled
    mgr = proxy.get_manager()
    mgr.clear()
    mgr.enabled = False
    assert get_proxy() is None

    # get_proxy returns dict when enabled with proxies
    mgr.add("1.2.3.4:8080")
    mgr.enabled = True
    result = get_proxy()
    assert result is not None and "http" in result and "https" in result
    mgr.enabled = False
    mgr.clear()


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
