# -*- mode: python ; coding: utf-8 -*-
# Build a standalone, self-contained nullsec.exe:  pyinstaller nullsec.spec --clean --noconfirm
# The icon and data file are referenced by relative path, so this builds on any
# machine with the repo checked out — no dependency on files outside the project.

TOOLKIT_MODULES = [
    'toolkit', 'toolkit.adattacks', 'toolkit.ai', 'toolkit.arsenal', 'toolkit.bootstrap',
    'toolkit.bruteforce', 'toolkit.elevate', 'toolkit.toolbox',
    'toolkit.catalog', 'toolkit.catalog_data', 'toolkit.cloud', 'toolkit.crypto',
    'toolkit.cryptotools', 'toolkit.database', 'toolkit.detect',
    'toolkit.email_analyzer', 'toolkit.evasion', 'toolkit.offense',
    'toolkit.extractor', 'toolkit.forensics', 'toolkit.generators',
    'toolkit.hardware', 'toolkit.hashes', 'toolkit.installer',
    'toolkit.interceptor', 'toolkit.iot', 'toolkit.lolbins', 'toolkit.metadata',
    'toolkit.mobile', 'toolkit.network', 'toolkit.osint', 'toolkit.passwords',
    'toolkit.payloadenc', 'toolkit.postex', 'toolkit.recipe', 'toolkit.recon',
    'toolkit.proxy', 'toolkit.reversing', 'toolkit.smb', 'toolkit.stego',
    'toolkit.vulnscan', 'toolkit.web', 'toolkit.wireless', 'toolkit.wordlists',
    'toolkit.workspace',
]

# Optional libraries the toolkit imports lazily (via need_lib / importlib), so
# PyInstaller's static scan can miss them. Naming them here guarantees the exe
# ships with the crypto lab and PNG/EXIF stego features working out of the box.
OPTIONAL_LIBS = [
    'cryptography', 'cryptography.hazmat.primitives.padding',
    'cryptography.hazmat.primitives.ciphers',
    'PIL', 'PIL.Image', 'PIL.ExifTags',
    'pyfiglet',
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('data\\tools.json', 'data'), ('toolkit\\arsenal.dat', 'toolkit'),
           ('wordlists\\top-1million-passwords.txt', 'wordlists'),
           ('data\\proxies.txt', 'data')],
    hiddenimports=TOOLKIT_MODULES + OPTIONAL_LIBS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='nullsec',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX packing trips more AV engines and isn't installed here anyway
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['nullsec.ico'],
)
