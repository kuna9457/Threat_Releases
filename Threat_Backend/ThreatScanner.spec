# -*- mode: python ; coding: utf-8 -*-
# ThreatScanner.spec
#
# Builds TWO executables from a single spec:
#   - ThreatScanner.exe     (windowed GUI — CustomTkinter dashboard)
#   - ThreatScanner_CLI.exe (console CLI — original text-mode scanner)
#
# Both are collected into a single dist/ThreatScanner folder that Inno Setup
# will package into the installer.

# ── Common data / hidden imports shared by both executables ───────────────────
_shared_datas = [
    ('app/services/icici_logo_transparent.png', 'app/services'),
    ('.env', '.'),
    ('version.ini', '.'),
    ('assets/fonts/Mulish.ttf', 'assets/fonts'),
]

_shared_hiddenimports = [
    'customtkinter',
    'darkdetect',
    'PIL',
    'PIL._tkinter_finder',
    'app.utils.ssl_patch',
]

# ─────────────────────────────────────────────────────────────────────────────
# 1.  GUI executable (windowed, no console)
# ─────────────────────────────────────────────────────────────────────────────
gui = Analysis(
    ['gui_scanner.py'],
    pathex=[],
    binaries=[],
    datas=_shared_datas,
    hiddenimports=_shared_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
gui_pyz = PYZ(gui.pure)

gui_exe = EXE(
    gui_pyz,
    gui.scripts,
    [],
    exclude_binaries=True,
    name='ThreatScanner',           # → ThreatScanner.exe  (shortcuts point here)
    icon='..\\Installer\\app_icon.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,                  # windowed — no black terminal box
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    contents_directory='.',
)

# ─────────────────────────────────────────────────────────────────────────────
# 2.  CLI executable (console)
# ─────────────────────────────────────────────────────────────────────────────
cli = Analysis(
    ['cli_scanner.py'],
    pathex=[],
    binaries=[],
    datas=_shared_datas,
    hiddenimports=_shared_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
cli_pyz = PYZ(cli.pure)

cli_exe = EXE(
    cli_pyz,
    cli.scripts,
    [],
    exclude_binaries=True,
    name='ThreatScanner_CLI',       # → ThreatScanner_CLI.exe
    icon='..\\Installer\\app_icon.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,                   # keeps the terminal window open
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    contents_directory='.',
)

# ─────────────────────────────────────────────────────────────────────────────
# 3.  Collect both into one output folder: dist/ThreatScanner/
# ─────────────────────────────────────────────────────────────────────────────
coll = COLLECT(
    gui_exe,
    gui.binaries,
    gui.datas,
    cli_exe,
    cli.binaries,
    cli.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='ThreatScanner',
)
