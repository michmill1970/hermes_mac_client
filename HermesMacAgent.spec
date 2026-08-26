# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['websockets.asyncio.server', 'mss', 'pyautogui', 'HIServices', 'ApplicationServices']
hiddenimports += collect_submodules('hermes_mac_agent')


a = Analysis(
    ['hermes_mac_agent/menubar/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
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
    [],
    exclude_binaries=True,
    name='HermesMacAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='HermesMacAgent',
)
app = BUNDLE(
    coll,
    name='HermesMacAgent.app',
    icon=None,
    bundle_identifier='com.hermes.mac-agent',
)
