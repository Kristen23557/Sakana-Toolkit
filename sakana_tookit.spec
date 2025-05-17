# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['sakana_tookit.py'],
    pathex=[],
    binaries=[],
    datas=[('localization/*.json', 'localization'), ('plugins/*.py', 'plugins')],
    hiddenimports=['tkinter', 'json', 'os', 'sys', 'locale', 'datetime', 'importlib', 'inspect', 'random', 'string'],
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
    name='sakana_tookit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'],
)
