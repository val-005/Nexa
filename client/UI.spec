# -*- mode: python ; coding: utf-8 -*-
import sys

a = Analysis(
    ['UI.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('privkey.key', '.'),
        ('message.db', '.'),
        # Pour l'icône système (déjà incluse pour macOS ou Windows)
        ('NexaIcon.icns', '.') if sys.platform == 'darwin' else ('NexaIcon.ico', '.') if sys.platform == 'win32' else ('NexaIcon.png', '.'),
        # Ajoute également NexaIcon.png pour Tkinter dans tous les cas
        ('NexaIcon.png', '.'),
    ],
    hiddenimports=[
        'websockets',
        'websockets.legacy',
        'websockets.legacy.client',
        'websockets.legacy.protocol',
        'coincurve._cffi_backend',
    ],
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
    name='NexaChat',
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
    icon=['NexaIcon.icns'] if sys.platform == 'darwin' else
         ['NexaIcon.ico'] if sys.platform == 'win32' else None,
)

if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='NexaChat.app',
        icon='NexaIcon.icns',
        bundle_identifier=None,
    )
