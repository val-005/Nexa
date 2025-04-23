# -*- mode: python ; coding: utf-8 -*-
import sys

datas = []
if sys.platform == 'darwin':
	datas.append(('Nexa.icns', '.'))
	datas.append(('Nexa.png', '.'))
elif sys.platform == 'win32':
	datas.append(('Nexa.ico', '.'))
	datas.append(('Nexa.png', '.'))
else:
	datas.append(('Nexa.png', '.'))

a = Analysis(
	['UI.py'],
	pathex=[],
	binaries=[],
	datas=datas,
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
	icon=['Nexa.icns'] if sys.platform == 'darwin' else ['Nexa.ico'] if sys.platform == 'win32' else None,
	)

if sys.platform == 'darwin':
	app = BUNDLE(
		exe,
		name='NexaChat.app',
		icon='Nexa.icns',
		bundle_identifier=None,
	)