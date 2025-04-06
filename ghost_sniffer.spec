# -*- mode: python -*-
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# Special handling for problematic packages
def get_hidden_imports():
    imports = [
        'scapy.all',
        'scapy.arch',
        'scapy.arch.windows',
        'scapy.layers',
        'scapy.layers.inet',
        'scapy.layers.l2',
        'scapy.layers.http',
        'scapy.layers.dns',
        'scapy.sendrecv',
        'scapy.supersocket',
        'scapy.utils',
        'scapy.pipetool',
        'scapy.automaton',
        'customtkinter'
    ]
    return imports

def get_datas():
    datas = []
    for pkg in ['scapy', 'customtkinter']:
        datas += collect_all(pkg)[0]
    return datas

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=get_datas(),
    hiddenimports=get_hidden_imports(),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='GhostSniffer',
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
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='GhostSniffer',
)