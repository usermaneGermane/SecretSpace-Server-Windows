# -*- mode: python ; coding: utf-8 -*-
#
# The Windows server's program folder, which PassMan-Server-Installer.exe
# ships. Two console programs sharing one _internal\ folder:
#
#   PassMan-Server.exe        the server; the startup task runs it
#   PassMan-Server-Setup.exe  network, port and token; installs nothing
#
# A folder build, not a single file, because a scheduled task should not
# unpack itself to %TEMP% on every boot. Standard library only, so it is
# small. Built by builder\build.py.
import os
import sys

SERVER = SPECPATH
sys.path.insert(0, SERVER)
from build_version import version_info   # Properties > Details

ICON = [os.path.join(SERVER, 'PassMan-logo.ico')]
# Nothing graphical: keep the GUI toolkits out even if installed.
EXCLUDES = ['tkinter', 'customtkinter', 'PIL']


def program(script, name, description):
    a = Analysis([os.path.join(SERVER, script)], pathex=[SERVER],
                 excludes=EXCLUDES, noarchive=False, optimize=0)
    exe = EXE(PYZ(a.pure), a.scripts, [], exclude_binaries=True, name=name,
              debug=False, bootloader_ignore_signals=False, strip=False,
              upx=False, console=True, disable_windowed_traceback=False,
              argv_emulation=False, target_arch=None, codesign_identity=None,
              entitlements_file=None, icon=ICON,
              version=version_info(description, name + '.exe'))
    return a, exe


server_a, server_exe = program('passman_server_exe.py', 'PassMan-Server',
                               'PassMan sync server')
setup_a, setup_exe = program('passman_server_setup_exe.py',
                             'PassMan-Server-Setup',
                             'PassMan sync server setup')

coll = COLLECT(
    server_exe, setup_exe,
    server_a.binaries, server_a.datas,
    setup_a.binaries, setup_a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='PassMan-Server',
)
