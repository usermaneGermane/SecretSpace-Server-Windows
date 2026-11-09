"""
The Windows version resource for PassMan-Server.exe and
PassMan-Server-Setup.exe -- what Explorer shows under Properties > Details.
Used by PassMan-Server.spec at build time only; the server never imports it,
so PyInstaller does not bundle it.

It reads version.py, so the exes and the installer (the builder passes the
same version to Inno Setup) can never disagree.
"""

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo,
    VarStruct, VSVersionInfo)

from version import __version__


def version_info(description="SecretSpace sync server",
                 filename="PassMan-Server.exe") -> VSVersionInfo:
    numbers = tuple(int(part) for part in __version__.split(".")) + (0,)
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=numbers, prodvers=numbers),
        kids=[
            StringFileInfo([StringTable("040904B0", [
                StringStruct("FileDescription", description),
                StringStruct("FileVersion", __version__),
                StringStruct("InternalName", filename[:-4]),
                StringStruct("OriginalFilename", filename),
                StringStruct("ProductName", "SecretSpace Server"),
                StringStruct("ProductVersion", __version__),
            ])]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )
