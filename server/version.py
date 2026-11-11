"""
Single source of truth for the Windows server's version.

Read by build_version.py for the exe's Properties > Details, and by the
builder, which passes it to Inno Setup for the installer. Bump it on release
and tag the release commit v<version>. It started at 1.0.0 and is separate
from the app's and from the Linux server's.

A test version carries a pre-release tag, ``2.0.0-alpha.2``.
"""

import re

__version__ = "2.0.0-alpha.3"

_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-(?:alpha|beta|rc)\.(\d+))?")


def file_version(text: str = __version__) -> tuple:
    """
    The four plain numbers Windows wants for a file version: (2, 0, 0, 2)
    for '2.0.0-alpha.2', (2, 0, 0, 0) for '2.0.0'. The same rule as the
    client's version.file_version.
    """
    m = _VERSION.fullmatch(text)
    if not m:
        raise ValueError(f"Not a SecretSpace version: {text!r}")
    return tuple(int(g or 0) for g in m.groups())
