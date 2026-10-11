"""
Single source of truth for the Windows server's version.

Read by build_version.py for the exe's Properties > Details, and by the
builder, which passes it to Inno Setup for the installer. Bump it on release
and tag the release commit v<version>. It started at 1.0.0 and is separate
from the app's and from the Linux server's.
"""

__version__ = "1.1.1"
