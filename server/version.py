"""
Single source of truth for the server's version.

Read by build_version.py for the exe's Properties > Details, and by the
builder, which passes it to Inno Setup for the installer. Bump it on
release.
"""

__version__ = "2.2.0"
