"""
PassMan-Server-Setup.exe -- changes the Windows server's settings.

    PassMan-Server-Setup.exe               a menu of the below (double-click it)
    PassMan-Server-Setup.exe setup         network and port
    PassMan-Server-Setup.exe new-token     replace the token
    PassMan-Server-Setup.exe show-token    print the token
    PassMan-Server-Setup.exe remove        remove the task and firewall rule

It installs nothing and unpacks nothing: it rewrites
%ProgramData%\\PassMan Server\\sync.env, replaces the firewall rule and the
startup task, and restarts the server. Installing and upgrading the program
is PassMan-Server-Installer.exe's job, which runs this once at the end.

Every command needs administrator rights; started without them, it asks
Windows (the UAC prompt) to run it elevated, in a new window.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import passman_setup                                            # noqa: E402


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        # Double-clicked: the menu -- network and port, or the token. It
        # stays open until Close, so what it printed can be read.
        argv = ["menu"]
    wants_help = "-h" in argv or "--help" in argv
    if getattr(sys, "frozen", False) and not wants_help \
            and not passman_setup.is_admin("windows"):
        if not passman_setup.relaunch_as_admin(argv):
            sys.exit("This needs administrator rights.")
        return
    passman_setup.main(argv)


if __name__ == "__main__":
    main()
