"""
SecretSpace-Server.exe -- the Windows sync server itself.

The startup task runs it with the settings SecretSpace-Server-Setup.exe chose:

    SecretSpace-Server.exe --host ... --port ... --store ... --token-file ...

To change the network, the port or the token, use SecretSpace-Server-Setup.exe
(Start Menu -> SecretSpace Server). This program still accepts the setup
commands (setup, new-token, show-token, remove) and hands them over, because
an installation made before the two were split uninstalls with
`SecretSpace-Server.exe remove`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import secretspace_setup                                            # noqa: E402
import secretspace_server                                           # noqa: E402
from version import __version__                                     # noqa: E402

# Built, there is no version.py beside the server for it to read.
secretspace_server.SERVER_VERSION = __version__

USAGE = ("This is the server that the startup task runs. To change its "
         "network, port or token, run SecretSpace-Server-Setup.exe (Start Menu "
         "-> SecretSpace Server).")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        # Double-clicked: say what it is instead of failing for lack of a
        # token in a window that closes at once.
        print("SecretSpace sync server.\n\n" + USAGE)
        input("\nPress Enter to close this window.")
        return
    # No server option takes a value that is also a command name.
    if any(a in secretspace_setup.COMMANDS for a in argv):
        if getattr(sys, "frozen", False) \
                and not secretspace_setup.is_admin("windows"):
            if not secretspace_setup.relaunch_as_admin(argv):
                sys.exit("This needs administrator rights.")
            return
        secretspace_setup.main(argv)
        return
    secretspace_server.main(argv)


if __name__ == "__main__":
    main()
