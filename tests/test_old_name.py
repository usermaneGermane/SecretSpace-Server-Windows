"""
The project was called PassMan until November 2026. The old name may stay
in exactly one kind of place in the program: a constant named ``LEGACY_...``
(a name that is only ever read, to move an older install or serve an older
app) and the sentence that introduces those constants. Anything else is a
leftover of the rename, and this test names the line.
"""

import os
import re

SERVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server")
OLD = re.compile(r"passman|PMV3|PMK3", re.IGNORECASE)
#: Prose that explains the constants; nothing a program acts on.
EXPLAINS = ("The project was called PassMan until November 2026",
            "PassMan: it gives the folders, the service, its user")


def leftovers():
    found = []
    for name in sorted(os.listdir(SERVER)):
        path = os.path.join(SERVER, name)
        if not os.path.isfile(path):
            continue
        if OLD.search(name):
            found.append(f"{name}: the file's own name")
        if not name.endswith((".py", ".service", ".spec")):
            continue                              # an icon, a cache
        with open(path, encoding="utf-8") as f:
            for number, line in enumerate(f, 1):
                if not OLD.search(line):
                    continue
                if re.match(r"\s*LEGACY_[A-Z_]+ = ", line):
                    continue
                if any(text in line for text in EXPLAINS):
                    continue
                found.append(f"{name}:{number}: {line.strip()}")
    return found


def test_the_old_name_is_only_in_the_legacy_constants():
    assert leftovers() == []


def test_the_legacy_constants_are_never_written_with():
    """They are read to find old things; what is written uses the current
    names. A legacy name on the left of a write is the mistake to catch."""
    writes = re.compile(r"(render_env\([^)]*LEGACY|"
                        r"headers\[[^\]]*LEGACY|"
                        r"environ\[[^\]]*LEGACY[^\]]*\]\s*=)")
    bad = []
    for name in sorted(os.listdir(SERVER)):
        if name.endswith(".py"):
            with open(os.path.join(SERVER, name), encoding="utf-8") as f:
                for number, line in enumerate(f, 1):
                    if writes.search(line):
                        bad.append(f"{name}:{number}: {line.strip()}")
    assert bad == []
