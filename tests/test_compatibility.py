"""The README's Compatibility table says what the code does.

This file is the same in all four SecretSpace repositories (compare with
cmp), and so is the section it checks: SECTION_SHA256 makes an edit to one
README fail until the section, and this file, are changed everywhere.
"""

import hashlib
import os
import re
import sys

import pytest

SECTION_SHA256 = "999e4fc0bdadac4ccab0c7f2647caf754cae7e47c60f4928f4f348c223a84be0"


def _root():
    here = os.path.dirname(os.path.abspath(__file__))
    while not os.path.isfile(os.path.join(here, "README.md")):
        here, before = os.path.dirname(here), here
        assert here != before, "no README.md above this test"
    return here


ROOT = _root()
CLIENT = os.path.isfile(os.path.join(ROOT, "sourceFiles", "gui.py"))
SOURCE = os.path.join(ROOT, "sourceFiles" if CLIENT else "server")


def _read(*path):
    with open(os.path.join(*path), encoding="utf-8") as f:
        return f.read()


def _section():
    text = _read(ROOT, "README.md")
    start = text.index("<!-- compatibility:start")
    end = text.index("<!-- compatibility:end -->")
    return text[start:end] + "<!-- compatibility:end -->\n"


def _rows():
    rows = []
    for line in _section().splitlines():
        cells = [c.strip() for c in line.strip("|").split("|")]
        if line.startswith("|") and len(cells) == 4 and \
                re.match(r"\d", cells[0]):
            rows.append(cells)
    return rows


def _covers(cell, major, minor):
    """Does "4.6 and newer", "4.0 \u2013 4.2", "4.5" or "3.x" hold this version?"""
    if cell.endswith(".x"):
        return major == int(cell[:-2])
    numbers = [tuple(map(int, n)) for n in re.findall(r"(\d+)\.(\d+)", cell)]
    if not numbers:
        return False
    if cell.endswith("and newer"):
        return (major, minor) >= numbers[0]
    return numbers[0] <= (major, minor) <= numbers[-1]


def _own_version():
    found = re.search(r'^__version__ = "(\d+)\.(\d+)\.(\d+)',
                      _read(SOURCE, "version.py"), re.M)
    return tuple(map(int, found.groups()))


def test_the_section_is_the_one_in_the_other_repositories():
    assert hashlib.sha256(_section().encode()).hexdigest() == SECTION_SHA256


@pytest.mark.parametrize("cell, version, want", [
    ("4.6 and newer", (4, 6), True), ("4.6 and newer", (5, 0), True),
    ("4.6 and newer", (4, 5), False), ("4.5", (4, 5), True),
    ("4.5", (4, 6), False), ("4.0 \u2013 4.2", (4, 1), True),
    ("4.0 \u2013 4.2", (4, 3), False), ("3.x", (3, 9), True),
    ("3.x", (4, 0), False), ("\u2013", (4, 3), False)])
def test_reading_a_cell(cell, version, want):
    assert _covers(cell, *version) is want


def test_every_version_is_in_at_most_one_row():
    rows = _rows()
    assert len(rows) >= 7
    for column in (0, 1):
        for major in range(0, 7):
            for minor in range(0, 30):
                hits = [r for r in rows if _covers(r[column], major, minor)]
                assert len(hits) <= 1, (column, major, minor)


@pytest.mark.skipif(not CLIENT, reason="an app's check")
def test_this_app_is_in_the_table_with_the_server_it_asks_for():
    major, minor, _ = _own_version()
    column = 0 if os.path.isdir(os.path.join(ROOT, "installer")) else 1
    row = [r for r in _rows() if _covers(r[column], major, minor)]
    assert len(row) == 1, "this version has no row"
    code = _read(SOURCE, "account_sync.py")
    needs = re.search(r'^MIN_SERVER = "([\d.]+)"', code, re.M).group(1)
    assert row[0][2] == needs
    assert "{MIN_SERVER} or newer" in code          # what the user is told


@pytest.mark.skipif(CLIENT, reason="a server's check")
def test_this_server_serves_every_row_of_the_table():
    own = _own_version()
    needs = [tuple(map(int, r[2].split("."))) for r in _rows()
             if r[2] != "any"]
    assert needs and max(needs) <= own
    sys.path.insert(0, SOURCE)
    import secretspace_server
    assert secretspace_server.LEGACY_VAULT_MAGIC == b"PMV3"   # 3.x / 1.x
    code = _read(SOURCE, "secretspace_server.py")
    assert '"api": [1, 2]' in code and '"format-2"' in code
