"""
Build PassMan-Server-Installer.exe from the source, after checking every
prerequisite:

    py builder\\build.py                      check, then build
    py builder\\build.py --install-missing    install what is missing first

The server is standard library only, so the build needs Python, PyInstaller
and Inno Setup 6 and nothing else. Everything here is plain functions over
an injectable command runner, so the tests can check every decision without
starting a single process. The app (PassMan-Client-Installer.exe) is built
from its own repository, PassMan-Client-Windows.
"""

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

#: Files the build reads. If one is missing, the folder is incomplete.
REQUIRED_FILES = (
    os.path.join("server", "passman_server.py"),
    os.path.join("server", "passman_setup.py"),
    os.path.join("server", "passman_server_exe.py"),
    os.path.join("server", "passman_server_setup_exe.py"),
    os.path.join("server", "PassMan-Server.spec"),
    os.path.join("server", "version.py"),
    os.path.join("server", "build_version.py"),
    os.path.join("server", "PassMan-logo.ico"),
    os.path.join("installer", "PassMan-Server.iss"),
)

#: winget packages for what pip cannot install.
WINGET_PYTHON = "Python.Python.3.13"
WINGET_INNO = "JRSoftware.InnoSetup"


# ---------------------------------------------------------------------------
# Running commands
# ---------------------------------------------------------------------------
@dataclass
class Result:
    code: int
    output: str = ""


def run(cmd, cwd=None, env=None, on_line=None) -> Result:
    """
    Run ``cmd`` and return its exit code and combined output. With
    ``on_line``, each output line is passed on as it arrives, so a long
    PyInstaller run shows progress instead of looking frozen.
    """
    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace")
    except OSError as e:                       # e.g. "py" is not installed
        return Result(127, str(e))
    lines = []
    for line in proc.stdout:
        line = line.rstrip("\r\n")
        lines.append(line)
        if on_line:
            on_line(line)
    return Result(proc.wait(), "\n".join(lines))


# ---------------------------------------------------------------------------
# Where things are
# ---------------------------------------------------------------------------
def project_dir() -> str:
    """The repository folder: the parent of builder/ where this file lives."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def missing_files(project: str) -> list:
    return [f for f in REQUIRED_FILES
            if not os.path.isfile(os.path.join(project, f))]


def app_version(project: str) -> str:
    """__version__ from server/version.py, read as text."""
    path = os.path.join(project, "server", "version.py")
    with open(path, encoding="utf-8") as f:
        match = re.search(r'^__version__\s*=\s*"([^"]+)"', f.read(), re.M)
    if not match:
        raise ValueError(f"No __version__ in {path}")
    return match.group(1)


def iscc_candidates() -> list:
    """Where Inno Setup 6 installs its compiler, per-user first."""
    out = []
    for var in ("LOCALAPPDATA", "ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(var)
        if base:
            sub = "Programs" if var == "LOCALAPPDATA" else ""
            out.append(os.path.join(base, sub, "Inno Setup 6", "ISCC.exe"))
    return out


def find_iscc(exists=os.path.isfile):
    return next((p for p in iscc_candidates() if exists(p)), None)


# A Python that can build: any real CPython 3. The newest launcher-registered
# one is preferred; a bare "python" on PATH comes last because it is often a
# virtualenv or the Microsoft Store placeholder (which exits with an error,
# so it is rejected by the probe rather than by name).
PYTHON_CANDIDATES = (["py", "-3"], ["python"], ["python3"])

_PROBE = "import sys; print(sys.version.split()[0]); print(sys.executable)"


@dataclass
class Python:
    cmd: list
    version: str
    executable: str


def find_python(runner=run):
    for cmd in PYTHON_CANDIDATES:
        res = runner(cmd + ["-c", _PROBE])
        lines = res.output.strip().splitlines()
        if res.code == 0 and len(lines) >= 2 and lines[0].startswith("3."):
            return Python(cmd, lines[0], lines[1])
    return None


# ---------------------------------------------------------------------------
# The checklist
# ---------------------------------------------------------------------------
@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    #: How to fix it: None (nothing to do), "pip", "winget-python",
    #: "winget-inno" or "manual" (detail says what to do).
    fix: str = None
    #: For "pip": the pip names to install.
    packages: list = field(default_factory=list)


def check_all(project: str, runner=run, find_iscc=find_iscc) -> list:
    """
    Every prerequisite, in the order the build needs them. Checks after a
    missing Python are reported as not checked rather than as failures:
    they cannot be known until Python is there.
    """
    checks = []
    gone = missing_files(project)
    checks.append(Check(
        "Server source files", not gone,
        "all present" if not gone else
        "missing: " + ", ".join(gone) + ". Copy the whole project folder.",
        None if not gone else "manual"))

    py = find_python(runner)
    if py is None:
        checks.append(Check("Python 3", False, "not found", "winget-python"))
        for name in ("PyInstaller", "The server imports cleanly"):
            checks.append(Check(name, False, "needs Python first"))
    else:
        checks.append(Check("Python 3", True,
                            f"{py.version}  ({py.executable})"))
        pyi = runner(py.cmd + ["-c", "import PyInstaller"]).code == 0
        checks.append(Check("PyInstaller", pyi,
                            "ok" if pyi else "missing",
                            None if pyi else "pip",
                            [] if pyi else ["pyinstaller"]))

        # PyInstaller does NOT fail on a missing module -- it builds an exe
        # that crashes on launch -- so prove both programs import first.
        if not gone:
            src = os.path.join(project, "server")
            imp = runner(py.cmd + ["-c", "import sys; sys.path.insert(0, "
                                   f"{src!r}); import passman_server_exe, "
                                   "passman_server_setup_exe"])
            last = imp.output.strip().splitlines()[-1:] or [""]
            checks.append(Check(
                "The server imports cleanly", imp.code == 0,
                "ok" if imp.code == 0 else last[0],
                None if imp.code == 0 else "manual"))
        else:
            checks.append(Check("The server imports cleanly", False,
                                "needs the files first"))

    iscc = find_iscc()
    checks.append(Check("Inno Setup 6 (for the installer)", bool(iscc),
                        iscc or "not found", None if iscc else "winget-inno"))
    return checks


def can_build(checks) -> bool:
    return all(c.ok for c in checks)


def fix_commands(checks, project: str, py: "Python" = None) -> list:
    """The commands that would fix the failing checks, as (label, cmd)."""
    out = []
    winget = ["winget", "install", "--exact", "--scope", "user",
              "--accept-package-agreements", "--accept-source-agreements",
              "--disable-interactivity", "--id"]
    for c in checks:
        if c.ok or not c.fix:
            continue
        if c.fix == "winget-python":
            out.append(("Install Python 3.13", winget + [WINGET_PYTHON]))
        elif c.fix == "winget-inno":
            out.append(("Install Inno Setup 6", winget + [WINGET_INNO]))
        elif c.fix == "pip" and py is not None:
            out.append((f"Install {', '.join(c.packages)}",
                        py.cmd + ["-m", "pip", "install"] + c.packages))
    return out


def manual_steps(checks) -> list:
    return [f"{c.name}: {c.detail}" for c in checks
            if not c.ok and c.fix == "manual"]


# ---------------------------------------------------------------------------
# The build
# ---------------------------------------------------------------------------
def remove_previous(project: str) -> None:
    """Delete the old outputs first, so a failed build cannot look like a
    successful one because last time's files are still there."""
    import shutil
    path = os.path.join(project, "PassMan-Server-Installer.exe")
    if os.path.exists(path):
        os.remove(path)
    folder = os.path.join(project, "build", "server", "PassMan-Server")
    if os.path.isdir(folder):
        shutil.rmtree(folder)


def build_steps(project: str, py: "Python", iscc: str, version: str) -> list:
    """The commands, as (label, cmd, the file it must produce): the server's
    folder build, then its installer."""
    return [
        ("Building the server",
         py.cmd + ["-m", "PyInstaller", "--noconfirm",
                   "--distpath", os.path.join(project, "build", "server"),
                   "--workpath", os.path.join(project, "build",
                                              "server-work"),
                   os.path.join(project, "server", "PassMan-Server.spec")],
         os.path.join(project, "build", "server", "PassMan-Server",
                      "PassMan-Server.exe")),
        ("Packing PassMan-Server-Installer.exe",
         [iscc, "/Q", f"/DAppVersion={version}",
          os.path.join(project, "installer", "PassMan-Server.iss")],
         os.path.join(project, "PassMan-Server-Installer.exe")),
    ]


def build(project: str, py: "Python", iscc: str, log=print, runner=run,
          exists=os.path.isfile) -> bool:
    """Run the build, logging as it goes. True when every output exists."""
    version = app_version(project)
    log(f"PassMan Server {version}")
    remove_previous(project)
    for label, cmd, product in build_steps(project, py, iscc, version):
        log("")
        log(label + "...")
        res = runner(cmd, cwd=project, on_line=log)
        if res.code != 0 or not exists(product):
            log("")
            log(f"FAILED: {label} (exit code {res.code}). "
                "The messages above give the reason.")
            return False
    log("")
    log(f"DONE. Version {version}: PassMan-Server-Installer.exe")
    return True


# ---------------------------------------------------------------------------
# Terminal use:  py builder\build.py [--install-missing]
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    project = project_dir()
    checks = check_all(project)
    for c in checks:
        print(f"  [{'x' if c.ok else ' '}] {c.name}: {c.detail}")
    if not can_build(checks):
        fixes = fix_commands(checks, project, find_python())
        if "--install-missing" in argv and fixes:
            for label, cmd in fixes:
                print(f"\n{label}...")
                run(cmd, on_line=print)
            return main([a for a in argv if a != "--install-missing"])
        print("\nNot everything the build needs is here.")
        for label, cmd in fixes:
            print(f"  {label}:  {subprocess.list2cmdline(cmd)}")
        for step in manual_steps(checks):
            print(f"  {step}")
        if fixes:
            print("\nRun again with --install-missing to install them.")
        return 1
    return 0 if build(project, find_python(), find_iscc()) else 1


if __name__ == "__main__":
    sys.exit(main())
