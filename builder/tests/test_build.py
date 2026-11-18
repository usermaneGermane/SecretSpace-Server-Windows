"""The builder's decisions, with a fake command runner: no process starts."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import build                                                   # noqa: E402

PROJECT = build.project_dir()          # the real repo: its files all exist
PY_OUT = "3.13.5\nC:\\Python313\\python.exe"


class FakeRunner:
    """Answers commands from a table of (substring -> Result); records calls."""

    def __init__(self, answers=None, default=build.Result(0, "")):
        self.answers = answers or {}
        self.default = default
        self.calls = []

    def __call__(self, cmd, cwd=None, env=None, on_line=None):
        self.calls.append((cmd, env))
        text = " ".join(cmd)
        for needle, result in self.answers.items():
            if needle in text:
                return result
        return self.default


def healthy(**overrides):
    answers = {"import sys; print(sys.version": build.Result(0, PY_OUT)}
    answers.update(overrides)
    return FakeRunner(answers)


def checks_by_name(checks):
    return {c.name: c for c in checks}


def has_iscc():
    return r"C:\Inno\ISCC.exe"


# --- finding Python --------------------------------------------------------
def test_prefers_the_py_launcher():
    py = build.find_python(healthy())
    assert py.cmd == ["py", "-3"] and py.version == "3.13.5"


def test_skips_a_broken_candidate():
    runner = FakeRunner({"py -3": build.Result(1, "no"),
                         "python -c": build.Result(0, PY_OUT)})
    assert build.find_python(runner).cmd == ["python"]


def test_no_python_at_all():
    assert build.find_python(FakeRunner(default=build.Result(127, ""))) is None


def test_the_python_the_workflow_names_is_the_only_one_tried():
    exe = r"C:\hostedtoolcache\Python\3.13.5\x64\python.exe"
    runner = healthy()
    py = build.find_python(runner, environ={build.PYTHON_ENV: exe})
    assert py.cmd == [exe]
    assert [cmd[0] for cmd, _ in runner.calls] == [exe]


def test_a_named_python_that_fails_is_not_replaced_by_another():
    # Building with a different Python than the one asked for would be a
    # silent surprise; finding none makes the checklist say so instead.
    runner = FakeRunner({"broken.exe": build.Result(1, "no"),
                         "-c": build.Result(0, PY_OUT)})
    assert build.find_python(runner, environ={build.PYTHON_ENV: "broken.exe"}) is None


def test_the_licence_page_and_pictures_are_required():
    for name in ("LICENSE", os.path.join("installer", "licence-notice.txt"),
                 os.path.join("installer", "wizard-large-200.bmp"),
                 os.path.join("installer", "wizard-small-100.bmp")):
        assert name in build.REQUIRED_FILES


# --- the checklist ---------------------------------------------------------
def test_everything_present_means_ready():
    checks = build.check_all(PROJECT, healthy(), find_iscc=has_iscc)
    assert build.can_build(checks), [(c.name, c.detail) for c in checks]
    assert build.fix_commands(checks, PROJECT) == []


def test_the_server_needs_no_libraries_beyond_pyinstaller():
    """Standard library only: there is no requirements.txt to install."""
    checks = build.check_all(PROJECT, healthy(), find_iscc=has_iscc)
    assert [c.name for c in checks] == [
        "Server source files", "Python 3", "PyInstaller",
        "The server imports cleanly", "Inno Setup 6 (for the installer)"]


def test_missing_pyinstaller_is_its_own_install():
    runner = healthy(**{"import PyInstaller": build.Result(1, "")})
    checks = build.check_all(PROJECT, runner, find_iscc=has_iscc)
    [(label, cmd)] = build.fix_commands(checks, PROJECT,
                                        build.find_python(runner))
    assert cmd[-3:] == ["pip", "install", "pyinstaller"]


def test_without_python_the_rest_waits_and_winget_is_offered():
    runner = FakeRunner(default=build.Result(127, ""))
    checks = build.check_all(PROJECT, runner, find_iscc=has_iscc)
    by = checks_by_name(checks)
    assert by["Python 3"].fix == "winget-python"
    assert by["PyInstaller"].detail == "needs Python first"
    [(label, cmd)] = build.fix_commands(checks, PROJECT, None)
    assert cmd[0] == "winget" and cmd[-1] == build.WINGET_PYTHON
    assert "--scope" in cmd and cmd[cmd.index("--scope") + 1] == "user"
    assert not build.can_build(checks)


def test_missing_inno_setup_offers_winget():
    checks = build.check_all(PROJECT, healthy(), find_iscc=lambda: None)
    [(label, cmd)] = build.fix_commands(checks, PROJECT,
                                        build.find_python(healthy()))
    assert cmd[-1] == build.WINGET_INNO


def test_both_programs_must_import():
    runner = healthy(**{"import secretspace_server_exe": build.Result(
        1, "Traceback...\nModuleNotFoundError: No module named 'secretspace_setup'")})
    checks = build.check_all(PROJECT, runner, find_iscc=has_iscc)
    imp = checks_by_name(checks)["The server imports cleanly"]
    assert not imp.ok and "No module named 'secretspace_setup'" in imp.detail
    cmd = " ".join(next(c for c, _ in runner.calls
                        if "secretspace_server_exe" in " ".join(c)))
    assert "secretspace_server_setup_exe" in cmd


def test_an_incomplete_folder_is_reported(tmp_path):
    checks = build.check_all(str(tmp_path), healthy(), find_iscc=has_iscc)
    files = checks_by_name(checks)["Server source files"]
    assert not files.ok and "Copy the whole project folder" in files.detail


# --- versions and paths ----------------------------------------------------
def test_version_is_read_from_version_py():
    import re
    assert re.fullmatch(r"\d+\.\d+\.\d+(-(alpha|beta|rc)\.\d+)?",
                        build.app_version(PROJECT))


def test_iscc_found_in_the_per_user_location(monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\x\AppData\Local")
    found = build.find_iscc(exists=lambda p: "AppData" in p)
    assert found == r"C:\Users\x\AppData\Local\Programs\Inno Setup 6\ISCC.exe"


# --- the build -------------------------------------------------------------
@pytest.fixture
def project(tmp_path):
    (tmp_path / "server").mkdir()
    (tmp_path / "server" / "version.py").write_text('__version__ = "9.8.7"\n')
    (tmp_path / "SecretSpace-Server-Installer.exe").write_text("last time's build")
    return str(tmp_path)


def test_build_runs_the_steps_in_order(project):
    runner = FakeRunner()
    py = build.Python(["py", "-3"], "3.13.5", "python.exe")
    assert build.build(project, py, r"C:\Inno\ISCC.exe", log=lambda s: None,
                       runner=runner, exists=lambda p: True)
    cmds = [" ".join(c) for c, _ in runner.calls]
    assert "SecretSpace-Server.spec" in cmds[0]
    assert "/DAppVersion=9.8.7" in cmds[1] and "SecretSpace-Server.iss" in cmds[1]
    assert len(cmds) == 2


def test_only_the_server_is_built():
    """The app has its own repository and its own build."""
    steps = build.build_steps("P", build.Python(["py"], "3", "p"), "iscc", "1.0.0")
    products = [os.path.basename(product) for _, _, product in steps]
    assert products == ["SecretSpace-Server.exe", "SecretSpace-Server-Installer.exe"]


def test_old_outputs_are_removed_before_building(project):
    build.remove_previous(project)
    assert not os.path.exists(os.path.join(project,
                                           "SecretSpace-Server-Installer.exe"))


def test_build_stops_at_the_first_failure(project):
    runner = FakeRunner({"SecretSpace-Server.spec": build.Result(1, "boom")})
    lines = []
    ok = build.build(project, build.Python(["py"], "3", "p"), "iscc",
                     log=lines.append, runner=runner, exists=lambda p: True)
    assert not ok
    assert not any("iscc" in c for c, _ in runner.calls)
    assert any(line.startswith("FAILED") for line in lines)


def test_a_missing_product_counts_as_failure(project):
    """Exit code 0 is not enough: PyInstaller can 'succeed' and write nothing."""
    ok = build.build(project, build.Python(["py"], "3", "p"), "iscc",
                     log=lambda s: None, runner=FakeRunner(),
                     exists=lambda p: False)
    assert not ok


@pytest.mark.parametrize("text, numbers", [
    ("1.2.0", "1.2.0.0"), ("2.0.0-alpha.1", "2.0.0.1"), ("2.0.0", "2.0.0.0"),
    ("2.0.0-rc.3", "2.0.0.3")])
def test_file_version(text, numbers):
    assert build.file_version(text) == numbers


def test_file_version_refuses_junk():
    with pytest.raises(ValueError):
        build.file_version("2.0.0-dev")


def test_the_installer_gets_a_plain_file_version():
    """Inno's VersionInfoVersion takes four numbers only; a test version's
    own name (2.0.0-alpha.1) would stop the installer from compiling."""
    steps = build.build_steps("P", build.Python(["py"], "3", "p"), "iscc",
                              "2.0.0-alpha.1")
    cmd = steps[1][1]
    assert "/DAppVersion=2.0.0-alpha.1" in cmd and "/DFileVersion=2.0.0.1" in cmd


# --- the terminal survives winget's progress characters --------------------
def test_a_console_in_an_old_code_page_does_not_stop_the_builder():
    """winget's spinner and bar, printed to cp1252, stopped the builder with
    UnicodeEncodeError; safe_console() prints them as "?" instead."""
    import subprocess
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = ("import sys; sys.path.insert(0, %r); import build; "
            "build.safe_console(); print('\\u2588\\u2592 \\u280b installing')" % here)
    env = dict(os.environ, PYTHONIOENCODING="cp1252")
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, env=env)
    assert done.returncode == 0, done.stderr.decode(errors="replace")
    assert b"installing" in done.stdout
    # Without it, the same print is what stopped the builder.
    bare = subprocess.run([sys.executable, "-c", code.replace("build.safe_console(); ", "")],
                          capture_output=True, env=env)
    assert bare.returncode != 0 and b"UnicodeEncodeError" in bare.stderr
