"""
`secretspace_setup.py migrate`: an install from before the rename gets the
current names -- folders, service, its user, the settings' keys -- and the
port, the token and the vaults stay exactly as they were.

A whole Linux install is laid out under a temporary root; `systemctl`,
`usermod`, `groupmod` and `id` are a fake that records what was run.
"""

import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "server"))
import secretspace_server                                       # noqa: E402
import secretspace_setup                                        # noqa: E402

OLD_ENV = ("# PassMan sync server\n"
           "PASSMAN_HOST=0.0.0.0\n"
           "PASSMAN_PORT=59872\n"
           "PASSMAN_ALLOW_FROM=172.17.17.2,192.168.0.106\n")
TOKEN = "the-token-stays-the-same\n"
VAULT = b"ciphertext of a vault"


class Box:
    """A machine: the users it has and every command that was run on it."""

    def __init__(self, users=("passman",), fail=()):
        self.users = set(users)
        self.fail = fail
        self.calls = []

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        text = " ".join(cmd)
        if any(needle in text for needle in self.fail):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="no")
        if cmd[:2] == ["id", "-u"]:
            return types.SimpleNamespace(
                returncode=0 if cmd[2] in self.users else 1, stdout="",
                stderr="")
        if cmd[0] == "usermod":
            self.users.discard(cmd[3])
            self.users.add(cmd[2])
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    def ran(self, *words):
        return [c for c in self.calls if c[:len(words)] == list(words)]


@pytest.fixture(autouse=True)
def systemctl_present(monkeypatch):
    monkeypatch.setattr(secretspace_setup.shutil, "which", lambda name: "/bin/x")


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def read(path):
    with open(path, "rb") as f:
        return f.read()


@pytest.fixture
def old_install(tmp_path):
    """An install as 1.5.0 / 2.0.0 left it, with the 2.1.0 program files
    copied in beside the old ones (the update step before `migrate`)."""
    root = str(tmp_path)
    write(os.path.join(root, "opt/passman/server/passman_server.py"), "old")
    write(os.path.join(root, "opt/passman/server/passman_setup.py"), "old")
    write(os.path.join(root, "opt/passman/server/secretspace_server.py"), "new")
    write(os.path.join(root, "opt/passman/server/secretspace_setup.py"), "new")
    write(os.path.join(root, "etc/passman/sync.env"), OLD_ENV)
    write(os.path.join(root, "etc/passman/token"), TOKEN)
    write(os.path.join(root, "var/lib/passman/store/alice/vault.enc"), VAULT)
    write(os.path.join(root, "var/lib/passman/store/_v2/accounts/alice.json"),
          "{}")
    write(os.path.join(root, "etc/systemd/system/passman-sync.service"), "old")
    return root


def migrate(root, *flags, box=None, answers=()):
    box = box or Box()
    answers = list(answers)
    said = []
    secretspace_setup.main(["--platform", "linux", "migrate", "--root", root,
                            *flags],
                           ask=lambda prompt: answers.pop(0),
                           say=said.append, run=box)
    assert not answers, "not every answer was asked for"
    return "\n".join(said), box


def tree(root):
    found = {}
    for folder, _, files in os.walk(root):
        for name in files:
            path = os.path.join(folder, name)
            found[os.path.relpath(path, root).replace("\\", "/")] = read(path)
    return found


# --- the move -------------------------------------------------------------------

def test_migrate_moves_the_three_folders(old_install):
    migrate(old_install, "--yes")
    for gone in ("opt/passman", "etc/passman", "var/lib/passman"):
        assert not os.path.exists(os.path.join(old_install, gone))
    for there in ("opt/secretspace/server", "etc/secretspace",
                  "var/lib/secretspace/store"):
        assert os.path.isdir(os.path.join(old_install, there))


def test_the_token_and_the_vaults_are_exactly_as_they_were(old_install):
    migrate(old_install, "--yes")
    new = os.path.join(old_install, "var/lib/secretspace/store")
    assert read(os.path.join(old_install, "etc/secretspace/token")) == \
        TOKEN.encode()
    assert read(os.path.join(new, "alice/vault.enc")) == VAULT
    assert read(os.path.join(new, "_v2/accounts/alice.json")) == b"{}"


def test_the_settings_keep_their_values_under_the_current_keys(old_install):
    migrate(old_install, "--yes")
    path = os.path.join(old_install, "etc/secretspace/sync.env")
    values = secretspace_setup.read_env(path)
    assert values == {"SECRETSPACE_HOST": "0.0.0.0",
                      "SECRETSPACE_PORT": "59872",
                      "SECRETSPACE_ALLOW_FROM": "172.17.17.2,192.168.0.106"}
    assert "passman" not in read(path).decode().lower()


def test_the_server_reads_what_migrate_wrote(old_install):
    migrate(old_install, "--yes")
    values = secretspace_setup.read_env(
        os.path.join(old_install, "etc/secretspace/sync.env"))
    args = types.SimpleNamespace(host=None, port=None)
    assert secretspace_server.resolve_listen(args, values) == ("0.0.0.0", 59872)


def test_the_user_and_group_are_renamed_not_made_anew(old_install):
    _, box = migrate(old_install, "--yes")
    assert box.ran("usermod") == [["usermod", "-l", "secretspace", "passman"]]
    assert box.ran("groupmod") == [["groupmod", "-n", "secretspace", "passman"]]
    assert not box.ran("useradd") and not box.ran("chown")


def test_a_user_that_already_has_the_current_name_is_left_alone(old_install):
    _, box = migrate(old_install, "--yes", box=Box(users=("secretspace",)))
    assert not box.ran("usermod") and not box.ran("groupmod")


def test_with_both_users_there_neither_is_renamed(old_install):
    """A half-done move by hand: do not rename one user onto another."""
    _, box = migrate(old_install, "--yes",
                     box=Box(users=("passman", "secretspace")))
    assert not box.ran("usermod") and not box.ran("groupmod")
    assert os.path.isdir(os.path.join(old_install, "etc/secretspace"))


def test_the_old_service_is_stopped_before_anything_moves(old_install):
    _, box = migrate(old_install, "--yes")
    first = [c for c in box.calls if c[0] != "id"][:2]
    assert first == [["systemctl", "stop", "passman-sync"],
                     ["systemctl", "disable", "passman-sync"]]


def test_the_current_unit_is_installed_and_the_old_one_removed(old_install):
    _, box = migrate(old_install, "--yes")
    units = os.path.join(old_install, "etc/systemd/system")
    assert sorted(os.listdir(units)) == ["secretspace-sync.service"]
    unit = read(os.path.join(units, "secretspace-sync.service")).decode()
    assert unit == secretspace_setup.unit_text()
    assert box.calls[-2:] == [["systemctl", "daemon-reload"],
                              ["systemctl", "enable", "--now",
                               "secretspace-sync"]]


def test_the_unit_it_installs_is_the_one_the_repository_ships():
    shipped = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                           "server", "secretspace-sync.service")
    if not os.path.exists(shipped):
        pytest.skip("this repository ships no systemd unit (Windows server)")
    with open(shipped, encoding="utf-8", newline="") as f:
        assert f.read() == secretspace_setup.unit_text()


def test_the_unit_names_nothing_from_before_the_rename():
    assert "passman" not in secretspace_setup.unit_text().lower()


def test_the_old_program_files_go_once_the_current_ones_are_there(old_install):
    migrate(old_install, "--yes")
    server = os.path.join(old_install, "opt/secretspace/server")
    assert sorted(os.listdir(server)) == ["secretspace_server.py",
                                          "secretspace_setup.py"]


def test_the_old_program_files_stay_if_the_current_ones_are_missing(old_install):
    for name in ("secretspace_server.py", "secretspace_setup.py"):
        os.remove(os.path.join(old_install, "opt/passman/server", name))
    migrate(old_install, "--yes")
    server = os.path.join(old_install, "opt/secretspace/server")
    assert sorted(os.listdir(server)) == ["passman_server.py",
                                          "passman_setup.py"]


def test_it_says_how_to_check_and_how_to_go_back(old_install):
    said, _ = migrate(old_install, "--yes")
    assert "curl http://127.0.0.1:59872/health" in said
    assert "migrate --undo" in said


# --- asking first ----------------------------------------------------------------

def test_it_shows_the_plan_and_a_backup_line_before_asking(old_install):
    said, _ = migrate(old_install, answers=["n"])
    assert "sudo tar czf" in said and "/var/lib/passman" in said
    assert "move /etc/passman to /etc/secretspace" in said
    assert "rename the user and group passman to secretspace" in said
    assert "Nothing was changed." in said


def test_no_means_nothing_is_touched(old_install):
    before = tree(old_install)
    _, box = migrate(old_install, answers=["n"])
    assert tree(old_install) == before
    assert [c for c in box.calls if c[0] != "id"] == []


def test_yes_at_the_question_does_it(old_install):
    migrate(old_install, answers=["y"])
    assert os.path.isdir(os.path.join(old_install, "etc/secretspace"))


def test_dry_run_only_shows(old_install):
    before = tree(old_install)
    said, box = migrate(old_install, "--dry-run")
    assert "Dry run: nothing was changed." in said
    assert tree(old_install) == before
    assert [c for c in box.calls if c[0] != "id"] == []


# --- when there is nothing to do, or it cannot be done ----------------------------

def test_a_server_that_already_has_the_current_names_is_left_alone(old_install):
    migrate(old_install, "--yes")
    before = tree(old_install)
    said, box = migrate(old_install, "--yes")
    assert "already has the current names" in said
    assert tree(old_install) == before and box.calls == []


def test_a_machine_without_a_server_is_told_so(tmp_path):
    said, box = migrate(str(tmp_path), "--yes")
    assert "no SecretSpace sync server" in said and box.calls == []


def test_old_and_new_folders_together_stop_it_untouched(old_install):
    write(os.path.join(old_install, "etc/secretspace/sync.env"), "x")
    before = tree(old_install)
    with pytest.raises(SystemExit) as stop:
        migrate(old_install, "--yes")
    assert "/etc/secretspace" in str(stop.value)
    assert "Nothing was changed" in str(stop.value)
    assert tree(old_install) == before


def test_a_user_that_cannot_be_renamed_stops_it_before_any_move(old_install):
    with pytest.raises(SystemExit) as stop:
        migrate(old_install, "--yes", box=Box(fail=("usermod",)))
    assert "usermod" in str(stop.value)
    assert "systemctl enable --now passman-sync" in str(stop.value)
    assert os.path.isdir(os.path.join(old_install, "etc/passman"))
    assert not os.path.exists(os.path.join(old_install, "etc/secretspace"))


def test_an_install_without_a_settings_file_still_moves(old_install):
    os.remove(os.path.join(old_install, "etc/passman/sync.env"))
    said, _ = migrate(old_install, "--yes")
    assert os.path.isdir(os.path.join(old_install, "etc/secretspace"))
    assert "sync.env" not in os.listdir(
        os.path.join(old_install, "etc/secretspace"))


def test_without_systemd_it_says_to_start_the_server_by_hand(old_install,
                                                            monkeypatch):
    monkeypatch.setattr(secretspace_setup.shutil, "which", lambda name: None)
    said, box = migrate(old_install, "--yes")
    assert "start the server yourself" in said
    assert not box.ran("systemctl")
    assert os.path.isdir(os.path.join(old_install, "etc/secretspace"))


# --- the way back -----------------------------------------------------------------

def test_undo_puts_every_name_back(old_install):
    data_before = {k: v for k, v in tree(old_install).items()
                   if k.startswith(("var/", "etc/passman/token"))}
    migrate(old_install, "--yes")
    _, box = migrate(old_install, "--undo", "--yes",
                     box=Box(users=("secretspace",)))
    for there in ("opt/passman/server", "etc/passman", "var/lib/passman/store"):
        assert os.path.isdir(os.path.join(old_install, there))
    for gone in ("opt/secretspace", "etc/secretspace", "var/lib/secretspace"):
        assert not os.path.exists(os.path.join(old_install, gone))
    now = tree(old_install)
    assert {k: now[k] for k in data_before} == data_before
    assert box.ran("usermod") == [["usermod", "-l", "passman", "secretspace"]]
    assert secretspace_setup.read_env(
        os.path.join(old_install, "etc/passman/sync.env"))["PASSMAN_PORT"] == \
        "59872"
    units = os.path.join(old_install, "etc/systemd/system")
    assert os.listdir(units) == ["passman-sync.service"]
    unit = read(os.path.join(units, "passman-sync.service")).decode()
    # The old names, running the program that is there now.
    assert "/opt/passman/server/secretspace_server.py" in unit
    assert "User=passman" in unit and "/etc/passman/sync.env" in unit
    assert box.calls[-1] == ["systemctl", "enable", "--now", "passman-sync"]


def test_the_server_still_reads_the_settings_undo_wrote(old_install):
    migrate(old_install, "--yes")
    migrate(old_install, "--undo", "--yes", box=Box(users=("secretspace",)))
    values = secretspace_setup.read_env(
        os.path.join(old_install, "etc/passman/sync.env"))
    args = types.SimpleNamespace(host=None, port=None)
    assert secretspace_server.resolve_listen(args, values) == ("0.0.0.0", 59872)


# --- needing root -----------------------------------------------------------------

def test_the_real_thing_needs_sudo(monkeypatch):
    monkeypatch.setattr(secretspace_setup, "is_admin", lambda platform: False)
    with pytest.raises(SystemExit) as stop:
        secretspace_setup.main(["--platform", "linux", "migrate"],
                               say=lambda *a: None, run=Box())
    assert "sudo" in str(stop.value)


def test_a_dry_run_does_not_need_sudo(monkeypatch, tmp_path):
    monkeypatch.setattr(secretspace_setup, "is_admin", lambda platform: False)
    said = []
    secretspace_setup.main(["--platform", "linux", "migrate", "--dry-run",
                            "--root", str(tmp_path)],
                           say=said.append, run=Box())
    assert said


# --- Windows: the installer's setup step does it ------------------------------------

def windows_setup(tmp_path, monkeypatch, system=None):
    """`setup --keep` as the installer runs it, with ProgramData in tmp."""
    from test_server_setup import FakeSystem
    monkeypatch.setenv("ProgramData", str(tmp_path))
    monkeypatch.setattr(secretspace_setup, "is_admin", lambda platform: True)
    monkeypatch.setattr(secretspace_setup, "port_in_use", lambda h, p: False)
    system = system or FakeSystem()
    said = []
    secretspace_setup.main(["--platform", "windows", "setup", "--keep"],
                           ask=lambda prompt: "", say=said.append, run=system)
    return "\n".join(said), system


def test_windows_setup_moves_an_old_data_folder_first(tmp_path, monkeypatch):
    old = tmp_path / "PassMan Server"
    write(str(old / "sync.env"), "PASSMAN_HOST=0.0.0.0\nPASSMAN_PORT=60517\n")
    write(str(old / "token"), TOKEN)
    write(str(old / "store" / "alice" / "vault.enc"), VAULT)
    said, system = windows_setup(tmp_path, monkeypatch)
    new = tmp_path / "SecretSpace Server"
    assert not old.exists()
    assert read(str(new / "token")) == TOKEN.encode()
    assert read(str(new / "store" / "alice" / "vault.enc")) == VAULT
    assert secretspace_setup.read_env(str(new / "sync.env")) == {
        "SECRETSPACE_HOST": "0.0.0.0", "SECRETSPACE_PORT": "60517"}
    assert "Moved the server's data" in said
    # The old task and firewall rules go; the current ones are made.
    assert system.ran("Unregister-ScheduledTask -TaskName 'PassMan Sync Server'")
    assert system.ran("Remove-NetFirewallRule -Group 'PassMan Sync Server'")
    assert system.ran("Register-ScheduledTask -TaskName 'SecretSpace Sync Server'")
    assert system.ran("-LocalPort 60517")


def test_windows_setup_keeps_the_saved_port_without_asking(tmp_path, monkeypatch):
    old = tmp_path / "PassMan Server"
    write(str(old / "sync.env"),
          "PASSMAN_HOST=0.0.0.0\nPASSMAN_PORT=60517\n"
          "PASSMAN_ALLOW_FROM=172.17.17.2\n")
    write(str(old / "token"), TOKEN)
    said, system = windows_setup(tmp_path, monkeypatch)
    assert "listening on 0.0.0.0:60517" in said
    assert system.ran("'172.17.17.2'")


def test_windows_setup_without_an_old_install_touches_nothing_old(tmp_path, monkeypatch):
    new = tmp_path / "SecretSpace Server"
    write(str(new / "sync.env"),
          "SECRETSPACE_HOST=0.0.0.0\nSECRETSPACE_PORT=60517\n")
    write(str(new / "token"), TOKEN)
    said, system = windows_setup(tmp_path, monkeypatch)
    assert not system.ran("PassMan Sync Server")
    assert "Moved" not in said


def test_windows_old_and_new_folders_together_use_the_new_one(tmp_path, monkeypatch):
    old, new = tmp_path / "PassMan Server", tmp_path / "SecretSpace Server"
    write(str(old / "token"), "old-token\n")
    write(str(new / "sync.env"),
          "SECRETSPACE_HOST=0.0.0.0\nSECRETSPACE_PORT=60517\n")
    write(str(new / "token"), TOKEN)
    said, _ = windows_setup(tmp_path, monkeypatch)
    assert read(str(old / "token")) == b"old-token\n"
    assert read(str(new / "token")) == TOKEN.encode()
    assert "leaving the other alone" in said


def test_migrate_on_windows_points_to_the_installer():
    said = []
    secretspace_setup.main(["--platform", "windows", "migrate"],
                           say=said.append, run=Box())
    assert "installer" in said[0]
