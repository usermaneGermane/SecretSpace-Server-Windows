"""
The sync server's listen settings and its setup script.

Where it listens: a flag wins, then PASSMAN_HOST / PASSMAN_PORT (which the
systemd unit loads from /etc/passman/sync.env), then 127.0.0.1:8787. The
setup script writes that file and the token; nothing here touches the real
/etc -- every test points --config-dir at a temporary folder and fakes
`ip` and `systemctl`.
"""

import os
import sys
import json
import types
import argparse

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

import passman_server                                           # noqa: E402
import passman_setup                                            # noqa: E402
import passman_server_exe                                       # noqa: E402
import passman_server_setup_exe                                 # noqa: E402


def listen(environ, host=None, port=None):
    return passman_server.resolve_listen(
        argparse.Namespace(host=host, port=port), environ)


# --- flag > env > default -------------------------------------------------

def test_with_nothing_set_it_listens_on_this_machine_only():
    assert listen({}) == ("127.0.0.1", 8787)


def test_the_environment_sets_host_and_port():
    env = {"PASSMAN_HOST": "0.0.0.0", "PASSMAN_PORT": "9000"}
    assert listen(env) == ("0.0.0.0", 9000)


def test_a_flag_beats_the_environment():
    env = {"PASSMAN_HOST": "0.0.0.0", "PASSMAN_PORT": "9000"}
    assert listen(env, host="10.0.0.5", port=9100) == ("10.0.0.5", 9100)


def test_each_setting_falls_back_on_its_own():
    assert listen({"PASSMAN_PORT": "9000"}) == ("127.0.0.1", 9000)
    assert listen({"PASSMAN_HOST": "0.0.0.0"}, port=9100) == ("0.0.0.0", 9100)


def test_an_empty_variable_counts_as_unset():
    assert listen({"PASSMAN_HOST": " ", "PASSMAN_PORT": ""}) == \
        ("127.0.0.1", 8787)


@pytest.mark.parametrize("bad", ["eighty", "0", "65536", "-1", "80.5"])
def test_a_bad_port_in_the_environment_stops_with_its_name(bad):
    with pytest.raises(SystemExit) as stop:
        listen({"PASSMAN_PORT": bad})
    assert "PASSMAN_PORT" in str(stop.value)


def test_a_bad_port_flag_stops_too():
    with pytest.raises(SystemExit) as stop:
        listen({}, port=70000)
    assert "--port" in str(stop.value)


# --- the setup script ------------------------------------------------------

IP_JSON = json.dumps([
    {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]},
    {"ifname": "eth0", "addr_info": [{"local": "192.168.1.50",
                                      "prefixlen": 24}]},
    {"ifname": "wg0", "addr_info": [{"local": "10.8.0.1", "prefixlen": 24}]},
])


WIN_JSON = json.dumps([
    {"InterfaceAlias": "Loopback Pseudo-Interface 1", "IPAddress": "127.0.0.1",
     "PrefixLength": 8},
    {"InterfaceAlias": "Ethernet", "IPAddress": "192.168.1.60",
     "PrefixLength": 24},
    {"InterfaceAlias": "Wi-Fi", "IPAddress": "169.254.3.4",
     "PrefixLength": 16},
])


class FakeSystem:
    """Stands in for `ip`, `systemctl`, `ufw`, PowerShell and icacls;
    records what was run."""

    def __init__(self, active=False, ip_output=IP_JSON, ufw=False,
                 win_output=WIN_JSON, fail=()):
        self.active = active
        self.ip_output = ip_output
        self.ufw = ufw
        self.win_output = win_output
        self.fail = fail
        self.calls = []

    def __call__(self, cmd):
        self.calls.append(cmd)
        text = " ".join(cmd)
        if any(needle in text for needle in self.fail):
            return types.SimpleNamespace(returncode=1, stdout="",
                                         stderr="denied")
        if cmd[0] == "ip":
            if self.ip_output is None:
                return None
            return types.SimpleNamespace(returncode=0, stdout=self.ip_output,
                                         stderr="")
        if "Get-NetIPAddress" in text:
            return types.SimpleNamespace(returncode=0, stdout=self.win_output,
                                         stderr="")
        if cmd[:2] == ["ufw", "status"]:
            return types.SimpleNamespace(
                returncode=0, stderr="",
                stdout="Status: active\n" if self.ufw else
                "Status: inactive\n")
        if cmd[:2] == ["systemctl", "is-active"]:
            return types.SimpleNamespace(
                returncode=0 if self.active else 3,
                stdout="active\n" if self.active else "inactive\n", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    @property
    def restarted(self):
        return ["systemctl", "restart", "passman-sync"] in self.calls

    def ran(self, needle):
        """Every command (as one string) that contains needle."""
        return [" ".join(c) for c in self.calls if needle in " ".join(c)]


@pytest.fixture(autouse=True)
def systemctl_present(monkeypatch):
    monkeypatch.setattr(passman_setup.shutil, "which", lambda name: "/bin/x")


@pytest.fixture(autouse=True)
def port_free(monkeypatch):
    monkeypatch.setattr(passman_setup, "port_in_use", lambda h, p: False)


def run_setup(tmp_path, answers=(), argv=(), system=None, platform="linux"):
    answers = list(answers)
    said = []
    system = system or FakeSystem()
    passman_setup.main(["--config-dir", str(tmp_path), "--platform", platform,
                        *argv],
                       ask=lambda prompt: answers.pop(0),
                       say=said.append, run=system)
    assert not answers, "not every answer was asked for"
    return "\n".join(said), system


def test_it_lists_this_machines_networks_without_loopback():
    assert passman_setup.list_addresses(FakeSystem()) == [
        ("eth0", "192.168.1.50", 24), ("wg0", "10.8.0.1", 24)]


def test_without_ip_there_is_simply_nothing_to_list():
    assert passman_setup.list_addresses(FakeSystem(ip_output=None)) == []


def test_setup_writes_the_chosen_address_and_port(tmp_path):
    out, _ = run_setup(tmp_path, answers=["2", "9443", ""])
    env = passman_setup.read_env(tmp_path / "sync.env")
    assert env == {"PASSMAN_HOST": "192.168.1.50", "PASSMAN_PORT": "9443"}
    assert "http://192.168.1.50:9443" in out
    assert "ufw allow from 192.168.1.0/24 to any port 9443" in out


def test_the_defaults_are_every_network_and_8787(tmp_path):
    out, _ = run_setup(tmp_path, answers=["", "", ""])
    env = passman_setup.read_env(tmp_path / "sync.env")
    assert env == {"PASSMAN_HOST": "0.0.0.0", "PASSMAN_PORT": "8787"}
    # Every network: one address and one firewall rule per network.
    assert "http://192.168.1.50:8787" in out and "http://10.8.0.1:8787" in out
    assert "from 10.8.0.0/24 to any port 8787" in out


def test_what_setup_writes_is_what_the_server_reads(tmp_path):
    run_setup(tmp_path, argv=["setup", "--host", "10.8.0.1", "--port", "9000"])
    env = passman_setup.read_env(tmp_path / "sync.env")
    assert listen(env) == ("10.8.0.1", 9000)


def test_running_setup_again_offers_the_current_values(tmp_path):
    run_setup(tmp_path, argv=["setup", "--host", "10.8.0.1", "--port", "9000"])
    run_setup(tmp_path, answers=["", "", ""])
    assert passman_setup.read_env(tmp_path / "sync.env") == \
        {"PASSMAN_HOST": "10.8.0.1", "PASSMAN_PORT": "9000"}


@pytest.mark.parametrize("bad", ["80", "70000", "web"])
def test_a_bad_port_is_asked_again(tmp_path, bad):
    out, _ = run_setup(tmp_path, answers=["1", bad, "9000", ""])
    assert passman_setup.read_env(tmp_path / "sync.env")["PASSMAN_PORT"] == \
        "9000"


def test_an_address_this_machine_does_not_have_is_refused(tmp_path):
    out, _ = run_setup(tmp_path, answers=["192.168.7.7", "3", "", ""])
    assert "does not have 192.168.7.7" in out
    assert passman_setup.read_env(tmp_path / "sync.env")["PASSMAN_HOST"] == \
        "10.8.0.1"


def test_a_bad_flag_stops_without_writing(tmp_path):
    with pytest.raises(SystemExit):
        run_setup(tmp_path, argv=["setup", "--host", "1.2.3.4", "--port",
                                  "9000"])
    assert not (tmp_path / "sync.env").exists()


def test_the_first_setup_creates_a_token_and_a_later_one_keeps_it(tmp_path):
    run_setup(tmp_path, answers=["", "", ""])
    token = (tmp_path / "token").read_text().strip()
    assert len(token) >= 32
    run_setup(tmp_path, answers=["", "9000", ""])
    assert (tmp_path / "token").read_text().strip() == token


def test_a_change_restarts_a_running_service(tmp_path):
    run_setup(tmp_path, answers=["", "", ""])
    _, system = run_setup(tmp_path, answers=["", "9000", ""],
                          system=FakeSystem(active=True))
    assert system.restarted


def test_no_change_means_no_restart(tmp_path):
    run_setup(tmp_path, answers=["", "", ""])
    _, system = run_setup(tmp_path, answers=["", "", ""],
                          system=FakeSystem(active=True))
    assert not system.restarted


def test_a_stopped_service_is_not_started(tmp_path):
    _, system = run_setup(tmp_path, answers=["", "9000", ""],
                          system=FakeSystem(active=False))
    assert not system.restarted


# --- new-token -------------------------------------------------------------

def test_new_token_replaces_the_token_restarts_and_prints_it(tmp_path):
    run_setup(tmp_path, answers=["", "", ""])
    old = (tmp_path / "token").read_text().strip()
    out, system = run_setup(tmp_path, answers=["y"], argv=["new-token"],
                            system=FakeSystem(active=True))
    new = (tmp_path / "token").read_text().strip()
    assert new != old and len(new) >= 32
    assert new in out
    assert system.restarted


def test_new_token_asks_first_and_no_keeps_the_old_one(tmp_path):
    run_setup(tmp_path, answers=["", "", ""])
    old = (tmp_path / "token").read_text()
    out, system = run_setup(tmp_path, answers=[""], argv=["new-token"],
                            system=FakeSystem(active=True))
    assert (tmp_path / "token").read_text() == old
    assert "unchanged" in out and not system.restarted


def test_new_token_yes_skips_the_question(tmp_path):
    out, _ = run_setup(tmp_path, argv=["new-token", "--yes"])
    assert (tmp_path / "token").read_text().strip() in out


def test_the_server_accepts_the_token_setup_wrote(tmp_path):
    run_setup(tmp_path, argv=["new-token", "--yes"])
    args = argparse.Namespace(token_file=str(tmp_path / "token"))
    token = passman_server.load_token(args)
    assert token == (tmp_path / "token").read_text().strip()
    assert len(token) >= 16


def test_show_token_prints_it(tmp_path):
    run_setup(tmp_path, argv=["new-token", "--yes"])
    out, _ = run_setup(tmp_path, argv=["show-token"])
    assert out == (tmp_path / "token").read_text().strip()


def test_show_token_without_one_says_to_run_setup(tmp_path):
    with pytest.raises(SystemExit) as stop:
        run_setup(tmp_path, argv=["show-token"])
    assert "setup" in str(stop.value)


def test_keep_reuses_the_saved_values_without_asking(tmp_path):
    run_setup(tmp_path, argv=["setup", "--host", "10.8.0.1", "--port", "9000"])
    run_setup(tmp_path, argv=["setup", "--keep"])          # no answers given
    assert passman_setup.read_env(tmp_path / "sync.env") == \
        {"PASSMAN_HOST": "10.8.0.1", "PASSMAN_PORT": "9000"}


def test_keep_with_nothing_saved_asks(tmp_path):
    run_setup(tmp_path, answers=["", "", ""], argv=["setup", "--keep"])
    assert passman_setup.read_env(tmp_path / "sync.env")["PASSMAN_PORT"] == \
        "8787"


def test_pause_shows_an_error_before_waiting(tmp_path):
    said, asked = [], []
    with pytest.raises(SystemExit):
        passman_setup.main(
            ["--config-dir", str(tmp_path), "--platform", "linux", "--pause",
             "show-token"],
            ask=lambda prompt: asked.append((prompt, list(said))) or "",
            say=said.append, run=FakeSystem())
    [(prompt, said_before)] = asked
    assert "Press Enter" in prompt
    assert any("no token" in line for line in said_before)


# --- Linux firewall --------------------------------------------------------

def test_with_ufw_on_setup_adds_the_rule_itself(tmp_path):
    out, system = run_setup(tmp_path, answers=["2", "9443", ""],
                            system=FakeSystem(ufw=True))
    assert system.ran("ufw allow from 192.168.1.0/24 to any port 9443 "
                      "proto tcp")
    assert "allowed 192.168.1.0/24 to port 9443" in out


def test_every_network_gets_one_rule_each(tmp_path):
    _, system = run_setup(tmp_path, answers=["", "", ""],
                          system=FakeSystem(ufw=True))
    assert len(system.ran("ufw allow from")) == 2


def test_a_new_port_replaces_the_old_rule(tmp_path):
    run_setup(tmp_path, answers=["2", "", ""], system=FakeSystem(ufw=True))
    _, system = run_setup(tmp_path, answers=["", "9443", ""],
                          system=FakeSystem(ufw=True))
    assert system.ran("ufw delete allow from 192.168.1.0/24 to any port 8787")
    assert system.ran("ufw allow from 192.168.1.0/24 to any port 9443")


def test_with_ufw_off_nothing_is_switched_on(tmp_path):
    out, system = run_setup(tmp_path, answers=["", "", ""],
                            system=FakeSystem(ufw=False))
    assert not system.ran("ufw allow") and not system.ran("ufw enable")
    assert "sudo ufw allow from 192.168.1.0/24" in out


def test_no_change_touches_no_firewall_rule(tmp_path):
    run_setup(tmp_path, answers=["", "", ""], system=FakeSystem(ufw=True))
    _, system = run_setup(tmp_path, answers=["", "", ""],
                          system=FakeSystem(ufw=True))
    assert not system.ran("ufw allow") and not system.ran("ufw delete")


# --- extra addresses (--allow-from) -----------------------------------------

def allowed(tmp_path):
    return passman_setup.read_env(tmp_path / "sync.env").get(
        passman_setup.ALLOW_KEY)


@pytest.mark.parametrize("text, expected", [
    ("192.168.0.1", ["192.168.0.1"]),
    (" 192.168.0.1 , 10.20.0.0/24 ", ["192.168.0.1", "10.20.0.0/24"]),
    ("10.20.0.7/24", ["10.20.0.0/24"]),
    ("192.168.0.1/32", ["192.168.0.1"]),     # matches a rule typed by hand
    ("1.2.3.4,1.2.3.4", ["1.2.3.4"]),
    ("-", []), ("none", []), ("", []),
])
def test_allow_from_accepts_addresses_and_networks(text, expected):
    assert passman_setup.check_allow(text) == (expected, None)


@pytest.mark.parametrize("bad", ["0.0.0.0/0", "everyone", "fe80::1",
                                 "10.0.0.300", "1.2.3.4/33"])
def test_allow_from_refuses_everyone_and_nonsense(bad):
    allow, problem = passman_setup.check_allow(bad)
    assert allow is None and problem


def test_the_question_saves_extra_addresses(tmp_path):
    out, _ = run_setup(tmp_path, answers=["", "", "192.168.0.1"])
    assert allowed(tmp_path) == "192.168.0.1"
    assert "Also let in: 192.168.0.1" in out
    # Host and port are still what the server reads.
    env = passman_setup.read_env(tmp_path / "sync.env")
    assert listen(env) == ("0.0.0.0", 8787)


def test_a_bad_extra_address_is_asked_again(tmp_path):
    out, _ = run_setup(tmp_path, answers=["", "", "0.0.0.0/0", "10.20.0.0/24"])
    assert "everyone" in out
    assert allowed(tmp_path) == "10.20.0.0/24"


def test_enter_keeps_the_extra_addresses_and_dash_clears_them(tmp_path):
    run_setup(tmp_path, answers=["", "", "192.168.0.1"])
    run_setup(tmp_path, answers=["", "", ""])
    assert allowed(tmp_path) == "192.168.0.1"
    run_setup(tmp_path, answers=["", "", "-"])
    assert allowed(tmp_path) is None


def test_with_ufw_on_the_extra_address_gets_its_rule(tmp_path):
    out, system = run_setup(tmp_path, answers=["2", "9443", "192.168.0.1"],
                            system=FakeSystem(ufw=True))
    assert system.ran("ufw allow from 192.168.1.0/24 to any port 9443 "
                      "proto tcp")
    assert system.ran("ufw allow from 192.168.0.1 to any port 9443 proto tcp")


def test_allow_from_alone_adds_the_rule_without_a_restart(tmp_path):
    """The case it was made for: the service is set up and running, a PC on
    another network needs in. Only the firewall changes."""
    run_setup(tmp_path, argv=["setup", "--host", "0.0.0.0", "--port", "9443"])
    out, system = run_setup(
        tmp_path, argv=["setup", "--keep", "--allow-from", "192.168.0.1"],
        system=FakeSystem(ufw=True, active=True))
    assert system.ran("ufw allow from 192.168.0.1 to any port 9443 proto tcp")
    assert not system.ran("ufw delete")
    assert not system.restarted
    assert allowed(tmp_path) == "192.168.0.1"


def test_allow_from_repeats_and_none_clears(tmp_path):
    run_setup(tmp_path, argv=["setup", "--host", "0.0.0.0", "--port", "9443",
                              "--allow-from", "192.168.0.1",
                              "--allow-from", "10.20.0.0/24"])
    assert allowed(tmp_path) == "192.168.0.1,10.20.0.0/24"
    _, system = run_setup(tmp_path, argv=["setup", "--keep", "--allow-from",
                                          "none"],
                          system=FakeSystem(ufw=True))
    assert allowed(tmp_path) is None
    assert system.ran("ufw delete allow from 192.168.0.1 to any port 9443")
    assert system.ran("ufw delete allow from 10.20.0.0/24 to any port 9443")


def test_a_bad_allow_from_stops_without_writing(tmp_path):
    with pytest.raises(SystemExit) as stop:
        run_setup(tmp_path, argv=["setup", "--host", "0.0.0.0", "--port",
                                  "9443", "--allow-from", "0.0.0.0/0"])
    assert "everyone" in str(stop.value)
    assert not (tmp_path / "sync.env").exists()


def test_flags_and_keep_leave_the_extra_addresses_as_they_are(tmp_path):
    run_setup(tmp_path, answers=["", "", "192.168.0.1"])
    run_setup(tmp_path, argv=["setup", "--keep", "--port", "9000"])
    assert allowed(tmp_path) == "192.168.0.1"
    run_setup(tmp_path, argv=["setup", "--keep"])
    assert allowed(tmp_path) == "192.168.0.1"


def test_a_new_port_moves_the_extra_rule_too(tmp_path):
    run_setup(tmp_path, answers=["2", "", "192.168.0.1"],
              system=FakeSystem(ufw=True))
    _, system = run_setup(tmp_path, argv=["setup", "--keep", "--port", "9443"],
                          system=FakeSystem(ufw=True))
    assert system.ran("ufw delete allow from 192.168.0.1 to any port 8787")
    assert system.ran("ufw allow from 192.168.0.1 to any port 9443")


def test_this_machine_only_is_not_asked_and_opens_nothing(tmp_path):
    _, system = run_setup(tmp_path, answers=["4", ""],
                          system=FakeSystem(ufw=True))
    assert not system.ran("ufw allow")


def test_with_ufw_off_the_extra_rule_is_printed(tmp_path):
    out, system = run_setup(tmp_path, answers=["", "", "192.168.0.1"])
    assert "sudo ufw allow from 192.168.0.1 to any port 8787" in out
    assert not system.ran("ufw allow")


def test_windows_extra_addresses_join_the_one_rule(tmp_path):
    out, system = win_setup(tmp_path, answers=["", "9443", "192.168.0.1"])
    [rule] = system.ran("New-NetFirewallRule")
    assert "-RemoteAddress 'LocalSubnet','192.168.0.1'" in rule
    assert "and 192.168.0.1" in out


def test_windows_upgrade_keeps_the_extra_addresses(tmp_path):
    win_setup(tmp_path, answers=["", "", "192.168.0.1"])
    _, system = win_setup(tmp_path, argv=["setup", "--keep"])
    [rule] = system.ran("New-NetFirewallRule")
    assert "'192.168.0.1'" in rule


# --- Windows ---------------------------------------------------------------

def win_setup(tmp_path, answers=(), argv=(), system=None):
    return run_setup(tmp_path, answers, argv, system or FakeSystem(),
                     platform="windows")


def test_windows_lists_its_networks_without_loopback_or_link_local():
    assert passman_setup.list_addresses(FakeSystem(), "windows") == \
        [("Ethernet", "192.168.1.60", 24)]


def test_windows_one_network_comes_back_as_an_object_not_a_list():
    one = json.dumps({"InterfaceAlias": "Ethernet", "IPAddress": "10.0.0.9",
                      "PrefixLength": 16})
    assert passman_setup.list_addresses(FakeSystem(win_output=one),
                                        "windows") == \
        [("Ethernet", "10.0.0.9", 16)]


def test_windows_setup_creates_the_startup_task(tmp_path):
    out, system = win_setup(tmp_path, answers=["", "9443", ""])
    [task] = system.ran("Register-ScheduledTask")
    assert "LOCAL SERVICE" in task and "-AtStartup" in task
    assert "[TimeSpan]::Zero" in task            # no 72-hour time limit
    assert "--host 0.0.0.0 --port 9443" in task
    assert str(tmp_path / "store") in task and "--retry-bind" in task
    assert system.ran("Start-ScheduledTask")
    assert "Started the server" in out


def test_windows_setup_opens_the_firewall_for_local_networks(tmp_path):
    out, system = win_setup(tmp_path, answers=["", "9443", ""])
    [rule] = system.ran("New-NetFirewallRule")
    assert "-LocalPort 9443" in rule and "'LocalSubnet'" in rule
    assert "-Direction Inbound" in rule
    # The previous rule goes first, so a port change leaves no stale one.
    assert rule.index("Remove-NetFirewallRule") < rule.index("New-NetFirewall")


def test_windows_one_network_allows_just_that_range(tmp_path):
    _, system = win_setup(tmp_path, answers=["2", "", ""])
    [rule] = system.ran("New-NetFirewallRule")
    assert "'192.168.1.0/24'" in rule


def test_windows_this_machine_only_needs_no_rule(tmp_path):
    out, system = win_setup(tmp_path, answers=["3", ""])
    assert not system.ran("New-NetFirewallRule")
    assert system.ran("Remove-NetFirewallRule")


def test_windows_token_is_locked_down_and_shown_once(tmp_path):
    out, system = win_setup(tmp_path, answers=["", "", ""])
    token = (tmp_path / "token").read_text().strip()
    assert token in out
    [acl] = system.ran("icacls " + str(tmp_path / "token"))
    assert "/inheritance:r" in acl and "*S-1-5-19:R" in acl
    # The store and logs are writable by the service account.
    assert len(system.ran("*S-1-5-19:(OI)(CI)M")) == 2


def test_windows_rerunning_setup_replaces_the_task(tmp_path):
    win_setup(tmp_path, answers=["", "", ""])
    _, system = win_setup(tmp_path, argv=["setup", "--keep"])
    assert system.ran("Register-ScheduledTask") and \
        "-Force" in system.ran("Register-ScheduledTask")[0]


def test_windows_a_task_that_cannot_be_created_stops_setup(tmp_path):
    with pytest.raises(SystemExit) as stop:
        win_setup(tmp_path, answers=["", "", ""],
                  system=FakeSystem(fail=("Register-ScheduledTask",)))
    assert "scheduled task" in str(stop.value)


def test_windows_new_token_restarts_the_task(tmp_path):
    out, system = win_setup(tmp_path, argv=["new-token", "--yes"])
    assert system.ran("Start-ScheduledTask")
    assert (tmp_path / "token").read_text().strip() in out


def test_windows_remove_deletes_task_and_rule_but_keeps_the_data(tmp_path):
    win_setup(tmp_path, answers=["", "", ""])
    out, system = win_setup(tmp_path, argv=["remove"])
    [cmd] = system.calls
    text = " ".join(cmd)
    assert "Unregister-ScheduledTask" in text
    assert "Remove-NetFirewallRule" in text
    assert (tmp_path / "token").exists() and (tmp_path / "sync.env").exists()


def test_remove_on_linux_points_at_systemctl(tmp_path):
    with pytest.raises(SystemExit) as stop:
        run_setup(tmp_path, argv=["remove"])
    assert "systemctl disable" in str(stop.value)


def test_a_quote_in_a_path_cannot_break_out_of_powershell():
    assert passman_setup.ps_quote("C:\\it's here") == "'C:\\it''s here'"


# --- the server's Windows options -------------------------------------------

def test_the_log_file_stamps_every_line(tmp_path):
    log = passman_server.open_log(str(tmp_path / "logs" / "server.log"))
    log.write("one\ntwo ")
    log.write("still two\n")
    lines = (tmp_path / "logs" / "server.log").read_text().splitlines()
    assert len(lines) == 2
    assert lines[0].endswith("Z one") and lines[1].endswith("Z two still two")


def test_a_large_log_is_rotated_at_start(tmp_path, monkeypatch):
    monkeypatch.setattr(passman_server, "LOG_ROTATE_BYTES", 10)
    path = tmp_path / "server.log"
    path.write_text("x" * 20)
    passman_server.open_log(str(path)).write("new\n")
    assert (tmp_path / "server.log.1").read_text() == "x" * 20
    assert path.read_text().endswith("new\n")


def test_bind_retries_an_address_that_is_not_there_yet(monkeypatch):
    attempts = []

    def flaky(address, handler):
        attempts.append(address)
        if len(attempts) < 3:
            raise OSError(10049, "not there")
        return "server"
    monkeypatch.setattr(passman_server, "ThreadingHTTPServer", flaky)
    slept = []
    assert passman_server.bind("10.9.9.9", 9000, 10, sleep=slept.append) == \
        "server"
    assert slept == [10, 10]


def test_bind_without_retry_fails_at_once(monkeypatch):
    def broken(address, handler):
        raise OSError(10049, "not there")
    monkeypatch.setattr(passman_server, "ThreadingHTTPServer", broken)
    with pytest.raises(OSError):
        passman_server.bind("10.9.9.9", 9000)


# --- PassMan-Server.exe and PassMan-Server-Setup.exe -------------------------

def test_the_task_runs_the_server_not_the_setup_program():
    """Run from PassMan-Server-Setup.exe, the task must still start
    PassMan-Server.exe beside it -- never the setup program itself."""
    setup = os.path.join("C:\\Program Files", "SecretSpace Server",
                         "PassMan-Server-Setup.exe")
    program, prefix = passman_setup.server_command(frozen=True,
                                                   executable=setup)
    assert program == os.path.join("C:\\Program Files", "SecretSpace Server",
                                   "PassMan-Server.exe")
    assert prefix == []


def test_from_source_the_task_runs_passman_server_py():
    program, prefix = passman_setup.server_command(frozen=False,
                                                   executable="python.exe")
    assert program == "python.exe"
    assert prefix[0].endswith("passman_server.py")


def test_the_setup_program_double_clicked_opens_the_menu(monkeypatch):
    seen = []
    monkeypatch.setattr(passman_setup, "main", seen.append)
    passman_server_setup_exe.main([])
    assert seen == [["menu"]]


# --- the menu ----------------------------------------------------------------

def test_the_menu_offers_network_port_and_the_token(tmp_path):
    run_setup(tmp_path, argv=["setup", "--host", "10.8.0.1", "--port", "9000"])
    out, _ = run_setup(tmp_path, answers=["4"], argv=["menu"])
    assert "Listening on 10.8.0.1:9000" in out
    assert "1) Change network, port or allowed addresses" in out
    assert "2) Replace the token" in out
    assert "3) Show the token" in out
    assert "4) Close" in out


def test_the_menu_replaces_the_token(tmp_path):
    run_setup(tmp_path, argv=["setup", "--host", "10.8.0.1", "--port", "9000"])
    old = (tmp_path / "token").read_text().strip()
    out, _ = run_setup(tmp_path, answers=["2", "y", "4"], argv=["menu"])
    new = (tmp_path / "token").read_text().strip()
    assert new != old and new in out


def test_the_menu_changes_the_port_then_comes_back(tmp_path):
    run_setup(tmp_path, argv=["setup", "--host", "10.8.0.1", "--port", "9000"])
    out, _ = run_setup(tmp_path, answers=["1", "", "9443", "", "3", "4"],
                       argv=["menu"])
    assert passman_setup.read_env(tmp_path / "sync.env")["PASSMAN_PORT"] == \
        "9443"
    # Back at the menu with the new port, and then the token was shown.
    assert "Listening on 10.8.0.1:9443" in out
    assert (tmp_path / "token").read_text().strip() in out


def test_the_menu_shows_a_problem_and_carries_on(tmp_path):
    out, _ = run_setup(tmp_path, answers=["3", "4"], argv=["menu"])
    assert "Not set up yet." in out
    assert "no token yet" in out           # show-token stopped; menu did not


def test_the_menu_asks_again_after_a_wrong_choice(tmp_path):
    out, _ = run_setup(tmp_path, answers=["9", "x", "4"], argv=["menu"])
    assert out.count("Type a number from 1 to 4.") == 2


def test_the_menu_closes_on_end_of_input(tmp_path):
    said = []

    def ask(prompt):
        raise EOFError
    passman_setup.main(["--config-dir", str(tmp_path), "--platform", "linux",
                        "menu"], ask=ask, say=said.append, run=FakeSystem())


def test_the_menu_does_not_add_a_second_press_enter(tmp_path):
    """An elevated relaunch always adds --pause; the menu has Close."""
    asked = []
    passman_setup.main(["--config-dir", str(tmp_path), "--platform", "linux",
                        "--pause", "menu"],
                       ask=lambda prompt: asked.append(prompt) or "4",
                       say=lambda line: None, run=FakeSystem())
    assert asked == ["Choice: "]


def test_the_setup_program_passes_commands_on(monkeypatch):
    seen = []
    monkeypatch.setattr(passman_setup, "main", seen.append)
    monkeypatch.setattr(passman_server, "main",
                        lambda a: pytest.fail("the server must not start"))
    passman_server_setup_exe.main(["--pause", "new-token"])
    assert seen == [["--pause", "new-token"]]


def test_the_server_exe_still_hands_old_commands_over(monkeypatch):
    """Installs from before the split uninstall with
    `PassMan-Server.exe remove`; that must keep working."""
    seen = []
    monkeypatch.setattr(passman_setup, "main", seen.append)
    passman_server_exe.main(["remove"])
    assert seen == [["remove"]]


def test_the_exe_sends_commands_to_setup_and_the_rest_to_the_server(
        monkeypatch):
    seen = []
    monkeypatch.setattr(passman_setup, "main", lambda a: seen.append(("setup", a)))
    monkeypatch.setattr(passman_server, "main",
                        lambda a: seen.append(("server", a)))
    passman_server_exe.main(["--pause", "new-token"])
    passman_server_exe.main(["--host", "0.0.0.0", "--port", "8787"])
    assert seen == [("setup", ["--pause", "new-token"]),
                    ("server", ["--host", "0.0.0.0", "--port", "8787"])]
