"""
HTTPS: the server serving TLS, and the setup's `tls` command that turns it
on. Real certificates (made with openssl, skipped where there is none), real
TLS connections, a client that pins the certificate as the app does.
"""

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import types
import urllib.request

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "server"))
import secretspace_server                                       # noqa: E402
import secretspace_setup                                        # noqa: E402
from test_server_setup import FakeSystem, IP_JSON               # noqa: E402

OPENSSL = shutil.which("openssl")
needs_openssl = pytest.mark.skipif(OPENSSL is None, reason="no openssl here")
TOKEN = "a-token-that-is-long-enough-for-tests"


class Box(FakeSystem):
    """FakeSystem, except that openssl really runs."""

    def __call__(self, cmd):
        if os.path.basename(cmd[0]).lower().startswith("openssl"):
            self.calls.append(cmd)
            return subprocess.run(cmd, capture_output=True, text=True)
        return super().__call__(cmd)


def make_pair(folder, ips=("127.0.0.1",)):
    cert, key = os.path.join(folder, "server.crt"), os.path.join(folder, "server.key")
    problem = secretspace_setup.make_certificate(Box(), cert, key, list(ips),
                                                 ["localhost"])
    assert problem is None, problem
    return cert, key


@pytest.fixture
def https_server(tmp_path):
    """The real server with TLS on 127.0.0.1, and the certificate it uses."""
    if OPENSSL is None:
        pytest.skip("no openssl here")
    cert, key = make_pair(str(tmp_path))
    httpd = secretspace_server.bind("127.0.0.1", 0)
    httpd.store = secretspace_server.Store(str(tmp_path / "store"))
    httpd.token = TOKEN
    os.makedirs(httpd.store.root, exist_ok=True)
    httpd.ssl_context = secretspace_server.tls_context(cert, key)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    httpd.port = httpd.server_address[1]
    httpd.cert = cert
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def pinned(cert):
    """What the app does with its 'Certificate file': trust that one only."""
    return ssl.create_default_context(cafile=cert)


def health(port, context, timeout=5):
    with urllib.request.urlopen(f"https://127.0.0.1:{port}/health",
                                context=context, timeout=timeout) as reply:
        return json.loads(reply.read())


# ===========================================================================
# The server
# ===========================================================================
def test_https_answers_a_client_that_pins_its_certificate(https_server):
    assert health(https_server.port, pinned(https_server.cert))["ok"] is True


def test_a_client_with_another_certificate_is_refused(https_server, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    impostor, _ = make_pair(str(other))
    with pytest.raises(urllib.error.URLError) as e:
        health(https_server.port, pinned(impostor))
    assert isinstance(e.value.reason, ssl.SSLCertVerificationError)


def test_plain_http_to_the_https_port_gets_nothing_and_the_server_carries_on(
        https_server):
    with pytest.raises(Exception):
        urllib.request.urlopen(f"http://127.0.0.1:{https_server.port}/health",
                               timeout=5).read()
    assert health(https_server.port, pinned(https_server.cert))["ok"] is True


def test_a_client_that_never_finishes_the_handshake_blocks_nobody(https_server):
    """The handshake runs in the connection's own thread: a silent client
    must not hold up the next one."""
    silent = socket.create_connection(("127.0.0.1", https_server.port))
    try:
        started = time.monotonic()
        assert health(https_server.port, pinned(https_server.cert))["ok"]
        assert time.monotonic() - started < 3
    finally:
        silent.close()


def test_tls_older_than_1_2_is_refused(https_server):
    context = pinned(https_server.cert)
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
    except (ValueError, ssl.SSLError):
        pytest.skip("this OpenSSL cannot even offer TLS 1.1")
    with pytest.raises(Exception):
        health(https_server.port, context, timeout=3)


def test_the_api_works_over_https(https_server):
    """The 2.x route with the token, as an app would use it."""
    request = urllib.request.Request(
        f"https://127.0.0.1:{https_server.port}/vault/alice/meta",
        headers={"Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(request, context=pinned(https_server.cert),
                                timeout=5) as reply:
        assert json.loads(reply.read())["revision"] == 0


@pytest.mark.parametrize("flags,environ,expected", [
    ({}, {}, (None, None)),
    ({"cert": "a.crt", "key": "a.key"}, {}, ("a.crt", "a.key")),
    ({}, {"SECRETSPACE_CERT": "e.crt", "SECRETSPACE_KEY": "e.key"},
     ("e.crt", "e.key")),
    ({"cert": "a.crt", "key": "a.key"},
     {"SECRETSPACE_CERT": "e.crt", "SECRETSPACE_KEY": "e.key"},
     ("a.crt", "a.key")),
])
def test_the_certificate_comes_from_the_flags_else_the_settings(flags, environ,
                                                                 expected):
    args = types.SimpleNamespace(cert=flags.get("cert"), key=flags.get("key"))
    assert secretspace_server.resolve_tls(args, environ) == expected


@pytest.mark.parametrize("environ", [{"SECRETSPACE_CERT": "e.crt"},
                                     {"SECRETSPACE_KEY": "e.key"}])
def test_half_a_pair_stops_the_server_with_a_reason(environ):
    args = types.SimpleNamespace(cert=None, key=None)
    with pytest.raises(SystemExit) as stop:
        secretspace_server.resolve_tls(args, environ)
    assert "needs its" in str(stop.value)


# ===========================================================================
# The setup's `tls` command
# ===========================================================================
def setup(tmp_path, *argv, answers=(), box=None, platform="linux"):
    box = box or Box(active=True)
    answers = list(answers)
    said = []
    secretspace_setup.main(["--config-dir", str(tmp_path), "--platform",
                            platform, *argv],
                           ask=lambda prompt: answers.pop(0),
                           say=said.append, run=box)
    assert not answers, "not every answer was asked for"
    return "\n".join(said), box


@pytest.fixture(autouse=True)
def quiet_system(monkeypatch):
    monkeypatch.setattr(secretspace_setup, "port_in_use", lambda h, p: False)
    real = shutil.which
    monkeypatch.setattr(secretspace_setup.shutil, "which",
                        lambda name: real(name) if name == "openssl"
                        else "/bin/" + name)


@pytest.fixture
def set_up(tmp_path):
    """A server set up on every network (two of them in IP_JSON), port 9000."""
    setup(tmp_path, "setup", "--host", "0.0.0.0", "--port", "9000")
    return tmp_path


@needs_openssl
def test_tls_makes_a_certificate_for_every_address_and_turns_https_on(set_up):
    out, box = setup(set_up, "tls")
    cert, key = set_up / "server.crt", set_up / "server.key"
    assert cert.exists() and key.exists()
    assert not (set_up / "server.crt.new").exists()
    values = secretspace_setup.read_env(set_up / "sync.env")
    assert values["SECRETSPACE_CERT"] == str(cert)
    assert values["SECRETSPACE_KEY"] == str(key)
    assert values["SECRETSPACE_PORT"] == "9000"
    covered = secretspace_setup.certificate_addresses(str(cert))
    assert {"192.168.1.50", "10.8.0.1", "127.0.0.1"} <= set(covered)
    assert "SHA-256: " in out and "https://" in out
    assert box.restarted
    # What it made really serves TLS, with a client that pins it.
    context = secretspace_server.tls_context(str(cert), str(key))
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


@needs_openssl
def test_the_key_is_private_and_the_certificate_is_not(set_up):
    if os.name != "posix":
        pytest.skip("POSIX file modes")
    setup(set_up, "tls")
    assert (set_up / "server.key").stat().st_mode & 0o777 == 0o600
    assert (set_up / "server.crt").stat().st_mode & 0o777 == 0o644


@needs_openssl
def test_one_network_only_gets_a_certificate_for_that_address(tmp_path):
    setup(tmp_path, "setup", "--host", "10.8.0.1", "--port", "9000")
    setup(tmp_path, "tls")
    covered = secretspace_setup.certificate_addresses(
        str(tmp_path / "server.crt"))
    assert "10.8.0.1" in covered and "192.168.1.50" not in covered


@needs_openssl
def test_the_server_reads_what_tls_wrote(set_up):
    setup(set_up, "tls")
    values = secretspace_setup.read_env(set_up / "sync.env")
    args = types.SimpleNamespace(cert=None, key=None)
    assert secretspace_server.resolve_tls(args, values) == (
        str(set_up / "server.crt"), str(set_up / "server.key"))


@needs_openssl
def test_running_the_setup_again_keeps_https_on(set_up):
    setup(set_up, "tls")
    out, _ = setup(set_up, "setup", "--keep")
    values = secretspace_setup.read_env(set_up / "sync.env")
    assert values["SECRETSPACE_CERT"].endswith("server.crt")
    setup(set_up, "setup", "--host", "0.0.0.0", "--port", "9443")
    values = secretspace_setup.read_env(set_up / "sync.env")
    assert values["SECRETSPACE_PORT"] == "9443"
    assert values["SECRETSPACE_CERT"].endswith("server.crt")


@needs_openssl
def test_a_new_address_the_certificate_does_not_cover_is_named(set_up):
    setup(set_up, "tls")
    box = Box(active=True,
              ip_output=IP_JSON.replace("192.168.1.50", "192.168.1.77"))
    out, _ = setup(set_up, "setup", "--host", "192.168.1.77", "--port", "9000",
                   box=box)
    assert "does not cover 192.168.1.77" in out and "`tls` command again" in out


@needs_openssl
def test_tls_again_asks_then_replaces_the_certificate(set_up):
    setup(set_up, "tls")
    first = (set_up / "server.crt").read_bytes()
    out, _ = setup(set_up, "tls", answers=["n"])
    assert "Nothing changed." in out
    assert (set_up / "server.crt").read_bytes() == first
    setup(set_up, "tls", answers=["y"])
    assert (set_up / "server.crt").read_bytes() != first


def test_a_failed_openssl_leaves_the_working_certificate_alone(set_up, monkeypatch):
    (set_up / "server.crt").write_text("the working one")
    (set_up / "server.key").write_text("its key")
    before = (set_up / "sync.env").read_text()
    monkeypatch.setattr(secretspace_setup, "make_certificate",
                        lambda *a: "openssl could not make the certificate: boom")
    with pytest.raises(SystemExit) as stop:
        setup(set_up, "tls")
    assert "boom" in str(stop.value)
    assert (set_up / "server.crt").read_text() == "the working one"
    assert (set_up / "sync.env").read_text() == before
    assert not list(set_up.glob("*.new"))


def test_without_openssl_it_says_how_to_get_it(set_up, monkeypatch):
    monkeypatch.setattr(secretspace_setup.shutil, "which", lambda name: None)
    with pytest.raises(SystemExit) as stop:
        setup(set_up, "tls")
    assert "apt install openssl" in str(stop.value)


def test_tls_before_any_setup_says_so(tmp_path):
    with pytest.raises(SystemExit) as stop:
        setup(tmp_path, "tls")
    assert "Run the setup first" in str(stop.value)


def test_tls_for_this_machine_only_is_refused(tmp_path):
    setup(tmp_path, "setup", "--host", "127.0.0.1", "--port", "9000")
    with pytest.raises(SystemExit) as stop:
        setup(tmp_path, "tls")
    assert "this machine only" in str(stop.value)


@needs_openssl
def test_tls_off_goes_back_to_http_and_keeps_the_files(set_up):
    setup(set_up, "tls")
    out, box = setup(set_up, "tls", "off", answers=["y"])
    values = secretspace_setup.read_env(set_up / "sync.env")
    assert "SECRETSPACE_CERT" not in values and values["SECRETSPACE_PORT"] == "9000"
    assert (set_up / "server.crt").exists()
    assert box.restarted and "http://" in out


@needs_openssl
def test_tls_off_asks_first(set_up):
    setup(set_up, "tls")
    out, _ = setup(set_up, "tls", "off", answers=["n"])
    assert "Nothing changed." in out
    assert "SECRETSPACE_CERT" in secretspace_setup.read_env(set_up / "sync.env")


@needs_openssl
def test_tls_show_says_what_is_in_use(set_up):
    out, _ = setup(set_up, "tls", "show")
    assert "HTTPS is off" in out
    setup(set_up, "tls")
    out, box = setup(set_up, "tls", "show")
    assert "HTTPS is on" in out and "SHA-256:" in out and "10.8.0.1" in out
    assert not box.restarted


def test_the_windows_task_gets_the_certificate(tmp_path):
    args = secretspace_setup.task_arguments(
        r"C:\ProgramData\SecretSpace Server", "0.0.0.0", 9000, (),
        (r"C:\ProgramData\SecretSpace Server\server.crt",
         r"C:\ProgramData\SecretSpace Server\server.key"))
    assert '--cert "C:\\ProgramData\\SecretSpace Server\\server.crt"' in args
    assert '--key "C:\\ProgramData\\SecretSpace Server\\server.key"' in args
    plain = secretspace_setup.task_arguments(r"C:\x", "0.0.0.0", 9000)
    assert "--cert" not in plain


@needs_openssl
def test_on_windows_tls_updates_the_task_and_restarts_it(tmp_path, monkeypatch):
    monkeypatch.setattr(secretspace_setup, "is_admin", lambda platform: True)
    box = Box()
    setup(tmp_path, "setup", "--host", "0.0.0.0", "--port", "9000",
          platform="windows", box=box)
    out, box = setup(tmp_path, "tls", platform="windows", box=Box())
    assert box.ran("Register-ScheduledTask")
    assert any("--cert" in c and "server.crt" in c
               for c in box.ran("Register-ScheduledTask"))
    assert box.ran("Start-ScheduledTask")


# ===========================================================================
# migrate: HTTPS set up by hand in the old unit file is not lost
# ===========================================================================
def test_migrate_carries_a_certificate_from_the_old_unit(tmp_path):
    root = str(tmp_path)

    def write(rel, text):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    write("opt/passman/server/secretspace_server.py", "new")
    write("etc/passman/sync.env", "PASSMAN_HOST=0.0.0.0\nPASSMAN_PORT=59872\n")
    write("etc/passman/token", "t\n")
    write("etc/passman/server.crt", "c")
    write("etc/passman/server.key", "k")
    write("var/lib/passman/store/x", "v")
    write("etc/systemd/system/passman-sync.service",
          "[Service]\nExecStart=/usr/bin/python3 /opt/passman/server/passman_server.py \\\n"
          "    --store /var/lib/passman/store \\\n"
          "    --token-file /etc/passman/token \\\n"
          "    --cert /etc/passman/server.crt --key /etc/passman/server.key\n")
    said = []
    secretspace_setup.main(["--platform", "linux", "migrate", "--root", root,
                            "--yes"], ask=lambda p: "y", say=said.append,
                           run=Box())
    values = secretspace_setup.read_env(os.path.join(root, "etc/secretspace/sync.env"))
    assert values["SECRETSPACE_CERT"] == "/etc/secretspace/server.crt"
    assert values["SECRETSPACE_KEY"] == "/etc/secretspace/server.key"
    assert any("HTTPS" in line for line in said)


def test_unit_tls_reads_the_flags_or_nothing(tmp_path):
    unit = tmp_path / "u.service"
    unit.write_text("ExecStart=/x --store /s \\\n --cert /a.crt --key /a.key\n")
    assert secretspace_setup.unit_tls(str(unit)) == ("/a.crt", "/a.key")
    unit.write_text("ExecStart=/x --store /s --cert /a.crt\n")
    assert secretspace_setup.unit_tls(str(unit)) is None
    assert secretspace_setup.unit_tls(str(tmp_path / "missing")) is None


def test_a_half_made_certificate_is_cleaned_up(set_up, monkeypatch):
    """openssl wrote something, then failed: nothing of it stays behind."""
    def half(run, cert, key, ips, names):
        open(cert, "w").write("half")
        open(key, "w").write("half")
        return "openssl could not make the certificate: died half-way"
    monkeypatch.setattr(secretspace_setup, "make_certificate", half)
    with pytest.raises(SystemExit):
        setup(set_up, "tls")
    assert not list(set_up.glob("*.new"))
    assert not (set_up / "server.crt").exists()
    assert "SECRETSPACE_CERT" not in secretspace_setup.read_env(set_up / "sync.env")


def test_every_answer_arrives_whole_when_the_connection_ends(https_server):
    """
    Each request on its own connection, with a body the server does not
    read (it refuses the token first): over plain HTTP the server ends a
    connection with a graceful half-close, and over TLS it must too -- an
    abrupt close with unread data turns into a reset, and the answer it had
    already sent can be lost on the way (seen in CI: IncompleteRead).
    """
    import http.client
    context = pinned(https_server.cert)
    body = json.dumps({"blob": "x" * 50000})
    for _ in range(150):
        conn = http.client.HTTPSConnection("127.0.0.1", https_server.port,
                                           context=context, timeout=5)
        try:
            conn.request("PUT", "/vault/alice", body=body,
                         headers={"Authorization": "Bearer wrong-token",
                                  "Content-Type": "application/json"})
            reply = conn.getresponse()
            assert reply.status == 401
            assert json.loads(reply.read())["error"]
        finally:
            conn.close()


def test_every_answer_arrives_whole_over_plain_http_too(tmp_path):
    """The same graceful end for a plain connection."""
    import http.client
    httpd = secretspace_server.bind("127.0.0.1", 0)
    httpd.store = secretspace_server.Store(str(tmp_path / "store"))
    httpd.token = TOKEN
    os.makedirs(httpd.store.root, exist_ok=True)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        body = json.dumps({"blob": "x" * 50000})
        for _ in range(150):
            conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1],
                                              timeout=5)
            try:
                conn.request("PUT", "/vault/alice", body=body,
                             headers={"Authorization": "Bearer wrong-token"})
                reply = conn.getresponse()
                assert reply.status == 401
                assert json.loads(reply.read())["error"]
            finally:
                conn.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
