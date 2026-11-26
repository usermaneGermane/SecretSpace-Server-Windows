"""The version handshake, the server's half (9c)."""

import http.client
import json
import os
import sys
import threading

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "server"))

import secretspace_server                                       # noqa: E402
from version import __version__                                 # noqa: E402

H = secretspace_server.HEADER_CLIENT


@pytest.fixture
def server(tmp_path):
    httpd = secretspace_server.SyncServer(
        ("127.0.0.1", 0), secretspace_server.Handler)
    httpd.store = secretspace_server.Store(str(tmp_path / "store"))
    httpd.token = "test-token-that-is-long-enough"
    os.makedirs(httpd.store.root, exist_ok=True)
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()

    def ask(method, path, client=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1],
                                       timeout=10)
        headers = {"Authorization": "Bearer " + httpd.token}
        if client is not None:
            headers[H] = client
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        text = r.read()
        c.close()
        try:
            return r.status, json.loads(text)
        except ValueError:
            return r.status, {}
    yield ask
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def test_health_says_the_version_and_the_oldest_apps(server):
    status, body = server("GET", "/health")
    assert status == 200 and body["version"] == __version__
    assert body["min_client"] == {"windows": "4.0.0", "linux": "2.0.0"}


def test_health_answers_an_app_that_is_too_old(server):
    """So that it can read why."""
    assert server("GET", "/health", "windows/3.9.9")[0] == 200


@pytest.mark.parametrize("method, path", [
    ("GET", "/v2/me"), ("GET", "/vault/me"), ("PUT", "/vault/me"),
    ("PUT", "/v2/me/keyset"), ("POST", "/v2/login"), ("DELETE", "/v2/vaults/x")])
def test_an_app_that_is_too_old_is_refused_everywhere_else(server, method, path):
    status, body = server(method, path, "windows/3.9.9",
                          "{}" if method in ("PUT", "POST") else None)
    assert status == 426
    assert "4.0.0 or newer" in body["error"]
    assert server(method, path, "windows/4.0.0",
                  "{}" if method in ("PUT", "POST") else None)[0] != 426


@pytest.mark.parametrize("client, refused", [
    (None, False), ("", False), ("windows/4.0.0", False),
    ("windows/3.99.99", True), ("windows/10.0.0", False),
    ("linux/2.0.0", False), ("linux/1.9.0", True),
    ("android/0.0.1", False),            # a kind this server knows no limit for
    ("windows/4", False), ("windows/1.0.0 x", False), ("WINDOWS/1.0.0", False),
    ("windows/99999.0.0", False), ("\u0663", False)])
def test_who_is_refused(client, refused):
    assert bool(secretspace_server.refused_client(client)) is refused


def test_without_a_version_file_it_says_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(secretspace_server, "__file__", str(tmp_path / "s.py"))
    assert secretspace_server.read_version() == ""


@pytest.mark.parametrize("method, path", [
    ("GET", "/v2/me"), ("GET", "/vault/me"), ("PUT", "/vault/me"),
    ("PUT", "/v2/me/keyset"), ("POST", "/v2/login"), ("DELETE", "/v2/vaults/x")])
def test_a_refused_request_does_nothing_else(server, monkeypatch, method, path):
    """Not even store the upload it just refused."""
    did = []
    for name in ("_v2", "_send_blob", "_store_blob"):
        monkeypatch.setattr(secretspace_server.Handler, name,
                            lambda self, *a, _n=name: did.append(_n))
    server(method, path, "windows/3.9.9",
           "{}" if method in ("PUT", "POST") else None)
    assert did == []
