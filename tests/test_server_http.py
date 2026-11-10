"""
The sync server over HTTP, with no client in the way.

The clients' end-to-end tests (sourceFiles/tests/test_sync_server.py in both
client repositories) run this same server, but only ever send what a
well-behaved client sends. This file talks to it directly, so it also reaches
the refusals that exist for a broken, outdated or hostile client: a push
without If-Match, an oversized or malformed body, a path that is not a vault,
two pushes racing for the same revision.

Standard library only, like the server. Every test gets its own server on a
free port of 127.0.0.1 and its own store in a temporary folder.
"""

import os
import sys
import json
import time
import base64
import socket
import threading
import http.client

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

import passman_server                                           # noqa: E402

TOKEN = "test-token-that-is-long-enough"

#: Not a real vault -- the server cannot tell -- but shaped like one: "PMV2"
#: and comfortably above MIN_BLOB_BYTES.
VAULT_1 = base64.b64encode(b"PMV2" + bytes(range(60))).decode()
VAULT_2 = base64.b64encode(b"PMV2" + bytes(range(1, 61))).decode()


class Server:
    """A running server and the few calls the tests make to it."""

    def __init__(self, httpd):
        self.httpd = httpd
        self.port = httpd.server_address[1]
        self.store = httpd.store

    def request(self, method, path, body=None, headers=None, token=TOKEN):
        """Send one request; return (status, headers, decoded JSON or None)."""
        headers = dict(headers or {})
        if token is not None:
            headers.setdefault("Authorization", f"Bearer {token}")
        if isinstance(body, dict):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read()
        finally:
            conn.close()
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = None
        return response.status, response.headers, payload

    def push(self, user, blob, if_match=None, **headers):
        if if_match is not None:
            headers["If-Match"] = if_match
        return self.request("PUT", f"/vault/{user}", {"blob": blob}, headers)

    def pull(self, user):
        return self.request("GET", f"/vault/{user}")

    def history(self, user):
        folder = os.path.join(self.store.root, user, "history")
        if not os.path.isdir(folder):
            return []
        return sorted(os.listdir(folder))


@pytest.fixture
def server(tmp_path):
    """A real ThreadingHTTPServer on a free port, torn down after the test."""
    httpd = passman_server.ThreadingHTTPServer(
        ("127.0.0.1", 0), passman_server.Handler)
    httpd.store = passman_server.Store(str(tmp_path / "store"))
    httpd.token = TOKEN
    os.makedirs(httpd.store.root, exist_ok=True)
    # serve_forever notices shutdown() only between polls; the default half
    # second, paid once per test, would be most of this file's run time.
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield Server(httpd)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


# --- the token ----------------------------------------------------------------

def test_health_answers_without_a_token(server):
    status, _, body = server.request("GET", "/health", token=None)
    assert status == 200
    assert body == {"ok": True, "service": "passman-sync", "api": [1, 2]}


@pytest.mark.parametrize("header", [
    None,                                   # no Authorization at all
    "Bearer wrong-token-of-a-decent-length",
    f"Basic {TOKEN}",                       # right secret, wrong scheme
    TOKEN,                                  # right secret, no scheme
    f"bearer {TOKEN}",                      # the scheme is matched exactly
    "Bearer ",
])
def test_everything_but_health_needs_the_token(server, header):
    headers = {} if header is None else {"Authorization": header}
    for method, path in (("GET", "/vault/alice"),
                         ("GET", "/vault/alice/meta"),
                         ("PUT", "/vault/alice")):
        body = None                     # refused before any body is read
        status, _, payload = server.request(method, path, body, headers,
                                            token=None)
        assert status == 401, (method, path)
        assert "token" in payload["error"].lower()
    assert server.store.exists("alice") is False


def test_the_token_is_checked_before_the_path(server):
    """A caller without the token cannot even learn which paths exist."""
    status, _, _ = server.request("GET", "/no/such/thing", token=None)
    assert status == 401


def test_the_right_token_is_let_in(server):
    status, _, body = server.request("GET", "/vault/alice/meta")
    assert status == 200
    assert body["revision"] == 0


# --- paths ------------------------------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("GET", "/"),
    ("GET", "/vault"),
    ("GET", "/vault/"),
    ("GET", "/vault/alice/history"),
    ("GET", "/vault/alice/meta/extra"),
    ("GET", "/vaults/alice"),
    ("PUT", "/vault/alice/meta"),           # meta is read-only
    ("PUT", "/health"),
])
def test_anything_but_a_vault_or_its_meta_is_not_found(server, method, path):
    body = None                         # refused before any body is read
    status, _, _ = server.request(method, path, body)
    assert status == 404


@pytest.mark.parametrize("user", [
    "..", ".hidden", "-dash-first", "a%2Fb", "a%2e%2e", "con", "NUL", "com1",
    "lpt9", "x" * 64,
])
def test_a_dangerous_or_impossible_username_is_refused(server, user):
    for method in ("GET", "PUT"):
        body = None                     # refused before any body is read
        status, _, _ = server.request(method, f"/vault/{user}", body)
        assert status == 404, (method, user)
    assert os.listdir(server.store.root) == []


def test_a_path_cannot_climb_out_of_the_store(server):
    status, _, _ = server.request("PUT", "/vault/../outside")
    assert status == 404
    assert not os.path.exists(os.path.join(server.store.root, "..", "outside"))


def test_the_longest_allowed_username_works(server):
    user = "a" * 63
    status, _, _ = server.push(user, VAULT_1)
    assert status == 200
    assert server.store.exists(user)


def test_a_query_string_does_not_change_the_route(server):
    server.push("alice", VAULT_1)
    status, _, body = server.request("GET", "/vault/alice/meta?x=1")
    assert status == 200 and body["revision"] == 1
    status, _, _ = server.request("GET", "/health?x=1", token=None)
    assert status == 200


@pytest.mark.parametrize("method", ["POST", "DELETE", "PATCH"])
def test_methods_other_than_get_and_put_are_not_served(server, method):
    server.push("alice", VAULT_1)
    status, _, _ = server.request(method, "/vault/alice")
    assert status == 501
    assert server.store.read("alice") == VAULT_1.encode()


# --- reading ----------------------------------------------------------------

def test_a_user_who_never_pushed_reads_as_revision_zero(server):
    status, _, body = server.pull("nobody-yet")
    assert status == 200
    assert body["revision"] == 0 and body["blob"] is None
    status, _, meta = server.request("GET", "/vault/nobody-yet/meta")
    assert status == 200
    assert meta == {"revision": 0, "sha256": "", "updated_at": "", "size": 0,
                    "key_generation": 0}
    assert os.listdir(server.store.root) == []       # reading creates nothing


def test_what_is_pushed_comes_back_unchanged(server):
    status, _, pushed = server.push("alice", VAULT_1)
    assert status == 200
    status, _, pulled = server.pull("alice")
    assert status == 200
    assert pulled["blob"] == VAULT_1
    assert pulled["revision"] == pushed["revision"] == 1
    assert pulled["sha256"] == pushed["sha256"]
    assert pulled["size"] == len(VAULT_1)


def test_meta_never_carries_the_blob(server):
    server.push("alice", VAULT_1)
    _, _, meta = server.request("GET", "/vault/alice/meta")
    assert "blob" not in meta
    assert meta["revision"] == 1


def test_users_do_not_see_each_others_vaults(server):
    server.push("alice", VAULT_1)
    _, _, body = server.pull("bob")
    assert body["blob"] is None and body["revision"] == 0


@pytest.mark.parametrize("method,path,token", [
    ("GET", "/health", None),
    ("GET", "/vault/alice", TOKEN),
    ("GET", "/vault/alice/meta", TOKEN),
    ("GET", "/vault/alice", "wrong-token-of-a-decent-length"),   # an error
    ("GET", "/nowhere", TOKEN),                                  # an error
])
def test_no_answer_may_be_cached(server, method, path, token):
    """A proxy or browser cache must never keep a copy of a vault."""
    server.push("alice", VAULT_1)
    _, headers, _ = server.request(method, path, token=token)
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Type"] == "application/json"


# --- If-Match: no blind overwrites -------------------------------------------

def test_the_first_push_needs_no_if_match(server):
    status, _, meta = server.push("alice", VAULT_1)
    assert status == 200 and meta["revision"] == 1


def test_a_later_push_without_if_match_is_refused(server):
    """
    The check that stops a client which never read the vault from replacing
    it. Clients always send If-Match, so only this file reaches it.
    """
    server.push("alice", VAULT_1)
    status, _, body = server.push("alice", VAULT_2)
    assert status == 428
    assert "If-Match" in body["error"]
    assert server.store.read("alice") == VAULT_1.encode()
    assert server.store.meta("alice")["revision"] == 1


def test_a_push_against_the_current_revision_is_accepted(server):
    server.push("alice", VAULT_1)
    status, _, meta = server.push("alice", VAULT_2, if_match="1")
    assert status == 200 and meta["revision"] == 2
    assert server.store.read("alice") == VAULT_2.encode()


def test_a_quoted_revision_is_accepted_like_an_etag(server):
    server.push("alice", VAULT_1)
    status, _, meta = server.push("alice", VAULT_2, if_match='"1"')
    assert status == 200 and meta["revision"] == 2


@pytest.mark.parametrize("stale", ["0", "2", "abc", "-1"])
def test_a_push_against_any_other_revision_is_refused(server, stale):
    server.push("alice", VAULT_1)
    status, _, body = server.push("alice", VAULT_2, if_match=stale)
    assert status == 409
    assert "revision 1" in body["error"]
    assert server.store.read("alice") == VAULT_1.encode()
    assert server.store.meta("alice")["revision"] == 1


def test_if_match_star_overwrites_on_purpose(server):
    server.push("alice", VAULT_1)
    server.push("alice", VAULT_1, if_match="1")
    status, _, meta = server.push("alice", VAULT_2, if_match="*")
    assert status == 200 and meta["revision"] == 3
    assert server.store.read("alice") == VAULT_2.encode()


def test_two_pushes_racing_for_one_revision_cannot_both_win(server,
                                                            monkeypatch):
    """
    Check-then-write must be one step. The store's write is slowed down here
    so that, without the server's lock, both pushes would pass the revision
    check before either had written -- and one PC's changes would vanish.
    """
    server.push("alice", VAULT_1)
    real_write = passman_server.Store.write

    def slow_write(self, *args, **kwargs):
        time.sleep(0.3)
        return real_write(self, *args, **kwargs)

    monkeypatch.setattr(passman_server.Store, "write", slow_write)

    results = []
    start = threading.Barrier(2)

    def push(blob):
        start.wait()
        results.append(server.push("alice", blob, if_match="1")[0])

    threads = [threading.Thread(target=push, args=(blob,))
               for blob in (VAULT_1, VAULT_2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert sorted(results) == [200, 409]
    assert server.store.meta("alice")["revision"] == 2


# --- what a push must look like ---------------------------------------------

def raw_put(server, body, content_length=None):
    """A PUT whose Content-Length the test sets, true or not."""
    headers = {"Content-Type": "application/json"}
    if content_length is not None:
        headers["Content-Length"] = str(content_length)
    return server.request("PUT", "/vault/alice", body, headers)


@pytest.mark.parametrize("body,expected", [
    ("not json at all", "JSON"),
    ('{"vault": "x"}', "JSON"),                          # no "blob"
    ('{"blob": 12345}', "JSON"),                         # not a string
    ('["blob"]', "JSON"),
    ('{"blob": "caf\\u00e9"}', "JSON"),                  # not ASCII
    ('{"blob": "!!!not base64!!!"}', "base64"),
    ('{"blob": "%s"}' % base64.b64encode(b"short").decode(), "too short"),
])
def test_a_body_that_is_not_a_vault_is_refused(server, body, expected):
    status, _, payload = raw_put(server, body)
    assert status == 400
    assert expected in payload["error"]
    assert server.store.exists("alice") is False


def test_an_empty_body_is_refused(server):
    status, _, payload = raw_put(server, b"", content_length=0)
    assert status == 400 and "Empty" in payload["error"]


def test_a_nonsense_content_length_is_refused(server):
    status, _, payload = raw_put(server, b"", content_length="lots")
    assert status == 400 and "Content-Length" in payload["error"]


def test_a_body_larger_than_any_vault_is_refused_unread(server):
    """Refused on the declared length alone, before reading a byte of it."""
    status, _, payload = raw_put(server, b"",
                                 content_length=passman_server.MAX_BODY + 1)
    assert status == 413
    assert server.store.exists("alice") is False


def test_a_refused_push_leaves_the_stored_vault_alone(server):
    server.push("alice", VAULT_1)
    raw_put(server, '{"blob": "!!!"}')
    assert server.store.read("alice") == VAULT_1.encode()
    assert server.store.meta("alice")["revision"] == 1
    assert server.history("alice") == []


# --- history ----------------------------------------------------------------

def test_each_push_keeps_the_revision_it_replaces(server):
    server.push("alice", VAULT_1)
    server.push("alice", VAULT_2, if_match="1")
    assert server.history("alice") == ["00000001.enc"]
    kept = os.path.join(server.store.root, "alice", "history", "00000001.enc")
    with open(kept, "rb") as f:
        assert f.read() == VAULT_1.encode()


def test_only_the_newest_revisions_are_kept(server, monkeypatch):
    monkeypatch.setattr(passman_server, "HISTORY_LIMIT", 3)
    server.push("alice", VAULT_1)
    for revision in range(1, 6):
        status, _, _ = server.push("alice", VAULT_2, if_match=str(revision))
        assert status == 200
    # Revisions 1-5 went to the history as they were replaced; 6 is live.
    assert server.history("alice") == ["00000003.enc", "00000004.enc",
                                       "00000005.enc"]


def test_the_history_limit_is_twenty(server):
    server.push("alice", VAULT_1)
    for revision in range(1, 23):
        server.push("alice", VAULT_2, if_match=str(revision))
    history = server.history("alice")
    assert len(history) == 20
    assert history[0] == "00000003.enc" and history[-1] == "00000022.enc"


def test_drop_history_clears_every_earlier_revision(server):
    """Asked for after a password change: the old copies use the old one."""
    server.push("alice", VAULT_1)
    server.push("alice", VAULT_2, if_match="1")
    server.push("alice", VAULT_1, if_match="2")
    assert len(server.history("alice")) == 2
    status, _, meta = server.push("alice", VAULT_2, if_match="3",
                                  **{"X-PassMan-Drop-History": "1"})
    assert status == 200 and meta["revision"] == 4
    assert server.history("alice") == []      # not even revision 3 is kept
    assert server.store.read("alice") == VAULT_2.encode()


def test_drop_history_only_means_1(server):
    server.push("alice", VAULT_1)
    server.push("alice", VAULT_2, if_match="1",
                **{"X-PassMan-Drop-History": "yes"})
    assert server.history("alice") == ["00000001.enc"]


# --- key generation ---------------------------------------------------------

def test_a_key_generation_is_stored_and_kept_until_changed(server):
    _, _, meta = server.push("alice", VAULT_1,
                             **{"X-PassMan-Key-Generation": "2"})
    assert meta["key_generation"] == 2
    _, _, meta = server.push("alice", VAULT_2, if_match="1")   # header left out
    assert meta["key_generation"] == 2
    _, _, meta = server.push("alice", VAULT_1, if_match="2",
                             **{"X-PassMan-Key-Generation": "3"})
    assert meta["key_generation"] == 3
    _, _, pulled = server.pull("alice")
    assert pulled["key_generation"] == 3


@pytest.mark.parametrize("generation", ["-1", "two", "1.5", ""])
def test_a_nonsense_key_generation_is_refused(server, generation):
    status, _, body = server.push("alice", VAULT_1,
                                  **{"X-PassMan-Key-Generation": generation})
    assert status == 400
    assert "Key-Generation" in body["error"]
    assert server.store.exists("alice") is False


# --- the access log ---------------------------------------------------------

def test_the_log_names_the_request_but_never_the_body_or_token(server,
                                                               capsys):
    server.push("alice", VAULT_1)
    log = capsys.readouterr().err
    assert "PUT /vault/alice" in log
    assert VAULT_1 not in log
    assert TOKEN not in log


def test_the_log_leaves_out_the_query_string(server, capsys):
    """passman_server.Handler.log_message promises this."""
    server.request("GET", "/vault/alice/meta?leak=something-private")
    server.request("GET", "/health?also=private-too", token=None)
    log = capsys.readouterr().err
    assert '"GET /vault/alice/meta HTTP/1.1" 200' in log
    assert '"GET /health HTTP/1.1" 200' in log
    assert "private" not in log


@pytest.mark.parametrize("line", [b"GARBAGE", b"GET", b"GET /x?q HTTP/9.9",
                                  b"\x00\xff"])
def test_a_garbled_request_is_refused_and_the_server_carries_on(server,
                                                                line):
    with socket.create_connection(("127.0.0.1", server.port), timeout=10) as s:
        # Only the line: the server refuses it before reading further, and
        # bytes left unread when it closes can turn the close into a reset
        # that loses the answer.
        s.sendall(line + b"\r\n")
        # Read until the server closes: headers and page may arrive apart.
        answer = b""
        while chunk := s.recv(4096):
            answer += chunk
    # Some Python versions answer a line without an HTTP version
    # HTTP/0.9-style, with no status line; every version sends the error
    # page. Either way it is an error, never a vault.
    assert b"Error code" in answer and b"blob" not in answer
    status, _, _ = server.request("GET", "/health", token=None)
    assert status == 200
