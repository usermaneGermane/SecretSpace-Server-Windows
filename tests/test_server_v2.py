"""
API v2 over HTTP: SecretSpace 3 accounts, sessions and per-vault blobs.

The server cannot decrypt anything, so these tests need no cryptography:
keysets and vaults are byte strings shaped like the client's (the right
magic and header, random "ciphertext"). The client's own tests check the
real thing end to end against a copy of this server.
"""

import os
import json
import base64
import struct

import pytest

# First: it puts server/ on the path, and brings the running-server fixture.
from test_server_http import TOKEN, server  # noqa: F401  (fixture)
import passman_server                                           # noqa: E402


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def keyset_blob(salt: bytes = None, kdf: int = 1, memory_kib: int = 65536,
                passes: int = 3, lanes: int = 1) -> str:
    """Shaped like account_crypto.seal_keyset: header, nonce, ciphertext."""
    salt = salt if salt is not None else os.urandom(16)
    header = struct.pack(">4sBBIBB16s", b"PMK3", 1, kdf, memory_kib, passes,
                         lanes, salt)
    return b64(header + os.urandom(12) + os.urandom(80))


def vault_blob(vault_id: str, generation: int = 0) -> str:
    """Shaped like account_crypto.encrypt_vault."""
    header = struct.pack(">4sB16sI", b"PMV3", 1, bytes.fromhex(vault_id),
                         generation)
    return b64(header + os.urandom(12) + os.urandom(64))


class Account:
    """What a client sends to make an account, kept to use it afterwards."""

    def __init__(self, username="alice"):
        self.username = username
        self.login_key = os.urandom(32)
        self.salt = os.urandom(16)
        self.keyset = keyset_blob(self.salt)
        self.recovery = keyset_blob(bytes(16), kdf=0, memory_kib=0, passes=0,
                                    lanes=0)
        self.public_key = os.urandom(32)
        self.vault = os.urandom(16).hex()

    def signup_body(self, **changes):
        body = {"username": self.username, "login_key": b64(self.login_key),
                "keyset": self.keyset, "recovery": self.recovery,
                "public_key": b64(self.public_key),
                "personal_vault": self.vault}
        body.update(changes)
        return body


def signup(server, account, token=TOKEN, **changes):
    return server.request("POST", "/v2/accounts", account.signup_body(**changes),
                          token=token)


def login(server, account, login_key=None, username=None):
    return server.request("POST", "/v2/login", {
        "username": username or account.username,
        "login_key": b64(login_key or account.login_key)}, token=None)


def session_for(server, account) -> str:
    status, _, body = login(server, account)
    assert status == 200, body
    return body["session"]


def put_vault(server, session, vault_id, blob, if_match=None):
    headers = {} if if_match is None else {"If-Match": if_match}
    return server.request("PUT", f"/v2/vaults/{vault_id}", {"blob": blob},
                          headers, token=session)


@pytest.fixture
def alice(server):
    account = Account("alice")
    status, _, body = signup(server, account)
    assert status == 201, body
    return account


# --- pre-login ---------------------------------------------------------------

def test_prelogin_gives_the_salt_and_cost_from_the_stored_keyset(server, alice):
    status, _, body = server.request("GET", "/v2/prelogin/alice", token=None)
    assert status == 200
    assert body["username"] == "alice"
    assert body["kdf"] == {"salt": b64(alice.salt), "memory_kib": 65536,
                           "passes": 3, "lanes": 1}


def test_prelogin_gives_the_stored_spelling_of_the_name(server, alice):
    """Keys are derived with the username, so a device must use its exact
    spelling; the pre-login tells it."""
    _, _, body = server.request("GET", "/v2/prelogin/ALICE", token=None)
    assert body["username"] == "alice"


def test_prelogin_for_no_such_account_looks_like_a_real_one(server, alice):
    _, _, first = server.request("GET", "/v2/prelogin/mallory", token=None)
    _, _, again = server.request("GET", "/v2/prelogin/mallory", token=None)
    _, _, other = server.request("GET", "/v2/prelogin/eve", token=None)
    assert first == again                        # stable: asking twice tells nothing
    assert first["kdf"]["salt"] != other["kdf"]["salt"]
    assert len(base64.b64decode(first["kdf"]["salt"])) == 16
    assert set(first["kdf"]) == {"salt", "memory_kib", "passes", "lanes"}


def test_prelogin_refuses_a_name_that_could_not_exist(server):
    status, _, _ = server.request("GET", "/v2/prelogin/..%2Fetc", token=None)
    assert status == 400


# --- sign-up -----------------------------------------------------------------

@pytest.mark.parametrize("token", [None, "wrong-token-of-a-decent-length"])
def test_signup_needs_the_servers_token(server, token):
    status, _, _ = signup(server, Account(), token=token)
    assert status == 401
    assert not os.path.exists(os.path.join(server.store.root, "_v2", "accounts"))


def test_signup_makes_the_account_and_its_personal_vault(server, alice):
    session = session_for(server, alice)
    status, _, me = server.request("GET", "/v2/me", token=session)
    assert status == 200
    assert me["username"] == "alice"
    assert me["keyset"] == alice.keyset and me["recovery"] == alice.recovery
    assert me["public_key"] == b64(alice.public_key)
    assert me["personal_vault"] == alice.vault
    assert me["vaults"] == [{"id": alice.vault, "kind": "personal",
                             "role": "owner", "revision": 0,
                             "key_generation": 0, "members": 1}]


@pytest.mark.parametrize("name", ["alice", "Alice", "ALICE"])
def test_a_name_is_taken_whatever_its_case(server, alice, name):
    other = Account(name)
    status, _, body = signup(server, other)
    assert status == 409
    assert "already an account" in body["error"]
    # ...and the first account is unchanged
    assert login(server, alice)[0] == 200


@pytest.mark.parametrize("change, reason", [
    ({"username": "../x"}, "username"),
    ({"username": "_v2"}, "username"),
    ({"login_key": b64(os.urandom(16))}, "login key"),
    ({"login_key": "not base64!"}, "login key"),
    ({"keyset": keyset_blob(kdf=0)}, "swapped"),
    ({"recovery": keyset_blob(kdf=1)}, "swapped"),
    ({"keyset": b64(b"PMV2" + os.urandom(80))}, "keyset"),
    ({"public_key": b64(os.urandom(31))}, "public key"),
    ({"personal_vault": "not-hex"}, "vault id"),
    ({"personal_vault": "AB" * 16}, "vault id"),
])
def test_signup_refuses_what_is_not_an_account(server, change, reason):
    status, _, body = signup(server, Account(), **change)
    assert status == 400, body
    assert reason in body["error"].lower()


def test_two_accounts_cannot_claim_one_vault(server, alice):
    other = Account("bob")
    other.vault = alice.vault
    status, _, _ = signup(server, other)
    assert status == 409


# --- logging in --------------------------------------------------------------

def test_a_wrong_login_key_and_no_such_account_answer_alike(server, alice):
    wrong = login(server, alice, login_key=os.urandom(32))
    missing = login(server, Account("nobody"))
    assert wrong[0] == missing[0] == 401
    assert wrong[2] == missing[2]


def test_login_wants_the_exact_spelling(server, alice):
    assert login(server, alice, username="Alice")[0] == 401


def test_a_disabled_account_cannot_log_in(server, alice):
    path = os.path.join(server.store.root, "_v2", "accounts", "alice.json")
    with open(path, encoding="utf-8") as f:
        record = json.load(f)
    session = session_for(server, alice)
    record["disabled"] = True
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f)
    assert login(server, alice)[0] == 401
    # a session from before is no longer accepted either
    assert server.request("GET", "/v2/me", token=session)[0] == 401


def test_too_many_wrong_logins_pause_the_account(server, alice):
    for _ in range(passman_server.MAX_LOGIN_FAILURES):
        assert login(server, alice, login_key=os.urandom(32))[0] == 401
    # paused: even the right key waits
    status, _, body = login(server, alice)
    assert status == 429 and "minute" in body["error"]


def test_the_pause_ends(server, alice, monkeypatch):
    for _ in range(passman_server.MAX_LOGIN_FAILURES):
        login(server, alice, login_key=os.urandom(32))
    later = passman_server.time.time() + passman_server.LOCKOUT_SECONDS + 1
    monkeypatch.setattr(passman_server.time, "time", lambda: later)
    assert login(server, alice)[0] == 200


def test_nothing_on_disk_logs_anyone_in(server, alice):
    """The login hash is not the Login Key, and sessions are stored hashed:
    a copy of the store opens no account."""
    session = session_for(server, alice)
    root = os.path.join(server.store.root, "_v2")
    everything = b""
    for folder, _, files in os.walk(root):
        for name in files:
            with open(os.path.join(folder, name), "rb") as f:
                everything += f.read() + name.encode()
    assert alice.login_key not in everything
    assert b64(alice.login_key).encode() not in everything
    assert session.encode() not in everything


# --- sessions ----------------------------------------------------------------

@pytest.mark.parametrize("token", [None, "", TOKEN, "x" * 43])
def test_v2_calls_need_a_session(server, alice, token):
    """Not even the server's token opens an account."""
    assert server.request("GET", "/v2/me", token=token)[0] == 401
    assert server.request("GET", f"/v2/vaults/{alice.vault}", token=token)[0] == 401


def test_a_session_expires(server, alice, monkeypatch):
    session = session_for(server, alice)
    later = passman_server.time.time() + passman_server.SESSION_SECONDS + 1
    monkeypatch.setattr(passman_server.time, "time", lambda: later)
    assert server.request("GET", "/v2/me", token=session)[0] == 401


def test_logout_ends_the_session(server, alice):
    session = session_for(server, alice)
    other = session_for(server, alice)
    assert server.request("POST", "/v2/logout", {}, token=session)[0] == 200
    assert server.request("GET", "/v2/me", token=session)[0] == 401
    assert server.request("GET", "/v2/me", token=other)[0] == 200


# --- the personal vault --------------------------------------------------------

def test_a_vault_follows_the_2x_revision_rules(server, alice):
    session = session_for(server, alice)
    status, _, body = server.request("GET", f"/v2/vaults/{alice.vault}",
                                     token=session)
    assert status == 200 and body["revision"] == 0 and body["blob"] is None

    first = vault_blob(alice.vault)
    assert put_vault(server, session, alice.vault, first)[0] == 200
    # thereafter If-Match is required, and must be current
    assert put_vault(server, session, alice.vault, vault_blob(alice.vault))[0] == 428
    assert put_vault(server, session, alice.vault, vault_blob(alice.vault), "0")[0] == 409
    second = vault_blob(alice.vault)
    status, _, meta = put_vault(server, session, alice.vault, second, "1")
    assert status == 200 and meta["revision"] == 2

    status, _, body = server.request("GET", f"/v2/vaults/{alice.vault}",
                                     token=session)
    assert body["blob"] == second and body["revision"] == 2
    status, _, meta = server.request("GET", f"/v2/vaults/{alice.vault}/meta",
                                     token=session)
    assert meta["revision"] == 2
    history = os.path.join(server.store.root, "_v2", "vaults", alice.vault,
                           "history")
    assert os.listdir(history) == ["00000001.enc"]
    # the account's view follows
    _, _, me = server.request("GET", "/v2/me", token=session)
    assert me["vaults"][0]["revision"] == 2


def test_a_vault_refuses_another_vaults_file(server, alice):
    session = session_for(server, alice)
    status, _, body = put_vault(server, session, alice.vault,
                                vault_blob(os.urandom(16).hex()))
    assert status == 400 and "another vault" in body["error"]


def test_a_vault_refuses_a_2x_vault(server, alice):
    session = session_for(server, alice)
    blob = b64(b"PMV2" + os.urandom(80))
    status, _, body = put_vault(server, session, alice.vault, blob)
    assert status == 400 and "SecretSpace 3" in body["error"]


def test_someone_elses_vault_is_not_there(server, alice):
    bob = Account("bob")
    assert signup(server, bob)[0] == 201
    bobs = session_for(server, bob)
    alices = session_for(server, alice)
    assert put_vault(server, alices, alice.vault, vault_blob(alice.vault))[0] == 200

    missing = server.request("GET", f"/v2/vaults/{os.urandom(16).hex()}", token=bobs)
    theirs = server.request("GET", f"/v2/vaults/{alice.vault}", token=bobs)
    assert missing[0] == theirs[0] == 404
    assert missing[2] == theirs[2]                 # no hint that it exists
    assert put_vault(server, bobs, alice.vault, vault_blob(alice.vault), "*")[0] == 404


def test_a_reader_cannot_write(server, alice):
    bob = Account("bob")
    assert signup(server, bob)[0] == 201
    members = os.path.join(server.store.root, "_v2", "vaults", alice.vault,
                           "members.json")
    with open(members, encoding="utf-8") as f:
        record = json.load(f)
    record["members"]["bob"] = {"role": "reader"}
    with open(members, "w", encoding="utf-8") as f:
        json.dump(record, f)
    bobs = session_for(server, bob)
    assert server.request("GET", f"/v2/vaults/{alice.vault}", token=bobs)[0] == 200
    status, _, body = put_vault(server, bobs, alice.vault, vault_blob(alice.vault))
    assert status == 403 and "read" in body["error"]


@pytest.mark.parametrize("path", ["/v2/vaults/../../accounts/alice",
                                  "/v2/vaults/ABC", "/v2/vaults/x/y/z",
                                  "/v2/nothing", "/v2/"])
def test_paths_that_are_not_endpoints(server, alice, path):
    session = session_for(server, alice)
    assert server.request("GET", path, token=session)[0] == 404


# --- changing the master password ---------------------------------------------

def test_a_new_password_replaces_the_login_and_ends_other_sessions(server, alice):
    this_device = session_for(server, alice)
    other_device = session_for(server, alice)
    new_key, new_salt = os.urandom(32), os.urandom(16)
    new_keyset = keyset_blob(new_salt)
    status, _, _ = server.request("PUT", "/v2/me/keyset", {
        "login_key": b64(new_key), "keyset": new_keyset}, token=this_device)
    assert status == 200

    assert login(server, alice)[0] == 401                     # old password
    assert login(server, alice, login_key=new_key)[0] == 200  # new one
    assert server.request("GET", "/v2/me", token=this_device)[0] == 200
    assert server.request("GET", "/v2/me", token=other_device)[0] == 401
    _, _, pre = server.request("GET", "/v2/prelogin/alice", token=None)
    assert pre["kdf"]["salt"] == b64(new_salt)
    _, _, me = server.request("GET", "/v2/me", token=this_device)
    assert me["keyset"] == new_keyset
    assert me["recovery"] == alice.recovery                   # untouched


def test_a_new_password_must_come_with_a_real_keyset(server, alice):
    session = session_for(server, alice)
    status, _, _ = server.request("PUT", "/v2/me/keyset", {
        "login_key": b64(os.urandom(32)), "keyset": keyset_blob(kdf=0)},
        token=session)
    assert status == 400
    assert login(server, alice)[0] == 200                     # unchanged


# --- 2.x beside it --------------------------------------------------------------

def test_2x_sync_is_untouched_by_accounts(server, alice):
    blob = b64(b"PMV2" + os.urandom(60))
    assert server.push("alice", blob)[0] == 200               # 2.x user "alice"
    status, _, body = server.pull("alice")
    assert body["blob"] == blob
    # the two "alice"s are unrelated: the account's vault is still empty
    session = session_for(server, alice)
    _, _, mine = server.request("GET", f"/v2/vaults/{alice.vault}", token=session)
    assert mine["blob"] is None
    # and no 2.x name can reach the v2 folder
    assert server.pull("_v2")[0] == 404


def test_a_session_does_not_open_2x_vaults(server, alice):
    session = session_for(server, alice)
    assert server.request("GET", "/vault/alice", token=session)[0] == 401


def test_health_says_which_apis(server):
    _, _, body = server.request("GET", "/health", token=None)
    assert body["api"] == [1, 2]
