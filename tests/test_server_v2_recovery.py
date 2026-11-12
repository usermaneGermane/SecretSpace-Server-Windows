"""
API v2, phase 5: recovering an account with its 12-word phrase, over HTTP.

The server cannot read keysets, so these tests use byte strings of the right
shape (a PMK3 header with kdf byte 1 for a keyset and 0 for a recovery copy).
What the server does check is covered here: the recovery proof is stored only
hashed and set once; a made-up recovery copy hides which names exist; a
successful recovery swaps the keys, ends every session of the account and is
logged; a refused request changes nothing on disk. Wrong proofs count with
wrong logins (one failure counter per name, shared by both calls).
"""

import os
import json
import base64
import struct

import pytest

# First: it puts server/ on the path, and brings the running-server fixture.
from test_server_http import TOKEN, server  # noqa: F401  (fixture)
from test_server_v2 import (Account, alice, b64, keyset_blob,  # noqa: F401
                            login, session_for, signup)
import passman_server                                           # noqa: E402


# --- helpers -----------------------------------------------------------------

def new_proof() -> bytes:
    return os.urandom(32)


def unb64(text) -> bytes:
    return base64.b64decode(text, validate=True)


def account_file(server, name="alice"):
    return os.path.join(server.store.root, "_v2", "accounts",
                        name.lower() + ".json")


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def record(server, name="alice"):
    return json.loads(read_bytes(account_file(server, name)))


def write_record(server, data, name="alice"):
    with open(account_file(server, name), "w", encoding="utf-8") as f:
        json.dump(data, f)


def logins_text(server):
    try:
        return read_bytes(os.path.join(server.store.root, "_v2",
                                       "logins.log")).decode("utf-8")
    except FileNotFoundError:
        return ""


def log_lines(server, event):
    lines = [json.loads(line) for line in logins_text(server).splitlines()
             if line.strip()]
    return [line for line in lines if line["event"] == event]


def recovery_blob() -> str:
    return keyset_blob(bytes(16), kdf=0, memory_kib=0, passes=0, lanes=0)


def client_sized_recovery() -> bytes:
    """A recovery copy with the body size of the real client's (a nonce, 133
    bytes of keyset JSON and a tag), which the Account helper does not make."""
    header = struct.pack(">4sBBIBB16s", b"PMK3", 1, 0, 0, 0, 0, bytes(16))
    return header + os.urandom(12 + 133 + 16)


def with_proof(server, account, proof=None):
    """Sign `account` up with a recovery proof; returns the proof."""
    proof = proof or new_proof()
    assert signup(server, account, recovery_proof=b64(proof))[0] == 201
    return proof


class Fresh:
    """What a device sends after recovering: a new Login Key, keyset and phrase."""

    def __init__(self):
        self.login_key = os.urandom(32)
        self.keyset = keyset_blob()
        self.recovery = recovery_blob()


def recover_body(account, proof, fresh=None, **changes):
    fresh = fresh or Fresh()
    body = {"username": account.username, "recovery_proof": b64(proof),
            "login_key": b64(fresh.login_key), "keyset": fresh.keyset,
            "recovery": fresh.recovery}
    body.update(changes)
    return body


def recover(server, body):
    return server.request("POST", "/v2/recovery", body, token=None)


def get_me(server, session):
    return server.request("GET", "/v2/me", token=session)


def get_copy(server, name):
    return server.request("GET", f"/v2/recovery/{name}", token=None)


def put_proof(server, session, value):
    return server.request("PUT", "/v2/me/recovery-proof",
                          {"recovery_proof": value}, token=session)


def put_recovery(server, session, value):
    return server.request("PUT", "/v2/me/recovery", {"recovery": value},
                          token=session)


@pytest.fixture
def proved(server):
    """alice, signed up with a proof (kept as .proof)."""
    account = Account("alice")
    account.proof = with_proof(server, account)
    return account


@pytest.fixture
def small_lockout(monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_LOGIN_FAILURES", 3)
    return 3


# --- health ------------------------------------------------------------------

def test_health_lists_vaults_sharing_and_recovery(server):
    _, _, body = server.request("GET", "/health", token=None)
    assert body["features"] == ["vaults", "sharing", "recovery"]


# --- sign-up with a proof ----------------------------------------------------

def test_signup_without_a_proof_still_works_and_cannot_recover(server, alice):
    _, _, me = get_me(server, session_for(server, alice))
    assert me["can_recover"] is False


def test_signup_with_a_proof_can_recover(server, proved):
    _, _, me = get_me(server, session_for(server, proved))
    assert me["can_recover"] is True


def test_signup_keeps_the_proof_only_as_a_hash(server, proved):
    stored = read_bytes(account_file(server))
    assert proved.proof not in stored
    assert b64(proved.proof).encode() not in stored
    assert set(record(server)["recovery_check"]) == {"salt", "hash", "n", "r", "p"}


@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_signup_refuses_a_proof_of_the_wrong_length(server, size):
    status, _, _ = signup(server, Account(), recovery_proof=b64(os.urandom(size)))
    assert status == 400
    assert not os.path.exists(account_file(server))


def test_signup_refuses_a_proof_that_is_not_base64(server):
    assert signup(server, Account(), recovery_proof="not base64!!")[0] == 400
    assert not os.path.exists(account_file(server))


# --- PUT /v2/me/recovery-proof -----------------------------------------------

def test_a_proof_can_be_set_later_by_an_older_account(server, alice):
    session = session_for(server, alice)
    assert put_proof(server, session, b64(new_proof()))[0] == 200
    assert get_me(server, session)[2]["can_recover"] is True


def test_a_proof_set_later_is_stored_only_as_a_hash(server, alice):
    proof = new_proof()
    put_proof(server, session_for(server, alice), b64(proof))
    stored = read_bytes(account_file(server))
    assert proof not in stored and b64(proof).encode() not in stored


def test_setting_the_same_proof_again_is_fine(server, proved):
    session = session_for(server, proved)
    assert put_proof(server, session, b64(proved.proof))[0] == 200


def test_the_same_proof_again_changes_nothing_on_disk(server, proved):
    session = session_for(server, proved)
    before = read_bytes(account_file(server))
    put_proof(server, session, b64(proved.proof))
    assert read_bytes(account_file(server)) == before


def test_a_different_proof_is_refused_and_the_first_stays(server, proved):
    session = session_for(server, proved)
    before = read_bytes(account_file(server))
    status, _, body = put_proof(server, session, b64(new_proof()))
    assert status == 409 and "cannot be replaced" in body["error"]
    assert read_bytes(account_file(server)) == before
    assert recover(server, recover_body(proved, proved.proof))[0] == 200


def test_the_first_proof_set_later_is_the_one_that_counts(server, alice):
    session = session_for(server, alice)
    first = new_proof()
    assert put_proof(server, session, b64(first))[0] == 200
    assert put_proof(server, session, b64(new_proof()))[0] == 409
    assert recover(server, recover_body(alice, first))[0] == 200


@pytest.mark.parametrize("value", [b64(b"short"), b64(os.urandom(33)), "", None,
                                   "%%%not-base64%%%"])
def test_a_proof_of_the_wrong_shape_is_refused(server, alice, value):
    session = session_for(server, alice)
    before = read_bytes(account_file(server))
    assert put_proof(server, session, value)[0] == 400
    assert read_bytes(account_file(server)) == before


@pytest.mark.parametrize("token", [None, "", TOKEN, "x" * 43])
def test_setting_a_proof_needs_a_session(server, alice, token):
    assert put_proof(server, token, b64(new_proof()))[0] == 401
    assert "recovery_check" not in record(server) or record(server)["recovery_check"] is None


# --- PUT /v2/me/recovery -----------------------------------------------------

def test_a_new_recovery_copy_replaces_the_old_one(server, alice):
    session = session_for(server, alice)
    new = recovery_blob()
    assert put_recovery(server, session, new)[0] == 200
    assert get_me(server, session)[2]["recovery"] == new
    assert get_copy(server, "alice")[2]["recovery"] == new


def test_a_new_recovery_copy_leaves_keyset_and_login_alone(server, alice):
    session = session_for(server, alice)
    put_recovery(server, session, recovery_blob())
    assert get_me(server, session)[2]["keyset"] == alice.keyset
    assert login(server, alice)[0] == 200


def test_a_new_recovery_copy_leaves_the_proof_alone(server, proved):
    put_recovery(server, session_for(server, proved), recovery_blob())
    assert recover(server, recover_body(proved, proved.proof))[0] == 200


def test_a_new_recovery_copy_keeps_the_session(server, alice):
    session = session_for(server, alice)
    put_recovery(server, session, recovery_blob())
    assert get_me(server, session)[0] == 200


def test_a_new_recovery_copy_is_logged_without_its_content(server, alice):
    new = recovery_blob()
    put_recovery(server, session_for(server, alice), new)
    lines = log_lines(server, "recovery_phrase_changed")
    assert len(lines) == 1 and lines[0]["by"] == "alice"
    assert new not in logins_text(server)


@pytest.mark.parametrize("make", [
    lambda: keyset_blob(),                       # a keyset (kdf byte 1)
    lambda: b64(os.urandom(100)),                # junk
    lambda: b64(b"XXXX" + os.urandom(80)),       # wrong magic
    lambda: b64(b"PMK3"),                        # far too short
    lambda: "%%%not base64%%%",
    lambda: None,
], ids=["keyset", "junk", "wrong-magic", "short", "not-base64", "missing"])
def test_a_blob_that_is_not_a_recovery_copy_is_refused_and_nothing_changes(server, alice, make):
    session = session_for(server, alice)
    before = read_bytes(account_file(server))
    logged = logins_text(server)
    assert put_recovery(server, session, make())[0] == 400
    assert read_bytes(account_file(server)) == before
    assert logins_text(server) == logged


@pytest.mark.parametrize("token", [None, "", TOKEN])
def test_changing_the_recovery_copy_needs_a_session(server, alice, token):
    before = read_bytes(account_file(server))
    assert put_recovery(server, token, recovery_blob())[0] == 401
    assert read_bytes(account_file(server)) == before


# --- GET /v2/recovery/<name> -------------------------------------------------

def test_the_recovery_copy_of_an_account_needs_no_login(server, alice):
    status, _, body = get_copy(server, "alice")
    assert status == 200
    assert body == {"username": "alice", "recovery": alice.recovery}


def test_the_recovery_copy_lookup_ignores_case_and_gives_the_servers_spelling(server):
    account = Account("Alice")
    signup(server, account)
    _, _, body = get_copy(server, "aLiCe")
    assert body == {"username": "Alice", "recovery": account.recovery}


def test_the_recovery_copy_of_an_unknown_name_is_made_up_but_the_same_shape(server, alice):
    status, _, body = get_copy(server, "mallory")
    assert status == 200
    assert set(body) == {"username", "recovery"}
    assert body["username"] == "mallory"
    raw = unb64(body["recovery"])
    assert raw[:4] == b"PMK3" and raw[5] == 0


def test_the_made_up_copy_is_the_same_on_every_ask(server):
    assert get_copy(server, "mallory")[2] == get_copy(server, "mallory")[2]


def test_the_made_up_copy_does_not_depend_on_letter_case(server):
    assert (get_copy(server, "Mallory")[2]["recovery"]
            == get_copy(server, "mallory")[2]["recovery"])


def test_the_made_up_copy_differs_between_names(server):
    assert (get_copy(server, "mallory")[2]["recovery"]
            != get_copy(server, "eve")[2]["recovery"])


def test_the_made_up_copy_depends_on_a_key_only_the_server_has(server):
    first = get_copy(server, "mallory")[2]["recovery"]
    os.remove(os.path.join(server.store.root, "_v2", "server.key"))
    assert get_copy(server, "mallory")[2]["recovery"] != first


def test_the_made_up_copy_has_the_length_of_a_clients_real_one(server):
    """The real client's copy is a header, a nonce, 133 bytes of keyset JSON
    and a tag."""
    account = Account("real")
    account.recovery = b64(client_sized_recovery())
    assert signup(server, account)[0] == 201
    real = unb64(get_copy(server, "real")[2]["recovery"])
    made = unb64(get_copy(server, "nobody")[2]["recovery"])
    assert len(made) == len(real)


def test_the_made_up_copy_length_against_the_account_test_helper(server, alice):
    """Recorded, not required to match: the Account helper's copy has a
    92-byte body (120 bytes in all), the client's and the made-up one 161
    (189 in all)."""
    real = unb64(get_copy(server, "alice")[2]["recovery"])
    made = unb64(get_copy(server, "nobody")[2]["recovery"])
    assert (len(real), len(made)) == (28 + 12 + 80, 28 + 12 + 133 + 16)


def test_a_disabled_account_answers_like_an_unknown_name(server, alice):
    data = record(server)
    data["disabled"] = True
    write_record(server, data)
    status, _, body = get_copy(server, "alice")
    assert status == 200
    assert body["recovery"] != alice.recovery
    assert body["recovery"] == get_copy(server, "alice")[2]["recovery"]
    raw = unb64(body["recovery"])
    assert raw[:4] == b"PMK3" and raw[5] == 0
    assert len(raw) == 28 + 12 + 133 + 16


@pytest.mark.parametrize("name", ["..%2Fetc", "a%2Fb", "%20", "x" * 200])
def test_the_recovery_copy_of_an_invalid_name_is_400(server, name):
    assert get_copy(server, name)[0] == 400


# --- POST /v2/recovery: the good path -----------------------------------------

def test_recovery_with_the_right_proof_works(server, proved):
    status, _, body = recover(server, recover_body(proved, proved.proof))
    assert status == 200 and body == {"username": "alice"}


def test_after_recovery_the_new_login_key_logs_in_and_the_old_one_does_not(server, proved):
    fresh = Fresh()
    assert recover(server, recover_body(proved, proved.proof, fresh))[0] == 200
    assert login(server, proved, login_key=fresh.login_key)[0] == 200
    assert login(server, proved)[0] == 401


def test_after_recovery_me_shows_the_new_keyset_and_recovery(server, proved):
    fresh = Fresh()
    recover(server, recover_body(proved, proved.proof, fresh))
    _, _, body = login(server, proved, login_key=fresh.login_key)
    me = get_me(server, body["session"])[2]
    assert me["keyset"] == fresh.keyset and me["recovery"] == fresh.recovery
    assert me["keyset"] != proved.keyset


def test_after_recovery_prelogin_gives_the_new_salt(server, proved):
    fresh = Fresh()
    fresh.keyset = keyset_blob(b"\x07" * 16)
    recover(server, recover_body(proved, proved.proof, fresh))
    _, _, body = server.request("GET", "/v2/prelogin/alice", token=None)
    assert body["kdf"]["salt"] == b64(b"\x07" * 16)


def test_after_recovery_the_recovery_lookup_gives_the_new_copy(server, proved):
    fresh = Fresh()
    recover(server, recover_body(proved, proved.proof, fresh))
    assert get_copy(server, "alice")[2]["recovery"] == fresh.recovery


def test_recovery_wants_the_exact_spelling_of_the_name(server):
    """Like login: the name the account was made with."""
    account = Account("Alice")
    proof = with_proof(server, account)
    assert recover(server, recover_body(account, proof, username="alice"))[0] == 401
    assert recover(server, recover_body(account, proof))[0] == 200


def test_the_proof_still_works_for_a_second_recovery(server, proved):
    assert recover(server, recover_body(proved, proved.proof))[0] == 200
    assert recover(server, recover_body(proved, proved.proof))[0] == 200


def test_recovery_ends_every_earlier_session_of_the_account(server, proved):
    first, second = session_for(server, proved), session_for(server, proved)
    recover(server, recover_body(proved, proved.proof))
    assert get_me(server, first)[0] == 401
    assert get_me(server, second)[0] == 401


def test_recovery_leaves_other_accounts_sessions_alone(server, proved):
    bob = Account("bob")
    signup(server, bob)
    bobs = session_for(server, bob)
    recover(server, recover_body(proved, proved.proof))
    assert get_me(server, bobs)[0] == 200


def test_recovery_keeps_the_personal_vault_and_public_key(server, proved):
    fresh = Fresh()
    recover(server, recover_body(proved, proved.proof, fresh))
    session = login(server, proved, login_key=fresh.login_key)[2]["session"]
    me = get_me(server, session)[2]
    assert me["personal_vault"] == proved.vault
    assert me["public_key"] == b64(proved.public_key)
    assert me["can_recover"] is True


def test_recovery_is_logged_without_the_proof_or_the_login_key(server, proved):
    fresh = Fresh()
    recover(server, recover_body(proved, proved.proof, fresh))
    lines = log_lines(server, "account_recovered")
    assert len(lines) == 1 and lines[0]["by"] == "alice"
    text = logins_text(server)
    for secret in (proved.proof, fresh.login_key):
        assert b64(secret) not in text
    assert log_lines(server, "recovery_failed") == []


def test_the_new_login_key_and_the_proof_are_stored_only_as_hashes(server, proved):
    fresh = Fresh()
    recover(server, recover_body(proved, proved.proof, fresh))
    stored = read_bytes(account_file(server))
    for secret in (fresh.login_key, proved.proof):
        assert secret not in stored and b64(secret).encode() not in stored


def test_recovery_needs_no_token_and_no_session(server, proved):
    assert recover(server, recover_body(proved, proved.proof))[0] == 200


# --- POST /v2/recovery: refusals ---------------------------------------------

def test_a_wrong_proof_is_401_and_changes_nothing(server, proved):
    session = session_for(server, proved)
    before = read_bytes(account_file(server))
    status, _, body = recover(server, recover_body(proved, new_proof()))
    assert status == 401 and "recovery phrase" in body["error"]
    assert read_bytes(account_file(server)) == before
    assert login(server, proved)[0] == 200
    assert get_me(server, session)[0] == 200


def test_an_unknown_name_gets_the_same_401_as_a_wrong_proof(server, proved):
    _, _, wrong = recover(server, recover_body(proved, new_proof()))
    status, _, unknown = recover(server, recover_body(Account("ghost"), new_proof()))
    assert status == 401 and unknown == wrong
    assert not os.path.exists(account_file(server, "ghost"))


def test_an_account_without_a_proof_is_409_and_says_to_sync_once(server, alice):
    before = read_bytes(account_file(server))
    status, _, body = recover(server, recover_body(alice, new_proof()))
    assert status == 409 and "sync it once" in body["error"]
    assert read_bytes(account_file(server)) == before


def test_a_disabled_account_cannot_be_recovered(server, proved):
    data = record(server)
    data["disabled"] = True
    write_record(server, data)
    before = read_bytes(account_file(server))
    assert recover(server, recover_body(proved, proved.proof))[0] == 401
    assert read_bytes(account_file(server)) == before


def test_a_disabled_account_without_a_proof_is_401_not_409(server, alice):
    data = record(server)
    data["disabled"] = True
    write_record(server, data)
    assert recover(server, recover_body(alice, new_proof()))[0] == 401


@pytest.mark.parametrize("change", [
    {"recovery_proof": None},
    {"recovery_proof": b64(os.urandom(31))},
    {"recovery_proof": b64(os.urandom(33))},
    {"recovery_proof": "%%%"},
    {"login_key": None},
    {"login_key": b64(os.urandom(31))},
    {"login_key": b64(os.urandom(33))},
    {"keyset": recovery_blob()},                  # a recovery copy (kdf 0)
    {"keyset": b64(os.urandom(100))},
    {"keyset": None},
    {"recovery": keyset_blob()},                  # a keyset (kdf 1)
    {"recovery": b64(os.urandom(100))},
    {"recovery": None},
    {"username": "../etc"},
    {"username": ""},
    {"username": None},
    {"username": 5},
], ids=["no-proof", "short-proof", "long-proof", "bad-b64-proof", "no-key",
        "short-key", "long-key", "keyset-is-recovery", "junk-keyset",
        "no-keyset", "recovery-is-keyset", "junk-recovery", "no-recovery",
        "bad-name", "empty-name", "null-name", "number-name"])
def test_bad_input_is_400_and_changes_nothing(server, proved, change):
    session = session_for(server, proved)
    before = read_bytes(account_file(server))
    assert recover(server, recover_body(proved, proved.proof, **change))[0] == 400
    assert read_bytes(account_file(server)) == before
    assert get_me(server, session)[0] == 200
    assert log_lines(server, "account_recovered") == []


def test_bad_input_does_not_count_as_a_wrong_attempt(server, proved, small_lockout):
    for _ in range(small_lockout + 2):
        recover(server, recover_body(proved, proved.proof, login_key=None))
    assert recover(server, recover_body(proved, proved.proof))[0] == 200


def test_a_body_that_is_not_json_is_refused(server, proved):
    status, _, _ = server.request("POST", "/v2/recovery", "not json", token=None)
    assert status == 400


# --- the failure log ---------------------------------------------------------

def test_a_wrong_proof_is_logged_with_its_status(server, proved):
    recover(server, recover_body(proved, new_proof()))
    lines = log_lines(server, "recovery_failed")
    assert len(lines) == 1
    assert lines[0]["by"] == "alice" and lines[0]["status"] == 401


def test_an_account_without_a_proof_is_logged_as_409(server, alice):
    recover(server, recover_body(alice, new_proof()))
    assert [x["status"] for x in log_lines(server, "recovery_failed")] == [409]


def test_a_bad_request_is_logged_as_400(server, proved):
    recover(server, recover_body(proved, proved.proof, login_key=None))
    assert [x["status"] for x in log_lines(server, "recovery_failed")] == [400]


def test_an_invalid_name_is_logged_as_a_question_mark(server, proved):
    recover(server, recover_body(proved, proved.proof, username="../x"))
    assert log_lines(server, "recovery_failed")[0]["by"] == "?"


def test_the_failure_log_holds_no_proof(server, proved):
    wrong = new_proof()
    recover(server, recover_body(proved, wrong))
    assert b64(wrong) not in logins_text(server)


# --- lock-out ----------------------------------------------------------------

def test_too_many_wrong_proofs_pause_recovery_even_for_the_right_one(server, proved, small_lockout):
    for _ in range(small_lockout):
        assert recover(server, recover_body(proved, new_proof()))[0] == 401
    status, _, body = recover(server, recover_body(proved, proved.proof))
    assert status == 429 and "minute" in body["error"]
    assert log_lines(server, "recovery_failed")[-1]["status"] == 429


def test_one_wrong_proof_fewer_than_the_limit_does_not_pause(server, proved, small_lockout):
    for _ in range(small_lockout - 1):
        recover(server, recover_body(proved, new_proof()))
    assert recover(server, recover_body(proved, proved.proof))[0] == 200


def test_the_recovery_pause_ends(server, proved, small_lockout, monkeypatch):
    for _ in range(small_lockout):
        recover(server, recover_body(proved, new_proof()))
    later = passman_server.time.time() + passman_server.LOCKOUT_SECONDS + 1
    monkeypatch.setattr(passman_server.time, "time", lambda: later)
    assert recover(server, recover_body(proved, proved.proof))[0] == 200


def test_a_successful_recovery_clears_the_failure_count(server, proved, small_lockout):
    for _ in range(small_lockout - 1):
        recover(server, recover_body(proved, new_proof()))
    assert recover(server, recover_body(proved, proved.proof))[0] == 200
    for _ in range(small_lockout - 1):
        recover(server, recover_body(proved, new_proof()))
    assert recover(server, recover_body(proved, proved.proof))[0] == 200


def test_wrong_logins_count_toward_the_recovery_pause(server, proved, small_lockout):
    """Observed: logins and recoveries share one counter per name."""
    for _ in range(small_lockout):
        login(server, proved, login_key=os.urandom(32))
    assert recover(server, recover_body(proved, proved.proof))[0] == 429


def test_wrong_proofs_count_toward_the_login_pause(server, proved, small_lockout):
    for _ in range(small_lockout):
        recover(server, recover_body(proved, new_proof()))
    assert login(server, proved)[0] == 429


def test_the_pause_is_per_name(server, proved, small_lockout):
    bob = Account("bob")
    bob.proof = with_proof(server, bob)
    for _ in range(small_lockout):
        recover(server, recover_body(proved, new_proof()))
    assert recover(server, recover_body(bob, bob.proof))[0] == 200


def test_the_pause_ignores_letter_case_of_the_name(server, proved, small_lockout):
    for _ in range(small_lockout):
        recover(server, recover_body(proved, new_proof(), username="ALICE"))
    assert recover(server, recover_body(proved, proved.proof))[0] == 429


def test_a_name_with_no_account_can_also_be_paused(server, small_lockout):
    ghost = Account("ghost")
    for _ in range(small_lockout):
        assert recover(server, recover_body(ghost, new_proof()))[0] == 401
    assert recover(server, recover_body(ghost, new_proof()))[0] == 429


def test_an_all_zero_proof_does_not_open_an_account_without_a_proof(server, alice):
    """The server compares unknown accounts against a hash of 32 zero bytes
    (to take the same time); that must never let a zero proof in."""
    before = read_bytes(account_file(server))
    assert recover(server, recover_body(alice, bytes(32)))[0] == 409
    assert read_bytes(account_file(server)) == before
    assert login(server, alice)[0] == 200


def test_an_all_zero_proof_does_not_open_an_unknown_name(server):
    assert recover(server, recover_body(Account("ghost"), bytes(32)))[0] == 401
    assert not os.path.exists(account_file(server, "ghost"))
