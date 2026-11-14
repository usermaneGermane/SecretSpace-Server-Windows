"""
The account and vault formats over HTTP (server 2.1.0).

Format 1 is what SecretSpace 3 wrote, while the project was still called
PassMan; format 2 is what SecretSpace 4 writes. The server reads both,
because an account is converted by its owner's own device, one account at a
time. These tests pin the rules that keep that safe:

- a converted account never goes back to the old format;
- a vault is stored in the new form only when every member's account is
  converted, so nobody is locked out by someone else's update;
- a converted vault takes neither an upload in the old form nor a member
  whose app could not read it;
- the names from before the rename (settings, headers) are still read.
"""

import os
import struct

import pytest

from test_server_http import TOKEN, VAULT_1, server  # noqa: F401  (fixture)
from test_server_v2 import (Account, alice, b64, keyset_blob,  # noqa: F401
                            put_vault, session_for, signup, vault_blob)
from test_server_v2 import login
from test_server_v2_recovery import (Fresh, get_copy, proved,  # noqa: F401
                                     recover, recover_body, unb64)
from test_server_v2_sharing import (bob, carol, members,  # noqa: F401
                                    post_rotate, put_member, rotate_body,
                                    team, team_up)
import secretspace_server


def new_keyset(salt: bytes = None, kdf: int = 1) -> str:
    """Shaped like a format-2 keyset: the current marker, version 2."""
    salt = salt if salt is not None else os.urandom(16)
    cost = (65536, 3, 1) if kdf else (0, 0, 0)
    header = struct.pack(">4sBBIBB16s", b"SSK4", 2, kdf, *cost, salt)
    return b64(header + os.urandom(12) + os.urandom(275))


def new_vault(vault_id: str, generation: int = 0) -> str:
    header = struct.pack(">4sB16sI", b"SSV4", 1, bytes.fromhex(vault_id),
                         generation)
    return b64(header + os.urandom(12) + os.urandom(64))


def me(server, session):
    return server.request("GET", "/v2/me", token=session)[2]


def convert(server, account, session=None) -> str:
    """Send the account's keyset in the new format, as a converting device
    does. Returns a session that is still valid afterwards."""
    session = session or session_for(server, account)
    account.keyset = new_keyset(account.salt)
    status, _, body = server.request("PUT", "/v2/me/keyset", {
        "login_key": b64(account.login_key), "keyset": account.keyset},
        token=session)
    assert status == 200, body
    return session


# --- the account's format -----------------------------------------------------

def test_an_account_from_secretspace_3_is_format_1(server, alice):
    assert me(server, session_for(server, alice))["format"] == 1


def test_an_account_made_in_the_new_format_is_format_2(server):
    dana = Account("dana")
    dana.keyset = new_keyset(dana.salt)
    dana.recovery = new_keyset(bytes(16), kdf=0)
    assert signup(server, dana)[0] == 201
    assert me(server, session_for(server, dana))["format"] == 2


def test_a_record_without_a_format_counts_as_format_1(server, alice):
    """Accounts stored by server 2.0.0 have no such field."""
    store = secretspace_server.AccountStore(server.store.root)
    record = store.account("alice")
    assert record.pop("format") == 1
    store._write_json(store._account_path("alice"), record)
    assert me(server, session_for(server, alice))["format"] == 1


def test_sending_the_keyset_in_the_new_format_converts_the_account(server, alice):
    session = convert(server, alice)
    assert me(server, session)["format"] == 2
    assert me(server, session)["keyset"] == alice.keyset


def test_prelogin_still_gives_the_salt_after_a_conversion(server, alice):
    before = server.request("GET", "/v2/prelogin/alice", token=None)[2]
    convert(server, alice)
    assert server.request("GET", "/v2/prelogin/alice", token=None)[2] == before


def test_a_converted_account_does_not_go_back(server, alice):
    session = convert(server, alice)
    status, _, body = server.request("PUT", "/v2/me/keyset", {
        "login_key": b64(alice.login_key), "keyset": keyset_blob(alice.salt)},
        token=session)
    assert status == 409 and "Update SecretSpace" in body["error"]
    assert me(server, session)["format"] == 2
    assert me(server, session)["keyset"] == alice.keyset


def test_a_conversion_is_logged_as_one_not_as_a_password_change(server, alice):
    convert(server, alice)
    path = os.path.join(server.store.root, "_v2", "logins.log")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    assert "account_converted" in text and "password_changed" not in text


def test_a_later_password_change_is_logged_as_that(server, alice):
    session = convert(server, alice)
    alice.keyset = new_keyset()
    assert server.request("PUT", "/v2/me/keyset", {
        "login_key": b64(os.urandom(32)), "keyset": alice.keyset},
        token=session)[0] == 200
    path = os.path.join(server.store.root, "_v2", "logins.log")
    with open(path, encoding="utf-8") as f:
        assert "password_changed" in f.read()


def test_a_keyset_that_is_neither_format_is_refused(server, alice):
    session = session_for(server, alice)
    header = struct.pack(">4sBBIBB16s", b"XXK9", 1, 1, 65536, 3, 1, bytes(16))
    status, _, body = server.request("PUT", "/v2/me/keyset", {
        "login_key": b64(os.urandom(32)),
        "keyset": b64(header + os.urandom(100))}, token=session)
    assert status == 400 and "not a SecretSpace keyset" in body["error"]


def test_the_recovery_copy_may_stay_in_the_old_form_after_a_conversion(server, alice):
    """It opens only with the 12 words, which the converting device may not
    have been given yet."""
    before = alice.recovery
    convert(server, alice)
    assert get_copy(server, "alice")[2]["recovery"] == before
    assert unb64(before)[:4] != b"SSK4"


def test_the_recovery_copy_can_be_sent_in_the_new_form(server, alice):
    session = convert(server, alice)
    copy = new_keyset(bytes(16), kdf=0)
    assert server.request("PUT", "/v2/me/recovery", {"recovery": copy},
                          token=session)[0] == 200
    assert get_copy(server, "alice")[2]["recovery"] == copy


# --- a recovery, which also replaces the keyset --------------------------------

def test_a_recovery_from_an_updated_device_converts_the_account(server, proved):
    fresh = Fresh()
    fresh.keyset = new_keyset()
    fresh.recovery = new_keyset(bytes(16), kdf=0)
    assert recover(server, recover_body(proved, proved.proof, fresh))[0] == 200
    session = login(server, proved, login_key=fresh.login_key)[2]["session"]
    assert me(server, session)["format"] == 2


def test_a_recovery_from_an_old_app_leaves_an_old_account_as_it_is(server, proved):
    fresh = Fresh()
    assert recover(server, recover_body(proved, proved.proof, fresh))[0] == 200
    session = login(server, proved, login_key=fresh.login_key)[2]["session"]
    assert me(server, session)["format"] == 1


def test_a_recovery_cannot_take_a_converted_account_back(server, proved):
    session = convert(server, proved)
    fresh = Fresh()                      # an old app: the old form
    status, _, body = recover(server, recover_body(proved, proved.proof, fresh))
    assert status == 409 and "Update SecretSpace" in body["error"]
    assert me(server, session)["format"] == 2
    assert me(server, session)["keyset"] == proved.keyset
    assert login(server, proved, login_key=fresh.login_key)[0] == 401


# --- the personal vault ---------------------------------------------------------

def test_an_unconverted_account_cannot_store_its_vault_in_the_new_form(server, alice):
    session = session_for(server, alice)
    status, _, body = put_vault(server, session, alice.vault,
                                new_vault(alice.vault))
    assert status == 409 and "old format" in body["error"]
    assert server.request("GET", f"/v2/vaults/{alice.vault}/meta",
                          token=session)[2]["revision"] == 0


def test_a_converted_account_stores_its_vault_in_the_new_form(server, alice):
    session = convert(server, alice)
    status, _, body = put_vault(server, session, alice.vault,
                                new_vault(alice.vault))
    assert status == 200 and body["revision"] == 1


def test_a_converted_account_may_still_store_the_old_form_until_the_vault_converts(server, alice):
    """Its other device may not have converted its files yet."""
    session = convert(server, alice)
    assert put_vault(server, session, alice.vault,
                     vault_blob(alice.vault))[0] == 200


def test_a_converted_vault_refuses_the_old_form(server, alice):
    session = convert(server, alice)
    assert put_vault(server, session, alice.vault,
                     new_vault(alice.vault))[0] == 200
    status, _, body = put_vault(server, session, alice.vault,
                                vault_blob(alice.vault), "1")
    assert status == 409 and "Update SecretSpace" in body["error"]
    assert server.request("GET", f"/v2/vaults/{alice.vault}/meta",
                          token=session)[2]["revision"] == 1


def test_a_vault_that_is_neither_form_is_refused(server, alice):
    session = session_for(server, alice)
    header = struct.pack(">4sB16sI", b"XXV9", 1, bytes.fromhex(alice.vault), 0)
    status, _, body = put_vault(server, session, alice.vault,
                                b64(header + os.urandom(76)))
    assert status == 400 and "not a SecretSpace vault" in body["error"]


def test_the_new_form_must_still_name_its_own_vault(server, alice):
    session = convert(server, alice)
    other = os.urandom(16).hex()
    status, _, body = put_vault(server, session, alice.vault, new_vault(other))
    assert status == 400 and "another vault" in body["error"]


# --- a shared vault -------------------------------------------------------------

def test_the_members_list_says_who_has_converted(server, team):
    convert(server, team.alice, team.sa)
    body = members(server, team.sa, team.vid)[2]
    assert body["format"] == 1
    assert {m["username"]: m["format"] for m in body["members"]} == {
        "alice": 2, "bob": 1, "Carol": 1}


def test_a_shared_vault_stays_in_the_old_form_while_a_member_has_not_converted(server, team):
    convert(server, team.alice, team.sa)
    convert(server, team.bob, team.sb)
    status, _, body = put_vault(server, team.sa, team.vid, new_vault(team.vid))
    assert status == 409 and "Not every member" in body["error"]
    # ... and everyone, converted or not, still writes it in the old form.
    assert put_vault(server, team.sa, team.vid, vault_blob(team.vid))[0] == 200
    assert put_vault(server, team.sb, team.vid, vault_blob(team.vid), "1")[0] == 200


def test_a_shared_vault_converts_once_every_member_has(server, team):
    for account, session in ((team.alice, team.sa), (team.bob, team.sb),
                             (team.carol, team.sc)):
        convert(server, account, session)
    assert put_vault(server, team.sa, team.vid, new_vault(team.vid))[0] == 200
    assert members(server, team.sa, team.vid)[2]["format"] == 2
    status, _, body = put_vault(server, team.sb, team.vid,
                                vault_blob(team.vid), "1")
    assert status == 409 and "Update SecretSpace" in body["error"]


def test_a_key_change_may_convert_the_vault_when_everyone_who_stays_has(server, team_up):
    """Removing the member who has not updated, in the same step."""
    team = team_up
    convert(server, team.alice, team.sa)
    convert(server, team.bob, team.sb)
    body = rotate_body(team.vid, ["alice", "bob"], remove=["Carol"])
    body["blob"] = new_vault(team.vid, 1)
    status, view = post_rotate(server, team.sa, team.vid, body)
    assert status == 200, view
    assert members(server, team.sa, team.vid)[2]["format"] == 2


def test_a_key_change_cannot_convert_the_vault_past_a_member_who_stays(server, team_up):
    team = team_up
    convert(server, team.alice, team.sa)
    body = rotate_body(team.vid, ["alice", "bob", "Carol"])
    body["blob"] = new_vault(team.vid, 1)
    status, answer = post_rotate(server, team.sa, team.vid, body)
    assert status == 409 and "Not every member" in answer["error"]
    assert members(server, team.sa, team.vid)[2]["key_generation"] == 0


def test_a_converted_vault_does_not_take_a_member_who_has_not_updated(server, team):
    for account, session in ((team.alice, team.sa), (team.bob, team.sb),
                             (team.carol, team.sc)):
        convert(server, account, session)
    assert put_vault(server, team.sa, team.vid, new_vault(team.vid))[0] == 200
    erin = Account("erin")
    assert signup(server, erin)[0] == 201
    status, body = put_member(server, team.sa, team.vid, "erin", "editor")
    assert status == 409 and "update SecretSpace" in body["error"]
    convert(server, erin)
    assert put_member(server, team.sa, team.vid, "erin", "editor")[0] == 200


def test_an_unconverted_vault_still_takes_any_member(server, team):
    erin = Account("erin")
    assert signup(server, erin)[0] == 201
    assert put_member(server, team.sa, team.vid, "erin", "editor")[0] == 200


# --- the names from before the rename are still read ------------------------------

def test_the_old_key_generation_header_is_still_read(server):
    status, _, _ = server.push("alice", VAULT_1,
                               **{"X-PassMan-Key-Generation": "3"})
    assert status == 200
    assert server.store.meta("alice")["key_generation"] == 3


def test_the_current_header_wins_over_the_old_one(server):
    status, _, _ = server.push("alice", VAULT_1,
                               **{"X-SecretSpace-Key-Generation": "5",
                                  "X-PassMan-Key-Generation": "3"})
    assert status == 200
    assert server.store.meta("alice")["key_generation"] == 5


def test_the_old_drop_history_header_is_still_read(server):
    server.push("alice", VAULT_1)
    server.push("alice", VAULT_1, if_match="1")
    assert server.history("alice") != []
    status, _, _ = server.push("alice", VAULT_1, if_match="2",
                               **{"X-PassMan-Drop-History": "1"})
    assert status == 200
    assert server.history("alice") == []


@pytest.mark.parametrize("prefix", ["SECRETSPACE_", "PASSMAN_"])
def test_settings_are_read_under_the_current_and_the_old_prefix(prefix):
    environ = {prefix + "HOST": "10.0.0.5", prefix + "PORT": "9000"}
    assert secretspace_server.env_setting(environ, "HOST") == "10.0.0.5"
    assert secretspace_server.env_setting(environ, "PORT") == "9000"


def test_the_current_prefix_wins_over_the_old_one():
    environ = {"SECRETSPACE_PORT": "9001", "PASSMAN_PORT": "9000"}
    assert secretspace_server.env_setting(environ, "PORT") == "9001"


def test_the_server_does_not_call_itself_by_the_old_name(server):
    status, headers, body = server.request("GET", "/health", token=None)
    assert body["service"] == "secretspace-sync"
    assert "passman" not in (headers.get("Server") or "").lower()
    assert "format-2" in body["features"]
