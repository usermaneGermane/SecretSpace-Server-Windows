"""
API v2: the signature kept with every wrapped vault key (2.0.0-alpha.5).

The server cannot check these signatures (standard library only) and does
not need to: a device does, before it takes a key. The server's part is to
store the signature with the key it came with, say who it came from -- the
account whose session sent it, never a name from the request -- and hand
both back.
"""

import os

import pytest

from test_server_http import TOKEN, server  # noqa: F401  (fixture)
from test_server_v2 import Account, alice, b64, session_for, signup  # noqa: F401
from test_server_v2_vaults import bob, create, made, wrapped_key  # noqa: F401
from test_server_v2_sharing import (carol, my_vault, post_rotate,  # noqa: F401
                                    put_member, rotate_body, state, team,
                                    team_up)
import passman_server                                           # noqa: E402


def sig(size: int = passman_server.KEY_SIG_LEN) -> str:
    return b64(os.urandom(size))


def put_key_sig(server, session, vault_id, body):
    status, _, answer = server.request(
        "PUT", f"/v2/vaults/{vault_id}/key-sig", body, token=session)
    return status, answer


def test_health_lists_signed_keys(server):
    _, _, body = server.request("GET", "/health", token=None)
    assert "signed-keys" in body["features"]


# --- creating a vault ---------------------------------------------------------
def test_a_vault_keeps_the_signature_it_was_made_with(server, alice):
    session = session_for(server, alice)
    signature = sig()
    status, view, sent = create(server, session, key_sig=signature)
    assert status == 201
    assert (view["key_sig"], view["key_signer"]) == (signature, "alice")
    mine = my_vault(server, session, sent["id"])
    assert (mine["key_sig"], mine["key_signer"]) == (signature, "alice")


def test_a_vault_made_without_a_signature_says_so(server, alice):
    session = session_for(server, alice)
    status, view, _ = create(server, session)
    assert status == 201
    assert view["key_sig"] == ""


@pytest.mark.parametrize("bad", [b64(os.urandom(63)), b64(os.urandom(65)),
                                 "not base64 !!", 12345])
def test_a_malformed_signature_is_refused_and_no_vault_is_made(server, alice, bad):
    session = session_for(server, alice)
    status, _, sent = create(server, session, key_sig=bad)
    assert status == 400
    assert my_vault(server, session, sent["id"]) is None


def test_the_signer_is_the_session_not_a_name_in_the_request(server, alice):
    session = session_for(server, alice)
    status, view, _ = create(server, session, key_sig=sig(), key_signer="mallory")
    assert status == 201
    assert view["key_signer"] == "alice"


# --- adding a member -----------------------------------------------------------
def test_a_new_member_gets_the_owners_signature_with_the_key(server, alice, bob):
    sa, sb = session_for(server, alice), session_for(server, bob)
    view, _ = made(server, sa)
    key, signature = wrapped_key(), sig()
    assert put_member(server, sa, view["id"], "bob", "editor", wrapped=key,
                      key_sig=signature)[0] == 200
    theirs = my_vault(server, sb, view["id"])
    assert (theirs["wrapped_key"], theirs["key_sig"], theirs["key_signer"]) == \
        (key, signature, "alice")


def test_a_bad_signature_adds_nobody(server, alice, bob):
    sa, sb = session_for(server, alice), session_for(server, bob)
    view, _ = made(server, sa)
    before = state(server, view["id"], "alice", "bob")
    assert put_member(server, sa, view["id"], "bob", "editor",
                      key_sig=b64(os.urandom(10)))[0] == 400
    assert state(server, view["id"], "alice", "bob") == before
    assert my_vault(server, sb, view["id"]) is None


def test_a_role_change_keeps_the_key_and_its_signature(server, alice, bob):
    sa, sb = session_for(server, alice), session_for(server, bob)
    view, _ = made(server, sa)
    signature = sig()
    put_member(server, sa, view["id"], "bob", "editor", key_sig=signature)
    before = my_vault(server, sb, view["id"])
    assert put_member(server, sa, view["id"], "bob", "reader", wrapped=None,
                      key_sig=sig())[0] == 200
    after = my_vault(server, sb, view["id"])
    assert (after["wrapped_key"], after["key_sig"], after["key_signer"]) == \
        (before["wrapped_key"], signature, "alice")


# --- changing the key ------------------------------------------------------------
def test_a_key_change_stores_each_members_new_signature(server, team_up):
    t = team_up
    body = rotate_body(t.vid, ["alice", "bob", "Carol"])
    body["key_sigs"] = {name: sig() for name in body["wrapped_keys"]}
    assert post_rotate(server, t.sa, t.vid, body)[0] == 200
    for name, session in (("alice", t.sa), ("bob", t.sb), ("Carol", t.sc)):
        mine = my_vault(server, session, t.vid)
        assert (mine["wrapped_key"], mine["key_sig"], mine["key_signer"]) == \
            (body["wrapped_keys"][name], body["key_sigs"][name], "alice")


def test_a_key_change_without_signatures_clears_the_old_ones(server, alice):
    sa = session_for(server, alice)
    status, view, sent = create(server, sa, key_sig=sig())
    body = rotate_body(sent["id"], ["alice"], revision=0)
    body.pop("blob"), body.pop("revision")
    assert post_rotate(server, sa, sent["id"], body)[0] == 200
    mine = my_vault(server, sa, sent["id"])
    # an old signature must not sit beside a key it was not made for
    assert mine["key_sig"] == "" and mine["wrapped_key"] == body["wrapped_keys"]["alice"]


@pytest.mark.parametrize("change", ["missing one", "one too many", "bad length",
                                    "not a dict"])
def test_signatures_that_do_not_fit_the_members_change_nothing(server, team_up,
                                                               change):
    t = team_up
    body = rotate_body(t.vid, ["alice", "bob", "Carol"])
    sigs = {name: sig() for name in body["wrapped_keys"]}
    if change == "missing one":
        sigs.pop("bob")
    elif change == "one too many":
        sigs["mallory"] = sig()
    elif change == "bad length":
        sigs["bob"] = b64(os.urandom(12))
    else:
        sigs = ["x"]
    body["key_sigs"] = sigs
    before = state(server, t.vid, "alice", "bob", "Carol")
    assert post_rotate(server, t.sa, t.vid, body)[0] == 400
    assert state(server, t.vid, "alice", "bob", "Carol") == before


# --- a member vouches for the key it holds (vaults from before signatures) ---------
def test_a_member_signs_its_own_unsigned_key_once(server, team):
    t = team
    signature = sig()
    assert put_key_sig(server, t.sb, t.vid, {"key_sig": signature})[0] == 200
    mine = my_vault(server, t.sb, t.vid)
    assert (mine["key_sig"], mine["key_signer"]) == (signature, "bob")
    # nobody else's entry changed
    assert my_vault(server, t.sa, t.vid)["key_sig"] == ""
    # and it cannot be replaced
    assert put_key_sig(server, t.sb, t.vid, {"key_sig": sig()})[0] == 409
    assert my_vault(server, t.sb, t.vid)["key_sig"] == signature


def test_a_key_signed_by_an_owner_is_not_replaced_by_the_member(server, alice, bob):
    sa, sb = session_for(server, alice), session_for(server, bob)
    view, _ = made(server, sa)
    signature = sig()
    put_member(server, sa, view["id"], "bob", "editor", key_sig=signature)
    assert put_key_sig(server, sb, view["id"], {"key_sig": sig()})[0] == 409
    mine = my_vault(server, sb, view["id"])
    assert (mine["key_sig"], mine["key_signer"]) == (signature, "alice")


@pytest.mark.parametrize("body", [{}, {"key_sig": ""}, {"key_sig": "!!"},
                                  {"key_sig": b64(os.urandom(63))}])
def test_a_missing_or_malformed_own_signature_is_refused(server, team, body):
    t = team
    before = state(server, t.vid, "alice", "bob", "Carol")
    assert put_key_sig(server, t.sb, t.vid, body or {"x": 1})[0] == 400
    assert state(server, t.vid, "alice", "bob", "Carol") == before


def test_only_a_member_can_sign_and_only_with_a_session(server, team):
    t = team
    outsider = Account("dave")
    assert signup(server, outsider)[0] == 201
    assert put_key_sig(server, session_for(server, outsider), t.vid,
                       {"key_sig": sig()})[0] == 404
    assert put_key_sig(server, None, t.vid, {"key_sig": sig()})[0] == 401
    status, _, _ = server.request("GET", f"/v2/vaults/{t.vid}/key-sig", token=t.sb)
    assert status == 404


def test_the_personal_vault_has_no_key_to_sign(server, alice):
    session = session_for(server, alice)
    assert put_key_sig(server, session, alice.vault, {"key_sig": sig()})[0] == 400
