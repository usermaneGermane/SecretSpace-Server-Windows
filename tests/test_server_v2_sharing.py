"""
API v2, phase 4: sharing a vault, roles, key change and the audit log, over
HTTP.

As in the other v2 test files, the server cannot read what it stores, so keys,
names and vault files are byte strings of the right shape. The tests that
refuse a request also check that nothing changed on disk: a half-done key
change would be worse than none.
"""

import os
import json
import struct

import pytest

# First: it puts server/ on the path, and brings the running-server fixture.
from test_server_http import TOKEN, server  # noqa: F401  (fixture)
from test_server_v2 import (Account, alice, b64, keyset_blob,  # noqa: F401
                            login, put_vault, session_for, signup, vault_blob)
from test_server_v2_vaults import (bob, create, create_body, made, me,  # noqa: F401
                                   new_id, sealed_name, vault_dir, wrapped_key)
import passman_server                                           # noqa: E402


@pytest.fixture
def carol(server):
    account = Account("Carol")
    assert signup(server, account)[0] == 201
    return account


class Team:
    """alice owns a vault; bob is an editor in it, Carol a reader."""


@pytest.fixture
def team(server, alice, bob, carol):
    t = Team()
    t.alice, t.bob, t.carol = alice, bob, carol
    t.sa = session_for(server, alice)
    t.sb = session_for(server, bob)
    t.sc = session_for(server, carol)
    t.view, t.sent = made(server, t.sa)
    t.vid = t.view["id"]
    assert put_member(server, t.sa, t.vid, "bob", "editor")[0] == 200
    assert put_member(server, t.sa, t.vid, "Carol", "reader")[0] == 200
    return t


@pytest.fixture
def team_up(server, team):
    """The same team, after three uploads (revision 3, two in history)."""
    assert put_vault(server, team.sa, team.vid, vault_blob(team.vid))[0] == 200
    for rev in ("1", "2"):
        assert put_vault(server, team.sa, team.vid, vault_blob(team.vid),
                         if_match=rev)[0] == 200
    return team


# --- helpers -------------------------------------------------------------------

def put_member(server, session, vault_id, name, role, wrapped="new", **changes):
    body = {"role": role}
    if wrapped == "new":
        body["wrapped_key"] = wrapped_key()
    elif wrapped is not None:
        body["wrapped_key"] = wrapped
    body.update(changes)
    body = {k: v for k, v in body.items() if v is not None}
    status, _, answer = server.request(
        "PUT", f"/v2/vaults/{vault_id}/members/{name}", body, token=session)
    return status, answer


def members(server, session, vault_id):
    return server.request("GET", f"/v2/vaults/{vault_id}/members", token=session)


def api_log(server, session, vault_id):
    return server.request("GET", f"/v2/vaults/{vault_id}/log", token=session)


def my_vault(server, session, vault_id):
    """This account's view of one vault in /v2/me, or None."""
    for each in me(server, session)["vaults"]:
        if each["id"] == vault_id:
            return each
    return None


def file_lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def vault_log_path(server, vault_id):
    return os.path.join(vault_dir(server, vault_id), "audit.log")


def logins_path(server):
    return os.path.join(server.store.root, "_v2", "logins.log")


def state(server, vault_id, *names):
    """Every file of a vault (except its log) and of the named accounts."""
    out = {}
    base = vault_dir(server, vault_id)
    for root, _, files in os.walk(base):
        for each in files:
            if each == "audit.log":
                continue
            path = os.path.join(root, each)
            with open(path, "rb") as f:
                out[os.path.relpath(path, base)] = f.read()
    for name in names:
        path = os.path.join(server.store.root, "_v2", "accounts",
                            name.lower() + ".json")
        with open(path, "rb") as f:
            out["account:" + name] = f.read()
    return out


def rotate_body(vault_id, staying, remove=(), generation=1, revision=3):
    body = {"generation": generation,
            "wrapped_keys": {name: wrapped_key() for name in staying},
            "name": sealed_name(),
            "blob": vault_blob(vault_id, generation),
            "revision": revision}
    if remove:
        body["remove"] = list(remove)
    return body


def post_rotate(server, session, vault_id, body):
    status, _, answer = server.request(
        "POST", f"/v2/vaults/{vault_id}/rotate", body, token=session)
    return status, answer


# --- /health and the account's keys ----------------------------------------------

def test_health_lists_sharing(server):
    _, _, body = server.request("GET", "/health", token=None)
    assert "sharing" in body["features"]


def test_me_has_an_empty_signing_key_until_one_is_set(server, alice):
    assert me(server, session_for(server, alice))["signing_key"] == ""


def test_signup_may_carry_a_signing_key(server):
    key = os.urandom(32)
    account = Account("dora")
    assert signup(server, account, signing_key=b64(key))[0] == 201
    assert me(server, session_for(server, account))["signing_key"] == b64(key)


@pytest.mark.parametrize("key", [b64(os.urandom(31)), b64(os.urandom(33)),
                                 "not base64 !!"])
def test_signup_refuses_a_bad_signing_key_and_makes_no_account(server, key):
    account = Account("dora")
    assert signup(server, account, signing_key=key)[0] == 400
    assert login(server, account)[0] == 401


def test_a_signing_key_can_be_set_later(server, alice):
    session = session_for(server, alice)
    key = b64(os.urandom(32))
    status, _, _ = server.request("PUT", "/v2/me/signing-key",
                                  {"signing_key": key}, token=session)
    assert status == 200
    assert me(server, session)["signing_key"] == key


def test_setting_the_same_signing_key_again_is_fine(server, alice):
    session = session_for(server, alice)
    key = b64(os.urandom(32))
    for _ in range(2):
        status, _, _ = server.request("PUT", "/v2/me/signing-key",
                                      {"signing_key": key}, token=session)
        assert status == 200


def test_a_different_signing_key_is_refused_and_the_first_stays(server, alice):
    session = session_for(server, alice)
    first = b64(os.urandom(32))
    server.request("PUT", "/v2/me/signing-key", {"signing_key": first},
                   token=session)
    status, _, _ = server.request("PUT", "/v2/me/signing-key",
                                  {"signing_key": b64(os.urandom(32))},
                                  token=session)
    assert status == 409
    assert me(server, session)["signing_key"] == first


@pytest.mark.parametrize("key", [b64(os.urandom(16)), b64(os.urandom(64)),
                                 "not base64 !!", None])
def test_a_signing_key_of_the_wrong_shape_is_refused(server, alice, key):
    session = session_for(server, alice)
    status, _, _ = server.request("PUT", "/v2/me/signing-key",
                                  {"signing_key": key}, token=session)
    assert status == 400
    assert me(server, session)["signing_key"] == ""


def test_setting_a_signing_key_needs_a_session(server, alice):
    status, _, _ = server.request("PUT", "/v2/me/signing-key",
                                  {"signing_key": b64(os.urandom(32))},
                                  token=None)
    assert status == 401


def test_public_key_lookup_gives_both_keys_and_the_servers_spelling(server, alice, carol):
    session = session_for(server, alice)
    status, _, body = server.request("GET", "/v2/accounts/CAROL/public-key",
                                     token=session)
    assert status == 200
    assert body == {"username": "Carol", "public_key": b64(carol.public_key),
                    "signing_key": ""}


def test_public_key_lookup_carries_the_signing_key_when_there_is_one(server, alice):
    key = os.urandom(32)
    dora = Account("dora")
    signup(server, dora, signing_key=b64(key))
    _, _, body = server.request("GET", "/v2/accounts/dora/public-key",
                                token=session_for(server, alice))
    assert body["signing_key"] == b64(key)


@pytest.mark.parametrize("name", ["nobody", "bad%2Fname", "..", "con"])
def test_public_key_of_an_unknown_name_is_404(server, alice, name):
    status, _, _ = server.request("GET", f"/v2/accounts/{name}/public-key",
                                  token=session_for(server, alice))
    assert status == 404


@pytest.mark.parametrize("token", [None, TOKEN, "not-a-session"])
def test_public_key_lookup_needs_a_login(server, alice, token):
    status, _, _ = server.request("GET", "/v2/accounts/alice/public-key",
                                  token=token)
    assert status == 401


def test_a_name_with_a_space_works_in_paths(server, alice):
    ann = Account("ann lee")
    assert signup(server, ann)[0] == 201
    status, _, pre = server.request("GET", "/v2/prelogin/ann%20lee", token=None)
    assert status == 200
    assert pre["username"] == "ann lee"
    assert pre["kdf"]["salt"] == b64(ann.salt)           # the real one
    session = session_for(server, alice)
    status, _, keys = server.request("GET", "/v2/accounts/ANN%20LEE/public-key",
                                     token=session)
    assert status == 200 and keys["username"] == "ann lee"
    view, _ = made(server, session)
    status, answer = put_member(server, session, view["id"], "ann%20lee", "reader")
    assert status == 200 and answer["username"] == "ann lee"
    assert my_vault(server, session_for(server, ann), view["id"])["role"] == "reader"


# --- adding members and changing roles ---------------------------------------------

def test_an_owner_adds_a_member_who_then_sees_the_vault_with_their_own_key(server, alice, bob):
    session = session_for(server, alice)
    view, _ = made(server, session)
    key = wrapped_key()
    status, answer = put_member(server, session, view["id"], "bob", "editor",
                                wrapped=key)
    assert status == 200
    assert answer == {"username": "bob", "role": "editor", "added": True}
    seen = my_vault(server, session_for(server, bob), view["id"])
    assert seen["role"] == "editor" and seen["wrapped_key"] == key
    assert seen["kind"] == "shared" and seen["members"] == 2
    assert seen["name"] == view["name"]
    # the owner's own key is not touched
    assert my_vault(server, session, view["id"])["wrapped_key"] == view["wrapped_key"]


def test_a_member_may_be_added_by_any_spelling_and_the_servers_is_stored(server, team):
    signup(server, Account("dora"))
    status, answer = put_member(server, team.sa, team.vid, "DORA", "reader")
    assert status == 200 and answer["username"] == "dora"
    names = [m["username"] for m in members(server, team.sa, team.vid)[2]["members"]]
    assert names == ["alice", "bob", "Carol", "dora"]
    # the same person again, in another case, is a role change and not a second member
    assert put_member(server, team.sa, team.vid, "Dora", "editor",
                      wrapped=None)[1]["added"] is False


def test_members_are_counted_in_me(server, team):
    assert my_vault(server, team.sa, team.vid)["members"] == 3
    assert my_vault(server, team.sc, team.vid)["members"] == 3


def test_a_role_change_leaves_the_wrapped_key_alone(server, team):
    before = my_vault(server, team.sb, team.vid)
    status, answer = put_member(server, team.sa, team.vid, "bob", "reader",
                                wrapped=None)
    assert status == 200
    assert answer == {"username": "bob", "role": "reader", "added": False}
    after = my_vault(server, team.sb, team.vid)
    assert after["role"] == "reader"
    assert after["wrapped_key"] == before["wrapped_key"]
    assert after["members"] == 3


def test_a_wrapped_key_sent_with_a_role_change_is_ignored(server, team):
    before = my_vault(server, team.sb, team.vid)["wrapped_key"]
    assert put_member(server, team.sa, team.vid, "bob", "owner")[0] == 200
    assert my_vault(server, team.sb, team.vid)["wrapped_key"] == before


def test_a_promoted_reader_can_then_upload(server, team):
    blob = vault_blob(team.vid)
    assert put_vault(server, team.sc, team.vid, blob)[0] == 403
    put_member(server, team.sa, team.vid, "Carol", "editor", wrapped=None)
    assert put_vault(server, team.sc, team.vid, blob)[0] == 200


def test_a_demoted_editor_can_no_longer_upload(server, team):
    put_member(server, team.sa, team.vid, "bob", "reader", wrapped=None)
    assert put_vault(server, team.sb, team.vid, vault_blob(team.vid))[0] == 403


@pytest.mark.parametrize("role", ["admin", "Owner", "", None, 7])
def test_a_bad_role_is_refused(server, team, role):
    assert put_member(server, team.sa, team.vid, "bob", role, wrapped=None)[0] == 400
    assert put_member(server, team.sa, team.vid, "dora", role)[0] == 400


def test_an_unknown_account_cannot_be_added(server, team):
    assert put_member(server, team.sa, team.vid, "nobody", "reader")[0] == 404


def test_a_personal_vault_cannot_be_shared(server, alice, bob):
    session = session_for(server, alice)
    before = my_vault(server, session, alice.vault)
    assert put_member(server, session, alice.vault, "bob", "reader")[0] == 400
    assert my_vault(server, session, alice.vault) == before
    assert my_vault(server, session_for(server, bob), alice.vault) is None


@pytest.mark.parametrize("key", [None, "not base64 !!",
                                 b64(os.urandom(passman_server.WRAPPED_KEY_LEN - 1)),
                                 b64(os.urandom(passman_server.WRAPPED_KEY_LEN + 1))])
def test_a_new_member_needs_a_whole_wrapped_key(server, alice, bob, key):
    session = session_for(server, alice)
    view, _ = made(server, session)
    before = state(server, view["id"], "alice", "bob")
    assert put_member(server, session, view["id"], "bob", "reader",
                      wrapped=key)[0] == 400
    assert state(server, view["id"], "alice", "bob") == before


def test_the_member_limit_refuses_a_new_member(server, team, monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_MEMBERS_PER_VAULT", 3)
    dora = Account("dora")
    signup(server, dora)
    before = state(server, team.vid, "dora")
    assert put_member(server, team.sa, team.vid, "dora", "reader")[0] == 403
    assert state(server, team.vid, "dora") == before
    assert my_vault(server, session_for(server, dora), team.vid) is None


def test_the_member_limit_does_not_stop_a_role_change(server, team, monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_MEMBERS_PER_VAULT", 3)
    assert put_member(server, team.sa, team.vid, "bob", "reader", wrapped=None)[0] == 200


def test_the_member_limit_allows_one_more_below_it(server, team, monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_MEMBERS_PER_VAULT", 4)
    signup(server, Account("dora"))
    assert put_member(server, team.sa, team.vid, "dora", "reader")[0] == 200


def test_an_account_in_too_many_vaults_cannot_be_added_to_another(server, alice, bob, monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_VAULTS_LISTED", 1)
    sa, sb = session_for(server, alice), session_for(server, bob)
    first, _ = made(server, sb)                  # bob lists one vault: the limit
    other, _ = made(server, sa)
    before = state(server, other["id"], "bob")
    assert put_member(server, sa, other["id"], "bob", "reader")[0] == 409
    assert state(server, other["id"], "bob") == before
    assert my_vault(server, sb, first["id"]) is not None


def test_the_only_owner_cannot_be_demoted(server, team):
    before = state(server, team.vid, "alice")
    for role in ("editor", "reader"):
        assert put_member(server, team.sa, team.vid, "alice", role,
                          wrapped=None)[0] == 409
    assert state(server, team.vid, "alice") == before
    assert my_vault(server, team.sa, team.vid)["role"] == "owner"


def test_an_owner_can_be_demoted_when_another_owner_remains(server, team):
    put_member(server, team.sa, team.vid, "bob", "owner", wrapped=None)
    assert put_member(server, team.sb, team.vid, "alice", "reader", wrapped=None)[0] == 200
    assert my_vault(server, team.sa, team.vid)["role"] == "reader"
    # and now bob is the only owner, so bob is the one who cannot step down
    assert put_member(server, team.sb, team.vid, "bob", "editor", wrapped=None)[0] == 409


def test_an_owner_may_set_their_own_role_to_owner(server, team):
    status, answer = put_member(server, team.sa, team.vid, "alice", "owner",
                                wrapped=None)
    assert status == 200 and answer["added"] is False


@pytest.mark.parametrize("who", ["bob", "carol"])
def test_only_an_owner_may_add_or_change_members(server, team, who):
    session = team.sb if who == "bob" else team.sc
    signup(server, Account("dora"))
    before = state(server, team.vid, "dora", "bob", "Carol")
    assert put_member(server, session, team.vid, "dora", "reader")[0] == 403
    assert put_member(server, session, team.vid, who if who == "bob" else "Carol",
                      "owner", wrapped=None)[0] == 403
    assert state(server, team.vid, "dora", "bob", "Carol") == before


def test_a_stranger_cannot_tell_the_vault_exists_when_adding_members(server, team, alice):
    dora = Account("dora")
    signup(server, dora)
    session = session_for(server, dora)
    assert put_member(server, session, team.vid, "dora", "owner")[0] == 404
    assert put_member(server, session, new_id(), "dora", "owner")[0] == 404


# --- the members list -----------------------------------------------------------------

def test_the_members_list_is_sorted_and_says_who_added_whom(server, team):
    status, _, body = members(server, team.sb, team.vid)
    assert status == 200
    assert body["key_generation"] == 0
    assert [(m["username"], m["role"], m["added_by"]) for m in body["members"]] == [
        ("alice", "owner", ""), ("bob", "editor", "alice"),
        ("Carol", "reader", "alice")]
    assert all(m["added_at"].endswith("Z") for m in body["members"][1:])
    assert set(body["members"][0]) == {"username", "role", "added_by", "added_at"}


def test_every_member_may_read_the_members_list_but_it_holds_no_keys(server, team):
    for session in (team.sa, team.sb, team.sc):
        status, _, body = members(server, session, team.vid)
        assert status == 200
        assert "wrapped_key" not in json.dumps(body)


def test_a_non_member_gets_404_for_the_members_list(server, team, alice):
    erin = Account("erin")
    signup(server, erin)
    session = session_for(server, erin)
    assert members(server, session, team.vid)[0] == 404
    assert members(server, session, new_id())[0] == 404


# --- roles on the blob --------------------------------------------------------------------

def test_a_reader_cannot_upload_but_can_read(server, team):
    put_vault(server, team.sa, team.vid, vault_blob(team.vid))
    before = state(server, team.vid)
    status, _, _ = put_vault(server, team.sc, team.vid, vault_blob(team.vid),
                             if_match="1")
    assert status == 403
    assert state(server, team.vid) == before
    status, _, body = server.request("GET", f"/v2/vaults/{team.vid}", token=team.sc)
    assert status == 200 and body["revision"] == 1 and body["blob"]
    assert server.request("GET", f"/v2/vaults/{team.vid}/meta",
                          token=team.sc)[0] == 200


def test_an_editor_can_upload(server, team):
    status, _, meta = put_vault(server, team.sb, team.vid, vault_blob(team.vid))
    assert status == 200 and meta["revision"] == 1


def test_an_owner_can_upload(server, team):
    assert put_vault(server, team.sa, team.vid, vault_blob(team.vid))[0] == 200


def test_a_non_member_cannot_upload_or_read(server, team):
    erin = Account("erin")
    signup(server, erin)
    session = session_for(server, erin)
    assert put_vault(server, session, team.vid, vault_blob(team.vid))[0] == 404
    assert server.request("GET", f"/v2/vaults/{team.vid}", token=session)[0] == 404


@pytest.mark.parametrize("who", ["editor", "reader"])
def test_only_owners_may_rename_delete_rotate_or_read_the_log(server, team_up, who):
    session = team_up.sb if who == "editor" else team_up.sc
    vid = team_up.vid
    before = state(server, vid, "alice", "bob", "Carol")
    calls = [
        ("PUT", f"/v2/vaults/{vid}/name", {"name": sealed_name()}),
        ("DELETE", f"/v2/vaults/{vid}", None),
        ("PUT", f"/v2/vaults/{vid}/members/alice", {"role": "reader"}),
        ("POST", f"/v2/vaults/{vid}/rotate", rotate_body(vid, ["alice", "bob", "Carol"])),
        ("GET", f"/v2/vaults/{vid}/log", None),
    ]
    for method, path, body in calls:
        status, _, _ = server.request(method, path, body, token=session)
        assert status == 403, (method, path)
    assert state(server, vid, "alice", "bob", "Carol") == before


def test_a_non_member_gets_404_for_the_owner_calls(server, team):
    erin = Account("erin")
    signup(server, erin)
    session = session_for(server, erin)
    vid = team.vid
    for method, path, body in [
            ("PUT", f"/v2/vaults/{vid}/name", {"name": sealed_name()}),
            ("DELETE", f"/v2/vaults/{vid}", None),
            ("POST", f"/v2/vaults/{vid}/rotate", {"generation": 1}),
            ("GET", f"/v2/vaults/{vid}/log", None),
            ("DELETE", f"/v2/vaults/{vid}/members/alice", None)]:
        assert server.request(method, path, body, token=session)[0] == 404, path


@pytest.mark.parametrize("method, tail", [
    ("GET", "rotate"), ("PUT", "rotate"), ("PUT", "log"), ("POST", "log"),
    ("GET", "name"), ("POST", "members"), ("GET", "members/bob"),
    ("POST", "members/bob")])
def test_other_methods_on_the_sharing_paths_are_404(server, team, method, tail):
    body = {} if method in ("PUT", "POST") else None
    status, _, _ = server.request(method, f"/v2/vaults/{team.vid}/{tail}", body,
                                  token=team.sa)
    assert status == 404


# --- the key generation on the blob --------------------------------------------------------

def test_an_upload_at_another_generation_than_the_vaults_is_refused(server, team):
    before = state(server, team.vid)
    status, _, body = put_vault(server, team.sa, team.vid, vault_blob(team.vid, 1))
    assert status == 409 and "key" in body["error"]
    assert state(server, team.vid) == before


def test_the_personal_vault_takes_generation_zero_only(server, alice):
    session = session_for(server, alice)
    assert put_vault(server, session, alice.vault, vault_blob(alice.vault, 1))[0] == 409
    assert put_vault(server, session, alice.vault, vault_blob(alice.vault, 0))[0] == 200


# --- leaving ---------------------------------------------------------------------------------

@pytest.mark.parametrize("who", ["bob", "carol"])
def test_a_member_can_leave_and_the_vault_goes_from_their_list(server, team, who):
    session = team.sb if who == "bob" else team.sc
    name = "bob" if who == "bob" else "Carol"
    status, _, _ = server.request("DELETE", f"/v2/vaults/{team.vid}/members/{name}",
                                  token=session)
    assert status == 200
    assert my_vault(server, session, team.vid) is None
    assert server.request("GET", f"/v2/vaults/{team.vid}", token=session)[0] == 404
    left = [m["username"] for m in members(server, team.sa, team.vid)[2]["members"]]
    assert left == [n for n in ("alice", "bob", "Carol") if n != name]
    assert my_vault(server, team.sa, team.vid)["members"] == 2


def test_the_only_owner_cannot_leave(server, team):
    before = state(server, team.vid, "alice")
    status, _, _ = server.request("DELETE", f"/v2/vaults/{team.vid}/members/alice",
                                  token=team.sa)
    assert status == 409
    assert state(server, team.vid, "alice") == before
    assert my_vault(server, team.sa, team.vid) is not None


def test_an_owner_can_leave_when_another_owner_remains(server, team):
    put_member(server, team.sa, team.vid, "bob", "owner", wrapped=None)
    status, _, _ = server.request("DELETE", f"/v2/vaults/{team.vid}/members/alice",
                                  token=team.sa)
    assert status == 200
    assert my_vault(server, team.sa, team.vid) is None
    assert my_vault(server, team.sb, team.vid)["role"] == "owner"


def test_an_owner_cannot_remove_someone_else_that_way(server, team):
    before = state(server, team.vid, "alice", "bob", "Carol")
    status, _, body = server.request("DELETE", f"/v2/vaults/{team.vid}/members/bob",
                                     token=team.sa)
    assert status == 400 and "rotate" in body["error"]
    assert state(server, team.vid, "alice", "bob", "Carol") == before


def test_a_non_owner_cannot_remove_someone_else(server, team):
    before = state(server, team.vid, "alice", "bob", "Carol")
    for session, victim in ((team.sb, "alice"), (team.sc, "bob"), (team.sb, "Carol")):
        status, _, _ = server.request(
            "DELETE", f"/v2/vaults/{team.vid}/members/{victim}", token=session)
        assert status == 403
    assert state(server, team.vid, "alice", "bob", "Carol") == before


def test_leaving_a_personal_vault_is_refused(server, alice):
    status, _, _ = server.request("DELETE", f"/v2/vaults/{alice.vault}/members/alice",
                                  token=session_for(server, alice))
    assert status == 400


def test_a_member_who_left_can_be_added_again(server, team):
    server.request("DELETE", f"/v2/vaults/{team.vid}/members/bob", token=team.sb)
    assert put_member(server, team.sa, team.vid, "bob", "reader")[1]["added"] is True
    assert my_vault(server, team.sb, team.vid)["role"] == "reader"


# --- deleting --------------------------------------------------------------------------------

def test_a_deleted_vault_disappears_from_every_members_list(server, team):
    status, _, _ = server.request("DELETE", f"/v2/vaults/{team.vid}", token=team.sa)
    assert status == 200
    for session in (team.sa, team.sb, team.sc):
        assert my_vault(server, session, team.vid) is None
        assert server.request("GET", f"/v2/vaults/{team.vid}", token=session)[0] == 404


# --- changing the key and removing members ----------------------------------------------------

def test_rotating_removes_members_and_gives_the_rest_new_keys(server, team_up):
    t = team_up
    body = rotate_body(t.vid, ["alice", "bob"], remove=["Carol"])
    status, view = post_rotate(server, t.sa, t.vid, body)
    assert status == 200
    assert view["key_generation"] == 1 and view["members"] == 2
    assert view["wrapped_key"] == body["wrapped_keys"]["alice"]

    # the removed member loses the vault altogether
    assert my_vault(server, t.sc, t.vid) is None
    assert server.request("GET", f"/v2/vaults/{t.vid}", token=t.sc)[0] == 404
    assert put_vault(server, t.sc, t.vid, vault_blob(t.vid, 1), if_match="4")[0] == 404

    # the others got their new key, the new generation and the new name
    for session, name in ((t.sa, "alice"), (t.sb, "bob")):
        seen = my_vault(server, session, t.vid)
        assert seen["wrapped_key"] == body["wrapped_keys"][name]
        assert seen["key_generation"] == 1
        assert seen["name"] == body["name"]
    assert members(server, t.sa, t.vid)[2]["key_generation"] == 1
    assert [m["username"] for m in members(server, t.sa, t.vid)[2]["members"]] \
        == ["alice", "bob"]


def test_rotating_stores_the_new_blob_as_a_new_revision_and_empties_the_history(server, team_up):
    t = team_up
    history = os.path.join(vault_dir(server, t.vid), "history")
    assert len(os.listdir(history)) == 2
    body = rotate_body(t.vid, ["alice", "bob", "Carol"])
    assert post_rotate(server, t.sa, t.vid, body)[0] == 200
    _, _, stored = server.request("GET", f"/v2/vaults/{t.vid}", token=t.sa)
    assert stored["revision"] == 4
    assert stored["blob"] == body["blob"]
    assert stored["key_generation"] == 1
    assert not os.path.isdir(history) or os.listdir(history) == []


def test_after_a_rotation_the_old_generation_is_refused_and_the_new_one_works(server, team_up):
    t = team_up
    assert post_rotate(server, t.sa, t.vid,
                       rotate_body(t.vid, ["alice", "bob", "Carol"]))[0] == 200
    assert put_vault(server, t.sb, t.vid, vault_blob(t.vid, 0), if_match="4")[0] == 409
    status, _, meta = put_vault(server, t.sb, t.vid, vault_blob(t.vid, 1),
                                if_match="4")
    assert status == 200 and meta["revision"] == 5


def test_rotating_without_removing_anyone_changes_the_key_for_all(server, team_up):
    t = team_up
    body = rotate_body(t.vid, ["alice", "bob", "Carol"])
    assert post_rotate(server, t.sa, t.vid, body)[0] == 200
    for session, name in ((t.sa, "alice"), (t.sb, "bob"), (t.sc, "Carol")):
        assert my_vault(server, session, t.vid)["wrapped_key"] \
            == body["wrapped_keys"][name]


def test_a_vault_never_uploaded_can_be_rotated_without_a_blob(server, team):
    body = rotate_body(team.vid, ["alice", "bob"], remove=["Carol"])
    del body["blob"], body["revision"]
    status, view = post_rotate(server, team.sa, team.vid, body)
    assert status == 200 and view["key_generation"] == 1
    assert my_vault(server, team.sc, team.vid) is None
    assert server.request("GET", f"/v2/vaults/{team.vid}", token=team.sa)[2]["blob"] is None
    # and the first upload must already be at the new generation
    assert put_vault(server, team.sa, team.vid, vault_blob(team.vid, 0))[0] == 409
    assert put_vault(server, team.sa, team.vid, vault_blob(team.vid, 1))[0] == 200


def test_a_vault_never_uploaded_may_still_be_rotated_with_a_blob(server, team):
    body = rotate_body(team.vid, ["alice", "bob", "Carol"], revision=0)
    status, _ = post_rotate(server, team.sa, team.vid, body)
    assert status == 200
    assert server.request("GET", f"/v2/vaults/{team.vid}",
                          token=team.sa)[2]["revision"] == 1


def test_the_removed_member_may_be_an_owner_when_another_owner_stays(server, team_up):
    t = team_up
    put_member(server, t.sa, t.vid, "bob", "owner", wrapped=None)
    status, _ = post_rotate(server, t.sb, t.vid,
                            rotate_body(t.vid, ["bob", "Carol"], remove=["alice"]))
    assert status == 200
    assert my_vault(server, t.sa, t.vid) is None


def test_two_members_may_be_removed_at_once(server, team_up):
    t = team_up
    status, view = post_rotate(server, t.sa, t.vid,
                               rotate_body(t.vid, ["alice"], remove=["bob", "Carol"]))
    assert status == 200 and view["members"] == 1
    assert my_vault(server, t.sb, t.vid) is None and my_vault(server, t.sc, t.vid) is None


def test_a_second_rotation_needs_the_next_generation(server, team_up):
    t = team_up
    assert post_rotate(server, t.sa, t.vid,
                       rotate_body(t.vid, ["alice", "bob", "Carol"]))[0] == 200
    again = rotate_body(t.vid, ["alice", "bob", "Carol"], revision=4)
    assert post_rotate(server, t.sa, t.vid, again)[0] == 409           # still 1
    again["generation"] = 2
    again["blob"] = vault_blob(t.vid, 2)
    assert post_rotate(server, t.sa, t.vid, again)[0] == 200


def _mutate(**changes):
    def apply(body):
        body.update(changes)
        return body
    return apply


def _without(*keys):
    def apply(body):
        for key in keys:
            body.pop(key, None)
        return body
    return apply


def _drop_key(name):
    def apply(body):
        del body["wrapped_keys"][name]
        return body
    return apply


def _add_key(name):
    def apply(body):
        body["wrapped_keys"][name] = wrapped_key()
        return body
    return apply


def _short_key(body):
    body["wrapped_keys"]["bob"] = b64(os.urandom(passman_server.WRAPPED_KEY_LEN - 1))
    return body


REFUSED = [
    ("generation too far ahead", 409, _mutate(generation=2)),
    ("generation not advanced", 409, _mutate(generation=0)),
    ("generation missing", 409, _without("generation")),
    ("a staying member has no key", 409, _drop_key("bob")),
    ("the removed member still has a key", 409, _add_key("Carol")),
    ("a key for an unknown account", 409, _add_key("zed")),
    ("no keys at all", 409, _without("wrapped_keys")),
    ("keys not an object", 409, _mutate(wrapped_keys=["alice", "bob"])),
    ("removing yourself", 400, _mutate(remove=["alice", "Carol"])),
    ("removing a non-member", 400, _mutate(remove=["Carol", "zed"])),
    ("remove is not a list", 400, _mutate(remove="Carol")),
    ("a key of the wrong length", 400, _short_key),
    ("a key that is not base64", 400,
     lambda b: _mutate(wrapped_keys={**b["wrapped_keys"], "bob": "!!"})(b)),
    ("stale revision", 409, _mutate(revision=2)),
    ("revision missing but a blob given", 409, _without("revision")),
    ("blob for another vault", 400, lambda b: _mutate(blob=vault_blob(new_id(), 1))(b)),
    ("blob with the old generation", 409, lambda b: _mutate(blob=vault_blob(b["blob_vault"], 0))(b)),
    ("blob not base64", 400, _mutate(blob="!!")),
    ("blob too short", 400, _mutate(blob=b64(b"PMV3"))),
    ("blob missing from a vault that has one", 400, _without("blob", "revision")),
    ("name missing", 400, _without("name")),
    ("name not base64", 400, _mutate(name="not base64 !!")),
    ("name too short", 400, _mutate(name=b64(b"x" * (passman_server.MIN_SEALED_NAME - 1)))),
    ("name too long", 400, _mutate(name=b64(b"x" * (passman_server.MAX_SEALED_NAME + 1)))),
]


@pytest.mark.parametrize("why, status, change", REFUSED, ids=[r[0] for r in REFUSED])
def test_a_bad_rotation_is_refused_and_changes_nothing(server, team_up, why, status, change):
    t = team_up
    body = rotate_body(t.vid, ["alice", "bob"], remove=["Carol"])
    body["blob_vault"] = t.vid               # for the lambdas above; not sent
    body = change(body)
    body.pop("blob_vault", None)
    before = state(server, t.vid, "alice", "bob", "Carol")
    sessions = [(t.sa, "alice"), (t.sb, "bob"), (t.sc, "Carol")]
    seen_before = [my_vault(server, s, t.vid) for s, _ in sessions]
    assert post_rotate(server, t.sa, t.vid, body)[0] == status
    assert state(server, t.vid, "alice", "bob", "Carol") == before
    assert [my_vault(server, s, t.vid) for s, _ in sessions] == seen_before


def test_rotating_a_personal_vault_is_refused(server, alice):
    session = session_for(server, alice)
    body = rotate_body(alice.vault, ["alice"], revision=0)
    before = state(server, alice.vault)
    assert post_rotate(server, session, alice.vault, body)[0] == 400
    assert state(server, alice.vault) == before


def test_rotating_needs_a_body(server, team):
    status, _, _ = server.request("POST", f"/v2/vaults/{team.vid}/rotate",
                                  token=team.sa)
    assert status == 400


def test_a_revision_other_than_zero_is_stale_for_a_vault_never_uploaded(server, team):
    body = rotate_body(team.vid, ["alice", "bob", "Carol"], revision=5)
    assert post_rotate(server, team.sa, team.vid, body)[0] == 409


# --- vault limits count only what an account made -------------------------------------------------

def test_a_vault_shared_with_you_does_not_count_against_your_own_limit(server, alice, bob, monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_VAULTS_PER_ACCOUNT", 1)
    sa, sb = session_for(server, alice), session_for(server, bob)
    theirs, _ = made(server, sb)
    put_member(server, sb, theirs["id"], "alice", "editor")
    assert create(server, sa)[0] == 201            # the shared one is not hers
    assert create(server, sa)[0] == 403            # but this one is


def test_the_limit_on_own_vaults_still_applies_to_a_member_of_many(server, alice, bob, monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_VAULTS_PER_ACCOUNT", 2)
    sa, sb = session_for(server, alice), session_for(server, bob)
    for _ in range(2):
        put_member(server, sb, made(server, sb)[0]["id"], "alice", "reader")
    assert create(server, sa)[0] == 201
    assert create(server, sa)[0] == 201
    assert create(server, sa)[0] == 403


def test_the_total_listed_limit_counts_shared_vaults_too(server, alice, bob, monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_VAULTS_LISTED", 2)
    sa, sb = session_for(server, alice), session_for(server, bob)
    put_member(server, sb, made(server, sb)[0]["id"], "alice", "reader")
    assert create(server, sa)[0] == 201
    assert create(server, sa)[0] == 403


# --- the vault's log ----------------------------------------------------------------------------------

def test_the_log_records_a_vault_from_its_creation(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    status, _, body = api_log(server, session, view["id"])
    assert status == 200
    [line] = body["lines"]
    assert line["event"] == "vault_created" and line["by"] == "alice"
    assert line["address"] == "127.0.0.1"
    assert line["at"].endswith("Z") and "T" in line["at"]


def test_the_log_tells_what_happened_oldest_first(server, team):
    t = team
    put_vault(server, t.sa, t.vid, vault_blob(t.vid))
    put_vault(server, t.sb, t.vid, vault_blob(t.vid), if_match="1")
    server.request("PUT", f"/v2/vaults/{t.vid}/name", {"name": sealed_name()},
                   token=t.sa)
    put_member(server, t.sa, t.vid, "bob", "reader", wrapped=None)
    server.request("DELETE", f"/v2/vaults/{t.vid}/members/Carol", token=t.sc)
    assert post_rotate(server, t.sa, t.vid,
                       rotate_body(t.vid, ["alice", "bob"], remove=[],
                                   revision=2))[0] == 200
    lines = api_log(server, t.sa, t.vid)[2]["lines"]
    assert [(l["event"], l["by"]) for l in lines] == [
        ("vault_created", "alice"), ("member_added", "alice"),
        ("member_added", "alice"), ("upload", "alice"), ("upload", "bob"),
        ("vault_renamed", "alice"), ("member_role", "alice"),
        ("member_left", "Carol"), ("key_changed", "alice")]
    by_event = {}
    for each in lines:
        by_event.setdefault(each["event"], []).append(each)
    assert [u["revision"] for u in by_event["upload"]] == [1, 2]
    assert [(m["member"], m["role"]) for m in by_event["member_added"]] == [
        ("bob", "editor"), ("Carol", "reader")]
    assert (by_event["member_role"][0]["member"],
            by_event["member_role"][0]["role"]) == ("bob", "reader")
    assert by_event["key_changed"][0]["generation"] == 1
    assert by_event["key_changed"][0]["removed"] == []
    assert [l["at"] for l in lines] == sorted(l["at"] for l in lines)


def test_a_key_change_logs_who_was_removed(server, team_up):
    t = team_up
    post_rotate(server, t.sa, t.vid,
                rotate_body(t.vid, ["alice", "bob"], remove=["Carol"]))
    last = api_log(server, t.sa, t.vid)[2]["lines"][-1]
    assert last["event"] == "key_changed" and last["removed"] == ["Carol"]
    assert last["generation"] == 1 and last["by"] == "alice"


def test_a_refused_call_leaves_no_line_in_the_log(server, team_up):
    t = team_up
    before = api_log(server, t.sa, t.vid)[2]
    put_vault(server, t.sa, t.vid, vault_blob(t.vid, 1), if_match="3")        # 409
    put_vault(server, t.sc, t.vid, vault_blob(t.vid), if_match="3")           # 403
    put_member(server, t.sa, t.vid, "nobody", "reader")                       # 404
    post_rotate(server, t.sa, t.vid, {"generation": 5})                       # 409
    assert api_log(server, t.sa, t.vid)[2] == before


def test_the_log_of_a_deleted_vault_goes_with_its_folder(server, team):
    server.request("DELETE", f"/v2/vaults/{team.vid}", token=team.sa)
    graveyard = os.path.join(server.store.root, "_v2", "deleted")
    [folder] = [f for f in os.listdir(graveyard) if f.startswith(team.vid)]
    lines = file_lines(os.path.join(graveyard, folder, "audit.log"))
    assert lines[-1]["event"] == "vault_deleted" and lines[-1]["by"] == "alice"


def test_the_log_is_cut_to_the_newest_lines(server, team, monkeypatch):
    monkeypatch.setattr(passman_server, "AUDIT_LINES_SENT", 3)
    put_vault(server, team.sa, team.vid, vault_blob(team.vid))
    for rev in "123":
        put_vault(server, team.sa, team.vid, vault_blob(team.vid), if_match=rev)
    lines = api_log(server, team.sa, team.vid)[2]["lines"]
    assert [l["revision"] for l in lines] == [2, 3, 4]
    assert len(file_lines(vault_log_path(server, team.vid))) == 7   # all kept on disk


def test_the_log_skips_a_line_it_cannot_read(server, team):
    with open(vault_log_path(server, team.vid), "a", encoding="utf-8") as f:
        f.write("this is not json\n[1, 2]\n")
    lines = api_log(server, team.sa, team.vid)[2]["lines"]
    assert [l["event"] for l in lines] == ["vault_created", "member_added",
                                           "member_added"]


def test_the_log_of_a_vault_without_one_is_empty(server, team):
    os.remove(vault_log_path(server, team.vid))
    assert api_log(server, team.sa, team.vid)[2] == {"lines": []}


def test_the_log_holds_no_blob_key_or_name_material(server, team_up):
    t = team_up
    sent = [t.sent["name"], t.sent["wrapped_key"]]
    key = wrapped_key()
    put_member(server, t.sa, t.vid, "bob", "owner", wrapped=None)
    signup(server, Account("dora"))
    put_member_body = {"role": "reader", "wrapped_key": key}
    server.request("PUT", f"/v2/vaults/{t.vid}/members/dora", put_member_body,
                   token=t.sa)
    renamed = sealed_name()
    server.request("PUT", f"/v2/vaults/{t.vid}/name", {"name": renamed}, token=t.sa)
    uploaded = vault_blob(t.vid)
    put_vault(server, t.sa, t.vid, uploaded, if_match="3")
    body = rotate_body(t.vid, ["alice", "bob", "Carol"], remove=["dora"], revision=4)
    assert post_rotate(server, t.sa, t.vid, body)[0] == 200
    sent += [key, renamed, uploaded, body["name"], body["blob"],
             *body["wrapped_keys"].values()]
    with open(vault_log_path(server, t.vid), encoding="utf-8") as f:
        text = f.read()
    assert text.count("\n") >= 10
    for secret in sent:
        assert secret not in text
    for fragment in ("wrapped_key", "blob", "PMV3"):
        assert fragment not in text


# --- the logins log -------------------------------------------------------------------------------------

def test_the_logins_log_records_sign_up_and_login(server, alice):
    session_for(server, alice)
    lines = file_lines(logins_path(server))
    assert [(l["event"], l["by"]) for l in lines] == [
        ("account_created", "alice"), ("login", "alice")]
    assert all(l["address"] == "127.0.0.1" for l in lines)


def test_a_failed_login_is_recorded_with_its_status(server, alice):
    status, _, _ = login(server, alice, login_key=os.urandom(32))
    assert status == 401
    last = file_lines(logins_path(server))[-1]
    assert last["event"] == "login_failed" and last["by"] == "alice"
    assert last["status"] == 401


def test_a_failed_login_for_a_name_with_no_account_is_recorded_under_that_name(server):
    login(server, Account("nobody"))
    last = file_lines(logins_path(server))[-1]
    assert (last["event"], last["by"], last["status"]) == ("login_failed", "nobody", 401)


@pytest.mark.parametrize("name", ["../etc", "", "a/b", "x" * 80, 7])
def test_a_failed_login_for_an_invalid_name_is_recorded_as_a_question_mark(server, name):
    status, _, _ = server.request("POST", "/v2/login", {
        "username": name, "login_key": b64(os.urandom(32))}, token=None)
    assert status == 400
    last = file_lines(logins_path(server))[-1]
    assert (last["event"], last["by"], last["status"]) == ("login_failed", "?", 400)


def test_a_password_change_is_recorded(server, alice):
    session = session_for(server, alice)
    new_key = os.urandom(32)
    status, _, _ = server.request("PUT", "/v2/me/keyset", {
        "login_key": b64(new_key), "keyset": keyset_blob()}, token=session)
    assert status == 200
    last = file_lines(logins_path(server))[-1]
    assert last["event"] == "password_changed" and last["by"] == "alice"


def test_a_refused_sign_up_is_not_recorded(server, alice):
    signup(server, Account("alice"))                           # name taken: 409
    signup(server, Account("zed"), token=None)                 # no code: 401
    assert [l["event"] for l in file_lines(logins_path(server))] == ["account_created"]


def test_the_logins_log_never_holds_a_key_or_a_session(server, alice):
    session = session_for(server, alice)
    wrong = os.urandom(32)
    login(server, alice, login_key=wrong)
    new_key = os.urandom(32)
    server.request("PUT", "/v2/me/keyset",
                   {"login_key": b64(new_key), "keyset": keyset_blob()}, token=session)
    with open(logins_path(server), encoding="utf-8") as f:
        text = f.read()
    for secret in (alice.login_key, wrong, new_key):
        assert b64(secret) not in text
    assert session not in text and alice.keyset not in text
    assert b64(alice.public_key) not in text


def test_the_logins_log_is_not_readable_through_the_api(server, alice):
    session = session_for(server, alice)
    for path in ("/v2/logins", "/v2/log", "/v2/me/log", "/v2/vaults/logins"):
        assert server.request("GET", path, token=session)[0] == 404


# --- rotation and failure of the log files ----------------------------------------------------------------

def test_a_log_that_reaches_the_size_is_renamed_and_a_new_one_started(tmp_path, monkeypatch):
    monkeypatch.setattr(passman_server, "AUDIT_ROTATE_BYTES", 300)
    store = passman_server.AccountStore(str(tmp_path))
    path = os.path.join(store.root, "logins.log")
    written = 0
    while not os.path.exists(path + ".1") and written < 20:
        store.audit(None, "login", "alice", "127.0.0.1")
        written += 1
    assert os.path.exists(path + ".1")
    old, new = file_lines(path + ".1"), file_lines(path)
    assert len(old) + len(new) == written
    assert len(new) == 1                       # a new file, not the old one grown
    assert os.path.getsize(path + ".1") >= 300


def test_a_second_rotation_replaces_the_earlier_dot_one(tmp_path, monkeypatch):
    monkeypatch.setattr(passman_server, "AUDIT_ROTATE_BYTES", 200)
    store = passman_server.AccountStore(str(tmp_path))
    for number in range(40):
        store.audit(None, "login", f"user{number}", "127.0.0.1")
    path = os.path.join(store.root, "logins.log")
    assert sorted(os.listdir(store.root)) == ["logins.log", "logins.log.1"]
    first = file_lines(path + ".1")[0]["by"]
    assert first != "user0"                    # the oldest file is gone


def test_a_vault_log_rotates_in_its_own_folder(server, team, monkeypatch):
    monkeypatch.setattr(passman_server, "AUDIT_ROTATE_BYTES", 400)
    put_vault(server, team.sa, team.vid, vault_blob(team.vid))
    for rev in range(1, 6):
        put_vault(server, team.sa, team.vid, vault_blob(team.vid), if_match=str(rev))
    folder = vault_dir(server, team.vid)
    assert os.path.exists(os.path.join(folder, "audit.log.1"))
    # the API reads the current file only
    lines = api_log(server, team.sa, team.vid)[2]["lines"]
    assert lines and lines[-1]["revision"] == 6


def test_a_log_below_the_size_is_not_rotated(tmp_path):
    store = passman_server.AccountStore(str(tmp_path))
    for _ in range(5):
        store.audit(None, "login", "alice")
    assert os.listdir(store.root) == ["logins.log"]


def test_audit_never_raises_when_the_folder_cannot_be_made(tmp_path, monkeypatch):
    store = passman_server.AccountStore(str(tmp_path))

    def refuse(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(passman_server.os, "makedirs", refuse)
    store.audit(None, "login", "alice", "127.0.0.1")
    store.audit("ab" * 16, "upload", "alice", revision=1)


def test_audit_never_raises_when_the_file_cannot_be_opened(tmp_path, monkeypatch):
    store = passman_server.AccountStore(str(tmp_path))
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a folder should be")
    monkeypatch.setattr(store, "_audit_path",
                        lambda vault_id=None: str(blocker / "x.log"))
    store.audit(None, "login", "alice")
    assert store.audit_lines("ab" * 16) == {"lines": []}


def test_an_upload_still_succeeds_when_the_log_cannot_be_written(server, team, tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a folder")
    monkeypatch.setattr(passman_server.AccountStore, "_audit_path",
                        lambda self, vault_id=None: str(blocker / "x.log"))
    status, _, meta = put_vault(server, team.sa, team.vid, vault_blob(team.vid))
    assert status == 200 and meta["revision"] == 1
    assert put_member(server, team.sa, team.vid, "bob", "reader", wrapped=None)[0] == 200


# --- the account's own list ----------------------------------------------------------------------------

def _listed(server, name):
    path = os.path.join(server.store.root, "_v2", "accounts", name.lower() + ".json")
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("vaults", [])


def test_a_removed_member_no_longer_has_the_vault_in_their_account_file(server, team_up):
    assert team_up.vid in _listed(server, "Carol")
    post_rotate(server, team_up.sa, team_up.vid,
                rotate_body(team_up.vid, ["alice", "bob"], remove=["Carol"]))
    assert team_up.vid not in _listed(server, "Carol")
    assert team_up.vid in _listed(server, "bob")


def test_a_member_who_left_no_longer_has_the_vault_in_their_account_file(server, team):
    server.request("DELETE", f"/v2/vaults/{team.vid}/members/bob", token=team.sb)
    assert team.vid not in _listed(server, "bob")


def test_a_deleted_vault_leaves_every_account_file(server, team):
    server.request("DELETE", f"/v2/vaults/{team.vid}", token=team.sa)
    for name in ("alice", "bob", "Carol"):
        assert team.vid not in _listed(server, name)
