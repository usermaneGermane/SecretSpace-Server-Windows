"""
API v2, phase 3: several vaults per account, over HTTP.

Names arrive sealed and keys wrapped, so (as in test_server_v2.py) the
tests only need byte strings of the right shape; the server cannot tell them
from the real thing.
"""

import os
import json

import pytest

# First: it puts server/ on the path, and brings the running-server fixture.
from test_server_http import TOKEN, VAULT_1, server  # noqa: F401  (fixture)
from test_server_v2 import (Account, alice, b64, put_vault,  # noqa: F401
                            session_for, signup, vault_blob)
import passman_server                                           # noqa: E402


def new_id() -> str:
    return os.urandom(16).hex()


def sealed_name(size: int = 40) -> str:
    return b64(os.urandom(size))


def wrapped_key(size: int = passman_server.WRAPPED_KEY_LEN) -> str:
    return b64(os.urandom(size))


def create_body(vault_id=None, **changes):
    body = {"id": vault_id or new_id(), "name": sealed_name(),
            "wrapped_key": wrapped_key()}
    body.update(changes)
    return body


def create(server, session, **changes):
    """Create a vault; return (status, body, the body that was sent)."""
    body = create_body(**changes)
    # A change of None means "leave that key out".
    body = {k: v for k, v in body.items() if v is not None}
    status, _, answer = server.request("POST", "/v2/vaults", body, token=session)
    return status, answer, body


def made(server, session):
    """A vault that was made successfully; return its view and request."""
    status, view, body = create(server, session)
    assert status == 201, view
    return view, body


def me(server, session):
    status, _, body = server.request("GET", "/v2/me", token=session)
    assert status == 200
    return body


def vault_dir(server, vault_id):
    return os.path.join(server.store.root, "_v2", "vaults", vault_id)


@pytest.fixture
def bob(server):
    account = Account("bob")
    assert signup(server, account)[0] == 201
    return account


# --- /health -------------------------------------------------------------------

def test_health_says_the_server_has_vaults(server):
    _, _, body = server.request("GET", "/health", token=None)
    assert body["features"] == ["vaults", "sharing"]


# --- create --------------------------------------------------------------------

def test_a_vault_is_made_and_the_owner_is_told_about_it(server, alice):
    session = session_for(server, alice)
    status, view, sent = create(server, session)
    assert status == 201
    assert view == {"id": sent["id"], "kind": "shared", "role": "owner",
                    "revision": 0, "key_generation": 0, "members": 1,
                    "name": sent["name"], "wrapped_key": sent["wrapped_key"]}


def test_me_lists_the_personal_vault_first_then_the_others(server, alice):
    session = session_for(server, alice)
    first, first_sent = made(server, session)
    second, second_sent = made(server, session)
    vaults = me(server, session)["vaults"]
    assert [v["id"] for v in vaults] == [alice.vault, first["id"], second["id"]]
    # the personal vault has no name and no wrapped key; the key is in the keyset
    assert vaults[0] == {"id": alice.vault, "kind": "personal", "role": "owner",
                         "revision": 0, "key_generation": 0, "members": 1}
    assert "name" not in vaults[0] and "wrapped_key" not in vaults[0]
    assert vaults[1]["name"] == first_sent["name"]
    assert vaults[1]["wrapped_key"] == first_sent["wrapped_key"]
    assert vaults[2]["name"] == second_sent["name"]
    assert vaults[2]["kind"] == "shared"


def test_the_names_size_limits_are_inclusive(server, alice):
    session = session_for(server, alice)
    for size in (passman_server.MIN_SEALED_NAME, passman_server.MAX_SEALED_NAME):
        assert create(server, session, name=sealed_name(size))[0] == 201


@pytest.mark.parametrize("changes", [
    {"id": "A" * 32},                       # uppercase hex
    {"id": "ab" * 15},                      # too short
    {"id": "ab" * 17},                      # too long
    {"id": "g" * 32},                       # not hex
    {"id": None},                           # missing
    {"id": 12345},                          # not a string
    {"name": None},                         # missing
    {"name": "not base64 !!"},
    {"name": b64(b"x" * (passman_server.MIN_SEALED_NAME - 1))},   # too short
    {"name": b64(b"x" * (passman_server.MAX_SEALED_NAME + 1))},   # too long
    {"name": 7},
    {"wrapped_key": None},
    {"wrapped_key": "not base64 !!"},
    {"wrapped_key": b64(os.urandom(passman_server.WRAPPED_KEY_LEN - 1))},
    {"wrapped_key": b64(os.urandom(passman_server.WRAPPED_KEY_LEN + 1))},
])
def test_a_bad_vault_is_refused_and_nothing_is_made(server, alice, changes):
    session = session_for(server, alice)
    status, answer, sent = create(server, session, **changes)
    assert status == 400, answer
    assert [v["id"] for v in me(server, session)["vaults"]] == [alice.vault]
    if isinstance(sent.get("id"), str):
        assert not os.path.exists(vault_dir(server, sent["id"]))


def test_a_vault_id_cannot_be_used_twice(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    status, _, _ = server.request("POST", "/v2/vaults",
                                  create_body(view["id"]), token=session)
    assert status == 409
    assert len(me(server, session)["vaults"]) == 2


def test_an_id_is_taken_across_accounts(server, alice, bob):
    alices, bobs = session_for(server, alice), session_for(server, bob)
    view, _ = made(server, alices)
    assert create(server, bobs, id=view["id"])[0] == 409


def test_a_personal_vault_id_cannot_be_claimed(server, alice, bob):
    bobs = session_for(server, bob)
    status, _, _ = server.request("POST", "/v2/vaults",
                                  create_body(alice.vault), token=bobs)
    assert status == 409
    # ... and not by its own account either
    status, _, _ = server.request("POST", "/v2/vaults", create_body(alice.vault),
                                  token=session_for(server, alice))
    assert status == 409


@pytest.mark.parametrize("token", [None, TOKEN, "not-a-session"])
def test_making_a_vault_needs_a_session(server, alice, token):
    status, _, _ = server.request("POST", "/v2/vaults", create_body(),
                                  token=token)
    assert status == 401


def test_the_limit_of_vaults_per_account(server, alice, bob, monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_VAULTS_PER_ACCOUNT", 3)
    session = session_for(server, alice)
    for _ in range(3):
        assert create(server, session)[0] == 201
    status, _, body = server.request("POST", "/v2/vaults", create_body(),
                                     token=session)
    assert status == 403 and "3" in body["error"]
    assert len(me(server, session)["vaults"]) == 4          # personal + 3
    # the limit is the account's own
    assert create(server, session_for(server, bob))[0] == 201


def test_deleting_a_vault_makes_room_under_the_limit(server, alice, monkeypatch):
    monkeypatch.setattr(passman_server, "MAX_VAULTS_PER_ACCOUNT", 1)
    session = session_for(server, alice)
    view, _ = made(server, session)
    assert create(server, session)[0] == 403
    assert server.request("DELETE", f"/v2/vaults/{view['id']}",
                          token=session)[0] == 200
    assert create(server, session)[0] == 201


# --- the blob of a new vault -----------------------------------------------------

def test_a_new_vault_follows_the_2x_revision_rules(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    vid = view["id"]
    status, _, body = server.request("GET", f"/v2/vaults/{vid}", token=session)
    assert status == 200 and body["revision"] == 0 and body["blob"] is None

    first = vault_blob(vid)
    status, _, meta = put_vault(server, session, vid, first, "0")
    assert status == 200 and meta["revision"] == 1
    assert put_vault(server, session, vid, vault_blob(vid))[0] == 428
    assert put_vault(server, session, vid, vault_blob(vid), "0")[0] == 409
    second = vault_blob(vid)
    status, _, meta = put_vault(server, session, vid, second, "1")
    assert status == 200 and meta["revision"] == 2

    _, _, body = server.request("GET", f"/v2/vaults/{vid}", token=session)
    assert body["blob"] == second and body["revision"] == 2
    _, _, meta = server.request("GET", f"/v2/vaults/{vid}/meta", token=session)
    assert meta["revision"] == 2
    # the account's view follows, and the personal vault is not touched
    vaults = me(server, session)["vaults"]
    assert vaults[1]["revision"] == 2 and vaults[0]["revision"] == 0


def test_a_new_vault_refuses_another_vaults_file(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    for other in (alice.vault, new_id()):          # even its owner's personal one
        status, _, body = put_vault(server, session, view["id"],
                                    vault_blob(other), "0")
        assert status == 400 and "another vault" in body["error"]
    assert server.request("GET", f"/v2/vaults/{view['id']}",
                          token=session)[2]["blob"] is None


def test_a_new_vault_refuses_a_file_that_is_not_pmv3(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    for blob in (b64(b"PMV2" + os.urandom(80)), VAULT_1):
        status, _, body = put_vault(server, session, view["id"], blob, "0")
        assert status == 400 and "SecretSpace 3" in body["error"]


def test_a_vault_and_the_personal_vault_hold_separate_blobs(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    mine, other = vault_blob(alice.vault), vault_blob(view["id"])
    assert put_vault(server, session, alice.vault, mine, "0")[0] == 200
    assert put_vault(server, session, view["id"], other, "0")[0] == 200
    get = lambda v: server.request("GET", f"/v2/vaults/{v}", token=session)[2]
    assert get(alice.vault)["blob"] == mine
    assert get(view["id"])["blob"] == other


# --- isolation -------------------------------------------------------------------

def test_someone_elses_new_vault_is_not_there(server, alice, bob):
    alices, bobs = session_for(server, alice), session_for(server, bob)
    view, sent = made(server, alices)
    vid = view["id"]
    blob = vault_blob(vid)
    assert put_vault(server, alices, vid, blob, "0")[0] == 200

    ghost = new_id()                    # what a vault that does not exist says
    _, _, expected = server.request("GET", f"/v2/vaults/{ghost}", token=bobs)

    def asks(target):
        return [
            server.request("GET", f"/v2/vaults/{target}", token=bobs),
            server.request("GET", f"/v2/vaults/{target}/meta", token=bobs),
            put_vault(server, bobs, target, vault_blob(target), "1"),
            server.request("PUT", f"/v2/vaults/{target}/name",
                           {"name": sealed_name()}, token=bobs),
            server.request("DELETE", f"/v2/vaults/{target}", token=bobs),
        ]

    real, absent = asks(vid), asks(ghost)
    for (status, _, answer), (ghost_status, _, ghost_answer) in zip(real, absent):
        assert status == 404 == ghost_status
        assert answer == ghost_answer == expected
        assert answer["error"] == "No such vault."

    # untouched: still there, same blob, same name, same revision
    _, _, body = server.request("GET", f"/v2/vaults/{vid}", token=alices)
    assert body["blob"] == blob and body["revision"] == 1
    listed = me(server, alices)["vaults"]
    assert listed[1]["name"] == sent["name"] and listed[1]["id"] == vid
    assert [v["id"] for v in me(server, bobs)["vaults"]] == [bob.vault]


# --- rename ----------------------------------------------------------------------

def test_the_owner_renames_a_vault(server, alice):
    session = session_for(server, alice)
    view, sent = made(server, session)
    new_name = sealed_name(60)
    assert new_name != sent["name"]
    status, _, answer = server.request("PUT", f"/v2/vaults/{view['id']}/name",
                                       {"name": new_name}, token=session)
    assert status == 200
    assert answer == dict(view, name=new_name)
    assert me(server, session)["vaults"][1]["name"] == new_name
    # the key and the blob are not touched
    assert me(server, session)["vaults"][1]["wrapped_key"] == sent["wrapped_key"]


@pytest.mark.parametrize("body", [
    {}, {"name": None}, {"name": "not base64 !!"}, {"name": 5},
    {"name": b64(b"x" * (passman_server.MIN_SEALED_NAME - 1))},
    {"name": b64(b"x" * (passman_server.MAX_SEALED_NAME + 1))},
])
def test_a_bad_new_name_is_refused(server, alice, body):
    session = session_for(server, alice)
    view, sent = made(server, session)
    status, _, _ = server.request("PUT", f"/v2/vaults/{view['id']}/name", body,
                                  token=session)
    assert status == 400
    assert me(server, session)["vaults"][1]["name"] == sent["name"]


def test_the_personal_vault_has_no_name_to_change(server, alice):
    session = session_for(server, alice)
    status, _, _ = server.request("PUT", f"/v2/vaults/{alice.vault}/name",
                                  {"name": sealed_name()}, token=session)
    assert status == 400
    assert "name" not in me(server, session)["vaults"][0]


def test_only_an_owner_may_rename_or_delete(server, alice, bob):
    """Nobody but an owner can become a member yet, so a non-owner is made
    here by editing the members file, the way a later phase will."""
    alices, bobs = session_for(server, alice), session_for(server, bob)
    view, sent = made(server, alices)
    path = os.path.join(vault_dir(server, view["id"]), "members.json")
    with open(path, encoding="utf-8") as f:
        members = json.load(f)
    members["members"]["bob"] = {"role": "viewer", "wrapped_key": sent["wrapped_key"]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(members, f)

    assert server.request("PUT", f"/v2/vaults/{view['id']}/name",
                          {"name": sealed_name()}, token=bobs)[0] == 403
    assert server.request("DELETE", f"/v2/vaults/{view['id']}",
                          token=bobs)[0] == 403
    # a viewer cannot write the blob either
    assert put_vault(server, bobs, view["id"], vault_blob(view["id"]),
                     "0")[0] == 403
    assert me(server, alices)["vaults"][1]["name"] == sent["name"]
    assert os.path.isdir(vault_dir(server, view["id"]))


def test_a_name_cannot_be_put_on_a_wrong_route(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    for method in ("GET", "POST", "DELETE"):
        status, _, _ = server.request(method, f"/v2/vaults/{view['id']}/name",
                                      {"name": sealed_name()}, token=session)
        assert status == 404
    status, _, _ = server.request("PUT", f"/v2/vaults/{view['id']}/other",
                                  {}, token=session)
    assert status == 404


# --- delete ----------------------------------------------------------------------

def test_the_owner_deletes_a_vault_and_it_is_moved_not_erased(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    vid = view["id"]
    blob = vault_blob(vid)
    assert put_vault(server, session, vid, blob, "0")[0] == 200
    keep = made(server, session)[0]

    status, _, _ = server.request("DELETE", f"/v2/vaults/{vid}", token=session)
    assert status == 200

    assert [v["id"] for v in me(server, session)["vaults"]] == [alice.vault,
                                                                keep["id"]]
    for tail in ("", "/meta"):
        assert server.request("GET", f"/v2/vaults/{vid}{tail}",
                              token=session)[0] == 404
    assert put_vault(server, session, vid, blob, "1")[0] == 404
    assert server.request("DELETE", f"/v2/vaults/{vid}", token=session)[0] == 404

    assert not os.path.exists(vault_dir(server, vid))
    graveyard = os.path.join(server.store.root, "_v2", "deleted")
    moved = [n for n in os.listdir(graveyard) if n.startswith(vid + "-")]
    assert len(moved) == 1
    folder = os.path.join(graveyard, moved[0])
    with open(os.path.join(folder, "vault.enc"), "rb") as f:
        assert f.read() == blob.encode("ascii")   # stored as sent
    assert os.path.isfile(os.path.join(folder, "members.json"))
    # the other vault is untouched
    assert os.path.isdir(vault_dir(server, keep["id"]))


def test_a_deleted_vault_id_is_free_again(server, alice):
    """Its folder left the vaults folder, so the id counts as unused: a new
    vault may take it, and the old one stays in the graveyard."""
    session = session_for(server, alice)
    view, _ = made(server, session)
    vid = view["id"]
    assert put_vault(server, session, vid, vault_blob(vid), "0")[0] == 200
    assert server.request("DELETE", f"/v2/vaults/{vid}", token=session)[0] == 200

    status, again, _ = create(server, session, id=vid)
    assert status == 201
    assert again["revision"] == 0
    assert server.request("GET", f"/v2/vaults/{vid}",
                          token=session)[2]["blob"] is None
    graveyard = os.path.join(server.store.root, "_v2", "deleted")
    assert len([n for n in os.listdir(graveyard) if n.startswith(vid)]) == 1


def test_the_personal_vault_cannot_be_deleted(server, alice):
    session = session_for(server, alice)
    blob = vault_blob(alice.vault)
    assert put_vault(server, session, alice.vault, blob, "0")[0] == 200
    status, _, _ = server.request("DELETE", f"/v2/vaults/{alice.vault}",
                                  token=session)
    assert status == 400
    status, _, body = server.request("GET", f"/v2/vaults/{alice.vault}",
                                     token=session)
    assert status == 200 and body["blob"] == blob
    assert me(server, session)["vaults"][0]["id"] == alice.vault
    assert os.path.isdir(vault_dir(server, alice.vault))
    assert not os.path.exists(os.path.join(server.store.root, "_v2", "deleted"))
    assert put_vault(server, session, alice.vault, vault_blob(alice.vault),
                     "1")[0] == 200


def test_delete_needs_a_session(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    for token in (None, TOKEN):
        assert server.request("DELETE", f"/v2/vaults/{view['id']}",
                              token=token)[0] == 401
    assert os.path.isdir(vault_dir(server, view["id"]))


@pytest.mark.parametrize("path", ["/vault/alice", "/vault/alice/meta", "/health",
                                  "/nowhere"])
def test_delete_outside_v2_is_not_implemented(server, path):
    server.push("alice", VAULT_1)
    status, _, _ = server.request("DELETE", path)
    assert status == 501
    assert server.pull("alice")[0] == 200


# --- older data and 2.x --------------------------------------------------------

def test_an_account_from_alpha_1_has_no_vault_list_and_still_works(server, alice):
    path = os.path.join(server.store.root, "_v2", "accounts", "alice.json")
    with open(path, encoding="utf-8") as f:
        record = json.load(f)
    assert record.pop("vaults", None) in (None, [])     # alpha.1 never wrote it
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f)
    assert "vaults" not in json.load(open(path, encoding="utf-8"))

    session = session_for(server, alice)
    assert [v["id"] for v in me(server, session)["vaults"]] == [alice.vault]
    view, _ = made(server, session)
    assert [v["id"] for v in me(server, session)["vaults"]] == [alice.vault,
                                                                view["id"]]
    assert server.request("DELETE", f"/v2/vaults/{view['id']}",
                          token=session)[0] == 200
    assert [v["id"] for v in me(server, session)["vaults"]] == [alice.vault]


def test_2x_vaults_are_unaffected_by_v2_vaults(server, alice):
    session = session_for(server, alice)
    view, _ = made(server, session)
    assert put_vault(server, session, view["id"], vault_blob(view["id"]),
                     "0")[0] == 200
    status, _, meta = server.push("alice", VAULT_1, if_match="0")
    assert status == 200 and meta["revision"] == 1
    status, _, body = server.pull("alice")
    assert status == 200 and body["blob"] == VAULT_1
    server.request("DELETE", f"/v2/vaults/{view['id']}", token=session)
    assert server.pull("alice")[2]["blob"] == VAULT_1
