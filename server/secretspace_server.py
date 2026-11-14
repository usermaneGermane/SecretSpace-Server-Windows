#!/usr/bin/env python3
"""
SecretSpace sync server -- a store for encrypted vault blobs.

What it is NOT: it cannot read your passwords. The client encrypts the vault
before it ever reaches the network, so this process holds AES-256-GCM
ciphertext it has no key for. It never sees a master password, a Secret Key or
a vault key, and there is deliberately nothing here that could -- no password
reset, no "forgot my vault".

What it does: stores vault blobs, stamps each with a revision number, and
refuses a write that was computed against an older revision. That refusal is
the whole point. Without it, two PCs that both edited offline would silently
overwrite each other; with it, the second one is told to merge first.

Two APIs side by side: /vault/<user> with one shared token for SecretSpace
2.x clients, and /v2/ with accounts and sessions for SecretSpace 3 (see the
API v2 section below).

Standard library only, so it runs on any box with Python 3 and nothing to
install. See README.md for deployment.
"""

import os
import re
import ssl
import sys
import json
import hmac
import base64
import hashlib
import argparse
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: Refuse anything larger than this. A vault is kilobytes; a megabyte is
#: already absurd, and the limit keeps a bad request from eating memory.
MAX_BODY = 8 * 1024 * 1024

#: Previous revisions kept per user. Server-side undo, in the same spirit as
#: the client's archive: getting it wrong should cost a restore, not a vault.
HISTORY_LIMIT = 20

#: A 2.x vault blob is base64 of marker||header||salt||nonce||ct, or the
#: older salt||nonce||ct. Below this it cannot be either, so it is a
#: misdirected request rather than a vault.
MIN_BLOB_BYTES = 28

#: Same rule the client applies, because these become directory names.
VALID_USER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,62})$")
WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

#: Where it listens when neither a flag nor the environment says otherwise.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------
#: What this server is called on the wire.
SERVICE_NAME = "secretspace-sync"
#: Settings come from the environment under this prefix (HOST, PORT, TOKEN).
ENV_PREFIX = "SECRETSPACE_"
#: The two optional headers of an upload.
HEADER_KEY_GENERATION = "X-SecretSpace-Key-Generation"
HEADER_DROP_HISTORY = "X-SecretSpace-Drop-History"

# The project was called PassMan until November 2026. These are the names
# from then. They are only ever READ -- from a settings file written by an
# older setup, a request from an older app, an account not converted yet --
# and never written. They go when the old apps do.
LEGACY_ENV_PREFIX = "PASSMAN_"
LEGACY_HEADER_KEY_GENERATION = "X-PassMan-Key-Generation"
LEGACY_HEADER_DROP_HISTORY = "X-PassMan-Drop-History"
LEGACY_KEYSET_MAGIC = b"PMK3"
LEGACY_VAULT_MAGIC = b"PMV3"


def env_setting(environ, name: str) -> str:
    """A setting from the environment: the current name, else the old one."""
    return (environ.get(ENV_PREFIX + name, "").strip()
            or environ.get(LEGACY_ENV_PREFIX + name, "").strip())


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def valid_username(name: str) -> bool:
    if not name or not VALID_USER.match(name):
        return False
    return name.rstrip(". ").lower() not in WINDOWS_RESERVED


def write_atomic(path: str, payload: bytes) -> None:
    """Same durability rule as the client: a crash must not truncate a vault."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Store:
    """One directory per user: the blob, its metadata, and recent history."""

    def __init__(self, root: str):
        self.root = os.path.abspath(root)

    def _dir(self, user: str) -> str:
        return os.path.join(self.root, user)

    def _blob_path(self, user: str) -> str:
        return os.path.join(self._dir(user), "vault.enc")

    def _meta_path(self, user: str) -> str:
        return os.path.join(self._dir(user), "meta.json")

    def meta(self, user: str) -> dict:
        """Current metadata, or revision 0 when this user has never pushed."""
        try:
            with open(self._meta_path(user), encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "revision" in data:
                # Stores written before key_generation existed read as 0,
                # which is also what a client that never changed its
                # password holds -- so an upgrade changes nothing.
                data.setdefault("key_generation", 0)
                return data
        except (OSError, ValueError):
            pass
        return {"revision": 0, "sha256": "", "updated_at": "", "size": 0,
                "key_generation": 0}

    def read(self, user: str) -> bytes:
        with open(self._blob_path(user), "rb") as f:
            return f.read()

    def exists(self, user: str) -> bool:
        return os.path.exists(self._blob_path(user))

    def write(self, user: str, blob: bytes, key_generation=None,
              drop_history: bool = False) -> dict:
        """
        Store a new revision and return its metadata.

        ``key_generation`` is how many times the client has changed this
        vault's master password. The server cannot check it -- it has no key
        -- it only keeps it, so another PC can tell whether the copy here was
        encrypted under an older or a newer password than its own. None keeps
        whatever was stored.

        ``drop_history`` discards every earlier revision, including the one
        this write replaces. The client asks for it after a password change:
        those revisions are still encrypted under the old password, which is
        exactly what someone changing a leaked password wants gone.
        """
        current = self.meta(user)
        revision = int(current["revision"]) + 1
        if key_generation is None:
            key_generation = int(current.get("key_generation", 0))

        if drop_history:
            self._drop_history(user)
        elif self.exists(user):
            self._archive(user, int(current["revision"]))

        meta = {
            "revision": revision,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "updated_at": utc_now(),
            "size": len(blob),
            "key_generation": key_generation,
        }
        write_atomic(self._blob_path(user), blob)
        write_atomic(self._meta_path(user),
                     json.dumps(meta, indent=2).encode("utf-8"))
        return meta

    def _drop_history(self, user: str) -> None:
        history = os.path.join(self._dir(user), "history")
        try:
            for name in os.listdir(history):
                os.remove(os.path.join(history, name))
        except OSError:
            pass                      # nothing there, or already gone

    def _archive(self, user: str, revision: int) -> None:
        """Keep the outgoing revision, then trim the oldest away."""
        history = os.path.join(self._dir(user), "history")
        try:
            write_atomic(os.path.join(history, f"{revision:08d}.enc"),
                         self.read(user))
        except OSError:
            return                    # history is a nicety, never block a write
        try:
            kept = sorted(f for f in os.listdir(history) if f.endswith(".enc"))
            for stale in kept[:-HISTORY_LIMIT]:
                os.remove(os.path.join(history, stale))
        except OSError:
            pass


# ===========================================================================
# SecretSpace 3 accounts: API v2
# ===========================================================================
#
# Everything above serves 2.x clients: one blob per username, one shared
# token. 3.0 clients get accounts instead. The server still never sees a
# master password, a Secret Key or a vault key:
#
# - an account is the client's Login Key (hashed here), its public key, and
#   its keyset and recovery copy, both sealed on the device;
# - a vault is a blob exactly like a 2.x one, kept by the same Store with the
#   same revision / If-Match / history rules, plus who may use it.
#
# It all lives in <store>/_v2/. A 2.x username cannot start with "_", so no
# 2.x vault folder can ever collide with it.

V2_DIR = "_v2"

#: How long a login lasts.
SESSION_SECONDS = 12 * 3600

#: The Login Key is 32 bytes from HKDF (password + Secret Key), already far
#: beyond guessing, so the stored hash needs no slow KDF of its own -- scrypt
#: with modest cost only makes a stolen accounts folder useless to replay.
#: It is in the standard library, which keeps the server free of packages.
LOGIN_KEY_LEN = 32
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1

#: Wrong logins per username before it is paused, the window they are counted
#: in, and the pause. The Login Key cannot be guessed; this is about noise.
MAX_LOGIN_FAILURES = 10
FAILURE_WINDOW = 15 * 60
LOCKOUT_SECONDS = 60

#: The client's Argon2id default, for the made-up answer to a pre-login for an
#: account that does not exist (see AccountStore.prelogin).
DEFAULT_KDF = {"memory_kib": 65536, "passes": 3, "lanes": 1}

VAULT_ID = re.compile(r"^[0-9a-f]{32}$")
ROLES = ("owner", "editor", "reader")
ROLES_THAT_WRITE = ("owner", "editor")

#: People in one vault, and vaults one account may be in (its own and the
#: ones shared with it). Both only keep a mistake or a prank from growing
#: without end.
MAX_MEMBERS_PER_VAULT = 50
MAX_VAULTS_LISTED = 200

#: The server's own record of what happened (who logged in, who uploaded,
#: who was added or removed): one JSON object per line, only ever appended.
#: A file that reaches this size is renamed to <name>.1 (replacing the
#: previous .1) and a new one started.
AUDIT_ROTATE_BYTES = 2 * 1024 * 1024
#: Lines an owner is sent when asking for a vault's log.
AUDIT_LINES_SENT = 200

#: Vaults an account may make besides its personal one. Whoever holds the
#: sign-up code can make an account; this keeps one from filling the disk
#: with empty vaults.
MAX_VAULTS_PER_ACCOUNT = 50

#: A vault key wrapped to a member (account_crypto.wrap_key on the client):
#: version, a one-off X25519 public key, a nonce, the key and its tag.
WRAPPED_KEY_LEN = 1 + 32 + 12 + 32 + 16

#: With each wrapped key comes a signature by the account that wrapped it
#: (Ed25519, 64 bytes). A device accepts a vault key only with a signature
#: from itself or from someone it knows -- so a dishonest server cannot hand
#: out a key of its own making and read what is then uploaded under it. The
#: server only keeps and returns the signature; the devices check it.
KEY_SIG_LEN = 64


def _key_sig(value):
    """An optional key signature as stored ("" when none came)."""
    if value is None or value == "":
        return ""
    return _b64(_unb64(value, "The key's signature", KEY_SIG_LEN))


#: A vault's name arrives sealed under the vault's key, so the server cannot
#: read it: a nonce, the name (up to 200 bytes) and a tag.
MIN_SEALED_NAME = 12 + 1 + 16
MAX_SEALED_NAME = 12 + 200 + 16

#: What a device proves it can open the account's keyset with, when it
#: recovers the account with the 12-word phrase (account_crypto.recovery_proof):
#: 32 bytes, stored here only as a hash, like the Login Key.
RECOVERY_PROOF_LEN = 32

#: The size of a recovery copy for an account's usual keyset, for the
#: made-up answer about a name that has no account (see recovery_copy).
_RECOVERY_BODY = 12 + 259 + 16

#: The account files' layouts, from the client (account_crypto.py). Format 2
#: is what SecretSpace 4 writes; format 1 is an account from SecretSpace 3
#: that has not been converted yet.
_KEYSET_MAGIC = b"SSK4"
_KEYSET_VERSION = 2
_KEYSET_HEADER = 4 + 1 + 1 + 4 + 1 + 1 + 16     # magic ver kdf mem passes lanes salt
_VAULT_MAGIC = b"SSV4"
FORMAT_OLD, FORMAT_NOW = 1, 2


class V2Error(Exception):
    """A refusal with its HTTP status and the message the user sees."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _unb64(text, what: str, length: int = None) -> bytes:
    try:
        raw = base64.b64decode(str(text).encode("ascii"), validate=True)
    except Exception:
        raise V2Error(400, f"{what} is not valid base64.") from None
    if length is not None and len(raw) != length:
        raise V2Error(400, f"{what} has the wrong length.")
    return raw


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def keyset_kdf(sealed: str, recovery: bool = False) -> dict:
    """
    The key-derivation header of a sealed keyset (what a new device needs to
    turn a master password into the key that opens it). The rest is
    ciphertext this server cannot and does not need to read.
    """
    raw = _unb64(sealed, "The recovery copy" if recovery else "The keyset")
    if len(raw) < _KEYSET_HEADER + 12 + 16 or \
            raw[:4] not in (_KEYSET_MAGIC, LEGACY_KEYSET_MAGIC):
        raise V2Error(400, "That is not a SecretSpace keyset.")
    kdf = raw[5]
    if kdf != (0 if recovery else 1):
        raise V2Error(400, "The keyset and its recovery copy are swapped.")
    memory_kib = int.from_bytes(raw[6:10], "big")
    return {"memory_kib": memory_kib, "passes": raw[10], "lanes": raw[11],
            "salt": _b64(raw[12:28])}


def keyset_format(sealed: str) -> int:
    """Which account format a sealed keyset is in (see keyset_kdf)."""
    raw = _unb64(sealed, "The keyset")
    return FORMAT_NOW if raw[:4] == _KEYSET_MAGIC else FORMAT_OLD


def hash_login_key(login_key: bytes, salt: bytes = None) -> dict:
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(login_key, salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                            p=SCRYPT_P, dklen=32)
    return {"salt": _b64(salt), "hash": _b64(digest), "n": SCRYPT_N,
            "r": SCRYPT_R, "p": SCRYPT_P}


def login_key_matches(login_key: bytes, stored: dict) -> bool:
    try:
        digest = hashlib.scrypt(login_key, salt=base64.b64decode(stored["salt"]),
                                n=int(stored["n"]), r=int(stored["r"]),
                                p=int(stored["p"]), dklen=32)
        return hmac.compare_digest(digest, base64.b64decode(stored["hash"]))
    except Exception:
        return False


class AccountStore:
    """Accounts, sessions and vaults of API v2, under <store>/_v2."""

    def __init__(self, store_root: str):
        self.root = os.path.join(os.path.abspath(store_root), V2_DIR)
        self.vaults = Store(os.path.join(self.root, "vaults"))
        self._failures = {}               # username (lower) -> [times]
        self._failure_lock = threading.Lock()
        self._audit_lock = threading.Lock()

    # -- files --------------------------------------------------------------
    def _account_path(self, username: str) -> str:
        # One file per name regardless of case: "Alice" and "alice" are one
        # account, as they are one folder on Windows.
        return os.path.join(self.root, "accounts", username.lower() + ".json")

    def _members_path(self, vault_id: str) -> str:
        return os.path.join(self.vaults.root, vault_id, "members.json")

    @staticmethod
    def _read_json(path: str):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    @staticmethod
    def _write_json(path: str, data) -> None:
        write_atomic(path, json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))

    # -- the audit log ----------------------------------------------------------
    def _audit_path(self, vault_id: str = None) -> str:
        if vault_id is None:
            return os.path.join(self.root, "logins.log")
        return os.path.join(self.vaults.root, vault_id, "audit.log")

    def audit(self, vault_id, event: str, by: str, address: str = "",
              **details) -> None:
        """
        Append one line to a vault's log (``vault_id`` None: the log of
        logins). Never raises: a full disk must not turn a finished upload
        into an error -- the line is then simply missing.
        """
        line = {"at": utc_now(), "event": event, "by": by, "address": address}
        line.update(details)
        path = self._audit_path(vault_id)
        try:
            with self._audit_lock:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                try:
                    if os.path.getsize(path) >= AUDIT_ROTATE_BYTES:
                        os.replace(path, path + ".1")
                except OSError:
                    pass
                with open(path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(line, sort_keys=True) + "\n")
        except OSError:
            pass

    def audit_lines(self, vault_id: str) -> dict:
        """The newest lines of a vault's log, oldest first."""
        lines = []
        try:
            with open(self._audit_path(vault_id), encoding="utf-8") as f:
                for text in f.readlines()[-AUDIT_LINES_SENT:]:
                    try:
                        line = json.loads(text)
                    except ValueError:
                        continue
                    if isinstance(line, dict):
                        lines.append(line)
        except OSError:
            pass
        return {"lines": lines}

    def account(self, username: str):
        """The stored account, or None. Matches the name exactly."""
        if not valid_username(username):
            return None
        record = self._read_json(self._account_path(username))
        if not record or record.get("username") != username:
            return None
        return record

    def _server_key(self) -> bytes:
        path = os.path.join(self.root, "server.key")
        try:
            with open(path, "rb") as f:
                key = f.read()
            if len(key) == 32:
                return key
        except OSError:
            pass
        key = os.urandom(32)
        write_atomic(path, key)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return key

    # -- pre-login ------------------------------------------------------------
    def prelogin(self, username: str) -> dict:
        """
        How a device turns this account's master password into keys: the
        Argon2id salt and cost from the stored keyset. For a name with no
        account the answer is made up -- a salt derived from a key only this
        server has, so it is the same on every ask -- and the login then simply
        fails. That way the answer says nothing about which names exist.
        """
        if not valid_username(username):
            raise V2Error(400, "Not a valid username.")
        record = self._read_json(self._account_path(username))
        if record:
            return {"username": record["username"], "kdf": record["kdf"]}
        salt = hmac.new(self._server_key(), b"prelogin|" + username.lower().encode(),
                        hashlib.sha256).digest()[:16]
        return {"username": username, "kdf": {**DEFAULT_KDF, "salt": _b64(salt)}}

    # -- sign-up ------------------------------------------------------------
    def create_account(self, body: dict) -> dict:
        username = body.get("username")
        if not isinstance(username, str) or not valid_username(username):
            raise V2Error(400, "Not a valid username.")
        login_key = _unb64(body.get("login_key"), "The login key", LOGIN_KEY_LEN)
        kdf = keyset_kdf(body.get("keyset"))
        keyset_kdf(body.get("recovery"), recovery=True)
        public_key = _unb64(body.get("public_key"), "The public key", 32)
        signing_key = body.get("signing_key")
        if signing_key is not None:
            signing_key = _b64(_unb64(signing_key, "The signing key", 32))
        proof = body.get("recovery_proof")
        if proof is not None:
            proof = hash_login_key(_unb64(proof, "The recovery proof",
                                          RECOVERY_PROOF_LEN))
        vault_id = body.get("personal_vault")
        if not isinstance(vault_id, str) or not VAULT_ID.match(vault_id):
            raise V2Error(400, "The personal vault id is not valid.")

        with _lock:
            if self._read_json(self._account_path(username)) is not None:
                raise V2Error(409, f"There is already an account called "
                                   f"“{username}” on this server.")
            if os.path.exists(os.path.join(self.vaults.root, vault_id)):
                raise V2Error(409, "That vault id is already in use.")
            self._write_json(self._members_path(vault_id), {
                "kind": "personal", "created_at": utc_now(),
                "members": {username: {"role": "owner"}}})
            self._write_json(self._account_path(username), {
                "username": username,
                "created_at": utc_now(),
                "login": hash_login_key(login_key),
                "public_key": _b64(public_key),
                "signing_key": signing_key or "",
                "recovery_check": proof,
                "keyset": body["keyset"],
                "recovery": body["recovery"],
                "kdf": kdf,
                "format": keyset_format(body["keyset"]),
                "personal_vault": vault_id,
                "disabled": False,
            })
        return {"username": username, "personal_vault": vault_id}

    # -- logging in ---------------------------------------------------------
    def _paused(self, username: str) -> bool:
        now = time.time()
        with self._failure_lock:
            recent = [t for t in self._failures.get(username.lower(), [])
                      if now - t < FAILURE_WINDOW]
            self._failures[username.lower()] = recent
            return (len(recent) >= MAX_LOGIN_FAILURES
                    and now - recent[-1] < LOCKOUT_SECONDS)

    def _failed(self, username: str) -> None:
        with self._failure_lock:
            self._failures.setdefault(username.lower(), []).append(time.time())

    def login(self, body: dict) -> dict:
        username = body.get("username")
        if not isinstance(username, str) or not valid_username(username):
            raise V2Error(400, "Not a valid username.")
        login_key = _unb64(body.get("login_key"), "The login key", LOGIN_KEY_LEN)
        if self._paused(username):
            raise V2Error(429, "Too many wrong attempts for this account. "
                               "Wait a minute, then try again.")
        record = self.account(username)
        # Hash even when there is no such account, so the answer takes as long
        # either way and its timing does not tell which names exist.
        stored = record["login"] if record else hash_login_key(b"\0" * 32)
        ok = login_key_matches(login_key, stored) and record is not None
        if not ok or record.get("disabled"):
            self._failed(username)
            raise V2Error(401, "Wrong username, master password or Secret Key.")
        with self._failure_lock:
            self._failures.pop(username.lower(), None)
        token = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        self._write_json(self._session_path(token), {
            "username": username, "expires": time.time() + SESSION_SECONDS})
        self._drop_expired_sessions()
        return {"session": token, "username": username,
                "expires_in": SESSION_SECONDS}

    # -- sessions -----------------------------------------------------------
    def _session_path(self, token: str) -> str:
        # Stored under its hash: a copy of this folder logs nobody in.
        name = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return os.path.join(self.root, "sessions", name + ".json")

    def session_user(self, token: str):
        """The username a session token belongs to, or None."""
        if not token or len(token) > 200:
            return None
        try:
            session = self._read_json(self._session_path(token))
        except (OSError, ValueError):
            return None
        if not session or session.get("expires", 0) < time.time():
            return None
        record = self.account(session.get("username", ""))
        if not record or record.get("disabled"):
            return None
        return record["username"]

    def logout(self, token: str) -> None:
        try:
            os.remove(self._session_path(token))
        except OSError:
            pass

    def _drop_expired_sessions(self, keep_user: str = None, keep_token: str = None,
                               user_to_end: str = None) -> None:
        """Remove expired sessions; with ``user_to_end``, also every session
        of that user except ``keep_token``'s."""
        folder = os.path.join(self.root, "sessions")
        keep = os.path.basename(self._session_path(keep_token)) if keep_token else None
        now = time.time()
        try:
            names = os.listdir(folder)
        except OSError:
            return
        for name in names:
            path = os.path.join(folder, name)
            try:
                session = self._read_json(path) or {}
            except (OSError, ValueError):
                session = {}
            ending = (user_to_end is not None and name != keep
                      and session.get("username") == user_to_end)
            if ending or session.get("expires", 0) < now:
                try:
                    os.remove(path)
                except OSError:
                    pass

    # -- the account itself -------------------------------------------------
    def _vault_view(self, username: str, vault_id: str):
        """What an account is told about one of its vaults, or None when it
        is not (or no longer) a member."""
        members = self._read_json(self._members_path(vault_id)) or {}
        member = members.get("members", {}).get(username)
        if member is None:
            return None
        meta = self.vaults.meta(vault_id)
        view = {"id": vault_id, "kind": members.get("kind", "personal"),
                "role": member.get("role", "owner"),
                "revision": meta["revision"],
                "key_generation": int(members.get("key_generation", 0)),
                "members": len(members.get("members", {}))}
        # The personal vault's key is in the keyset and it has no name; every
        # other vault carries its key wrapped to this member, and its name
        # sealed under that key.
        if view["kind"] != "personal":
            view["name"] = members.get("name", "")
            view["wrapped_key"] = member.get("wrapped_key", "")
            view["key_sig"] = member.get("key_sig", "")
            view["key_signer"] = member.get("key_signer", "")
        return view

    def me(self, username: str) -> dict:
        record = self.account(username)
        vault_id = record["personal_vault"]
        vaults = []
        for each in [vault_id] + list(record.get("vaults", [])):
            view = self._vault_view(username, each)
            if view is not None:
                vaults.append(view)
        return {"username": record["username"], "public_key": record["public_key"],
                "signing_key": record.get("signing_key", ""),
                "can_recover": bool(record.get("recovery_check")),
                "keyset": record["keyset"], "recovery": record["recovery"],
                "kdf": record["kdf"], "personal_vault": vault_id,
                "format": self.account_format(record),
                "vaults": vaults}

    @staticmethod
    def account_format(record) -> int:
        """1 for an account from SecretSpace 3 not converted yet, else 2."""
        return int((record or {}).get("format", FORMAT_OLD) or FORMAT_OLD)

    def change_keyset(self, username: str, body: dict, keep_token: str) -> bool:
        """
        A new master password: the same keys under a new seal, and the Login
        Key that goes with it. Every other session of the account ends -- a
        password is changed when it may have leaked.

        It is also how an account from SecretSpace 3 is converted: the same
        keys sealed in the new format. Returns True when this call converted
        the account. A converted account never goes back: a device that
        still sends the old format has an old app.
        """
        login_key = _unb64(body.get("login_key"), "The login key", LOGIN_KEY_LEN)
        kdf = keyset_kdf(body.get("keyset"))
        new_format = keyset_format(body["keyset"])
        with _lock:
            record = self.account(username)
            had = self.account_format(record)
            if new_format < had:
                raise V2Error(409, "This account was converted to the new "
                                   "format on another device. Update "
                                   "SecretSpace on this one.")
            record.update({"login": hash_login_key(login_key),
                           "keyset": body["keyset"], "kdf": kdf,
                           "format": new_format,
                           "password_changed_at": utc_now()})
            if new_format > had:
                record["converted_at"] = utc_now()
            self._write_json(self._account_path(username), record)
        self._drop_expired_sessions(user_to_end=username, keep_token=keep_token)
        return new_format > had

    def set_signing_key(self, username: str, body: dict) -> None:
        """
        The public half of the key an account signs its changes with. Set
        once: an account made before signing existed sends it at its next
        login, and from then on it cannot be swapped -- not even by someone
        holding a session of the account.
        """
        key = _b64(_unb64(body.get("signing_key"), "The signing key", 32))
        with _lock:
            record = self.account(username)
            had = record.get("signing_key", "")
            if had and had != key:
                raise V2Error(409, "This account already has a signing key; "
                                   "it cannot be replaced.")
            if not had:
                record["signing_key"] = key
                self._write_json(self._account_path(username), record)

    # -- recovery (phase 5) -----------------------------------------------------
    def set_recovery_proof(self, username: str, body: dict) -> None:
        """
        What lets this account be recovered here with its 12-word phrase.
        An account made before recovery existed sends it once, at its next
        sync; it cannot be replaced afterwards. (It comes from the account's
        own keys, which a new phrase does not change.)
        """
        proof = _unb64(body.get("recovery_proof"), "The recovery proof",
                       RECOVERY_PROOF_LEN)
        with _lock:
            record = self.account(username)
            had = record.get("recovery_check")
            if had and not login_key_matches(proof, had):
                raise V2Error(409, "This account can already be recovered; "
                                   "that cannot be replaced.")
            if not had:
                record["recovery_check"] = hash_login_key(proof)
                self._write_json(self._account_path(username), record)

    def set_recovery_copy(self, username: str, body: dict) -> None:
        """A new 12-word phrase: the keyset under it replaces the old copy,
        so the old phrase opens nothing from now on."""
        keyset_kdf(body.get("recovery"), recovery=True)
        with _lock:
            record = self.account(username)
            record.update({"recovery": body["recovery"],
                           "recovery_changed_at": utc_now()})
            self._write_json(self._account_path(username), record)

    def recovery_copy(self, username: str) -> dict:
        """
        The account's keyset under its 12-word phrase, for a device that
        recovers the account. Handing it out is safe: it opens only with the
        phrase, 128 random bits. For a name with no account the answer is
        made up, the same on every ask, so it says nothing about which names
        exist (as prelogin).
        """
        if not valid_username(username):
            raise V2Error(400, "Not a valid username.")
        # Any letter case, as the account's file is found (prelogin's rule).
        record = self._read_json(self._account_path(username))
        if record and record.get("username") and not record.get("disabled"):
            return {"username": record["username"], "recovery": record["recovery"]}
        key = self._server_key()
        filler, block = b"", 0
        while len(filler) < _RECOVERY_BODY:
            filler += hmac.new(key, b"recovery|%d|" % block +
                               username.lower().encode(), hashlib.sha256).digest()
            block += 1
        header = _KEYSET_MAGIC + bytes([_KEYSET_VERSION, 0]) + \
            bytes(4 + 1 + 1 + 16)
        return {"username": username,
                "recovery": _b64(header + filler[:_RECOVERY_BODY])}

    def recover(self, body: dict) -> dict:
        """
        A forgotten master password: the device opened the recovery copy
        with the phrase, proves it holds the account's keys, and sends the
        same keys under a new password (and the Login Key that goes with
        it) and under a new phrase. Every session of the account ends.
        """
        username = body.get("username")
        if not isinstance(username, str) or not valid_username(username):
            raise V2Error(400, "Not a valid username.")
        proof = _unb64(body.get("recovery_proof"), "The recovery proof",
                       RECOVERY_PROOF_LEN)
        login_key = _unb64(body.get("login_key"), "The login key", LOGIN_KEY_LEN)
        kdf = keyset_kdf(body.get("keyset"))
        keyset_kdf(body.get("recovery"), recovery=True)
        if self._paused(username):
            raise V2Error(429, "Too many wrong attempts for this account. "
                               "Wait a minute, then try again.")
        record = self.account(username)
        stored = (record or {}).get("recovery_check")
        # Hash even when there is nothing to compare with, as login does.
        ok = login_key_matches(proof, stored or hash_login_key(b"\0" * 32)) \
            and stored is not None and not record.get("disabled")
        if not ok:
            self._failed(username)
            if record is not None and stored is None and not record.get("disabled"):
                raise V2Error(409, "This account cannot be recovered on this "
                                   "server yet: sync it once from a device with "
                                   "SecretSpace 3.0.0-alpha.7 or newer.")
            raise V2Error(401, "The recovery phrase does not open this account.")
        with self._failure_lock:
            self._failures.pop(username.lower(), None)
        new_format = keyset_format(body["keyset"])
        if new_format < self.account_format(record):
            raise V2Error(409, "This account was converted to the new format "
                               "on another device. Update SecretSpace on "
                               "this one.")
        with _lock:
            record = self.account(username)
            record.update({"login": hash_login_key(login_key),
                           "keyset": body["keyset"], "kdf": kdf,
                           "format": max(new_format,
                                         self.account_format(record)),
                           "recovery": body["recovery"],
                           "password_changed_at": utc_now(),
                           "recovered_at": utc_now()})
            self._write_json(self._account_path(username), record)
        self._drop_expired_sessions(user_to_end=username)
        return {"username": username}

    def find_account(self, name: str):
        """An account by name in any letter case (as people type it when they
        share a vault), or None. Disabled accounts are not found."""
        if not isinstance(name, str) or not valid_username(name):
            return None
        record = self._read_json(self._account_path(name))
        if not record or record.get("disabled"):
            return None
        return record

    def public_keys(self, name: str) -> dict:
        """What is needed to share a vault with an account and to check what
        it signed: its public keys, and its name as it spells it."""
        record = self.find_account(name)
        if record is None:
            raise V2Error(404, f"There is no account called “{name}” on this "
                               "server.")
        return {"username": record["username"],
                "public_key": record["public_key"],
                "signing_key": record.get("signing_key", "")}

    # -- vaults -------------------------------------------------------------
    @staticmethod
    def _sealed_name(body: dict) -> str:
        name = body.get("name")
        try:
            size = len(base64.b64decode(name, validate=True))
        except Exception:
            size = 0
        if not isinstance(name, str) or not MIN_SEALED_NAME <= size <= MAX_SEALED_NAME:
            raise V2Error(400, "The vault's name is missing or too long.")
        return name

    def create_vault(self, username: str, body: dict) -> dict:
        """
        A further vault for ``username``, who becomes its owner. The client
        made the vault's id and key; the server gets the key only wrapped to
        the owner's public key, and the name only sealed under the vault key.
        """
        vault_id = body.get("id")
        if not isinstance(vault_id, str) or not VAULT_ID.match(vault_id):
            raise V2Error(400, "The vault id is not valid.")
        name = self._sealed_name(body)
        wrapped = _b64(_unb64(body.get("wrapped_key"), "The vault key",
                              WRAPPED_KEY_LEN))
        key_sig = _key_sig(body.get("key_sig"))
        with _lock:
            record = self.account(username)
            mine = list(record.get("vaults", []))
            made = sum(1 for each in mine
                       if (self._read_json(self._members_path(each)) or {})
                       .get("created_by") == username)
            if made >= MAX_VAULTS_PER_ACCOUNT or len(mine) >= MAX_VAULTS_LISTED:
                raise V2Error(403, f"An account can have {MAX_VAULTS_PER_ACCOUNT} "
                                   "vaults besides its personal one.")
            if os.path.exists(os.path.join(self.vaults.root, vault_id)):
                raise V2Error(409, "That vault id is already in use.")
            self._write_json(self._members_path(vault_id), {
                "kind": "shared", "created_at": utc_now(),
                "created_by": username, "name": name, "key_generation": 0,
                "members": {username: {"role": "owner", "wrapped_key": wrapped,
                                       "key_sig": key_sig,
                                       "key_signer": username}}})
            record["vaults"] = mine + [vault_id]
            self._write_json(self._account_path(username), record)
        return self._vault_view(username, vault_id)

    def rename_vault(self, username: str, vault_id: str, body: dict) -> dict:
        name = self._sealed_name(body)
        with _lock:
            members = self._read_json(self._members_path(vault_id)) or {}
            if members.get("kind") == "personal":
                raise V2Error(400, "The personal vault has no name to change.")
            members["name"] = name
            self._write_json(self._members_path(vault_id), members)
        return self._vault_view(username, vault_id)

    def delete_vault(self, username: str, vault_id: str) -> None:
        """
        Take a vault away from every member. Its folder is not erased but
        moved to <store>/_v2/deleted/, so whoever runs the server can bring a
        vault back that was deleted by mistake -- and can empty that folder
        when they are sure.
        """
        with _lock:
            members = self._read_json(self._members_path(vault_id)) or {}
            if members.get("kind") == "personal":
                raise V2Error(400, "The personal vault cannot be deleted; it "
                                   "goes with the account.")
            for name in members.get("members", {}):
                record = self.account(name)
                if record and vault_id in record.get("vaults", []):
                    record["vaults"] = [v for v in record["vaults"]
                                        if v != vault_id]
                    self._write_json(self._account_path(name), record)
            graveyard = os.path.join(self.root, "deleted")
            os.makedirs(graveyard, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            os.replace(os.path.join(self.vaults.root, vault_id),
                       os.path.join(graveyard, f"{vault_id}-{stamp}"))

    # -- members ------------------------------------------------------------
    def _shared(self, vault_id: str) -> dict:
        """A vault's members file, for a change to who is in it."""
        members = self._read_json(self._members_path(vault_id)) or {}
        if members.get("kind") == "personal":
            raise V2Error(400, "A personal vault cannot be shared; make "
                               "another vault for that.")
        return members

    @staticmethod
    def _owners(members: dict) -> list:
        return [n for n, m in members.get("members", {}).items()
                if m.get("role") == "owner"]

    def members(self, vault_id: str) -> dict:
        """Who is in a vault -- every member may know."""
        members = self._read_json(self._members_path(vault_id)) or {}
        return {"key_generation": int(members.get("key_generation", 0)),
                "format": self.vault_format(members),
                "members": [
                    {"username": name, "role": m.get("role", "owner"),
                     "added_by": m.get("added_by", ""),
                     "added_at": m.get("added_at", ""),
                     "format": self.account_format(
                         self._read_json(self._account_path(name)))}
                    for name, m in sorted(members.get("members", {}).items(),
                                          key=lambda kv: kv[0].lower())]}

    # -- the format of a vault ------------------------------------------------
    # A vault is converted (format 2) once it has been stored in the new
    # form. That may only happen when every member's account is converted,
    # so nobody is locked out of a vault by someone else's update; and from
    # then on it takes neither an upload in the old form nor a member whose
    # app could not read it.
    @staticmethod
    def vault_format(members: dict) -> int:
        return int((members or {}).get("format", FORMAT_OLD) or FORMAT_OLD)

    def _members_all_converted(self, members: dict) -> bool:
        return all(self.account_format(self._read_json(self._account_path(n)))
                   >= FORMAT_NOW for n in (members or {}).get("members", {}))

    def check_blob(self, raw: bytes, vault_id: str, generation: int = None,
                   staying=None) -> int:
        """check_vault_blob, plus the rules above. Returns the blob's format.
        ``staying``: the members after this call, when it removes some."""
        blob_format = check_vault_blob(raw, vault_id, generation)
        members = self._read_json(self._members_path(vault_id)) or {}
        if blob_format < self.vault_format(members):
            raise V2Error(409, "This vault was converted to the new format. "
                               "Update SecretSpace on this device.")
        if blob_format > self.vault_format(members):
            people = members if staying is None else {
                "members": {n: 1 for n in staying}}
            if not self._members_all_converted(people):
                raise V2Error(409, "Not every member of this vault has "
                                   "updated SecretSpace yet; it stays in the "
                                   "old format until they have.")
        return blob_format

    def note_vault_format(self, vault_id: str, blob_format: int) -> None:
        """Remember that a vault is now stored in the new form."""
        if blob_format < FORMAT_NOW:
            return
        with _lock:
            members = self._read_json(self._members_path(vault_id)) or {}
            if members and self.vault_format(members) < blob_format:
                members["format"] = blob_format
                self._write_json(self._members_path(vault_id), members)

    def put_member(self, actor: str, vault_id: str, name: str, body: dict) -> dict:
        """
        Add an account to a vault, or change a member's role (owners only;
        the caller has checked). A new member comes with the vault key
        wrapped to their public key by the owner's device -- the server never
        holds a key it could hand out itself. Returns {"username", "role",
        "added": bool}.
        """
        role = body.get("role")
        if role not in ROLES:
            raise V2Error(400, "The role must be owner, editor or reader.")
        with _lock:
            members = self._shared(vault_id)
            people = members.setdefault("members", {})
            target = self.find_account(name)
            if target is None:
                raise V2Error(404, f"There is no account called “{name}” on "
                                   "this server.")
            who = target["username"]
            if who in people:
                if people[who].get("role") == "owner" and role != "owner" \
                        and self._owners(members) == [who]:
                    raise V2Error(409, "A vault needs at least one owner.")
                people[who]["role"] = role
                self._write_json(self._members_path(vault_id), members)
                return {"username": who, "role": role, "added": False}
            wrapped = _b64(_unb64(body.get("wrapped_key"), "The vault key",
                                  WRAPPED_KEY_LEN))
            key_sig = _key_sig(body.get("key_sig"))
            if self.vault_format(members) > self.account_format(target):
                raise V2Error(409, f"“{who}” has to update SecretSpace and "
                                   "unlock their account once before they "
                                   "can join this vault.")
            if len(people) >= MAX_MEMBERS_PER_VAULT:
                raise V2Error(403, f"A vault can have {MAX_MEMBERS_PER_VAULT} "
                                   "members.")
            listed = list(target.get("vaults", []))
            if len(listed) >= MAX_VAULTS_LISTED:
                raise V2Error(409, f"“{who}” is in too many vaults already.")
            people[who] = {"role": role, "wrapped_key": wrapped,
                           "key_sig": key_sig, "key_signer": actor,
                           "added_by": actor, "added_at": utc_now()}
            self._write_json(self._members_path(vault_id), members)
            target["vaults"] = listed + [vault_id]
            self._write_json(self._account_path(who), target)
            return {"username": who, "role": role, "added": True}

    def _unlist(self, name: str, vault_id: str) -> None:
        record = self.account(name)
        if record and vault_id in record.get("vaults", []):
            record["vaults"] = [v for v in record["vaults"] if v != vault_id]
            self._write_json(self._account_path(name), record)

    def leave_vault(self, username: str, vault_id: str) -> None:
        """A member takes themself out of a vault. (An owner removes someone
        else with :meth:`rotate`, which changes the key in the same step.)"""
        with _lock:
            members = self._shared(vault_id)
            people = members.get("members", {})
            if self._owners(members) == [username]:
                raise V2Error(409, "You are this vault's only owner: make "
                                   "someone else an owner first, or delete "
                                   "the vault.")
            people.pop(username, None)
            self._write_json(self._members_path(vault_id), members)
            self._unlist(username, vault_id)

    def rotate(self, actor: str, vault_id: str, body: dict) -> dict:
        """
        Give a vault a new key, optionally removing members in the same step
        (owners only; the caller has checked). The owner's device made the
        key; what arrives is the vault re-encrypted under it, its name sealed
        again, and the key wrapped to every member who stays. It all changes
        together or not at all:

        - ``generation`` must be the next one;
        - ``wrapped_keys`` must name exactly the members who stay;
        - ``blob`` must be this vault at that generation, made against the
          revision the server holds (``revision``), or absent while the
          vault has never been uploaded.

        Earlier revisions are dropped: they are under the old key, which the
        removed members still have.
        """
        with _lock:
            members = self._shared(vault_id)
            people = members.get("members", {})
            generation = int(members.get("key_generation", 0)) + 1
            if body.get("generation") != generation:
                raise V2Error(409, "The vault's key was changed in the "
                                   "meantime. Sync, then try again.")
            removed = body.get("remove") or []
            if not isinstance(removed, list) or actor in removed or \
                    any(name not in people for name in removed):
                raise V2Error(400, "The members to remove are not valid.")
            staying = [name for name in people if name not in removed]
            wrapped = body.get("wrapped_keys")
            if not isinstance(wrapped, dict) or sorted(wrapped) != sorted(staying):
                raise V2Error(409, "The members of this vault changed in the "
                                   "meantime. Sync, then try again.")
            clean = {name: _b64(_unb64(wrapped[name], "A vault key",
                                       WRAPPED_KEY_LEN)) for name in staying}
            sigs = body.get("key_sigs") or {}
            if not isinstance(sigs, dict) or \
                    (sigs and sorted(sigs) != sorted(staying)):
                raise V2Error(400, "The keys' signatures do not match the "
                                   "members who stay.")
            sigs = {name: _key_sig(sigs.get(name)) for name in staying}
            name = self._sealed_name(body)

            current = int(self.vaults.meta(vault_id)["revision"])
            blob = body.get("blob")
            if blob is None:
                if current != 0:
                    raise V2Error(400, "The vault under its new key is missing.")
            else:
                if body.get("revision") != current:
                    raise V2Error(409, f"Vault has moved on: server is at "
                                       f"revision {current}. Sync, then try "
                                       "again.")
                try:
                    raw = base64.b64decode(str(blob).encode("ascii"), validate=True)
                except Exception:
                    raise V2Error(400, "Blob is not valid base64.") from None
                blob_format = self.check_blob(raw, vault_id, generation,
                                              staying=staying)
                self.vaults.write(vault_id, str(blob).encode("ascii"),
                                  generation, drop_history=True)
                if blob_format > self.vault_format(members):
                    members["format"] = blob_format

            for gone in removed:
                del people[gone]
            for each in staying:
                people[each]["wrapped_key"] = clean[each]
                people[each]["key_sig"] = sigs[each]
                people[each]["key_signer"] = actor
            members["key_generation"] = generation
            members["name"] = name
            self._write_json(self._members_path(vault_id), members)
            for gone in removed:
                self._unlist(gone, vault_id)
        return self._vault_view(actor, vault_id)

    def set_key_sig(self, username: str, vault_id: str, body: dict) -> None:
        """
        A member vouches for the wrapped key it already holds, for a vault
        made before keys were signed -- so its other devices will accept
        that key. Only while that key has no signature: one made by an
        owner is never replaced.
        """
        sig = _key_sig(body.get("key_sig"))
        if not sig:
            raise V2Error(400, "The key's signature is missing.")
        with _lock:
            members = self._shared(vault_id)
            entry = members.get("members", {}).get(username)
            if entry.get("key_sig"):
                raise V2Error(409, "This key is signed already.")
            entry["key_sig"], entry["key_signer"] = sig, username
            self._write_json(self._members_path(vault_id), members)

    def key_generation(self, vault_id: str) -> int:
        members = self._read_json(self._members_path(vault_id)) or {}
        return int(members.get("key_generation", 0))

    def role(self, username: str, vault_id: str):
        """This user's role in the vault, or None (also for no such vault)."""
        if not VAULT_ID.match(vault_id or ""):
            return None
        members = self._read_json(self._members_path(vault_id)) or {}
        member = members.get("members", {}).get(username)
        return member.get("role") if member else None


def check_vault_blob(raw: bytes, vault_id: str, generation: int = None) -> int:
    """A v2 vault blob must be a SecretSpace vault and name the vault it is
    stored as, so a confused client cannot put one vault's file in another's
    place. With ``generation`` it must also say it is under the vault's
    current key: a device that missed a key change must sync before it
    uploads, or it would put back a copy that the removed members can read.
    Returns the blob's format (1 = from SecretSpace 3, 2 = the current one)."""
    if raw[:4] not in (_VAULT_MAGIC, LEGACY_VAULT_MAGIC) or \
            len(raw) < 4 + 1 + 16 + 4 + 12 + 16:
        raise V2Error(400, "That is not a SecretSpace vault.")
    if raw[5:21] != bytes.fromhex(vault_id):
        raise V2Error(400, "That vault file belongs to another vault.")
    if generation is not None and \
            int.from_bytes(raw[21:25], "big") != generation:
        raise V2Error(409, "This vault's key was changed on another device. "
                           "Sync again to get the new key.")
    return FORMAT_NOW if raw[:4] == _VAULT_MAGIC else FORMAT_OLD


class Handler(BaseHTTPRequestHandler):
    server_version = "SecretSpaceSync/2"

    # -- plumbing ---------------------------------------------------------
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._send(status, {"error": message})

    def log_message(self, fmt, *args):
        """
        Access log without the query string, and never a body.

        Paths carry usernames, which is as much as this log should ever know.
        Flushed per line: under systemd stderr is a pipe, and before Python
        3.9 a pipe is block-buffered, so the journal would lag behind.
        """
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))
        sys.stderr.flush()

    def log_request(self, code="-", size="-"):
        """The standard access line, with the query string cut out."""
        if isinstance(code, HTTPStatus):
            code = code.value
        line = re.sub(r"\?\S*", "", self.requestline, count=1)
        self.log_message('"%s" %s %s', line, str(code), str(size))

    def _authorised(self) -> bool:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            return False
        # Constant-time: a timing oracle on the token would let it be guessed
        # byte by byte by anyone who can reach the port.
        return hmac.compare_digest(header[len(prefix):], self.server.token)

    def _user_from_path(self):
        """Parse /vault/<user>[/meta] and reject anything else."""
        parts = [p for p in self.path.split("?")[0].split("/") if p]
        if not parts or parts[0] != "vault" or not 2 <= len(parts) <= 3:
            return None, None
        user = parts[1]
        tail = parts[2] if len(parts) > 2 else ""
        if not valid_username(user) or tail not in ("", "meta"):
            return None, None
        return user, tail

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        if self.path.split("?")[0] == "/health":
            # "features" lets a 3.0 client say "this server is too old for
            # that" instead of failing half-way: "vaults" = several vaults
            # per account (2.0.0-alpha.2).
            # "sharing" = members, roles, key change and the audit log
            # (2.0.0-alpha.3). "recovery" = an account recovered with its
            # 12-word phrase (2.0.0-alpha.4). "signed-keys" = a signature is
            # kept with every wrapped vault key (2.0.0-alpha.5). "format-2" =
            # accounts and vaults in the format SecretSpace 4 writes (2.1.0).
            return self._send(200, {"ok": True, "service": SERVICE_NAME,
                                    "api": [1, 2],
                                    "features": ["vaults", "sharing",
                                                 "recovery", "signed-keys",
                                                 "format-2"]})
        if self._is_v2():
            return self._v2("GET")

        if not self._authorised():
            return self._error(401, "Bad or missing token.")

        user, tail = self._user_from_path()
        if user is None:
            return self._error(404, "No such endpoint.")
        return self._send_blob(self.server.store, user, tail)

    def do_PUT(self):
        if self._is_v2():
            return self._v2("PUT")
        if not self._authorised():
            return self._error(401, "Bad or missing token.")

        user, tail = self._user_from_path()
        if user is None or tail:
            return self._error(404, "No such endpoint.")
        return self._store_blob(self.server.store, user)

    def do_POST(self):
        if self._is_v2():
            return self._v2("POST")
        # 2.x never used POST: answer as before, when there was no do_POST.
        self.send_error(501, "Unsupported method ('POST')")

    def do_DELETE(self):
        if self._is_v2():
            return self._v2("DELETE")
        # Nor DELETE: a 2.x vault is never removed over the network.
        self.send_error(501, "Unsupported method ('DELETE')")

    # -- one blob, for 2.x users and v2 vaults alike ------------------------
    def _send_blob(self, store, name, tail):
        meta = store.meta(name)
        if tail == "meta":
            return self._send(200, meta)

        if not store.exists(name):
            # Not an error: it is how a client learns it is the first to push.
            return self._send(200, {**meta, "blob": None})
        try:
            blob = store.read(name)
        except OSError as e:
            return self._error(500, f"Could not read the stored vault: {e}")
        return self._send(200, {**meta, "blob": blob.decode("ascii")})

    def _read_body(self):
        """The request's JSON body, or (None, already answered)."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._error(400, "Bad Content-Length.")
            return None
        if length <= 0:
            self._error(400, "Empty body.")
            return None
        if length > MAX_BODY:
            self._error(413, "That is far larger than a vault.")
            return None
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._error(400, "Body must be JSON.")
            return None
        if not isinstance(payload, dict):
            self._error(400, "Body must be a JSON object.")
            return None
        return payload

    def _store_blob(self, store, name, check=None, stored=None):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._error(400, "Bad Content-Length.")
        if length <= 0:
            return self._error(400, "Empty body.")
        if length > MAX_BODY:
            return self._error(413, "That is far larger than a vault.")

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            blob = payload["blob"].encode("ascii")
        except Exception:
            return self._error(400, "Body must be JSON: {\"blob\": \"<base64>\"}")

        # A light sanity check. The server cannot validate a vault it cannot
        # decrypt, but it can refuse something that is plainly not one, so a
        # confused client cannot replace a good vault with garbage.
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:
            return self._error(400, "Blob is not valid base64.")
        if len(raw) < MIN_BLOB_BYTES:
            return self._error(400, "Blob is too short to be a vault.")
        if check is not None:
            try:
                check(raw)
            except V2Error as e:
                return self._error(e.status, str(e))

        # Optional, and absent from clients older than password-change
        # support; the store then keeps what it had.
        generation = self.headers.get(HEADER_KEY_GENERATION)
        if generation is None:
            generation = self.headers.get(LEGACY_HEADER_KEY_GENERATION)
        if generation is not None:
            try:
                generation = int(generation)
            except ValueError:
                generation = -1
            if generation < 0:
                return self._error(400, "The key generation header must be a "
                                        "whole number, 0 or more.")
        drop_history = "1" in (self.headers.get(HEADER_DROP_HISTORY),
                               self.headers.get(LEGACY_HEADER_DROP_HISTORY))

        # One writer at a time: check-then-write has to be atomic, or two
        # simultaneous pushes could both pass the revision check.
        with _lock:
            current = int(store.meta(name)["revision"])
            expected = self.headers.get("If-Match", "").strip().strip('"')

            if not expected:
                # Only a first push may omit If-Match. Requiring it thereafter
                # is what stops a client that never read from clobbering.
                if current != 0:
                    return self._error(
                        428, "Include If-Match with the revision you merged "
                             "against.")
            elif expected == "*":
                pass                        # explicit "I mean to overwrite"
            elif expected != str(current):
                return self._error(
                    409, f"Vault has moved on: server is at revision "
                         f"{current}, you merged against {expected}. "
                         f"Pull and merge again.")

            try:
                meta = store.write(name, blob, generation, drop_history)
            except OSError as e:
                return self._error(500, f"Could not store the vault: {e}")

        if stored is not None:
            stored(meta)
        return self._send(200, meta)

    # -- API v2: SecretSpace 3 accounts -------------------------------------
    def _is_v2(self) -> bool:
        return self.path.split("?")[0].startswith("/v2/")

    @property
    def accounts(self) -> AccountStore:
        # Made on first use from the 2.x store, so a server set up in code
        # (the tests, the clients' test copies) gets v2 without extra wiring.
        found = getattr(self.server, "accounts", None)
        if found is None:
            found = AccountStore(self.server.store.root)
            self.server.accounts = found
        return found

    def _bearer(self) -> str:
        header = self.headers.get("Authorization", "")
        return header[len("Bearer "):] if header.startswith("Bearer ") else ""

    def _v2(self, method: str):
        # Names in a path arrive percent-encoded ("a%20b"). Whatever a part
        # decodes to, it is only ever compared with fixed words or checked as
        # a username or a vault id before it is used.
        parts = [urllib.parse.unquote(p)
                 for p in self.path.split("?")[0].split("/") if p][1:]
        try:
            return self._v2_route(method, parts)
        except V2Error as e:
            return self._error(e.status, str(e))

    def _v2_route(self, method, parts):
        accounts = self.accounts
        route = (method, parts[0] if parts else "", len(parts))

        # -- no login needed ---------------------------------------------------
        if route == ("GET", "prelogin", 2):
            return self._send(200, accounts.prelogin(parts[1]))
        address = self.client_address[0]
        if route == ("POST", "login", 1):
            body = self._read_body()
            if body is None:
                return None
            tried = body.get("username")
            tried = tried if isinstance(tried, str) and valid_username(tried) else "?"
            try:
                reply = accounts.login(body)
            except V2Error as e:
                accounts.audit(None, "login_failed", tried, address,
                               status=e.status)
                raise
            accounts.audit(None, "login", reply["username"], address)
            return self._send(200, reply)
        if route == ("GET", "recovery", 2):
            return self._send(200, accounts.recovery_copy(parts[1]))
        if route == ("POST", "recovery", 1):
            body = self._read_body()
            if body is None:
                return None
            tried = body.get("username")
            tried = tried if isinstance(tried, str) and valid_username(tried) else "?"
            try:
                done = accounts.recover(body)
            except V2Error as e:
                accounts.audit(None, "recovery_failed", tried, address,
                               status=e.status)
                raise
            accounts.audit(None, "account_recovered", done["username"], address)
            return self._send(200, done)
        if route == ("POST", "accounts", 1):
            # The sign-up code is the server's token: whoever was given it may
            # make an account here, as whoever has it may sync a 2.x vault.
            if not self._authorised():
                return self._error(401, "Bad or missing sign-up code (the "
                                        "server's token).")
            body = self._read_body()
            if body is None:
                return None
            made = accounts.create_account(body)
            accounts.audit(None, "account_created", made["username"], address)
            return self._send(201, made)

        # -- everything else needs a session -------------------------------
        token = self._bearer()
        username = accounts.session_user(token)
        if username is None:
            return self._error(401, "Not logged in, or the login has expired.")

        if route == ("GET", "me", 1):
            return self._send(200, accounts.me(username))
        if route == ("POST", "logout", 1):
            accounts.logout(token)
            return self._send(200, {})
        if route == ("PUT", "me", 2) and parts[1] == "keyset":
            body = self._read_body()
            if body is None:
                return None
            converted = accounts.change_keyset(username, body, keep_token=token)
            accounts.audit(None, "account_converted" if converted
                           else "password_changed", username, address)
            return self._send(200, {})
        if route == ("PUT", "me", 2) and parts[1] == "signing-key":
            body = self._read_body()
            if body is None:
                return None
            accounts.set_signing_key(username, body)
            return self._send(200, {})
        if route == ("PUT", "me", 2) and parts[1] == "recovery-proof":
            body = self._read_body()
            if body is None:
                return None
            accounts.set_recovery_proof(username, body)
            return self._send(200, {})
        if route == ("PUT", "me", 2) and parts[1] == "recovery":
            body = self._read_body()
            if body is None:
                return None
            accounts.set_recovery_copy(username, body)
            accounts.audit(None, "recovery_phrase_changed", username, address)
            return self._send(200, {})
        if route == ("GET", "accounts", 3) and parts[2] == "public-key":
            return self._send(200, accounts.public_keys(parts[1]))
        if route == ("POST", "vaults", 1):
            body = self._read_body()
            if body is None:
                return None
            made = accounts.create_vault(username, body)
            accounts.audit(made["id"], "vault_created", username, address)
            return self._send(201, made)
        if parts and parts[0] == "vaults" and len(parts) in (2, 3, 4):
            vault_id = parts[1]
            tail = parts[2] if len(parts) >= 3 else ""
            role = accounts.role(username, vault_id)
            # Not a member and no such vault answer alike, so a guess at an
            # id learns nothing.
            if role is None or tail not in ("", "meta", "name", "members",
                                            "rotate", "log", "key-sig"):
                return self._error(404, "No such vault.")
            if len(parts) == 4 and tail != "members":
                return self._error(404, "No such endpoint.")
            owners_only = self._v2_vault_owner_call(
                method, tail, len(parts), parts[3] if len(parts) == 4 else "",
                username)
            if owners_only is not None:
                if role != "owner" and not owners_only["anyone"]:
                    return self._error(403, "Only an owner of this vault can "
                                            "do that.")
                return owners_only["run"](accounts, vault_id, username, address)
            if tail == "members" and method == "GET" and len(parts) == 3:
                return self._send(200, accounts.members(vault_id))
            if method == "GET" and tail in ("", "meta") and len(parts) <= 3:
                return self._send_blob(accounts.vaults, vault_id, tail)
            if method == "PUT" and not tail:
                if role not in ROLES_THAT_WRITE:
                    return self._error(403, "You can read this vault but not "
                                            "change it.")
                generation = accounts.key_generation(vault_id)
                seen = {}

                def check(raw):
                    seen["format"] = accounts.check_blob(raw, vault_id,
                                                         generation)

                def stored(meta):
                    accounts.note_vault_format(vault_id, seen.get("format", 0))
                    accounts.audit(vault_id, "upload", username, address,
                                   revision=meta["revision"])
                return self._store_blob(accounts.vaults, vault_id,
                                        check=check, stored=stored)
        return self._error(404, "No such endpoint.")

    def _v2_vault_owner_call(self, method, tail, count, member, username):
        """
        The calls about a vault itself rather than what is in it -- its
        name, its members, its key, its log, deleting it. Returns None for
        anything else, or {"run": the call, "anyone": may a member who is
        not an owner make it}.
        """
        def body_then(action):
            def run(accounts, vault_id, actor, address):
                body = self._read_body()
                if body is None:
                    return None
                return action(accounts, vault_id, actor, address, body)
            return run

        def rename(accounts, vault_id, actor, address, body):
            view = accounts.rename_vault(actor, vault_id, body)
            accounts.audit(vault_id, "vault_renamed", actor, address)
            return self._send(200, view)

        def delete(accounts, vault_id, actor, address):
            # Logged first: the line then leaves with the vault's folder.
            accounts.audit(vault_id, "vault_deleted", actor, address)
            accounts.delete_vault(actor, vault_id)
            return self._send(200, {})

        def put_member(accounts, vault_id, actor, address, body):
            done = accounts.put_member(actor, vault_id, member, body)
            accounts.audit(vault_id,
                           "member_added" if done["added"] else "member_role",
                           actor, address, member=done["username"],
                           role=done["role"])
            return self._send(200, done)

        def leave(accounts, vault_id, actor, address):
            accounts.leave_vault(actor, vault_id)
            accounts.audit(vault_id, "member_left", actor, address)
            return self._send(200, {})

        def rotate(accounts, vault_id, actor, address, body):
            view = accounts.rotate(actor, vault_id, body)
            accounts.audit(vault_id, "key_changed", actor, address,
                           generation=view["key_generation"],
                           removed=list(body.get("remove") or []))
            return self._send(200, view)

        def log(accounts, vault_id, actor, address):
            return self._send(200, accounts.audit_lines(vault_id))

        if (method, tail, count) == ("PUT", "name", 3):
            return {"run": body_then(rename), "anyone": False}
        if (method, tail, count) == ("DELETE", "", 2):
            return {"run": delete, "anyone": False}
        if (method, tail, count) == ("PUT", "members", 4):
            return {"run": body_then(put_member), "anyone": False}
        if (method, tail, count) == ("DELETE", "members", 4):
            # Only yourself; an owner removes others by changing the key.
            if member != username:
                return {"run": lambda *a: self._error(
                    400, "Remove a member by changing the vault's key "
                         "(rotate), so they cannot read what is written "
                         "afterwards."), "anyone": False}
            return {"run": leave, "anyone": True}
        if (method, tail, count) == ("POST", "rotate", 3):
            return {"run": body_then(rotate), "anyone": False}
        def key_sig(accounts, vault_id, actor, address, body):
            accounts.set_key_sig(actor, vault_id, body)
            return self._send(200, {})

        if (method, tail, count) == ("GET", "log", 3):
            return {"run": log, "anyone": False}
        if (method, tail, count) == ("PUT", "key-sig", 3):
            return {"run": body_then(key_sig), "anyone": True}
        if tail in ("name", "rotate", "log", "key-sig") or method == "DELETE" \
                or (tail == "members" and (count == 4 or method != "GET")):
            return {"run": lambda *a: self._error(404, "No such endpoint."),
                    "anyone": True}
        return None


def load_token(args) -> str:
    """
    The shared secret, from --token-file, $SECRETSPACE_TOKEN, or server/token.

    Deliberately not a command-line --token: arguments are visible in `ps` to
    every user on the box.
    """
    if args.token_file:
        try:
            with open(args.token_file, encoding="utf-8") as f:
                return f.read().strip()
        except OSError as e:
            # A traceback here is what a first-time systemd setup most often
            # ends in, so say what to check instead.
            sys.exit(f"Cannot read the token file {args.token_file}: "
                     f"{e.strerror}. Check that it exists and that the user "
                     f"running the server can read it.")

    env = env_setting(os.environ, "TOKEN")
    if env:
        return env

    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "token")
    if os.path.exists(default):
        with open(default, encoding="utf-8") as f:
            return f.read().strip()

    sys.exit("No token. Create one with:\n"
             "    python3 -c \"import secrets;print(secrets.token_urlsafe(32))\""
             " > server/token\n"
             "then chmod 600 server/token, and give the same value to the "
             "client.")


def parse_port(value: str, source: str) -> int:
    """A TCP port from text, or exit naming where the bad value came from."""
    try:
        port = int(value)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        sys.exit(f"{source} must be a port number from 1 to 65535, "
                 f"not {value!r}.")
    return port


def resolve_listen(args, environ=None):
    """
    Where to listen: a flag wins, then $SECRETSPACE_HOST / $SECRETSPACE_PORT,
    then 127.0.0.1:8787.

    The environment is how the systemd unit gets them: it loads
    /etc/secretspace/sync.env, which secretspace_setup.py writes, so changing
    the port never means editing the unit.
    """
    environ = os.environ if environ is None else environ
    host = args.host
    if host is None:
        host = env_setting(environ, "HOST") or DEFAULT_HOST
    port = args.port
    if port is None:
        env = env_setting(environ, "PORT")
        port = parse_port(env, ENV_PREFIX + "PORT") if env else DEFAULT_PORT
    else:
        port = parse_port(str(port), "--port")
    return host, port


#: A log file this size is moved to <name>.1 at start-up, replacing the last.
LOG_ROTATE_BYTES = 5 * 1024 * 1024


class StampedLog:
    """A text stream that starts every line with a UTC timestamp."""

    def __init__(self, stream):
        self.stream = stream
        self.at_line_start = True
        self.lock = threading.Lock()

    def write(self, text):
        with self.lock:
            for part in text.splitlines(keepends=True):
                if self.at_line_start:
                    self.stream.write(utc_now() + " ")
                self.stream.write(part)
                self.at_line_start = part.endswith("\n")
            self.stream.flush()
        return len(text)

    def flush(self):
        self.stream.flush()


def open_log(path):
    """The log file, appended to, rotated once it is large."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    try:
        if os.path.getsize(path) >= LOG_ROTATE_BYTES:
            os.replace(path, path + ".1")
    except OSError:
        pass
    return StampedLog(open(path, "a", encoding="utf-8"))


def bind(host, port, retry_seconds=0, sleep=None):
    """
    The listening server. With retry_seconds, an address that is not there
    yet -- a network that comes up after the server at boot -- is retried
    rather than ending the server; anything else still fails at once.
    """
    sleep = sleep or time.sleep
    warned = False
    while True:
        try:
            return ThreadingHTTPServer((host, port), Handler)
        except OSError as e:
            if not retry_seconds:
                raise
            if not warned:
                print(f"Cannot listen on {host}:{port} yet ({e.strerror}); "
                      f"retrying every {retry_seconds} s.")
                sys.stdout.flush()
                warned = True
            sleep(retry_seconds)


def main(argv=None):
    here =os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    parser.add_argument("--host",
                        help="address to listen on (default: $SECRETSPACE_HOST, "
                             "else 127.0.0.1, this machine only). Use 0.0.0.0 "
                             "for every network, or one of this machine's own "
                             "addresses (see `ip -4 addr show`) for just that "
                             "network.")
    parser.add_argument("--port", type=int,
                        help=f"port to listen on (default: $SECRETSPACE_PORT, "
                             f"else {DEFAULT_PORT})")
    parser.add_argument("--store", default=os.path.join(here, "store"),
                        help="directory for the encrypted blobs")
    parser.add_argument("--token-file", help="file holding the shared token")
    parser.add_argument("--cert", help="TLS certificate (enables HTTPS)")
    parser.add_argument("--key", help="TLS private key")
    parser.add_argument("--log-file",
                        help="write the log here, with timestamps, instead "
                             "of to the console (Windows: nothing reads the "
                             "console of a scheduled task)")
    parser.add_argument("--retry-bind", type=int, default=0, metavar="SECONDS",
                        help="if the address cannot be bound yet, retry this "
                             "often instead of exiting (a network that comes "
                             "up after the server at boot)")
    args = parser.parse_args(argv)

    if args.log_file:
        sys.stdout = sys.stderr = open_log(args.log_file)
    args.host, args.port = resolve_listen(args)
    token = load_token(args)
    if len(token) < 16:
        sys.exit("Token is too short to be worth having; use at least 16 "
                 "characters.")

    httpd = bind(args.host, args.port, args.retry_bind)
    httpd.store = Store(args.store)
    httpd.token = token
    os.makedirs(httpd.store.root, exist_ok=True)

    scheme = "http"
    if args.cert:
        if not args.key:
            sys.exit("--cert also needs --key.")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    # flush: under systemd stdout is a pipe and fully buffered, so without it
    # these lines never reach the journal while the server is running -- and
    # a silent journal after `systemctl start` reads as a failure.
    print(f"SecretSpace sync on {scheme}://{args.host}:{args.port}")
    print(f"Vault store: {httpd.store.root}")
    if scheme == "http" and args.host not in ("127.0.0.1", "localhost"):
        print("NOTE: plain HTTP on a network address. Vaults are encrypted "
              "either way, but the sync token travels in the clear -- fine on "
              "a home network or VPN you trust; see README.md for TLS.")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
