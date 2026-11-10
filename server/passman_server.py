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
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: Refuse anything larger than this. A vault is kilobytes; a megabyte is
#: already absurd, and the limit keeps a bad request from eating memory.
MAX_BODY = 8 * 1024 * 1024

#: Previous revisions kept per user. Server-side undo, in the same spirit as
#: the client's archive: getting it wrong should cost a restore, not a vault.
HISTORY_LIMIT = 20

#: A vault blob is base64 of "PMV2"||header||salt||nonce||ct, or a legacy
#: salt||nonce||ct. Below this it cannot be either, so it is a misdirected
#: request rather than a vault.
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
ROLES_THAT_WRITE = ("owner", "editor")

#: The account files' layouts, from the client (account_crypto.py).
_KEYSET_MAGIC = b"PMK3"
_KEYSET_HEADER = 4 + 1 + 1 + 4 + 1 + 1 + 16     # magic ver kdf mem passes lanes salt
_VAULT_MAGIC = b"PMV3"


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
    if len(raw) < _KEYSET_HEADER + 12 + 16 or raw[:4] != _KEYSET_MAGIC:
        raise V2Error(400, "That is not a SecretSpace 3 keyset.")
    kdf = raw[5]
    if kdf != (0 if recovery else 1):
        raise V2Error(400, "The keyset and its recovery copy are swapped.")
    memory_kib = int.from_bytes(raw[6:10], "big")
    return {"memory_kib": memory_kib, "passes": raw[10], "lanes": raw[11],
            "salt": _b64(raw[12:28])}


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
                "keyset": body["keyset"],
                "recovery": body["recovery"],
                "kdf": kdf,
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
    def me(self, username: str) -> dict:
        record = self.account(username)
        vaults = []
        vault_id = record["personal_vault"]
        members = self._read_json(self._members_path(vault_id)) or {}
        meta = self.vaults.meta(vault_id)
        vaults.append({"id": vault_id, "kind": members.get("kind", "personal"),
                       "role": members.get("members", {}).get(username, {})
                                      .get("role", "owner"),
                       "revision": meta["revision"],
                       "key_generation": meta.get("key_generation", 0)})
        return {"username": record["username"], "public_key": record["public_key"],
                "keyset": record["keyset"], "recovery": record["recovery"],
                "kdf": record["kdf"], "personal_vault": vault_id,
                "vaults": vaults}

    def change_keyset(self, username: str, body: dict, keep_token: str) -> None:
        """
        A new master password: the same keys under a new seal, and the Login
        Key that goes with it. Every other session of the account ends -- a
        password is changed when it may have leaked.
        """
        login_key = _unb64(body.get("login_key"), "The login key", LOGIN_KEY_LEN)
        kdf = keyset_kdf(body.get("keyset"))
        with _lock:
            record = self.account(username)
            record.update({"login": hash_login_key(login_key),
                           "keyset": body["keyset"], "kdf": kdf,
                           "password_changed_at": utc_now()})
            self._write_json(self._account_path(username), record)
        self._drop_expired_sessions(user_to_end=username, keep_token=keep_token)

    # -- vaults -------------------------------------------------------------
    def role(self, username: str, vault_id: str):
        """This user's role in the vault, or None (also for no such vault)."""
        if not VAULT_ID.match(vault_id or ""):
            return None
        members = self._read_json(self._members_path(vault_id)) or {}
        member = members.get("members", {}).get(username)
        return member.get("role") if member else None


def check_vault_blob(raw: bytes, vault_id: str) -> None:
    """A v2 vault blob must be PMV3 and name the vault it is stored as, so a
    confused client cannot put one vault's file in another's place."""
    if raw[:4] != _VAULT_MAGIC or len(raw) < 4 + 1 + 16 + 4 + 12 + 16:
        raise V2Error(400, "That is not a SecretSpace 3 vault.")
    if raw[5:21] != bytes.fromhex(vault_id):
        raise V2Error(400, "That vault file belongs to another vault.")


class Handler(BaseHTTPRequestHandler):
    server_version = "PassManSync/1.0"

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
            return self._send(200, {"ok": True, "service": "passman-sync",
                                    "api": [1, 2]})
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

    def _store_blob(self, store, name, check=None):
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
        generation = self.headers.get("X-PassMan-Key-Generation")
        if generation is not None:
            try:
                generation = int(generation)
            except ValueError:
                generation = -1
            if generation < 0:
                return self._error(400, "X-PassMan-Key-Generation must be a "
                                        "whole number, 0 or more.")
        drop_history = self.headers.get("X-PassMan-Drop-History") == "1"

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
        parts = [p for p in self.path.split("?")[0].split("/") if p][1:]
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
        if route == ("POST", "login", 1):
            body = self._read_body()
            return None if body is None else self._send(200, accounts.login(body))
        if route == ("POST", "accounts", 1):
            # The sign-up code is the server's token: whoever was given it may
            # make an account here, as whoever has it may sync a 2.x vault.
            if not self._authorised():
                return self._error(401, "Bad or missing sign-up code (the "
                                        "server's token).")
            body = self._read_body()
            if body is None:
                return None
            return self._send(201, accounts.create_account(body))

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
            accounts.change_keyset(username, body, keep_token=token)
            return self._send(200, {})
        if parts and parts[0] == "vaults" and len(parts) in (2, 3):
            vault_id = parts[1]
            tail = parts[2] if len(parts) == 3 else ""
            role = accounts.role(username, vault_id)
            # Not a member and no such vault answer alike, so a guess at an
            # id learns nothing.
            if role is None or tail not in ("", "meta"):
                return self._error(404, "No such vault.")
            if method == "GET":
                return self._send_blob(accounts.vaults, vault_id, tail)
            if method == "PUT" and not tail:
                if role not in ROLES_THAT_WRITE:
                    return self._error(403, "You can read this vault but not "
                                            "change it.")
                return self._store_blob(
                    accounts.vaults, vault_id,
                    check=lambda raw: check_vault_blob(raw, vault_id))
        return self._error(404, "No such endpoint.")


def load_token(args) -> str:
    """
    The shared secret, from --token-file, $PASSMAN_TOKEN, or server/token.

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

    env = os.environ.get("PASSMAN_TOKEN", "").strip()
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
    Where to listen: a flag wins, then $PASSMAN_HOST / $PASSMAN_PORT, then
    127.0.0.1:8787.

    The environment is how the systemd unit gets them: it loads
    /etc/passman/sync.env, which passman_setup.py writes, so changing the
    port never means editing the unit.
    """
    environ = os.environ if environ is None else environ
    host = args.host
    if host is None:
        host = environ.get("PASSMAN_HOST", "").strip() or DEFAULT_HOST
    port = args.port
    if port is None:
        env = environ.get("PASSMAN_PORT", "").strip()
        port = parse_port(env, "PASSMAN_PORT") if env else DEFAULT_PORT
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
                        help="address to listen on (default: $PASSMAN_HOST, "
                             "else 127.0.0.1, this machine only). Use 0.0.0.0 "
                             "for every network, or one of this machine's own "
                             "addresses (see `ip -4 addr show`) for just that "
                             "network.")
    parser.add_argument("--port", type=int,
                        help=f"port to listen on (default: $PASSMAN_PORT, "
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
