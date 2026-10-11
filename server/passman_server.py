#!/usr/bin/env python3
"""
PassMan sync server -- a store for encrypted vault blobs.

What it is NOT: it cannot read your passwords. The client encrypts the vault
with your master password before it ever reaches the network, so this process
holds AES-256-GCM ciphertext it has no key for. It never sees the master
password, and there is deliberately nothing here that could -- no user
accounts, no password reset, no "forgot my vault".

What it does: stores one blob per user, stamps it with a revision number, and
refuses a write that was computed against an older revision. That refusal is
the whole point. Without it, two PCs that both edited offline would silently
overwrite each other; with it, the second one is told to merge first.

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
            return self._send(200, {"ok": True, "service": "passman-sync"})

        if not self._authorised():
            return self._error(401, "Bad or missing token.")

        user, tail = self._user_from_path()
        if user is None:
            return self._error(404, "No such endpoint.")

        meta = self.server.store.meta(user)
        if tail == "meta":
            return self._send(200, meta)

        if not self.server.store.exists(user):
            # Not an error: it is how a client learns it is the first to push.
            return self._send(200, {**meta, "blob": None})
        try:
            blob = self.server.store.read(user)
        except OSError as e:
            return self._error(500, f"Could not read the stored vault: {e}")
        return self._send(200, {**meta, "blob": blob.decode("ascii")})

    def do_PUT(self):
        if not self._authorised():
            return self._error(401, "Bad or missing token.")

        user, tail = self._user_from_path()
        if user is None or tail:
            return self._error(404, "No such endpoint.")

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
            current = int(self.server.store.meta(user)["revision"])
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
                meta = self.server.store.write(user, blob, generation,
                                               drop_history)
            except OSError as e:
                return self._error(500, f"Could not store the vault: {e}")

        return self._send(200, meta)


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
    import time
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
    print(f"PassMan sync on {scheme}://{args.host}:{args.port}")
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
