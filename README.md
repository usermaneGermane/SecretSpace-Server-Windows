# SecretSpace sync server for Windows

A place to keep your encrypted vault so two PCs can stay in step. It stores
one blob per user, numbers each revision, and refuses a write computed against
an old one.

**It cannot read your passwords.** The client encrypts the vault with your
master password before anything is sent, so this server holds AES-256-GCM
ciphertext and no key. There is no account system, no password reset and no
recovery path here, by design — the only secret that matters never leaves
your PC.

It needs no Python: the installer brings everything with it.

**Formerly PassMan.** The project was renamed to SecretSpace in November
2026, because another password manager already uses the name PassMan. The
installer (`SecretSpace-Server-Installer.exe`), its entry in Settings → Apps
and the Start Menu folder carry the new name. What a running server is made
of keeps its name, so an upgrade finds and replaces it: the programs
`PassMan-Server.exe` and `PassMan-Server-Setup.exe`, the task and firewall
rule **PassMan Sync Server**, `%ProgramData%\PassMan Server`, and the
`X-PassMan-*` headers of the sync protocol. An upgrade keeps the program
folder it was installed in.

**Which apps it serves.** Server **2.0.0** serves both lines of the app:

- **SecretSpace 3** (Windows 3.0.0, Linux 1.0.0 and later): accounts with
  several vaults, sharing and recovery, through the routes under *API v2*
  below.
- **SecretSpace 2.x** (Windows 2.x, Linux 0.x): one vault per user, through
  the token routes, exactly as server 1.x did.

Updating from 1.x changes nothing for 2.x apps: the same store, token and
settings. SecretSpace 3 needs this version; it does not sync with a 1.x
server.

This repository is the server for **Windows**. The other parts of SecretSpace
have their own repositories:

| Repository | What it holds |
|---|---|
| [SecretSpace-Client-Windows](https://github.com/usermaneGermane/SecretSpace-Client-Windows) | the app for Windows — what your PCs run |
| [SecretSpace-Client-Linux](https://github.com/usermaneGermane/SecretSpace-Client-Linux) | the app for Linux — from source or a .deb package |
| **SecretSpace-Server-Windows** (this one) | the server for Windows |
| [SecretSpace-Server-Linux](https://github.com/usermaneGermane/SecretSpace-Server-Linux) | the same server for Linux, run by systemd |

## Before you start

You need:

- **A PC that stays on**, with Windows 10 or 11, 64-bit.
- **Its address**, as your other PCs will reach it. Run `ipconfig` on it and
  look for the IPv4 address of the network adapter in use, something like
  `192.168.1.60`. The setup lists them too.
- **A fixed address.** Set a DHCP reservation for this PC in your router.
  If its address ever changes, every PC's sync setting stops working.

The steps below use `192.168.1.60` for the server and `8787` for the port.
**Replace them with yours** — the setup prints your exact address.

## The three files

The server is its own download, **`SecretSpace-Server-Installer.exe`**, separate
from the app's `SecretSpace-Client-Installer.exe`. Either works without the
other: install only the server on the PC that stays on, only the app on the
PCs — or both on one PC.

| File | What it does |
|---|---|
| `SecretSpace-Server-Installer.exe` | **installs** (or upgrades) the server — the download |
| `PassMan-Server.exe` | **is** the server; the startup task runs it, you never need to |
| `PassMan-Server-Setup.exe` | **changes the settings** — network, port, token. Installs and unpacks nothing |

## Install

1. **Run `SecretSpace-Server-Installer.exe`** and allow it to make changes (it
   installs for the whole machine). It is not code-signed, so SmartScreen
   may warn first: **More info → Run anyway**. Near the end it runs
   `PassMan-Server-Setup.exe` in a console window, which asks two things:
   - **Which network to listen on.** It lists this PC's networks. Press
     Enter for the default, **every network** (`0.0.0.0`): it works on a
     LAN and behind a VPN at once, and does not care which network comes up
     first at boot. The firewall rule limits who can connect.
   - **The port** the PCs connect on. Press Enter for `8787`, or type
     another from 1024 to 65535.
2. **Note what it prints**: the token, and the address to enter on each PC,
   e.g. `http://192.168.1.60:8787`. Then press Enter to close the window.
3. **Connect SecretSpace** on each PC — see [below](#connect-secretspace).

The setup did the rest:

| What | Where |
|---|---|
| the programs | `C:\Program Files\SecretSpace Server\` (`PassMan-Server.exe`, `PassMan-Server-Setup.exe`) |
| settings, token, vaults, log | `C:\ProgramData\SecretSpace Server\` (`sync.env`, `token`, `store\`, `logs\server.log`) |
| starts with Windows, nobody logged in | Task Scheduler → **PassMan Sync Server**, as LOCAL SERVICE |
| firewall | Windows Defender Firewall → inbound rule **PassMan Sync Server (TCP *port*)**, open to the networks this PC is on (or just the one you picked) |

The token is readable by administrators and the server only. It is never
passed on the command line, which every user on the machine can read.

For a silent install, e.g. for testing:

```
SecretSpace-Server-Installer.exe /VERYSILENT /SUPPRESSMSGBOXES /HOST=0.0.0.0 /PORT=8787
```

## Connect SecretSpace

Get the token: double-click `PassMan-Server-Setup.exe` and choose **Show the
token**, or use the Start Menu shortcut of the same name.

**First PC (SecretSpace 2.x):** unlock your vault, open **Settings → Sync**, enter the address
the setup printed, e.g. `http://192.168.1.60:8787`, and the token, and press
**Save & sync**. It checks the connection, stores the settings only once the
server answers, and uploads the vault. The address and token are kept
**inside your vault**, which is encrypted — not in `config.json`, which is
not.

**Second PC:** on the login screen choose **Restore from server**, and enter
the same address and token, your username and your master password. After
that, press **Sync** on either PC whenever you like.

That is SecretSpace 2.x. **SecretSpace 3:** in *Settings → Sync → Set up…*
enter the address, and the token as the **sign-up code**; the account and
its vaults are uploaded. On every other device choose **Sign in from a
server** on the login screen. The token only lets someone make an account
here: it opens no SecretSpace 3 account. Its data is in
`C:\ProgramData\SecretSpace Server\store\_v2`.

To check it worked, `C:\ProgramData\SecretSpace Server\store\<username>\vault.enc`
appears after the first sync, and the server log shows the requests. The log
records usernames and status codes — never the vault, never the token.

## Changing the network, port or token

That is `PassMan-Server-Setup.exe`'s job. Double-click it (it asks for
administrator rights) and it shows where the server listens now, then:

```
  1) Change network, port or allowed addresses
  2) Replace the token
  3) Show the token
  4) Close
```

After each choice the menu comes back, so you can change the port and then
show the token, until **Close**. The Start Menu folder **SecretSpace Server** has
a shortcut for each, and one to open the **server log**. From an
administrator terminal, each one directly:

```
"C:\Program Files\SecretSpace Server\PassMan-Server-Setup.exe" setup | show-token | new-token
```

For a script, skip the questions: `… setup --host 0.0.0.0 --port 9443`.

**A new network or port** replaces the firewall rule and restarts the server
by itself. What is left is the new address in Settings → Sync on every PC,
in every synced vault.

**A PC on another network** — behind a router, or on a VPN this PC is not
part of — is outside the firewall rule, which covers the networks this PC
is on. The setup's third question asks for such addresses (`192.168.0.1`,
or a network such as `10.20.0.0/24`; comma-separated, `-` for none), or from
an administrator terminal: `… setup --keep --allow-from 192.168.0.1`. They
join the same rule, and an upgrade keeps them.

**If the token leaks**, choose **Replace the token**. It asks for
confirmation, writes a new random token, restarts the server and prints the
new value. From then on the old token is refused everywhere. On each PC,
unlock each synced vault, open **Settings → Sync**, paste the new token, keep
the address, and press **Save & sync**. A leaked token lets someone read and
overwrite the encrypted blobs, never decrypt them — but replace it anyway,
and if the vault might have been copied, change the master password too.

## Upgrading

Run the newer `SecretSpace-Server-Installer.exe`. It stops the server, replaces
the program files, keeps the network, port and token without asking, and
starts the server again — it is not the way to change the port.

**Upgrade the server before changing a master password** in SecretSpace. The
server records how many times each vault's password has changed; an older
server does not, and after a second change it can send a PC the wrong way.

## Uninstalling

Settings → Apps → **SecretSpace Server** removes the programs, the task and the
firewall rule, and **keeps** `C:\ProgramData\SecretSpace Server` — your vaults.
Delete that folder yourself if you are sure.

## Troubleshooting

**Start here if a PC cannot connect.** Check the server side first — most
failures are simply that nothing is running:

- Task Scheduler → **PassMan Sync Server** should be *Running*.
- The server log (Start Menu → SecretSpace Server → Server log) says why it
  stopped, if it did.
- On the server itself, in PowerShell:
  `curl.exe http://127.0.0.1:8787/health` should answer
  `{"ok": true, "service": "passman-sync"}`. (Use `curl.exe` — plain `curl`
  in PowerShell is an alias for something else. If the server listens on
  one network only, use that address instead of `127.0.0.1`.)

From the PC, `Test-NetConnection 192.168.1.60 -Port 8787` tells a blocked
port (`TcpTestSucceeded: False`) from an unreachable machine. Windows
answers no ping by default, so trust the TCP line over `PingSucceeded`. A
refused connection can take about 20 seconds to fail — Windows retries before
giving up — so a slow failure does **not** by itself mean a firewall is
dropping it.

| Symptom | Likely cause |
|---|---|
| Task not running; local `curl.exe` refused | Start it in Task Scheduler, then read the server log if it will not stay up |
| `curl.exe` works on the server but not from a PC | The firewall rule: check **PassMan Sync Server** in Windows Defender Firewall covers the PC's network, or run the setup again |
| PC and server on different networks | Compare `ipconfig` on both; a VPN address and a LAN address are not the same network |
| Server log: an address this PC no longer has | The network changed. Run the setup and pick again — every network (`0.0.0.0`) avoids this |
| `Address already in use` in the log | Something else on the port. Pick another port in the setup |
| SecretSpace: "rejected the sync token" | A stray space or line break when pasting; copy it again. Or the token was replaced — paste the new one |
| SecretSpace: "Could not reach …" | Wrong address or port in Settings → Sync, the PC is on another network, or the firewall is blocking it |
| It worked, then stopped | The server's address changed — see below |
| SecretSpace asks for a master password when you press Sync | Expected after a password change on another PC (or on this one while offline) — see [Changing the master password](https://github.com/usermaneGermane/SecretSpace-Client-Windows#changing-the-master-password-of-a-vault-you-sync) |

## If the server's address changes

Listening on every network (`0.0.0.0`), the server itself needs nothing.
Three other things do:

1. **Firewall.** With every network, nothing: the rule allows whichever
   networks this PC is on at the time (Windows' "local subnet"). If you
   picked one network, run the setup again and pick the new one; it
   replaces the rule and restarts the server.
2. **Every PC, every vault.** The address is stored inside each vault, so on
   each PC unlock each synced vault, open Settings → Sync, enter the new
   address, keep the token, and press **Save & sync**.
3. **A DHCP reservation**, so it does not change again.

## Removing a vault

A vault lives in two kinds of place: each PC that syncs it, and its folder on
the server. Removing only the server's copy does not get rid of it — the next
time any of those PCs syncs, it sees an empty server and **uploads the vault
again**. That is deliberate: an empty server can just as well be a new
server or a lost disk, and wiping your PCs in response would be the one
outcome that loses data.

To get rid of a vault for good:

1. **On every PC that has it:** if you might want it back one day, save a
   copy first (Settings → *Save encrypted backup*). Then unlock it and use
   Settings → **Delete this user**, which removes the vault, its backup and
   its sync state on that PC.
2. **Then on the server:** delete
   `C:\ProgramData\SecretSpace Server\store\<username>`. This removes the current
   copy, `meta.json` and all its history. The server does not need stopping;
   it reads the files on every request.

PCs first, server second: the other way round, a PC that syncs in between
simply puts it back.

## LAN or VPN

Nothing in the server cares which. What changes is the address your PCs type
into Settings → Sync: the server's LAN address, e.g.
`http://192.168.1.60:8787`, or its address *on the VPN*. With every network
(`0.0.0.0`), both work at once, and the firewall rule follows whichever
networks this PC is on.

## Plain HTTP

Your vault is encrypted before it leaves your PC, so nothing on the network
can read your passwords. What plain HTTP exposes is the **sync token**:
someone else on the same network could capture it, then read or overwrite
the encrypted blobs — without being able to decrypt them. On a home network
or a VPN you trust, that is usually acceptable.

The server can serve TLS with a pinned self-signed certificate (`--cert`,
`--key`; SecretSpace-Server-Linux's README shows how), but the Windows setup does
not set that up yet.

## API

Every route but `/health` needs `Authorization: Bearer <token>`.

| Route | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | liveness; no token needed |
| `/vault/<user>/meta` | GET | `{revision, sha256, updated_at, size, key_generation}` — cheap poll |
| `/vault/<user>` | GET | the blob plus its metadata; `blob: null` if nothing stored |
| `/vault/<user>` | PUT | store a new revision |

`PUT` takes `{"blob": "<base64>"}` and requires `If-Match: <revision>` — the
revision you merged against. Two optional headers:

- `X-PassMan-Key-Generation: <n>` — how many times the vault's master
  password has changed. Stored as-is; kept unchanged when absent.
- `X-PassMan-Drop-History: 1` — discard every earlier revision, including
  the one being replaced. Sent after a password change.

The server replies:

- **200** with the new metadata,
- **409** if it has moved on (pull, merge again, retry),
- **428** if `If-Match` was missing on a vault that already exists.

A first push may omit `If-Match`. `If-Match: *` overwrites whatever is there,
which the client never sends — it exists for recovering by hand.

### API v2: SecretSpace 3 accounts

Server **2.0** adds accounts for SecretSpace 3 (Windows 3.0.0, Linux
1.0.0). The paragraphs below name the test version in which each part
arrived; 2.0.0 has all of them. It sits beside the routes
above, which stay exactly as they are for 2.x clients. The server still never
sees a master password, a Secret Key or a vault key: an account is the
client's **Login Key** (stored as a salted scrypt hash), its public key, and
its keyset and recovery copy, both sealed on the device. A vault is a blob
like a 2.x one, with the same revision, `If-Match` and history rules.

| Route | Method | Who | Purpose |
| --- | --- | --- | --- |
| `/v2/prelogin/<user>` | GET | anyone | the Argon2id salt and cost a device needs to turn the master password into keys. A name with no account gets a made-up, stable answer, so this says nothing about which names exist |
| `/v2/accounts` | POST | the server's **token**, as the sign-up code | make an account (and its personal vault) |
| `/v2/login` | POST | anyone | Login Key → a session, valid 12 hours. After 10 wrong tries in 15 minutes the name is paused for a minute |
| `/v2/logout` | POST | session | end this session |
| `/v2/me` | GET | session | the account: public key, signing key, `can_recover` (whether a recovery proof is stored), keyset, recovery copy, its vaults (each with its role, key generation and member count) |
| `/v2/me/keyset` | PUT | session | a new master password: new keyset and Login Key; every other session of the account ends |
| `/v2/vaults/<id>` | GET / PUT | session, member | the vault blob, as `/vault/<user>` (PUT: owner or editor; it must be a PMV3 file naming this vault) |
| `/v2/vaults/<id>/meta` | GET | session, member | its metadata |
| `/v2/vaults` | POST | session | make a further vault, owned by the caller (**201**): `{id, name, wrapped_key}`. **400** for a bad id, name or key, **409** if the id is in use, **403** past 50 vaults |
| `/v2/vaults/<id>/name` | PUT | session, owner | change the vault's name (not for the personal vault) |
| `/v2/vaults/<id>` | DELETE | session, owner | delete the vault (not the personal one, which goes with the account); it disappears for every member |
| `/v2/me/signing-key` | PUT | session | set the public key the account signs its changes with: `{signing_key}`, 32 bytes in base64. Once only: the same key again is **200**, another one **409**, a wrong length **400** |
| `/v2/accounts/<user>/public-key` | GET | session | another account's public key and signing key, and its name as the server spells it (the lookup ignores letter case). **404** for an unknown name |
| `/v2/recovery/<user>` | GET | anyone | the account's recovery copy: `{username, recovery}`, with the name as the server spells it (the lookup ignores letter case). A name with no account, or a disabled one, gets a made-up, stable copy of the same shape. **400** for an invalid name |
| `/v2/recovery` | POST | anyone | recover the account: `{username, recovery_proof, login_key, keyset, recovery}`. **200** with the right proof; **401** for a wrong proof, an unknown name or a disabled account (the same message); **409** when the account has no proof stored yet; **400** for a bad input (a proof or Login Key that is not 32 bytes, a keyset that is a recovery copy or the other way round); **429** when the name is paused |
| `/v2/me/recovery-proof` | PUT | session | store the recovery proof (hashed): `{recovery_proof}`, 32 bytes in base64. Once only: the same proof again is **200**, another one **409**, a wrong length or bad base64 **400** |
| `/v2/me/recovery` | PUT | session | a new 12-word phrase: `{recovery}`, the keyset sealed under it. **400** if it is not a recovery copy (kdf byte 0); the old phrase then opens nothing |
| `/v2/vaults/<id>/members` | GET | session, member | who is in the vault: `key_generation` and a list of `{username, role, added_by, added_at}`, sorted by name |
| `/v2/vaults/<id>/members/<user>` | PUT | session, owner | add a member or change a role: `{role, wrapped_key}`. `role` is `owner`, `editor` or `reader`; `wrapped_key` is needed for a new member and ignored for an existing one. **400** for a bad role or key or for a personal vault, **404** for an unknown account, **403** past 50 members, **409** when it would leave the vault without an owner |
| `/v2/vaults/<id>/members/<user>` | DELETE | session, yourself | leave the vault. **409** for its only owner. Anyone else is removed with `rotate` (an owner who tries this gets **400**) |
| `/v2/vaults/<id>/rotate` | POST | session, owner | change the vault's key, and remove members in the same call: `{generation, remove, wrapped_keys, name, blob, revision}` (see below) |
| `/v2/vaults/<id>/log` | GET | session, owner | the vault's log: `{lines}`, oldest first, the newest 200 |
| `/v2/vaults/<id>/key-sig` | PUT | session, member | sign the wrapped key you already hold: `{key_sig}`, 64 bytes in base64. Only while that key has no signature (**409** otherwise) |

Sessions are sent as `Authorization: Bearer <session>`. The server's token
is not a session and opens no account; a session opens no 2.x vault. A vault
you are not a member of answers 404, the same as one that does not exist.

Server **2.0.0-alpha.2** lets an account hold **several vaults**: the
personal one, which every account has, and up to **50** more (`MAX_VAULTS_PER_ACCOUNT`
in `passman_server.py`). The client makes a vault's id and key. A vault's
name arrives sealed under that key and the key arrives wrapped to the owner's
public key, so the server can read neither; it only stores them and hands
them back in `/v2/me`, where the personal vault comes first. A deleted vault is
not erased: its folder is **moved** to `_v2\deleted\<id>-<date>` inside the
store, so a vault deleted by mistake is not lost at once. Whoever runs the
server may empty `_v2\deleted\` when sure. An
account made by 2.0.0-alpha.1 needs no change. `/health` now also lists
`"features": ["vaults"]`, so a client can tell whether a server has this.

Server **2.0.0-alpha.3** lets an account **share a vault** with other accounts
on the same server. It goes with the Windows 3.0.0-alpha.6 and Linux
1.0.0-alpha.6 test versions. Each member has a role:

- **owner**: everything, including adding and removing members, changing the
  vault's key, renaming or deleting it, and reading its log. A vault always
  keeps at least one owner.
- **editor**: reads and uploads.
- **reader**: reads only. The server refuses a reader's upload (**403**), so
  this does not depend on the app behaving.

The server never holds a key it could hand out. The owner's device wraps the
vault key to the new member's public key, and that wrapped key is all the
server stores for them. To remove a member, an owner's device makes a **new
vault key** and sends, in one call to `rotate`, the vault encrypted under it,
its name sealed again, and the new key wrapped to every member who stays.
The server checks that the keys are for exactly the members who stay, that
the vault file is this vault at the next key generation, and that it was
made against the revision the server holds. It then applies everything
together; if any check fails, nothing changes. The earlier revisions in
`history/` are deleted, because they are under the old key, which the removed
member still has. From then on the server refuses an upload that is still
under the old key (**409**), so a device that missed the change has to sync
first. A member can leave a vault on their own at any time.

The server keeps a log, one JSON line per event, only ever appended:

- `_v2/vaults/<id>/audit.log` for each vault: the vault was created, renamed
  or deleted, an upload (with its revision), a member was added, had their
  role changed or left, and the key was changed (with the new generation and
  who was removed). The vault's owners can read it with `GET
  /v2/vaults/<id>/log`.
- `_v2/logins.log` for the whole server: logins, failed logins (with the
  status), accounts made and passwords changed. Nothing in the API reads it;
  read it on the server.

Each line has the time, the event, the account that did it and the address
it came from. The log holds **no vault content, no keys and no names**: the
server cannot read those, so it cannot write them down. It does not record
who viewed or copied an entry either; that happens on the device and the
server never learns of it. A log file that reaches 2 MB is renamed to
`<name>.1`, replacing the earlier one, and a new file is started. If a line
cannot be written (a full disk, say), the request it belongs to still
succeeds and the line is missing. A name with a space in it (`ann lee`) works
in paths when it is sent percent-encoded (`ann%20lee`). `/health` now lists
`"features": ["vaults", "sharing", "recovery"]`.

Server **2.0.0-alpha.5** keeps a **signature with every wrapped vault key**.
It goes with the Windows 3.0.0-alpha.8 and Linux 1.0.0-alpha.8 test versions,
which sync only the Personal vault with an older server.

- *Why.* The server stores each member's copy of a vault key but must never
  be able to choose one. Before this version a dishonest server (or someone
  who broke into it) could wrap a key of its own to a member's public key and
  call it a new key generation; the device would then upload the vault under
  that key, and the server could read it.
- *How.* The account that wraps a key signs it (Ed25519): which vault, which
  key generation, for whom, the wrapped key itself. `key_sig` travels with
  `wrapped_key` in `POST /v2/vaults`, in `PUT /v2/vaults/<id>/members/<user>`
  for a new member, and as `key_sigs` (one per member who stays) in `rotate`.
  `/v2/me` returns `key_sig` and `key_signer` with each vault.
- *Who checks.* The devices, not the server: it has no key to check with and
  needs none. A device takes a key only when it is signed by its own account
  or by someone it has reason to trust, and never one of an older generation.
- `key_signer` is always the account whose session sent the key, never a
  name from the request.
- A vault from an earlier version has unsigned keys. A device that already
  holds such a key signs it at its next sync (`PUT /v2/vaults/<id>/key-sig`),
  after which the account's other devices take it. A signature made by an
  owner is never replaced this way.
- `/health` lists `"signed-keys"`.

Server **2.0.0-alpha.4** lets an account be **recovered with its 12-word
phrase** when the master password is forgotten. It goes with the Windows
3.0.0-alpha.7 and Linux 1.0.0-alpha.7 test versions.

- The device asks `GET /v2/recovery/<user>` and gets the recovery copy: the
  account's keyset sealed under the phrase. It opens only with the phrase, so
  handing it to anyone is safe. For a name with no account the server returns
  a made-up copy (the same on every ask, the same shape and size), so the
  call cannot be used to find out which names exist.
- The device opens the copy with the phrase and proves it by sending a
  **recovery proof**, a value derived from the account's own keys. The server
  keeps only a salted hash of it, as it does for the Login Key. A new phrase
  does not change the keys, so it does not change the proof.
- An account made by 2.0.0-alpha.4 sends the proof at sign-up. An older
  account sends it once, from a session, at its next sync
  (`PUT /v2/me/recovery-proof`); it cannot be replaced afterwards. Until then
  `can_recover` in `/v2/me` is false and a recovery answers **409**.
- With the right proof, `POST /v2/recovery` stores the same keys under the new
  password (a new keyset and Login Key) and under a new phrase (a new
  recovery copy), and **ends every session of the account**. The old Login Key
  stops working. A wrong proof changes nothing.
- A new phrase can also be set from a session, without recovering
  (`PUT /v2/me/recovery`). The server checks only that it is a recovery copy.
- Wrong proofs are counted with wrong logins: they share one count per name,
  so after 10 wrong tries in 15 minutes of either kind, both a login and a
  recovery for that name answer **429** for a minute. A successful login or
  recovery clears the count.
- `_v2/logins.log` gets `account_recovered`, `recovery_failed` (with the
  status) and `recovery_phrase_changed` lines. They never hold the proof, the
  Login Key or the copy.

Everything v2 keeps is in `_v2/` inside the vault store (a 2.x name cannot
start with `_`), so backing up the store backs it up too: `accounts/`,
`sessions/` (stored hashed), `vaults/<id>/` (with its `members.json` and
`audit.log`), `logins.log` and `server.key` (for the made-up pre-login
answers).

## What it keeps

Inside `C:\ProgramData\SecretSpace Server\store`:

```
<user>\vault.enc        the current blob — encrypted
<user>\meta.json        revision, sha256, timestamp, key generation — not encrypted
<user>\history\*.enc    the last 20 revisions — encrypted
```

One folder per SecretSpace username, so several vaults can share one server
without touching each other. `vault.enc` and the history are the same
AES-256-GCM files as on the PCs; the server never has the key. `meta.json`
and the folder name are plain: they reveal the username, when it last synced
and roughly how large the vault is — never an entry.

Each history file stays encrypted with the master password in use when it was
written. When you change a master password, SecretSpace offers to delete them —
ticked by default — since they would still open with the old one.

History is server-side undo. To roll back: stop **PassMan Sync Server** in
Task Scheduler, copy the revision you want over `vault.enc`, delete
`meta.json` so the numbering restarts, and start the task again. Every
client then sees a revision it did not expect and re-merges, which is the
safe outcome.

## Backups

This server is not a backup. It holds one copy of a file your PCs also hold,
and it will happily store a vault you damaged. Keep
`C:\ProgramData\SecretSpace Server\store` in whatever backs up the rest of the
machine — the contents are encrypted, so a backup of it is no more sensitive
than the vault itself.

## What it does not do

No rate limiting, and no access logging beyond the basics. No multi-user
isolation on the 2.x routes beyond the username in the path — everyone with the token can read
every user's blob, so treat the token as a single trust boundary
(API v2 accounts each have their own login). No push
notification: the client syncs when you press the button.

## Building it yourself

You need Python 3, PyInstaller and Inno Setup 6. From this folder:

```
py builder\build.py                      check, then build
py builder\build.py --install-missing    install what is missing first
```

It checks each prerequisite, offers pip and winget for what is missing, and
writes `SecretSpace-Server-Installer.exe` here. The version comes from
`server/version.py`.

## Versions

The Windows server has its own version, in `server/version.py`, and each
release is tagged `v<version>`. It started at 1.0.0 when the repositories
were split; an installed server from before then says 2.2.0 under Settings →
Apps, and the 1.0.0 installer upgrades it just the same. The version is
separate from the app's and from the Linux server's.

## Project layout

```
SecretSpace-Server-Windows/
├── builder/                     build.py: checks, then builds the installer
├── installer/SecretSpace-Server.iss the Inno Setup script
└── server/
    ├── passman_server.py        the server (standard library only)
    ├── passman_setup.py         network, port, token, the task, the firewall rule
    ├── passman_server_exe.py    → PassMan-Server.exe
    ├── passman_server_setup_exe.py → PassMan-Server-Setup.exe
    ├── PassMan-Server.spec      the PyInstaller build of both programs
    ├── version.py               the version
    └── build_version.py         the exes' version resource
```

## Development

```
pip install -r requirements-dev.txt
python -m pytest -q
```

The tests never touch the real `C:\ProgramData`, Task Scheduler or the
firewall: they point `--config-dir` at a temporary folder and fake
PowerShell. GitHub Actions runs them on Windows with Python 3.12 and 3.13
for every pull request and every push to `main`.

`tests/test_server_http.py` talks to a real server on a free port of
127.0.0.1, with no client involved: the token, which paths exist, If-Match
(including two pushes racing for one revision), malformed and oversized
bodies, the history limit and the access log. It is the same file in
SecretSpace-Server-Linux.

`server/passman_server.py` and `server/passman_setup.py` are the same files
as in SecretSpace-Server-Linux — `passman_setup.py` holds the setup for both
systems. Make a change to either in both repositories, so the two servers
never drift apart. SecretSpace-Client-Windows and SecretSpace-Client-Linux each keep
a copy of `passman_server.py` for their end-to-end sync tests; refresh
those too.

## License

Free software under the **GNU General Public License v3.0 only**
(GPL-3.0-only) — see [LICENSE](LICENSE). You may use, run, study, change and
share it; if you distribute a changed version, it must stay under the same
licence, with its source.

The other SecretSpace repositories (the Windows and Linux clients and sync servers)
are free software under the same licence.

Security issues: please report them privately, see [SECURITY.md](SECURITY.md).
