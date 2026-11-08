# PassMan sync server for Windows

A place to keep your encrypted vault so two PCs can stay in step. It stores
one blob per user, numbers each revision, and refuses a write computed against
an old one.

**It cannot read your passwords.** The client encrypts the vault with your
master password before anything is sent, so this server holds AES-256-GCM
ciphertext and no key. There is no account system, no password reset and no
recovery path here, by design — the only secret that matters never leaves
your PC.

It needs no Python: the installer brings everything with it.

This repository is the server for **Windows**. The other parts of PassMan
have their own repositories:

| Repository | What it holds |
|---|---|
| [PassMan-Client-Windows](https://github.com/usermaneGermane/PassMan-Client-Windows) | the app for Windows — what your PCs run |
| [PassMan-Client-Linux](https://github.com/usermaneGermane/PassMan-Client-Linux) | the app for Linux — from source or a .deb package |
| **PassMan-Server-Windows** (this one) | the server for Windows |
| [PassMan-Server-Linux](https://github.com/usermaneGermane/PassMan-Server-Linux) | the same server for Linux, run by systemd |

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

The server is its own download, **`PassMan-Server-Installer.exe`**, separate
from the app's `PassMan-Client-Installer.exe`. Either works without the
other: install only the server on the PC that stays on, only the app on the
PCs — or both on one PC.

| File | What it does |
|---|---|
| `PassMan-Server-Installer.exe` | **installs** (or upgrades) the server — the download |
| `PassMan-Server.exe` | **is** the server; the startup task runs it, you never need to |
| `PassMan-Server-Setup.exe` | **changes the settings** — network, port, token. Installs and unpacks nothing |

## Install

1. **Run `PassMan-Server-Installer.exe`** and allow it to make changes (it
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
3. **Connect PassMan** on each PC — see [below](#connect-passman).

The setup did the rest:

| What | Where |
|---|---|
| the programs | `C:\Program Files\PassMan Server\` (`PassMan-Server.exe`, `PassMan-Server-Setup.exe`) |
| settings, token, vaults, log | `C:\ProgramData\PassMan Server\` (`sync.env`, `token`, `store\`, `logs\server.log`) |
| starts with Windows, nobody logged in | Task Scheduler → **PassMan Sync Server**, as LOCAL SERVICE |
| firewall | Windows Defender Firewall → inbound rule **PassMan Sync Server (TCP *port*)**, open to the networks this PC is on (or just the one you picked) |

The token is readable by administrators and the server only. It is never
passed on the command line, which every user on the machine can read.

For a silent install, e.g. for testing:

```
PassMan-Server-Installer.exe /VERYSILENT /SUPPRESSMSGBOXES /HOST=0.0.0.0 /PORT=8787
```

## Connect PassMan

Get the token: double-click `PassMan-Server-Setup.exe` and choose **Show the
token**, or use the Start Menu shortcut of the same name.

**First PC:** unlock your vault, open **Settings → Sync**, enter the address
the setup printed, e.g. `http://192.168.1.60:8787`, and the token, and press
**Save & sync**. It checks the connection, stores the settings only once the
server answers, and uploads the vault. The address and token are kept
**inside your vault**, which is encrypted — not in `config.json`, which is
not.

**Second PC:** on the login screen choose **Restore from server**, and enter
the same address and token, your username and your master password. After
that, press **Sync** on either PC whenever you like.

To check it worked, `C:\ProgramData\PassMan Server\store\<username>\vault.enc`
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
show the token, until **Close**. The Start Menu folder **PassMan Server** has
a shortcut for each, and one to open the **server log**. From an
administrator terminal, each one directly:

```
"C:\Program Files\PassMan Server\PassMan-Server-Setup.exe" setup | show-token | new-token
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

Run the newer `PassMan-Server-Installer.exe`. It stops the server, replaces
the program files, keeps the network, port and token without asking, and
starts the server again — it is not the way to change the port.

**Upgrade the server before changing a master password** in PassMan. The
server records how many times each vault's password has changed; an older
server does not, and after a second change it can send a PC the wrong way.

## Uninstalling

Settings → Apps → **PassMan Server** removes the programs, the task and the
firewall rule, and **keeps** `C:\ProgramData\PassMan Server` — your vaults.
Delete that folder yourself if you are sure.

## Troubleshooting

**Start here if a PC cannot connect.** Check the server side first — most
failures are simply that nothing is running:

- Task Scheduler → **PassMan Sync Server** should be *Running*.
- The server log (Start Menu → PassMan Server → Server log) says why it
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
| PassMan: "rejected the sync token" | A stray space or line break when pasting; copy it again. Or the token was replaced — paste the new one |
| PassMan: "Could not reach …" | Wrong address or port in Settings → Sync, the PC is on another network, or the firewall is blocking it |
| It worked, then stopped | The server's address changed — see below |
| PassMan asks for a master password when you press Sync | Expected after a password change on another PC (or on this one while offline) — see [Changing the master password](https://github.com/usermaneGermane/PassMan-Client-Windows#changing-the-master-password-of-a-vault-you-sync) |

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
   `C:\ProgramData\PassMan Server\store\<username>`. This removes the current
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
`--key`; PassMan-Server-Linux's README shows how), but the Windows setup does
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

## What it keeps

Inside `C:\ProgramData\PassMan Server\store`:

```
<user>\vault.enc        the current blob — encrypted
<user>\meta.json        revision, sha256, timestamp, key generation — not encrypted
<user>\history\*.enc    the last 20 revisions — encrypted
```

One folder per PassMan username, so several vaults can share one server
without touching each other. `vault.enc` and the history are the same
AES-256-GCM files as on the PCs; the server never has the key. `meta.json`
and the folder name are plain: they reveal the username, when it last synced
and roughly how large the vault is — never an entry.

Each history file stays encrypted with the master password in use when it was
written. When you change a master password, PassMan offers to delete them —
ticked by default — since they would still open with the old one.

History is server-side undo. To roll back: stop **PassMan Sync Server** in
Task Scheduler, copy the revision you want over `vault.enc`, delete
`meta.json` so the numbering restarts, and start the task again. Every
client then sees a revision it did not expect and re-merges, which is the
safe outcome.

## Backups

This server is not a backup. It holds one copy of a file your PCs also hold,
and it will happily store a vault you damaged. Keep
`C:\ProgramData\PassMan Server\store` in whatever backs up the rest of the
machine — the contents are encrypted, so a backup of it is no more sensitive
than the vault itself.

## What it does not do

No rate limiting, and no access logging beyond the basics. No multi-user
isolation beyond the username in the path — everyone with the token can read
every user's blob, so treat the token as a single trust boundary. No push
notification: the client syncs when you press the button.

## Building it yourself

You need Python 3, PyInstaller and Inno Setup 6. From this folder:

```
py builder\build.py                      check, then build
py builder\build.py --install-missing    install what is missing first
```

It checks each prerequisite, offers pip and winget for what is missing, and
writes `PassMan-Server-Installer.exe` here. The version comes from
`server/version.py`.

## Versions

The Windows server has its own version, in `server/version.py`, and each
release is tagged `v<version>`. It started at 1.0.0 when the repositories
were split; an installed server from before then says 2.2.0 under Settings →
Apps, and the 1.0.0 installer upgrades it just the same. The version is
separate from the app's and from the Linux server's.

## Project layout

```
PassMan-Server-Windows/
├── builder/                     build.py: checks, then builds the installer
├── installer/PassMan-Server.iss the Inno Setup script
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
PassMan-Server-Linux.

`server/passman_server.py` and `server/passman_setup.py` are the same files
as in PassMan-Server-Linux — `passman_setup.py` holds the setup for both
systems. Make a change to either in both repositories, so the two servers
never drift apart. PassMan-Client-Windows and PassMan-Client-Linux each keep
a copy of `passman_server.py` for their end-to-end sync tests; refresh
those too.

## License

Free software under the **GNU General Public License v3.0 only**
(GPL-3.0-only) — see [LICENSE](LICENSE). You may use, run, study, change and
share it; if you distribute a changed version, it must stay under the same
licence, with its source.

The other PassMan repositories (the Windows and Linux clients and sync servers)
are free software under the same licence.

Security issues: please report them privately, see [SECURITY.md](SECURITY.md).
