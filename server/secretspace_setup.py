#!/usr/bin/env python3
"""
SecretSpace sync server setup -- where it listens, its token, its firewall rule.

Linux (systemd):
    sudo python3 secretspace_setup.py              # ask, then write the settings
    sudo python3 secretspace_setup.py new-token    # replace a leaked token
    sudo python3 secretspace_setup.py show-token   # print the token
    sudo python3 secretspace_setup.py tls          # turn HTTPS on (below)
    sudo python3 secretspace_setup.py migrate      # move an install from
                                                   # before the rename (below)

Windows (SecretSpace-Server-Installer.exe runs the first one for you):
    SecretSpace-Server-Setup.exe [setup] | new-token | show-token | remove

`setup` asks which address to listen on (listing this machine's networks)
and which port, writes them to sync.env, creates the token if there is none
yet, and opens the port in the firewall for the networks it serves -- plus
any other addresses you name, such as a PC on a network this machine is not
on (`--allow-from 192.168.0.1`):

- Linux: sync.env is /etc/secretspace/sync.env, which the systemd unit loads.
  The firewall rule is added when ufw is on; ufw is never switched on from
  here, because doing that over SSH without an SSH rule locks you out.
- Windows: everything lives in %ProgramData%\\SecretSpace Server. A Windows
  Firewall rule and a Task Scheduler task (at startup, as LOCAL SERVICE)
  are created or replaced, and the server is (re)started.

`new-token` writes a fresh token, restarts the server and prints the new
value. Every PC then needs it in Settings -> Sync before it can sync again.

`tls` turns HTTPS on: it makes a certificate for the addresses this server
is reached at (with `openssl`), keeps it beside the token, and restarts the
server. Each device then uses https:// and that certificate file, which the
app pins -- so a machine pretending to be the server is refused. `tls off`
goes back to plain HTTP; `tls show` says what is in use.

`migrate` is for a server installed while the project was still called
PassMan: it gives the folders, the service, its user and the settings the
current names. The port, the token and the vaults stay as they are, so no PC
needs a new setting. `migrate --dry-run` only shows what it would do;
`migrate --undo` puts the old names back. On Windows the installer does the
same by itself.

Standard library only, like the server.
"""

import os
import sys
import json
import shutil
import socket
import secrets
import argparse
import ipaddress
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secretspace_server import (DEFAULT_PORT, ENV_PREFIX,       # noqa: E402
                                LEGACY_ENV_PREFIX, write_atomic)

SERVICE = "secretspace-sync"
SERVICE_USER = "secretspace"
#: Linux: where the program, its settings and its vaults live.
PROGRAM_DIR = "/opt/secretspace"
CONFIG_DIR = "/etc/secretspace"
DATA_DIR = "/var/lib/secretspace"
UNIT_DIR = "/etc/systemd/system"
SERVER_FILE = "secretspace_server.py"

#: Windows: the scheduled task, the firewall rule group and their names.
TASK_NAME = "SecretSpace Sync Server"
FIREWALL_GROUP = "SecretSpace Sync Server"
WINDOWS_DIR = "SecretSpace Server"

# The project was called PassMan until November 2026. These are an install's
# names from then: `migrate` (and the Windows installer) move one to the
# names above. Nothing is ever created under them.
LEGACY_SERVICE = "passman-sync"
LEGACY_SERVICE_USER = "passman"
LEGACY_PROGRAM_DIR = "/opt/passman"
LEGACY_CONFIG_DIR = "/etc/passman"
LEGACY_DATA_DIR = "/var/lib/passman"
LEGACY_PROGRAM_FILES = ("passman_server.py", "passman_setup.py")
LEGACY_TASK_NAME = "PassMan Sync Server"
LEGACY_FIREWALL_GROUP = "PassMan Sync Server"
LEGACY_WINDOWS_DIR = "PassMan Server"
#: Well-known SIDs, so icacls works on any Windows display language.
SID_SYSTEM = "*S-1-5-18"
SID_LOCAL_SERVICE = "*S-1-5-19"
SID_ADMINS = "*S-1-5-32-544"

#: The service runs as an unprivileged user, which cannot bind below 1024.
MIN_PORT = 1024

ALL_NETWORKS = "0.0.0.0"
LOCALHOST = "127.0.0.1"

#: sync.env keys, without their prefix. ALLOW_FROM is the extra addresses
#: let through the firewall: only the setup reads it, the server ignores it.
SETTING_KEYS = ("HOST", "PORT", "ALLOW_FROM", "CERT", "KEY")
ALLOW_KEY = ENV_PREFIX + "ALLOW_FROM"
#: What clears the list, typed at the question or given to --allow-from.
NONE_WORDS = ("-", "none")


def default_platform():
    return "windows" if os.name == "nt" else "linux"


def default_config_dir(platform):
    if platform == "windows":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, WINDOWS_DIR)
    return CONFIG_DIR


def legacy_config_dir(platform):
    """Where an install from before the rename keeps its settings."""
    if platform == "windows":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, LEGACY_WINDOWS_DIR)
    return LEGACY_CONFIG_DIR


def _run(cmd):
    """subprocess.run that never raises for a missing program."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              creationflags=getattr(
                                  subprocess, "CREATE_NO_WINDOW", 0))
    except OSError:
        return None


def ok(result):
    return result is not None and result.returncode == 0


def ps_quote(text):
    """A PowerShell single-quoted string literal: nothing inside expands."""
    return "'" + str(text).replace("'", "''") + "'"


def powershell(script):
    return ["powershell", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-Command", script]


# ---------------------------------------------------------------------------
# This machine's networks
# ---------------------------------------------------------------------------
def list_addresses(run=_run, platform="linux"):
    """
    This machine's IPv4 addresses as (interface, address, prefix length),
    loopback and link-local excluded. Empty when the system cannot be asked.
    """
    if platform == "windows":
        result = run(powershell(
            "ConvertTo-Json -Compress -InputObject @(Get-NetIPAddress "
            "-AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, "
            "PrefixLength)"))
        rows = _json_list(result)
        raw = [(r.get("InterfaceAlias", "?"), r.get("IPAddress"),
                r.get("PrefixLength", 32)) for r in rows]
    else:
        result = run(["ip", "-j", "-4", "addr", "show"])
        raw = []
        for link in _json_list(result):
            for info in link.get("addr_info", []):
                raw.append((link.get("ifname", "?"), info.get("local"),
                            info.get("prefixlen", 32)))
    found = []
    for ifname, address, prefix in raw:
        if not address or address.startswith(("127.", "169.254.")):
            continue
        found.append((ifname, address, int(prefix)))
    return found


def _json_list(result):
    if not ok(result):
        return []
    try:
        data = json.loads(result.stdout or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else [data]


def networks_for(host, addresses):
    """(address the PCs use, network to let in) for each network served."""
    if host == ALL_NETWORKS:
        return [(a, ipaddress.ip_interface(f"{a}/{p}").network)
                for _, a, p in addresses]
    if host == LOCALHOST:
        return []
    prefix = next((p for _, a, p in addresses if a == host), 24)
    return [(host, ipaddress.ip_interface(f"{host}/{prefix}").network)]


# ---------------------------------------------------------------------------
# Settings file and token
# ---------------------------------------------------------------------------
def read_env(path):
    """KEY=value lines of an env file as a dict; {} if it does not exist."""
    values = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return values


def read_settings(path):
    """
    sync.env as {"HOST", "PORT", "ALLOW_FROM"} (those that are set). A file
    written before the rename has the old prefix on its keys; it reads the
    same, and the next write gives it the current ones.
    """
    values = read_env(path)
    found = {}
    for key in SETTING_KEYS:
        value = values.get(ENV_PREFIX + key, values.get(LEGACY_ENV_PREFIX + key))
        if value is not None:
            found[key] = value
    return found


def render_env(host, port, allow=(), prefix=ENV_PREFIX, tls=None):
    """sync.env. ``tls``: (certificate, key) when HTTPS is on."""
    text = ("# SecretSpace sync server -- written by its setup.\n"
            "# Change it by running the setup again.\n"
            f"{prefix}HOST={host}\n"
            f"{prefix}PORT={port}\n")
    if allow:
        text += (f"# Also let through the firewall (the server ignores "
                 f"this).\n{prefix}ALLOW_FROM={','.join(allow)}\n")
    if tls:
        text += (f"# HTTPS (the setup's `tls` command).\n"
                 f"{prefix}CERT={tls[0]}\n{prefix}KEY={tls[1]}\n")
    return text


def tls_of(settings):
    """(certificate, key) from read_settings, or None."""
    if settings.get("CERT") and settings.get("KEY"):
        return settings["CERT"], settings["KEY"]
    return None


def check_allow(text):
    """
    Extra addresses to let in, from "192.168.0.1, 10.20.0.0/24": a list of
    addresses and networks, or a message. One address stays one address
    (no /32), so it matches a rule typed by hand. Everyone (/0) is refused:
    that is what the firewall is there to stop.
    """
    text = (text or "").strip()
    if text.lower() in NONE_WORDS or not text:
        return [], None
    found = []
    for part in text.replace(" ", ",").split(","):
        if not part:
            continue
        try:
            if "/" in part:
                net = ipaddress.IPv4Network(part, strict=False)
                item = str(net.network_address if net.prefixlen == 32
                           else net)
            else:
                item = str(ipaddress.IPv4Address(part))
        except ValueError:
            return None, f"{part!r} is not an IPv4 address or network."
        if item.endswith("/0"):
            return None, f"{part} would let everyone in; name the networks."
        if item not in found:
            found.append(item)
    return found, None


def check_port(text):
    """The port as an int, or a message saying what is wrong with it."""
    try:
        port = int(text)
    except ValueError:
        return None, f"{text!r} is not a number."
    if not MIN_PORT <= port <= 65535:
        return None, (f"Use a port from {MIN_PORT} to 65535 (the service "
                      f"runs without admin rights, so it cannot use lower "
                      f"ones).")
    return port, None


def check_host(text, addresses):
    """The address, or a message. One the machine does not have is refused:
    the service would fail to start on it."""
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return None, f"{text!r} is not an IPv4 address."
    own = {a for _, a, _ in addresses}
    if str(ip) not in (ALL_NETWORKS, LOCALHOST) and addresses \
            and str(ip) not in own:
        return None, (f"This machine does not have {ip}; the service would "
                      f"not start on it.")
    return str(ip), None


def port_in_use(host, port):
    """True when something already listens there (bind test, IPv4)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            return True
    return False


def choose_host(ask, say, addresses, current):
    say("Which network should the server listen on?")
    choices = [(ALL_NETWORKS, "every network this machine is on")]
    choices += [(a, f"{ifname} only ({a}/{prefix})")
                for ifname, a, prefix in addresses]
    choices.append((LOCALHOST, "this machine only (for testing)"))
    default = 1
    for i, (address, label) in enumerate(choices, 1):
        mark = ""
        if address == current:
            default, mark = i, "  <- current"
        say(f"  {i}) {address:<15}  {label}{mark}")
    say("  or type another address of this machine")
    while True:
        answer = ask(f"Choice [{default}]: ").strip() or str(default)
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1][0]
        host, problem = check_host(answer, addresses)
        if host:
            return host
        say(problem)


def choose_port(ask, say, current):
    while True:
        answer = ask(f"Port the PCs connect on [{current}]: ").strip()
        port, problem = check_port(answer or str(current))
        if port:
            return port
        say(problem)


def choose_allow(ask, say, current):
    """Extra addresses; Enter keeps the current ones, - clears them."""
    say("Let in any other addresses? For a PC on a network this machine is "
        "not on, e.g. 192.168.0.1 or 10.20.0.0/24; comma-separated, - for "
        "none.")
    shown = ",".join(current) or "none"
    while True:
        answer = ask(f"Also let in [{shown}]: ").strip()
        if not answer:
            return list(current)
        allow, problem = check_allow(answer)
        if allow is not None:
            return allow
        say(problem)


def _own_file(path):
    """Give the file to the service user, where there is one (Linux)."""
    try:
        import pwd
        entry = pwd.getpwnam(SERVICE_USER)
    except (ImportError, KeyError):
        return False
    os.chown(path, entry.pw_uid, entry.pw_gid)
    return True


def write_token(path, platform="linux", run=_run):
    """A new random token, written atomically and readable by the service
    account (and administrators) only. Returns it."""
    token = secrets.token_urlsafe(32)
    write_atomic(path, (token + "\n").encode())
    if platform == "windows":
        run(["icacls", path, "/inheritance:r", "/grant:r",
             f"{SID_SYSTEM}:F", f"{SID_ADMINS}:F", f"{SID_LOCAL_SERVICE}:R"])
    else:
        os.chmod(path, 0o600)
        _own_file(path)
    return token


def read_token(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


# ---------------------------------------------------------------------------
# Linux: systemd and ufw
# ---------------------------------------------------------------------------
def restart_service(run=_run):
    """
    Restart the systemd service if it is running. Returns what happened, as
    text. Never starts one that was not running: a first setup still goes
    through `systemctl enable --now` in the README.
    """
    if not shutil.which("systemctl"):
        return "No systemd here; restart the server yourself."
    state = run(["systemctl", "is-active", SERVICE])
    if state is None or state.stdout.strip() != "active":
        return f"{SERVICE} is not running; nothing to restart."
    result = run(["systemctl", "restart", SERVICE])
    if not ok(result):
        return (f"Could not restart {SERVICE}: "
                f"{(result.stderr if result else '').strip()}\n"
                f"Run: sudo systemctl restart {SERVICE}")
    return f"Restarted {SERVICE}."


def ufw_active(run=_run):
    if not shutil.which("ufw"):
        return False
    result = run(["ufw", "status"])
    return ok(result) and "Status: active" in result.stdout


def ufw_rule(network, port):
    return ["from", str(network), "to", "any", "port", str(port),
            "proto", "tcp"]


def firewall_linux(run, say, new_networks, port, old_networks, old_port):
    """
    Allow the served networks and the extra addresses through ufw -- but
    only if ufw is on. Rules the setup made for the old values go; rules
    made by hand are left alone, unless they are for an address that the
    setup was once given as an extra.
    """
    if not ufw_active(run):
        if new_networks:
            say("ufw is not active, so no firewall rule was added. To limit "
                "who can connect, see README.md step 4:")
            for network in new_networks:
                say("    sudo ufw allow " + " ".join(ufw_rule(network, port)))
        return
    keep = {(str(n), port) for n in new_networks}
    for network in old_networks:
        if (str(network), old_port) not in keep:
            run(["ufw", "delete", "allow", *ufw_rule(network, old_port)])
            say(f"Firewall: removed the rule for {network} port {old_port}.")
    for network in new_networks:
        result = run(["ufw", "allow", *ufw_rule(network, port)])
        say(f"Firewall: allowed {network} to port {port}." if ok(result) else
            f"Firewall: could not add the rule for {network}: "
            f"{(result.stderr if result else '').strip()}")


# ---------------------------------------------------------------------------
# Windows: Task Scheduler and Windows Firewall
# ---------------------------------------------------------------------------
#: The frozen server, next to SecretSpace-Server-Setup.exe in the install
#: folder.
SERVER_EXE = "SecretSpace-Server.exe"


def server_command(frozen=None, executable=None):
    """
    (program, arguments before ours) that start the server. Frozen, that is
    SecretSpace-Server.exe beside whichever exe is running this -- the setup
    exe must not put itself in the startup task.
    """
    frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    executable = executable or sys.executable
    if frozen:
        return os.path.join(os.path.dirname(executable), SERVER_EXE), []
    return executable, [os.path.join(os.path.dirname(
        os.path.abspath(__file__)), SERVER_FILE)]


def task_arguments(config_dir, host, port, prefix=(), tls=None):
    return subprocess.list2cmdline([
        *prefix, "--host", host, "--port", str(port),
        "--store", os.path.join(config_dir, "store"),
        "--token-file", os.path.join(config_dir, "token"),
        "--log-file", os.path.join(config_dir, "logs", "server.log"),
        "--retry-bind", "10",
        *(["--cert", tls[0], "--key", tls[1]] if tls else [])])


def register_task(run, program, arguments):
    """Create or replace the startup task: LOCAL SERVICE, no time limit."""
    return run(powershell(
        f"$a = New-ScheduledTaskAction -Execute {ps_quote(program)} "
        f"-Argument {ps_quote(arguments)}; "
        "$t = New-ScheduledTaskTrigger -AtStartup; "
        "$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit "
        "([TimeSpan]::Zero) -AllowStartIfOnBatteries "
        "-DontStopIfGoingOnBatteries -StartWhenAvailable "
        "-RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1); "
        "$p = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\LOCAL "
        "SERVICE' -LogonType ServiceAccount; "
        f"Register-ScheduledTask -TaskName {ps_quote(TASK_NAME)} -Action $a "
        "-Trigger $t -Settings $s -Principal $p -Force | Out-Null"))


def restart_task(run):
    run(powershell(f"Stop-ScheduledTask -TaskName {ps_quote(TASK_NAME)} "
                   "-ErrorAction SilentlyContinue"))
    result = run(powershell(f"Start-ScheduledTask -TaskName "
                            f"{ps_quote(TASK_NAME)}"))
    return ok(result)


def firewall_windows(run, host, port, addresses, allow=()):
    """
    Replace SecretSpace's inbound rule and say what it allows. Every network
    means LocalSubnet -- the networks this PC is on, whichever they are
    today -- and one network means just that range; the extra addresses
    are added to either. This machine only needs no rule at all.
    """
    remove = (f"Remove-NetFirewallRule -Group {ps_quote(FIREWALL_GROUP)} "
              "-ErrorAction SilentlyContinue")
    if host == LOCALHOST:
        run(powershell(remove))
        return "Firewall: no rule needed for this machine only."
    if host == ALL_NETWORKS:
        remote, label = "LocalSubnet", "the networks this PC is on"
    else:
        remote = label = str(networks_for(host, addresses)[0][1])
    remotes = [remote, *allow]
    if allow:
        label += " and " + ", ".join(allow)
    result = run(powershell(
        f"{remove}; New-NetFirewallRule -DisplayName "
        f"{ps_quote(f'{TASK_NAME} (TCP {port})')} "
        f"-Group {ps_quote(FIREWALL_GROUP)} -Direction Inbound -Action Allow "
        f"-Protocol TCP -LocalPort {int(port)} -RemoteAddress "
        f"{','.join(ps_quote(r) for r in remotes)} -Profile Any | Out-Null"))
    if ok(result):
        return f"Firewall: allowed {label} to TCP port {port}."
    return (f"Firewall: could not add the rule: "
            f"{(result.stderr if result else '').strip()}")


def windows_folders(run, config_dir):
    """The store and log folders, writable by LOCAL SERVICE."""
    for sub in ("store", "logs"):
        path = os.path.join(config_dir, sub)
        os.makedirs(path, exist_ok=True)
        run(["icacls", path, "/grant", f"{SID_LOCAL_SERVICE}:(OI)(CI)M"])


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def next_steps(host, port, addresses, allow=(), https=False):
    """What to type on the PCs."""
    scheme = "https" if https else "http"
    lines = []
    targets = networks_for(host, addresses)
    if host == LOCALHOST:
        lines.append("Listening on this machine only: no PC can connect.")
        return lines
    if host == ALL_NETWORKS and not targets:
        lines.append(f"PCs: enter {scheme}://<this machine's address>:{port} "
                     f"in Settings -> Sync.")
    for address, network in targets:
        lines.append(f"PCs on {network}: enter {scheme}://{address}:{port} in "
                     f"Settings -> Sync.")
    if allow:
        lines.append(f"Also let in: {', '.join(allow)} -- they use whichever "
                     f"of the addresses above reaches this machine.")
    return lines


def cmd_setup(args, ask=input, say=print, run=_run):
    windows = args.platform == "windows"
    env_path = os.path.join(args.config_dir, "sync.env")
    token_path = os.path.join(args.config_dir, "token")
    if windows and args.default_dir:
        migrate_windows(run, say, legacy_config_dir("windows"), args.config_dir)
    current = read_settings(env_path)
    addresses = list_addresses(run, args.platform)
    keep = args.keep and "HOST" in current and "PORT" in current

    if args.host or keep:
        host, problem = check_host(args.host or current["HOST"],
                                   addresses)
        if problem:
            sys.exit(problem)
    else:
        host = choose_host(ask, say, addresses,
                           current.get("HOST", ALL_NETWORKS))
    if args.port or keep:
        port, problem = check_port(str(args.port or current["PORT"]))
        if problem:
            sys.exit(problem)
    else:
        port = choose_port(ask, say,
                           current.get("PORT", str(DEFAULT_PORT)))

    # The extra addresses: --allow-from sets them; with the other questions
    # answered by flags they stay as saved; otherwise they are asked too.
    old_allow, _ = check_allow(current.get("ALLOW_FROM"))
    old_allow = old_allow or []
    if args.allow_from is not None:
        allow, problem = check_allow(",".join(args.allow_from))
        if problem:
            sys.exit(problem)
    elif keep or args.host or args.port or host == LOCALHOST:
        allow = old_allow
    else:
        allow = choose_allow(ask, say, old_allow)

    changed = (current.get("HOST"), current.get("PORT")) != (host, str(port))
    if changed and port_in_use(host if host != ALL_NETWORKS else "", port):
        say(f"Note: something is already listening on port {port}. If it is "
            f"not this server, pick another port.")

    os.makedirs(args.config_dir, exist_ok=True)
    tls = tls_of(current)
    write_atomic(env_path, render_env(host, port, allow, tls=tls).encode())
    if not windows:
        os.chmod(env_path, 0o644)
    say(f"Wrote {env_path}: listening on {host}:{port}.")

    if read_token(token_path) is None:
        token = write_token(token_path, args.platform, run)
        say(f"Created the token in {token_path}.")
        if windows:
            say(f"Token (enter it on each PC in Settings -> Sync): {token}")
        else:
            say(f"Show it with: sudo cat {token_path}")

    if windows:
        windows_folders(run, args.config_dir)
        say(firewall_windows(run, host, port, addresses, allow))
        program, prefix = server_command()
        result = register_task(run, program, task_arguments(
            args.config_dir, host, port, prefix, tls))
        if not ok(result):
            sys.exit(f"Could not create the scheduled task: "
                     f"{(result.stderr if result else '').strip()}")
        say("Started the server; it also starts by itself when Windows "
            "starts." if restart_task(run) else
            f"Created the task, but it did not start. Open Task Scheduler, "
            f"find '{TASK_NAME}' and check its last result.")
    else:
        old_host = current.get("HOST")
        old_port = current.get("PORT")
        old_sources = [*(n for _, n in networks_for(old_host, addresses)),
                       *old_allow] if old_host and old_port else []
        new_sources = [] if host == LOCALHOST else \
            [*(n for _, n in networks_for(host, addresses)), *allow]
        if changed or allow != old_allow:
            firewall_linux(run, say, new_sources, port, old_sources,
                           int(old_port or 0))
        if changed:
            say(restart_service(run))
    if tls and changed:
        covered = certificate_addresses(tls[0])
        missing = [a for a, _ in networks_for(host, addresses)
                   if a not in covered]
        if missing:
            say(f"HTTPS is on, but its certificate does not cover "
                f"{', '.join(missing)}. Run the `tls` command again, then "
                f"copy the new certificate to the devices.")
    for line in next_steps(host, port, addresses, allow, bool(tls)):
        say(line)


def cmd_new_token(args, ask=input, say=print, run=_run):
    token_path = os.path.join(args.config_dir, "token")
    if not args.yes:
        say("Every PC that syncs will need the new token before it can sync "
            "again.")
        if ask("Replace the token? [y/N]: ").strip().lower() not in ("y",
                                                                      "yes"):
            say("Token unchanged.")
            return
    os.makedirs(args.config_dir, exist_ok=True)
    token = write_token(token_path, args.platform, run)
    if args.platform == "windows":
        say("Restarted the server." if restart_task(run) else
            f"Restart '{TASK_NAME}' in Task Scheduler to use the new token.")
    else:
        say(restart_service(run))
    say("")
    say("New token:")
    say(f"    {token}")
    say("")
    say("On each PC: unlock each synced vault, open Settings -> Sync, paste "
        "it as the token, keep the address, and press Save & sync.")


def cmd_show_token(args, ask=input, say=print, run=_run):
    token = read_token(os.path.join(args.config_dir, "token"))
    if token is None:
        sys.exit("There is no token yet; run the setup first.")
    say(token)


def cmd_remove(args, ask=input, say=print, run=_run):
    """Windows: delete the task and the firewall rule. Keeps the vaults."""
    if args.platform != "windows":
        sys.exit(f"On Linux: sudo systemctl disable --now {SERVICE}, then "
                 f"delete the files listed in README.md.")
    run(powershell(f"Stop-ScheduledTask -TaskName {ps_quote(TASK_NAME)} "
                   "-ErrorAction SilentlyContinue; "
                   f"Unregister-ScheduledTask -TaskName {ps_quote(TASK_NAME)} "
                   "-Confirm:$false -ErrorAction SilentlyContinue; "
                   f"Remove-NetFirewallRule -Group {ps_quote(FIREWALL_GROUP)} "
                   "-ErrorAction SilentlyContinue"))
    say(f"Removed the task and the firewall rule. The vaults, the token and "
        f"the settings are still in {args.config_dir}.")


# ---------------------------------------------------------------------------
# An install from before the rename
# ---------------------------------------------------------------------------
def unit_text(user=SERVICE_USER, program_dir=PROGRAM_DIR,
              config_dir=CONFIG_DIR, data_dir=DATA_DIR) -> str:
    """The systemd unit, as server/secretspace-sync.service ships it."""
    return f"""[Unit]
Description=SecretSpace sync server (encrypted vault blob store)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# These paths match the install steps in README.md. Change them only if you
# put things somewhere else.
User={user}
Group={user}
WorkingDirectory={program_dir}/server
# Where it listens comes from {config_dir}/sync.env (the HOST and PORT
# settings), which the setup writes: run it again to change them, no edit
# here needed. 0.0.0.0 listens on every network this machine is on; limit
# who can connect with the firewall (README.md, step 4). The file is
# required on purpose: without it the server would quietly fall back to
# 127.0.0.1, which no PC can reach.
EnvironmentFile={config_dir}/sync.env
ExecStart=/usr/bin/python3 {program_dir}/server/{SERVER_FILE} \\
    --store {data_dir}/store \\
    --token-file {config_dir}/token

Restart=on-failure
RestartSec=5

# The service reads one token and writes one directory; nothing else on the
# filesystem needs to be reachable from it.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={data_dir}
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
"""


#: Everything `migrate` renames on Linux, as (old, new); --undo swaps them.
_NOW = {"service": SERVICE, "user": SERVICE_USER, "program": PROGRAM_DIR,
        "config": CONFIG_DIR, "data": DATA_DIR, "prefix": ENV_PREFIX}
_BEFORE = {"service": LEGACY_SERVICE, "user": LEGACY_SERVICE_USER,
           "program": LEGACY_PROGRAM_DIR, "config": LEGACY_CONFIG_DIR,
           "data": LEGACY_DATA_DIR, "prefix": LEGACY_ENV_PREFIX}


def _user_exists(run, name) -> bool:
    return ok(run(["id", "-u", name]))


def cmd_migrate(args, ask=input, say=print, run=_run):
    """
    Linux: move an install from before the rename to the current names --
    folders, service, its user, the settings' keys. The port, the token and
    the vaults are not changed. Windows: the installer's setup step does the
    same (migrate_windows); here it only says so.
    """
    if args.platform == "windows":
        say("On Windows the installer does this: run the current "
            "SecretSpace-Server-Installer.exe.")
        return
    root = getattr(args, "root", "") or ""

    def at(path):
        return os.path.join(root, path.lstrip("/")) if root else path

    old, new = (_NOW, _BEFORE) if args.undo else (_BEFORE, _NOW)
    folders = [(old[k], new[k]) for k in ("program", "config", "data")]
    present = [(a, b) for a, b in folders if os.path.isdir(at(a))]
    if not present:
        say(f"Nothing to move: there is no {old['config']} here. "
            + ("This server already has the current names."
               if os.path.isdir(at(new["config"])) else
               "This machine has no SecretSpace sync server."))
        return
    in_the_way = [b for _, b in present if os.path.exists(at(b))]
    if in_the_way:
        sys.exit("Both the old and the new folders exist: "
                 + ", ".join(in_the_way) + ". Nothing was changed. Look at "
                 "them, remove the ones that are not in use, and run this "
                 "again.")

    rename_user = _user_exists(run, old["user"]) and \
        not _user_exists(run, new["user"])
    say("Back up first:")
    say("    sudo tar czf ~/secretspace-server-backup.tgz "
        + " ".join(a for a, _ in present))
    say("")
    say("This will:")
    say(f"  - stop and disable the service {old['service']}")
    if rename_user:
        say(f"  - rename the user and group {old['user']} to {new['user']}")
    for a, b in present:
        say(f"  - move {a} to {b}")
    say(f"  - write {new['config']}/sync.env with the "
        f"{new['prefix']}... settings")
    say(f"  - install {new['service']}.service, remove "
        f"{old['service']}.service, and start {new['service']}")
    say("The port, the token and the vaults stay as they are.")
    if args.dry_run:
        say("")
        say("Dry run: nothing was changed.")
        return
    if not args.yes and ask("Go ahead? [y/N]: ").strip().lower() not in (
            "y", "yes"):
        say("Nothing was changed.")
        return

    # Before the README had the `tls` command, HTTPS was turned on by adding
    # --cert and --key to the unit file by hand. The new unit does not have
    # them, so they are carried into sync.env instead of being lost.
    old_unit_tls = unit_tls(os.path.join(at(UNIT_DIR), old["service"] + ".service"))
    systemd = bool(shutil.which("systemctl"))
    if systemd:
        run(["systemctl", "stop", old["service"]])
        run(["systemctl", "disable", old["service"]])
    if rename_user:
        for cmd in (["usermod", "-l", new["user"], old["user"]],
                    ["groupmod", "-n", new["user"], old["user"]]):
            result = run(cmd)
            if not ok(result):
                sys.exit(f"Could not run {' '.join(cmd)}: "
                         f"{(result.stderr if result else '').strip()}\n"
                         "Nothing else was changed. Start the old service "
                         f"again with: sudo systemctl enable --now "
                         f"{old['service']}")
        say(f"Renamed the user {old['user']} to {new['user']}.")
    for a, b in present:
        os.makedirs(os.path.dirname(at(b)), exist_ok=True)
        shutil.move(at(a), at(b))
        say(f"Moved {a} to {b}.")

    env_path = os.path.join(at(new["config"]), "sync.env")
    settings = read_settings(env_path)
    if "HOST" in settings and "PORT" in settings:
        allow, _ = check_allow(settings.get("ALLOW_FROM"))
        tls = tls_of(settings) or old_unit_tls
        if tls:
            # The certificate moved with its folder.
            tls = tuple(path.replace(old["config"], new["config"], 1)
                        for path in tls)
        write_atomic(env_path, render_env(settings["HOST"], settings["PORT"],
                                          allow or [], new["prefix"],
                                          tls).encode())
        os.chmod(env_path, 0o644)
        say(f"Wrote {new['config']}/sync.env.")
        if old_unit_tls and not tls_of(settings):
            say("Your old unit served HTTPS (--cert/--key); that is now in "
                "sync.env, so it stays on.")

    # The program files of the old name, once the current ones are beside them.
    server_dir = os.path.join(at(new["program"]), "server")
    if not args.undo and os.path.isfile(os.path.join(server_dir, SERVER_FILE)):
        for name in LEGACY_PROGRAM_FILES:
            try:
                os.remove(os.path.join(server_dir, name))
            except OSError:
                pass

    unit_dir = at(UNIT_DIR)
    os.makedirs(unit_dir, exist_ok=True)
    write_atomic(os.path.join(unit_dir, new["service"] + ".service"),
                 unit_text(new["user"], new["program"], new["config"],
                           new["data"]).encode())
    try:
        os.remove(os.path.join(unit_dir, old["service"] + ".service"))
    except OSError:
        pass
    if systemd:
        run(["systemctl", "daemon-reload"])
        result = run(["systemctl", "enable", "--now", new["service"]])
        say(f"Started {new['service']}." if ok(result) else
            f"Could not start {new['service']}: "
            f"{(result.stderr if result else '').strip()}\n"
            f"Look at: journalctl -u {new['service']} -n 50")
    else:
        say("No systemd here; start the server yourself.")
    if "PORT" in settings:
        say(f"Check it: curl http://127.0.0.1:{settings['PORT']}/health")
    say("The other way round: sudo python3 "
        f"{new['program']}/server/secretspace_setup.py migrate"
        + ("" if args.undo else " --undo"))


def migrate_windows(run, say, old_dir, new_dir) -> bool:
    """
    Windows: an install from before the rename. Its task and firewall rules
    go (the setup that follows makes the current ones), its data folder
    moves to the current name. True when there was one. Port, token and
    vaults are not changed.
    """
    if not os.path.isdir(old_dir):
        return False
    run(powershell(
        f"Stop-ScheduledTask -TaskName {ps_quote(LEGACY_TASK_NAME)} "
        "-ErrorAction SilentlyContinue; "
        f"Unregister-ScheduledTask -TaskName {ps_quote(LEGACY_TASK_NAME)} "
        "-Confirm:$false -ErrorAction SilentlyContinue; "
        f"Remove-NetFirewallRule -Group {ps_quote(LEGACY_FIREWALL_GROUP)} "
        "-ErrorAction SilentlyContinue"))
    if os.path.exists(new_dir):
        say(f"Both {old_dir} and {new_dir} exist; using {new_dir} and "
            f"leaving the other alone.")
        return True
    try:
        shutil.move(old_dir, new_dir)
    except OSError as e:
        sys.exit(f"Could not move {old_dir} to {new_dir}: {e}. Close "
                 "anything that has it open and run the installer again.")
    # Its settings file still has the old keys; the setup that called this
    # reads them and writes the file again with the current ones.
    say(f"Moved the server's data from {old_dir} to {new_dir}.")
    return True


# ---------------------------------------------------------------------------
# HTTPS
# ---------------------------------------------------------------------------
CERT_FILE = "server.crt"
KEY_FILE = "server.key"
#: How long a certificate made here is valid. A self-signed certificate that
#: the devices pin is not checked against any authority, so a short life buys
#: nothing but a day when every device stops syncing.
CERT_DAYS = 3650


def unit_tls(path):
    """(certificate, key) from the --cert/--key of a unit file, or None."""
    try:
        with open(path, encoding="utf-8") as f:
            words = f.read().replace("\\\n", " ").split()
    except OSError:
        return None
    found = {}
    for flag in ("--cert", "--key"):
        if flag in words and words.index(flag) + 1 < len(words):
            found[flag] = words[words.index(flag) + 1]
    if "--cert" in found and "--key" in found:
        return found["--cert"], found["--key"]
    return None


def certificate_addresses(cert_path):
    """The IP addresses a certificate is made for (its subjectAltName)."""
    try:
        import ssl
        decoded = ssl._ssl._test_decode_cert(cert_path)
    except Exception:
        return []
    return [value for kind, value in decoded.get("subjectAltName", ())
            if kind == "IP Address"]


def certificate_fingerprint(cert_path):
    """SHA-256 of the certificate, as the colon-separated hex browsers show."""
    import hashlib
    import ssl
    with open(cert_path, encoding="ascii") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def tls_addresses(host, addresses):
    """What the certificate must name: every address the devices may use."""
    found = [a for a, _ in networks_for(host, addresses)]
    if host not in (ALL_NETWORKS, LOCALHOST) and host not in found:
        found.append(host)
    found.append(LOCALHOST)
    return list(dict.fromkeys(found))


def make_certificate(run, cert_path, key_path, ips, names):
    """
    A self-signed certificate and its key, with openssl: an EC P-256 key, the
    addresses and names it serves in subjectAltName (what a TLS client checks;
    the CN is ignored). Returns None, or a message saying what went wrong.
    """
    openssl = shutil.which("openssl")
    if not openssl:
        return ("openssl is not installed. On Ubuntu: sudo apt install "
                "openssl. On Windows it comes with Git for Windows "
                "(C:\\Program Files\\Git\\usr\\bin), or turn HTTPS on by hand "
                "as README.md describes.")
    san = ",".join([f"IP:{ip}" for ip in ips] + [f"DNS:{n}" for n in names])
    result = run([openssl, "req", "-x509", "-newkey", "ec",
                  "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                  "-sha256", "-days", str(CERT_DAYS),
                  "-keyout", key_path, "-out", cert_path,
                  "-subj", "/CN=SecretSpace sync server",
                  "-addext", f"subjectAltName={san}",
                  "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                  "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
                  "-addext", "extendedKeyUsage=serverAuth"])
    if not ok(result):
        return ("openssl could not make the certificate: "
                f"{(result.stderr if result else '').strip()}")
    return None


def protect_key(run, path, platform):
    """The private key: the service account and administrators only."""
    if platform == "windows":
        run(["icacls", path, "/inheritance:r", "/grant:r",
             f"{SID_SYSTEM}:F", f"{SID_ADMINS}:F", f"{SID_LOCAL_SERVICE}:R"])
    else:
        os.chmod(path, 0o600)
        _own_file(path)


def restart_server(run, platform, config_dir, settings):
    """Restart with the settings now in sync.env. Returns what happened."""
    if platform != "windows":
        return restart_service(run)
    program, prefix = server_command()
    result = register_task(run, program, task_arguments(
        config_dir, settings["HOST"], settings["PORT"], prefix,
        tls_of(settings)))
    if not ok(result):
        return ("Could not update the scheduled task: "
                f"{(result.stderr if result else '').strip()}")
    return ("Restarted the server." if restart_task(run) else
            f"Restart '{TASK_NAME}' in Task Scheduler to use it.")


def cmd_tls(args, ask=input, say=print, run=_run):
    """
    HTTPS on (`tls`), off (`tls off`), or what is in use (`tls show`).
    Turning it on makes a new certificate every time: the devices then need
    the new certificate file.
    """
    env_path = os.path.join(args.config_dir, "sync.env")
    settings = read_settings(env_path)
    if "HOST" not in settings or "PORT" not in settings:
        sys.exit("Run the setup first: there is no sync.env yet.")
    host, port = settings["HOST"], settings["PORT"]
    allow, _ = check_allow(settings.get("ALLOW_FROM"))
    current = tls_of(settings)
    action = args.action or "on"

    if action == "show":
        if not current:
            say(f"HTTPS is off: the server answers on http://...:{port}.")
            return
        say(f"HTTPS is on, with {current[0]}.")
        covered = certificate_addresses(current[0])
        if covered:
            say(f"  It is made for: {', '.join(covered)}")
        try:
            say(f"  SHA-256: {certificate_fingerprint(current[0])}")
        except (OSError, ValueError) as e:
            say(f"  It cannot be read: {e}")
        return

    if action == "off":
        if not current:
            say("HTTPS is already off.")
            return
        if not args.yes and ask(
                "Turn HTTPS off? Every device then needs http:// again. "
                "[y/N]: ").strip().lower() not in ("y", "yes"):
            say("Nothing changed.")
            return
        write_atomic(env_path, render_env(host, port, allow or []).encode())
        if args.platform != "windows":
            os.chmod(env_path, 0o644)
        say(f"HTTPS is off; the certificate files stay in {args.config_dir}.")
        fresh = read_settings(env_path)
        say(restart_server(run, args.platform, args.config_dir, fresh))
        say(f"On each device: Settings -> Sync, change the address to "
            f"http://...:{port} and clear the certificate file.")
        return

    if host == LOCALHOST:
        sys.exit("The server listens on this machine only; HTTPS would protect "
                 "nothing. Run the setup to choose a network first.")
    addresses = list_addresses(run, args.platform)
    ips = tls_addresses(host, addresses)
    names = list(dict.fromkeys(
        n for n in (socket.gethostname(), "localhost") if n))
    if current and not args.yes:
        say("HTTPS is on already. A new certificate replaces the old one: "
            "every device then needs the new certificate file.")
        if ask("Make a new certificate? [y/N]: ").strip().lower() not in (
                "y", "yes"):
            say("Nothing changed.")
            return
    os.makedirs(args.config_dir, exist_ok=True)
    cert = os.path.join(args.config_dir, CERT_FILE)
    key = os.path.join(args.config_dir, KEY_FILE)
    # Made beside the old pair and swapped in only once both exist, so a
    # failure leaves the server's working certificate alone.
    new_cert, new_key = cert + ".new", key + ".new"
    problem = make_certificate(run, new_cert, new_key, ips, names)
    if problem:
        for leftover in (new_cert, new_key):
            try:
                os.remove(leftover)
            except OSError:
                pass
        sys.exit(problem)
    protect_key(run, new_key, args.platform)
    if args.platform != "windows":
        os.chmod(new_cert, 0o644)
    os.replace(new_key, key)
    os.replace(new_cert, cert)
    write_atomic(env_path, render_env(host, port, allow or [],
                                      tls=(cert, key)).encode())
    if args.platform != "windows":
        os.chmod(env_path, 0o644)
    say(f"Made a certificate for {', '.join(ips)} "
        f"(and {', '.join(names)}), valid {CERT_DAYS // 365} years.")
    say(f"  {cert}")
    say(f"  SHA-256: {certificate_fingerprint(cert)}")
    say(restart_server(run, args.platform, args.config_dir,
                       read_settings(env_path)))
    say("")
    say("On each device:")
    say(f"  1. Copy {cert} to it (it is not secret; the key stays here).")
    for address, network in networks_for(host, addresses) or [("<address>", "")]:
        say(f"  2. Settings -> Sync: address https://{address}:{port}, "
            f"certificate file = the copied {CERT_FILE}.")
        break
    say("  The app checks the server against that file, so a machine that "
        "pretends to be the server is refused.")


#: What the menu offers, in order: (label, command).
MENU = (("Change network, port or allowed addresses", "setup"),
        ("Replace the token", "new-token"),
        ("Show the token", "show-token"),
        ("Turn HTTPS on (a new certificate)", "tls"))


def cmd_menu(args, ask=input, say=print, run=_run):
    """
    Everything in one place: what SecretSpace-Server-Setup.exe shows when it is
    double-clicked. Each choice runs its command, then the menu comes back,
    until Close.
    """
    env_path = os.path.join(args.config_dir, "sync.env")
    close = str(len(MENU) + 1)
    while True:
        current = read_settings(env_path)
        say("")
        say("SecretSpace sync server")
        if "HOST" in current and "PORT" in current:
            say(f"  Listening on {current['HOST']}:{current['PORT']}")
        else:
            say("  Not set up yet.")
        say("")
        for i, (label, _) in enumerate(MENU, 1):
            say(f"  {i}) {label}")
        say(f"  {close}) Close")
        try:
            answer = ask("Choice: ").strip()
        except EOFError:
            return
        if answer == close:
            return
        if not (answer.isdigit() and 1 <= int(answer) <= len(MENU)):
            say(f"Type a number from 1 to {close}.")
            continue
        say("")
        try:
            COMMANDS[MENU[int(answer) - 1][1]](args, ask, say, run)
        except SystemExit as stop:
            # A command that stops (no token yet, a task that cannot be
            # created) says why and returns here instead of closing.
            if stop.code not in (None, 0):
                say(str(stop.code))


COMMANDS = {"setup": cmd_setup, "new-token": cmd_new_token,
            "show-token": cmd_show_token, "remove": cmd_remove,
            "menu": cmd_menu, "migrate": cmd_migrate, "tls": cmd_tls}


def is_admin(platform):
    if platform == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (ImportError, AttributeError, OSError):
            return False
    return not hasattr(os, "geteuid") or os.geteuid() == 0


def relaunch_as_admin(argv):
    """
    Windows: ask (the UAC prompt) to run this exe again elevated. True if it
    started. The elevated copy gets a window of its own, so it always
    pauses at the end -- otherwise its answer would vanish with it.
    """
    import ctypes
    params = subprocess.list2cmdline(argv if "--pause" in argv
                                     else ["--pause", *argv])
    # ShellExecute returns a value above 32 on success.
    return ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1) > 32


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    parser.add_argument("--config-dir",
                        help="where sync.env and the token live (default: "
                             "/etc/secretspace, or %%ProgramData%%\\"
                             "SecretSpace Server on Windows)")
    parser.add_argument("--platform", choices=("linux", "windows"),
                        default=default_platform(), help=argparse.SUPPRESS)
    parser.add_argument("--pause", action="store_true",
                        help="wait for Enter at the end (for a console "
                             "window that would otherwise close)")
    sub = parser.add_subparsers(dest="command")
    setup = sub.add_parser("setup", help="address, port, firewall (default)")
    setup.add_argument("--host", help="listen address; skips the question")
    setup.add_argument("--port", type=int, help="port; skips the question")
    setup.add_argument("--keep", action="store_true",
                       help="reuse the saved address and port without "
                            "asking (an upgrade)")
    setup.add_argument("--allow-from", action="append", metavar="ADDRESS",
                       help="also let this address or network through the "
                            "firewall, e.g. a PC on another network; "
                            "repeat or comma-separate for more, 'none' "
                            "clears them; skips the question")
    new = sub.add_parser("new-token", help="replace the token")
    new.add_argument("--yes", action="store_true",
                     help="do not ask for confirmation")
    sub.add_parser("show-token", help="print the token")
    sub.add_parser("remove", help="Windows: remove the task and firewall rule")
    sub.add_parser("menu", help="choose one of the above from a list")
    migrate = sub.add_parser("migrate", help="Linux: give an install from "
                             "before the rename the current names")
    migrate.add_argument("--dry-run", action="store_true",
                         help="only show what would be done")
    migrate.add_argument("--undo", action="store_true",
                         help="put the old names back")
    migrate.add_argument("--yes", action="store_true",
                         help="do not ask for confirmation")
    migrate.add_argument("--root", default="", help=argparse.SUPPRESS)
    tls = sub.add_parser("tls", help="HTTPS: on (a new certificate), off, or "
                         "show what is in use")
    tls.add_argument("action", nargs="?", choices=("on", "off", "show"),
                     default="on")
    tls.add_argument("--yes", action="store_true",
                     help="do not ask for confirmation")
    # No command means setup, with every question asked.
    parser.set_defaults(command="setup", host=None, port=None, keep=False,
                        allow_from=None, yes=False, dry_run=False, undo=False,
                        root="", action=None)
    args = parser.parse_args(argv)
    args.default_dir = args.config_dir is None
    if args.config_dir is None:
        args.config_dir = default_config_dir(args.platform)
    return args


def main(argv=None, ask=input, say=print, run=_run):
    args = parse_args(argv)
    if args.command == "migrate" and args.platform != "windows" \
            and not args.root and not args.dry_run and not is_admin("linux"):
        sys.exit("Run it with sudo: it renames the service and its folders.")
    if args.default_dir and args.command != "migrate" \
            and not is_admin(args.platform):
        sys.exit("Run it as administrator: it writes to "
                 f"{args.config_dir}." if args.platform == "windows" else
                 f"Run it with sudo: it writes to {args.config_dir}.")
    # The menu ends with its own Close choice: no extra "Press Enter".
    if not args.pause or args.command == "menu":
        COMMANDS[args.command](args, ask, say, run)
        return
    # A console window opened for this closes when it ends: show any error
    # before waiting, not after.
    try:
        COMMANDS[args.command](args, ask, say, run)
        code = 0
    except SystemExit as stop:
        if stop.code not in (None, 0):
            say(str(stop.code))
        code = 0 if stop.code in (None, 0) else 1
    try:
        ask("\nPress Enter to close this window.")
    except EOFError:
        pass
    if code:
        sys.exit(code)


if __name__ == "__main__":
    main()
