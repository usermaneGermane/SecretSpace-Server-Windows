#!/usr/bin/env python3
"""
PassMan sync server setup -- where it listens, its token, its firewall rule.

Linux (systemd):
    sudo python3 passman_setup.py              # ask, then write the settings
    sudo python3 passman_setup.py new-token    # replace a leaked token
    sudo python3 passman_setup.py show-token   # print the token

Windows (PassMan-Server-Installer.exe runs the first one for you):
    PassMan-Server-Setup.exe [setup] | new-token | show-token | remove

`setup` asks which address to listen on (listing this machine's networks)
and which port, writes them to sync.env, creates the token if there is none
yet, and opens the port in the firewall for the networks it serves:

- Linux: sync.env is /etc/passman/sync.env, which the systemd unit loads.
  The firewall rule is added when ufw is on; ufw is never switched on from
  here, because doing that over SSH without an SSH rule locks you out.
- Windows: everything lives in %ProgramData%\\PassMan Server. A Windows
  Firewall rule and a Task Scheduler task (at startup, as LOCAL SERVICE)
  are created or replaced, and the server is (re)started.

`new-token` writes a fresh token, restarts the server and prints the new
value. Every PC then needs it in Settings -> Sync before it can sync again.

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
from passman_server import DEFAULT_PORT, write_atomic          # noqa: E402

SERVICE = "passman-sync"
SERVICE_USER = "passman"

#: Windows: the scheduled task, the firewall rule group and their names.
TASK_NAME = "PassMan Sync Server"
FIREWALL_GROUP = "PassMan Sync Server"
#: Well-known SIDs, so icacls works on any Windows display language.
SID_SYSTEM = "*S-1-5-18"
SID_LOCAL_SERVICE = "*S-1-5-19"
SID_ADMINS = "*S-1-5-32-544"

#: The service runs as an unprivileged user, which cannot bind below 1024.
MIN_PORT = 1024

ALL_NETWORKS = "0.0.0.0"
LOCALHOST = "127.0.0.1"


def default_platform():
    return "windows" if os.name == "nt" else "linux"


def default_config_dir(platform):
    if platform == "windows":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, "PassMan Server")
    return "/etc/passman"


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


def render_env(host, port):
    return ("# PassMan sync server -- written by passman_setup.py.\n"
            "# Change it by running the setup again.\n"
            f"PASSMAN_HOST={host}\n"
            f"PASSMAN_PORT={port}\n")


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
    """Allow the served networks through ufw -- but only if ufw is on."""
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
#: The frozen server, next to PassMan-Server-Setup.exe in the install folder.
SERVER_EXE = "PassMan-Server.exe"


def server_command(frozen=None, executable=None):
    """
    (program, arguments before ours) that start the server. Frozen, that is
    PassMan-Server.exe beside whichever exe is running this -- the setup
    exe must not put itself in the startup task.
    """
    frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    executable = executable or sys.executable
    if frozen:
        return os.path.join(os.path.dirname(executable), SERVER_EXE), []
    return executable, [os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "passman_server.py")]


def task_arguments(config_dir, host, port, prefix=()):
    return subprocess.list2cmdline([
        *prefix, "--host", host, "--port", str(port),
        "--store", os.path.join(config_dir, "store"),
        "--token-file", os.path.join(config_dir, "token"),
        "--log-file", os.path.join(config_dir, "logs", "server.log"),
        "--retry-bind", "10"])


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


def firewall_windows(run, host, port, addresses):
    """
    Replace PassMan's inbound rule and say what it allows. Every network
    means LocalSubnet -- the networks this PC is on, whichever they are
    today -- and one network means just that range. This machine only needs
    no rule at all.
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
    result = run(powershell(
        f"{remove}; New-NetFirewallRule -DisplayName "
        f"{ps_quote(f'{TASK_NAME} (TCP {port})')} "
        f"-Group {ps_quote(FIREWALL_GROUP)} -Direction Inbound -Action Allow "
        f"-Protocol TCP -LocalPort {int(port)} -RemoteAddress "
        f"{ps_quote(remote)} -Profile Any | Out-Null"))
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
def next_steps(host, port, addresses):
    """What to type on the PCs."""
    lines = []
    targets = networks_for(host, addresses)
    if host == LOCALHOST:
        lines.append("Listening on this machine only: no PC can connect.")
    elif host == ALL_NETWORKS and not targets:
        lines.append(f"PCs: enter http://<this machine's address>:{port} in "
                     f"Settings -> Sync.")
    for address, network in targets:
        lines.append(f"PCs on {network}: enter http://{address}:{port} in "
                     f"Settings -> Sync.")
    return lines


def cmd_setup(args, ask=input, say=print, run=_run):
    windows = args.platform == "windows"
    env_path = os.path.join(args.config_dir, "sync.env")
    token_path = os.path.join(args.config_dir, "token")
    current = read_env(env_path)
    addresses = list_addresses(run, args.platform)
    keep = args.keep and "PASSMAN_HOST" in current and "PASSMAN_PORT" in current

    if args.host or keep:
        host, problem = check_host(args.host or current["PASSMAN_HOST"],
                                   addresses)
        if problem:
            sys.exit(problem)
    else:
        host = choose_host(ask, say, addresses,
                           current.get("PASSMAN_HOST", ALL_NETWORKS))
    if args.port or keep:
        port, problem = check_port(str(args.port or current["PASSMAN_PORT"]))
        if problem:
            sys.exit(problem)
    else:
        port = choose_port(ask, say,
                           current.get("PASSMAN_PORT", str(DEFAULT_PORT)))

    changed = (current.get("PASSMAN_HOST"), current.get("PASSMAN_PORT")) \
        != (host, str(port))
    if changed and port_in_use(host if host != ALL_NETWORKS else "", port):
        say(f"Note: something is already listening on port {port}. If it is "
            f"not this server, pick another port.")

    os.makedirs(args.config_dir, exist_ok=True)
    write_atomic(env_path, render_env(host, port).encode())
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
        say(firewall_windows(run, host, port, addresses))
        program, prefix = server_command()
        result = register_task(run, program, task_arguments(
            args.config_dir, host, port, prefix))
        if not ok(result):
            sys.exit(f"Could not create the scheduled task: "
                     f"{(result.stderr if result else '').strip()}")
        say("Started the server; it also starts by itself when Windows "
            "starts." if restart_task(run) else
            f"Created the task, but it did not start. Open Task Scheduler, "
            f"find '{TASK_NAME}' and check its last result.")
    elif changed:
        old_host = current.get("PASSMAN_HOST")
        old_port = current.get("PASSMAN_PORT")
        old_networks = [n for _, n in networks_for(old_host, addresses)] \
            if old_host and old_port else []
        firewall_linux(run, say, [n for _, n in networks_for(host, addresses)],
                       port, old_networks, int(old_port or 0))
        say(restart_service(run))
    for line in next_steps(host, port, addresses):
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


#: What the menu offers, in order: (label, command).
MENU = (("Change network or port", "setup"),
        ("Replace the token", "new-token"),
        ("Show the token", "show-token"))


def cmd_menu(args, ask=input, say=print, run=_run):
    """
    Everything in one place: what PassMan-Server-Setup.exe shows when it is
    double-clicked. Each choice runs its command, then the menu comes back,
    until Close.
    """
    env_path = os.path.join(args.config_dir, "sync.env")
    close = str(len(MENU) + 1)
    while True:
        current = read_env(env_path)
        say("")
        say("PassMan sync server")
        if "PASSMAN_HOST" in current and "PASSMAN_PORT" in current:
            say(f"  Listening on {current['PASSMAN_HOST']}:"
                f"{current['PASSMAN_PORT']}")
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
            "menu": cmd_menu}


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
                             "/etc/passman, or %%ProgramData%%\\PassMan "
                             "Server on Windows)")
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
    new = sub.add_parser("new-token", help="replace the token")
    new.add_argument("--yes", action="store_true",
                     help="do not ask for confirmation")
    sub.add_parser("show-token", help="print the token")
    sub.add_parser("remove", help="Windows: remove the task and firewall rule")
    sub.add_parser("menu", help="choose one of the above from a list")
    # No command means setup, with every question asked.
    parser.set_defaults(command="setup", host=None, port=None, keep=False,
                        yes=False)
    args = parser.parse_args(argv)
    args.default_dir = args.config_dir is None
    if args.config_dir is None:
        args.config_dir = default_config_dir(args.platform)
    return args


def main(argv=None, ask=input, say=print, run=_run):
    args = parse_args(argv)
    if args.default_dir and not is_admin(args.platform):
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
