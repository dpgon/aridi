"""Running the collector on a machine over SSH (TODO.md 5.4).

ssh is always called with a list of arguments, never through a shell, with BatchMode
(no prompts) and strict host key checking. Credentials come from the ssh-agent
(SSH_AUTH_SOCK) or the ssh_config given to the central; none is stored.

Privilege (decision of TODO.md 5.0):
  sudo  the script installed at INSTALLED_PATH, owned by root, allowed in sudoers with
        'NOPASSWD: /usr/local/libexec/aridi-collect.sh ""'. Its SHA-256 is printed on
        stderr first, so the central can tell when it is outdated.
  user  the central's copy of the script through stdin, run as the SSH user.
"""

import logging
import re
import subprocess
import threading
from dataclasses import dataclass

from django.conf import settings

from aridi_central.inventory.models import Machine
from aridi_central.inventory.validators import PROXY_HOP, SSH_TARGET

log = logging.getLogger(__name__)

INSTALLED_PATH = "/usr/local/libexec/aridi-collect.sh"
# Fixed remote commands: nothing of the machine's fields goes into them.
REMOTE_SUDO = (f"sha256sum {INSTALLED_PATH} >&2 || echo 'aridi: sha256sum failed' >&2; "
               f"exec sudo -n {INSTALLED_PATH}")
REMOTE_USER = "exec sh -s"
SHA_LINE = re.compile(rf"^([0-9a-f]{{64}})\s+\*?{re.escape(INSTALLED_PATH)}$", re.M)
STDERR_LIMIT = 64 * 1024


@dataclass
class Result:
    ok: bool
    bundle: bytes = b""
    reason: str = ""
    installed_sha256: str = ""


def build_command(machine):
    """argv of ssh for MACHINE. ValueError if its SSH fields are not valid."""
    if not machine.ssh_target or not SSH_TARGET.fullmatch(machine.ssh_target):
        raise ValueError(f"invalid SSH target {machine.ssh_target!r}")
    if not 1 <= int(machine.ssh_port) <= 65535:
        raise ValueError(f"invalid SSH port {machine.ssh_port!r}")
    argv = ["ssh", "-T",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={settings.ARIDI_SSH_CONNECT_TIMEOUT}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4",
            "-o", "LogLevel=ERROR"]
    if settings.ARIDI_SSH_CONFIG:
        argv += ["-F", settings.ARIDI_SSH_CONFIG]
    if settings.ARIDI_KNOWN_HOSTS:
        argv += ["-o", f"UserKnownHostsFile={settings.ARIDI_KNOWN_HOSTS}"]
    argv += ["-p", str(int(machine.ssh_port))]
    if machine.proxy_jump:
        if not all(PROXY_HOP.fullmatch(hop) for hop in machine.proxy_jump.split(",")):
            raise ValueError(f"invalid jump host {machine.proxy_jump!r}")
        argv += ["-J", machine.proxy_jump]
    remote = REMOTE_SUDO if machine.privilege == Machine.Privilege.SUDO else REMOTE_USER
    # "--" ends the options: the target can never be read as one.
    argv += ["--", machine.ssh_target, remote]
    return argv


def _read(stream, limit, out, on_overflow=None):
    """Read STREAM into OUT (list) up to LIMIT bytes, then drain and discard the rest.

    The total size is appended last. ON_OVERFLOW runs once when LIMIT is passed.
    """
    size = 0
    while chunk := stream.read(65536):
        if size <= limit:
            out.append(chunk)
        size += len(chunk)
        if size > limit and on_overflow is not None:
            on_overflow()
            on_overflow = None
    out.append(size)


def failure_reason(returncode, stderr):
    """Short reason of a failed run, from ssh's exit code and stderr."""
    text = stderr.decode("utf-8", "replace")
    lines = [line for line in text.splitlines()
             if line and not SHA_LINE.match(line)]
    tail = " | ".join(lines[-3:])[:500]
    checks = (
        ("Host key verification failed", "unknown or changed host key"),
        ("REMOTE HOST IDENTIFICATION HAS CHANGED", "changed host key"),
        ("Permission denied", "authentication refused"),
        ("Could not resolve hostname", "host name not resolved"),
        ("Connection refused", "connection refused"),
        ("Connection timed out", "connection timed out"),
        ("No route to host", "no route to host"),
        ("a password is required", "sudo denied (no NOPASSWD rule for the script)"),
        ("a terminal is required", "sudo denied (no NOPASSWD rule for the script)"),
        ("is not allowed to execute", "sudo denied (the rule does not allow the script)"),
        ("not in the sudoers", "sudo denied (user not in sudoers)"),
        ("No such file or directory", f"the script is not installed at {INSTALLED_PATH}"),
        ("command not found", f"the script is not installed at {INSTALLED_PATH}"),
    )
    for needle, meaning in checks:
        if needle in text:
            return f"{meaning}: {tail}" if tail else meaning
    what = "ssh failed" if returncode == 255 else f"remote command exited with {returncode}"
    return f"{what}: {tail}" if tail else what


def collect(machine, script_path=None, timeout=None, max_bytes=None, ssh="ssh"):
    """Run the collector on MACHINE and return a Result (never raises for remote errors)."""
    try:
        argv = build_command(machine)
    except ValueError as exc:
        return Result(False, reason=str(exc))
    argv[0] = ssh
    timeout = timeout or settings.ARIDI_SSH_TIMEOUT
    max_bytes = max_bytes or settings.ARIDI_MAX_BUNDLE_BYTES
    script = b""
    if machine.privilege == Machine.Privilege.USER:
        try:
            with open(script_path or settings.ARIDI_COLLECTOR_SCRIPT, "rb") as handle:
                script = handle.read()
        except OSError as exc:
            return Result(False, reason=f"cannot read the collector script: {exc}")
    log.info("collecting %s: %s", machine.name, " ".join(argv))
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except OSError as exc:
        return Result(False, reason=f"cannot run ssh: {exc}")
    out, err = [], []
    readers = [threading.Thread(target=_read, args=(proc.stdout, max_bytes, out, proc.kill)),
               threading.Thread(target=_read, args=(proc.stderr, STDERR_LIMIT, err))]
    for reader in readers:
        reader.start()
    try:
        if script:
            proc.stdin.write(script)
        proc.stdin.close()
    except BrokenPipeError:
        pass
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    for reader in readers:
        reader.join()
    out_size, err_size = out.pop(), err.pop()
    stdout, stderr = b"".join(out), b"".join(err)
    match = SHA_LINE.search(stderr.decode("ascii", "replace"))
    installed = match.group(1) if match else ""
    if timed_out:
        return Result(False, reason=f"timed out after {timeout} s", installed_sha256=installed)
    if out_size > max_bytes:
        return Result(False, reason=f"output larger than {max_bytes} bytes",
                      installed_sha256=installed)
    if proc.returncode != 0:
        return Result(False, reason=failure_reason(proc.returncode, stderr),
                      installed_sha256=installed)
    if err_size > STDERR_LIMIT:
        log.warning("%s: stderr cut at %d bytes", machine.name, STDERR_LIMIT)
    return Result(True, bundle=stdout, installed_sha256=installed)
