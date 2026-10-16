"""Built-in alert rules (TODO.md 6.2, list decided by the user on 2026-10-16).

A rule looks at the previous snapshot with data and the new one (Snapshot.data dicts)
and returns findings. Rules about a change need a previous snapshot; rules about a state
(disk full, account file permissions) also fire on the first snapshot of a machine, and
afterwards only when the state starts. Volatile areas never fire anything: the disk rule
reads the storage area, which is stable.

"machine_unresponsive" is not about two snapshots; evaluate.py checks it.
"""

import posixpath
from dataclasses import dataclass, field

from django.db import models

from aridi.interpret import AREAS

OK = "ok"
PRIVILEGED_GROUPS = frozenset({"sudo", "wheel", "admin"})
# Shells that do not give a login, by base name.
NO_LOGIN_SHELLS = frozenset({"", "nologin", "false", "sync", "shutdown", "halt", "true"})
# Mounts that are full by design (images), live in memory, or show another file system
# (overlay: the containers of a Docker host repeat the disk below them).
NOT_FILLING = frozenset({"squashfs", "iso9660", "udf", "erofs", "cramfs", "tmpfs",
                         "devtmpfs", "shm", "ramfs", "proc", "sysfs", "devpts", "cgroup",
                         "cgroup2", "overlay"})


class Severity(models.TextChoices):
    LOW = "low", "low"
    MEDIUM = "medium", "medium"
    HIGH = "high", "high"


RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}


@dataclass
class Finding:
    key: str                  # what the alert is about, stable between snapshots
    title: str
    detail: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Rule:
    code: str
    title: str
    severity: str
    description: str
    check: object = None           # (before, after, threshold) -> [Finding]
    threshold: float | None = None
    threshold_label: str = ""


def _section(snapshot, name):
    if snapshot is None:
        return None
    return (snapshot.get("sections") or {}).get(name)


def _data(snapshot, name):
    """Data of area NAME when it could be seen, else None."""
    section = _section(snapshot, name)
    if section is None or section.get("status") != OK or not isinstance(section.get("data"),
                                                                           dict):
        return None
    return section["data"]


def _has_gap(snapshot, name, item):
    section = _section(snapshot, name) or {}
    return any(g.get("item") == item and g.get("status") not in ("ok", "na")
               for g in section.get("gaps") or [])


# Users

def _login_shell(shell):
    return posixpath.basename(shell or "") not in NO_LOGIN_SHELLS


def _privileges(user):
    """What makes USER worth an alert: login shell, uid 0, privileged groups."""
    found = set()
    if _login_shell(user.get("shell")):
        found.add("shell")
    if user.get("uid") == 0:
        found.add("uid0")
    found |= {f"group:{g}" for g in set(user.get("groups") or []) & PRIVILEGED_GROUPS}
    return found


def _describe(user, aspects):
    parts = []
    if "shell" in aspects:
        parts.append(f"login shell {user.get('shell')}")
    if "uid0" in aspects:
        parts.append("uid 0")
    groups = sorted(a.split(":", 1)[1] for a in aspects if a.startswith("group:"))
    if groups:
        parts.append("member of " + ", ".join(groups))
    return ", ".join(parts)


def privileged_user(before, after, threshold):
    old, new = _data(before, "users"), _data(after, "users")
    if old is None or new is None:
        return []
    known = {u.get("name"): u for u in old.get("users") or []}
    findings = []
    for user in new.get("users") or []:
        name = user.get("name")
        aspects = _privileges(user)
        if name not in known:
            if aspects:
                findings.append(Finding(f"{name}:new", f"New user {name} with "
                                        f"{_describe(user, aspects)}",
                                        {"user": name, "uid": user.get("uid"),
                                         "shell": user.get("shell"),
                                         "groups": user.get("groups")}))
            continue
        gained = aspects - _privileges(known[name])
        for aspect in sorted(gained):
            findings.append(Finding(f"{name}:{aspect}", f"User {name} gained "
                                    f"{_describe(user, {aspect})}",
                                    {"user": name, "uid": user.get("uid"),
                                     "shell": user.get("shell"),
                                     "groups": user.get("groups")}))
    return findings


# Network and services

def new_listening_port(before, after, threshold):
    old, new = _data(before, "network"), _data(after, "network")
    if old is None or new is None:
        return []

    def key(sock):
        return (sock.get("proto"), sock.get("address"), sock.get("port"))

    known = {key(s) for s in old.get("listening") or []}
    findings = []
    for sock in new.get("listening") or []:
        if key(sock) in known:
            continue
        proto, address, port = key(sock)
        processes = sorted({p.get("name") or str(p.get("pid"))
                            for p in sock.get("processes") or []})
        owner = f" ({', '.join(processes)})" if processes else ""
        findings.append(Finding(f"{proto}/{address}/{port}",
                                f"New listening socket {proto} {address} port {port}{owner}",
                                {"proto": proto, "address": address, "port": port,
                                 "processes": processes}))
    return findings


def service_failed(before, after, threshold):
    old, new = _data(before, "services"), _data(after, "services")
    if old is None or new is None:
        return []
    failed_before = set(old.get("failed") or [])
    return [Finding(name, f"Service {name} is failed", {"service": name})
            for name in sorted(set(new.get("failed") or []) - failed_before)]


# Permissions

def new_privileged_binary(before, after, threshold):
    old, new = _data(before, "permissions"), _data(after, "permissions")
    # A partial search before would make everything it missed look new.
    if old is None or new is None or not old.get("searched") or _has_gap(before,
                                                                          "permissions",
                                                                          "search"):
        return []
    findings = []
    for kind in ("suid", "sgid"):
        known = {e.get("path") for e in old.get(kind) or []}
        for entry in new.get(kind) or []:
            if entry.get("path") not in known:
                findings.append(Finding(
                    f"{kind}:{entry.get('path')}",
                    f"New {kind.upper()} binary {entry.get('path')} (mode {entry.get('mode')},"
                    f" uid {entry.get('uid')})",
                    {"kind": kind, "path": entry.get("path"), "mode": entry.get("mode"),
                     "uid": entry.get("uid"), "gid": entry.get("gid")}))
    return findings


SECRET_FILES = ("/etc/shadow", "/etc/gshadow")


def _too_open(entry, group_names):
    """Is an account file more open than its distribution's safe default?

    The core marks "too_open" against the 0400 of 2019, which flags the 0640 root:shadow
    that Debian and Ubuntu ship. The rule judges by what exposes the file: for shadow and
    gshadow, an owner other than root, any bit for others, write by the group, or read by
    a group other than root or "shadow"; for passwd and group, the core's 0644.
    """
    try:
        mode = int(entry.get("mode") or "", 8)
    except ValueError:
        return False
    if entry.get("path") not in SECRET_FILES:
        return bool(entry.get("too_open"))
    group = group_names.get(entry.get("gid"))
    group_read_ok = entry.get("gid") == 0 or group == "shadow"
    return bool(entry.get("uid") != 0 or mode & 0o007 or mode & 0o020
                or (mode & 0o040 and not group_read_ok))


def _group_names(snapshot):
    users = _data(snapshot, "users") or {}
    return {g.get("gid"): g.get("name") for g in users.get("groups") or []}


def account_file_permissions(before, after, threshold):
    new = _data(after, "permissions")
    if new is None:
        return []
    old = _data(before, "permissions") or {}
    names_before, names_after = _group_names(before), _group_names(after)
    open_before = {e.get("path") for e in old.get("account_files") or []
                   if _too_open(e, names_before)}
    return [Finding(e.get("path"), f"{e.get('path')} has mode {e.get('mode')} "
                                   f"(uid {e.get('uid')}, gid {e.get('gid')}), more open "
                                   f"than a safe default",
                    {"path": e.get("path"), "mode": e.get("mode"),
                     "recommended": e.get("recommended"), "uid": e.get("uid"),
                     "gid": e.get("gid"), "group": names_after.get(e.get("gid"))})
            for e in new.get("account_files") or []
            if _too_open(e, names_after) and e.get("path") not in open_before]


# System and storage

def kernel_changed(before, after, threshold):
    old, new = _data(before, "system"), _data(after, "system")
    if old is None or new is None:
        return []
    was, now = old.get("kernel") or {}, new.get("kernel") or {}
    if (was.get("release"), was.get("version")) == (now.get("release"), now.get("version")):
        return []
    return [Finding(f"{now.get('release')} {now.get('version')}",
                    f"Kernel changed from {was.get('release')} to {now.get('release')}",
                    {"before": {"release": was.get("release"), "version": was.get("version")},
                     "after": {"release": now.get("release"), "version": now.get("version")}})]


def _full(data, threshold):
    """{mountpoint: mount} of the mounts at or over THRESHOLD percent that can fill up."""
    full = {}
    for mount in (data or {}).get("mounts") or []:
        usage = mount.get("usage") or {}
        percent = usage.get("percent")
        if (percent is None or not usage.get("size") or mount.get("fstype") in NOT_FILLING
                or "ro" in (mount.get("options") or [])):
            continue
        if percent >= threshold:
            full.setdefault(mount.get("mountpoint"), mount)
    return full


def disk_full(before, after, threshold):
    new = _data(after, "storage")
    if new is None:
        return []
    already = _full(_data(before, "storage"), threshold)
    findings = []
    for mountpoint, mount in sorted(_full(new, threshold).items()):
        if mountpoint in already:
            continue
        usage = mount["usage"]
        findings.append(Finding(mountpoint, f"{mountpoint} is {usage['percent']} % full",
                                {"mountpoint": mountpoint, "source": mount.get("source"),
                                 "fstype": mount.get("fstype"), "percent": usage["percent"],
                                 "size": usage.get("size"),
                                 "available": usage.get("available"),
                                 "threshold": threshold}))
    return findings


# Visibility

def area_lost(before, after, threshold):
    if before is None:
        return []
    findings = []
    for area in AREAS:
        if area.volatile:
            continue
        old, new = _section(before, area.name) or {}, _section(after, area.name) or {}
        if old.get("status") == OK and new.get("status") not in (OK, "na"):
            findings.append(Finding(area.name, f"{area.title} could not be seen any more: "
                                               f"{new.get('status')}",
                                    {"area": area.name, "status": new.get("status"),
                                     "reason": new.get("reason")}))
    return findings


UNRESPONSIVE = "machine_unresponsive"

RULES = [
    Rule("privileged_user", "User with access or privileges", Severity.HIGH,
         "A new user with a login shell, uid 0 or in sudo/wheel/admin; or an existing user "
         "that gains one of those.", privileged_user),
    Rule("new_listening_port", "New listening port", Severity.MEDIUM,
         "A socket listening on a protocol, address and port that were not listening.",
         new_listening_port),
    Rule("service_failed", "Service failed", Severity.MEDIUM,
         "A service that is now in the failed state and was not.", service_failed),
    Rule("new_privileged_binary", "New SUID or SGID binary", Severity.HIGH,
         "A SUID or SGID file in the root file system that was not there.",
         new_privileged_binary),
    Rule("kernel_changed", "Kernel changed", Severity.LOW,
         "The running kernel (release or build) changed.", kernel_changed),
    Rule("disk_full", "Disk almost full", Severity.MEDIUM,
         "A mounted file system that can fill up reaches the threshold of use.", disk_full,
         threshold=90, threshold_label="percent of use"),
    Rule("account_file_permissions", "Account file permissions", Severity.HIGH,
         "/etc/passwd or /etc/group more open than 0644; /etc/shadow or /etc/gshadow not "
         "owned by root, open to others, writable by the group or readable by a group "
         "other than root or shadow.",
         account_file_permissions),
    Rule(UNRESPONSIVE, "Machine not responding", Severity.HIGH,
         "N failed collections in a row, or no snapshot for two periods of its schedule.",
         threshold=3, threshold_label="failed collections in a row"),
    Rule("area_lost", "Area could not be seen any more", Severity.LOW,
         "A non-volatile area that could be seen and now is denied, missing, timed out or "
         "failed.", area_lost),
]
BY_CODE = {rule.code: rule for rule in RULES}
CHOICES = [(rule.code, rule.title) for rule in RULES]
