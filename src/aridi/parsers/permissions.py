"""Area "permissions": dangerous permissions on the local root filesystem (TODO.md 3.5).

Replaces the aridi.badfiles file of 2019: everything goes into the snapshot, no file is
written. The search uses "find -xdev", so other mounted filesystems are not walked.
"""

import stat

from aridi.interpret import AreaResult, register
from aridi.model import Status
from aridi.parsers._common import gap

# Recommended maximum permission bits of the account files (dangerousperm() of 2019).
ACCOUNT_FILES = {"/etc/passwd": 0o644, "/etc/group": 0o644, "/etc/shadow": 0o400,
                 "/etc/gshadow": 0o400}


def parse_entries(content):
    """[(mode, uid, gid, path)] from lines "HEXMODE UID GID PATH"."""
    entries = []
    for line in content.splitlines():
        fields = line.split(" ", 3)
        if len(fields) != 4 or not fields[1].isdigit() or not fields[2].isdigit():
            continue
        try:
            mode = int(fields[0], 16)
        except ValueError:
            continue
        entries.append((mode, int(fields[1]), int(fields[2]), fields[3]))
    return entries


def _entry(mode, uid, gid, path):
    return {"path": path, "mode": f"{stat.S_IMODE(mode):04o}", "uid": uid, "gid": gid}


def classify(entries):
    result = {"suid": [], "sgid": [], "world_writable_files": [],
              "world_writable_dirs_no_sticky": [], "world_writable_dirs_sticky": 0}
    for mode, uid, gid, path in entries:
        item = _entry(mode, uid, gid, path)
        if stat.S_ISREG(mode):
            if mode & stat.S_ISUID:
                result["suid"].append(dict(item, root_owned=uid == 0))
            if mode & stat.S_ISGID:
                result["sgid"].append(dict(item, root_owned=gid == 0))
            if mode & stat.S_IWOTH:
                result["world_writable_files"].append(item)
        elif stat.S_ISDIR(mode) and mode & stat.S_IWOTH:
            if mode & stat.S_ISVTX:
                result["world_writable_dirs_sticky"] += 1
            else:
                result["world_writable_dirs_no_sticky"].append(item)
    return result


def account_files(content):
    files = []
    for mode, uid, gid, path in parse_entries(content):
        if path not in ACCOUNT_FILES:
            continue
        allowed = ACCOUNT_FILES[path]
        extra = stat.S_IMODE(mode) & ~allowed
        files.append(dict(_entry(mode, uid, gid, path), recommended=f"{allowed:04o}",
                          too_open=bool(extra)))
    return files


@register("permissions")
def parse(sections):
    gaps = []
    status, reason = Status.OK, None
    found = sections.get("permissions.find")
    partial = found is not None and found.status != "ok" and bool(found.content)
    data = classify(parse_entries(found.text()) if found is not None else [])
    data["searched"] = found is not None and (found.status == "ok" or partial)
    if found is None or found.status != "ok":
        cause = gap(sections, "search", ["permissions.find"], "no find output")
        if partial:
            # The search stopped early (timeout, permissions): keep what it found.
            status, reason = cause.status, f"partial result: {cause.reason}"
        else:
            gaps.append(cause)
    elif found.truncated:
        status, reason = Status.ERROR, f"partial result: output cut at {found.limit} bytes"

    accounts = sections.get("permissions.account_files")
    data["account_files"] = None
    if accounts is not None and accounts.status == "ok":
        data["account_files"] = account_files(accounts.text())
    else:
        gaps.append(gap(sections, "account files", ["permissions.account_files"],
                        "no stat of the account files"))
    return AreaResult(data, status=status, reason=reason, gaps=gaps)
