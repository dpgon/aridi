"""Area "storage": block devices, mounts, usage and swap (TODO.md 3.4).

Sizes are bytes. Mounts come from /proc/self/mountinfo, so a device mounted several
times, bind mounts and btrfs subvolumes are all kept; in 2019 a current lsblk broke the
whole area (docs/MVP.md n.º 13).
"""

import math
import re

from aridi.interpret import AreaResult, register
from aridi.model import Gap, Status
from aridi.parsers._common import gap, text

SECTOR = 512

# Filesystems that hold no data of their own; the summary leaves them out.
PSEUDO_FS = frozenset({
    "autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts",
    "devtmpfs", "efivarfs", "fusectl", "hugetlbfs", "mqueue", "nsfs", "proc", "pstore",
    "rpc_pipefs", "securityfs", "selinuxfs", "sysfs", "tracefs",
})

_OCTAL = re.compile(r"\\([0-7]{3})")
_LSBLK_PAIR = re.compile(r'([A-Z:-]+)="((?:[^"\\]|\\.)*)"')


def unescape(value):
    """Undo the octal escapes of mountinfo (\\040 is a space)."""
    return _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), value)


def parse_mountinfo(content):
    """List of mounts from /proc/self/mountinfo (proc(5) format)."""
    mounts = []
    for line in content.splitlines():
        left, sep, right = line.partition(" - ")
        fields = left.split()
        if not sep or len(fields) < 6:
            continue
        right_fields = right.split()
        if len(right_fields) < 2:
            continue
        fstype, source = right_fields[0], unescape(right_fields[1])
        super_options = right_fields[2] if len(right_fields) > 2 else ""
        mounts.append({
            "mount_id": int(fields[0]), "parent_id": int(fields[1]), "dev": fields[2],
            "root": unescape(fields[3]), "mountpoint": unescape(fields[4]),
            "options": fields[5].split(","), "fstype": fstype, "source": source,
            "super_options": super_options.split(",") if super_options else [],
        })
    seen = set()
    for mount in mounts:
        subvol = next((o.partition("=")[2] for o in mount["super_options"]
                       if o.startswith("subvol=")), None)
        mount["subvolume"] = subvol if mount["fstype"] == "btrfs" else None
        key = (mount["dev"], mount["root"])
        # A bind mount shows a directory of a filesystem (root is not "/"), or the same
        # directory of the same device already mounted elsewhere.
        mount["bind"] = (mount["fstype"] != "btrfs" and mount["root"] != "/") or key in seen
        seen.add(key)
    return mounts


def parse_df(content):
    """{mountpoint: usage} from "df -P -k" (POSIX format)."""
    usage = {}
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6 or not fields[1].isdigit():
            continue
        total, used, available = (int(fields[i]) * 1024 for i in (1, 2, 3))
        mountpoint = " ".join(fields[5:])
        # Same rule as df: used / (used + available), rounded up.
        percent = math.ceil(used * 100 / (used + available)) if used + available else 0
        usage[mountpoint] = {"filesystem": fields[0], "size": total, "used": used,
                             "available": available, "percent": percent}
    return usage


def parse_block(content):
    devices = []
    for line in content.splitlines():
        name, *fields = line.split()
        values = dict(field.partition("=")[::2] for field in fields)
        if not values.get("size", "").isdigit():
            continue
        kind = values.get("kind", "disk")
        if kind == "disk":
            for prefix, other in (("loop", "loop"), ("nbd", "nbd"), ("ram", "ram"),
                                  ("zram", "zram"), ("dm-", "dm"), ("md", "raid"),
                                  ("sr", "rom")):
                if name.startswith(prefix):
                    kind = other
                    break
        devices.append({
            "name": name, "kind": kind, "size": int(values["size"]) * SECTOR,
            "removable": values.get("removable") == "1", "read_only": values.get("ro") == "1",
            "dev": values.get("dev") or None, "dm_name": values.get("dm") or None,
            "holders": [h for h in values.get("holders", "").split(",") if h],
            "slaves": [s for s in values.get("slaves", "").split(",") if s],
        })
    return devices


def parse_partitions(content):
    """Block devices from /proc/partitions when /sys is not available."""
    devices = []
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) == 4 and fields[2].isdigit():
            devices.append({"name": fields[3], "kind": "unknown", "size": int(fields[2]) * 1024,
                            "removable": None, "read_only": None,
                            "dev": f"{fields[0]}:{fields[1]}", "dm_name": None,
                            "holders": [], "slaves": []})
    return devices


def parse_lsblk(content):
    rows = []
    for line in content.splitlines():
        row = {key.lower(): value.replace('\\"', '"') for key, value in
               _LSBLK_PAIR.findall(line)}
        if row.get("name"):
            rows.append(row)
    return rows


def parse_swaps(content):
    swaps = []
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[2].isdigit():
            swaps.append({"device": unescape(fields[0]), "type": fields[1],
                          "size": int(fields[2]) * 1024,
                          "used": int(fields[3]) * 1024 if fields[3].isdigit() else None})
    return swaps


@register("storage")
def parse(sections):
    gaps = []
    mountinfo = text(sections, "storage.mountinfo")
    mounts = parse_mountinfo(mountinfo) if mountinfo else []
    if not mountinfo:
        gaps.append(gap(sections, "mounts", ["storage.mountinfo"], "no /proc/self/mountinfo"))

    df = text(sections, "storage.df")
    usage = parse_df(df) if df else {}
    if df is None:
        gaps.append(gap(sections, "usage", ["storage.df"], "no df output"))
    for mount in mounts:
        mount["usage"] = usage.get(mount["mountpoint"])

    block = text(sections, "storage.block")
    if block is not None:
        devices = parse_block(block)
    else:
        partitions = text(sections, "storage.partitions")
        devices = parse_partitions(partitions) if partitions else []
        if not partitions:
            gaps.append(gap(sections, "block devices", ["storage.block", "storage.partitions"],
                            "neither /sys/class/block nor /proc/partitions"))

    lsblk_raw = sections.get("storage.lsblk")
    lsblk = parse_lsblk(lsblk_raw.text()) if lsblk_raw and lsblk_raw.status == "ok" else None
    if lsblk_raw is not None and lsblk_raw.status not in ("ok", "missing", "na"):
        gaps.append(Gap("lsblk", Status(lsblk_raw.status), lsblk_raw.note or "lsblk failed"))
    if lsblk:
        fstypes = {row.get("kname") or row["name"]: row.get("fstype") for row in lsblk}
        for device in devices:
            device["fstype"] = fstypes.get(device["name"]) or None

    swaps_text = text(sections, "storage.swaps")
    swaps = parse_swaps(swaps_text) if swaps_text is not None else None
    if swaps_text is None:
        gaps.append(gap(sections, "swap", ["storage.swaps"], "no /proc/swaps"))

    return AreaResult({"devices": devices, "mounts": mounts, "swaps": swaps,
                       "lsblk": lsblk}, gaps=gaps)
