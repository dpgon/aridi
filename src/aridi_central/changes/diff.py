"""Comparison of two snapshots, area by area (TODO.md 6.1).

Works on Snapshot.data (snapshot v1 of the core, docs/FORMATO.md). Each area lists its
collections with a stable key (a package by manager, name and architecture, a listening
socket by protocol, address and port, a user by name…) and the fields compared for each
element. An area that was "ok" and is not any more is reported as "could not be seen any
more", never as "everything disappeared". Volatile areas are compared only on request.
"""

from dataclasses import dataclass, field

from aridi.interpret import AREAS

OK = "ok"


@dataclass
class Collection:
    """A list (or mapping) inside an area's data whose elements are compared by key."""

    name: str
    path: str                  # dotted path inside the area's data
    key: tuple                 # fields of an element that identify it
    fields: tuple = ()         # fields compared between the two versions of an element
    mapping: bool = False      # the path holds {key: value} instead of a list


@dataclass
class Scalar:
    name: str
    path: str


def _get(data, path):
    for part in path.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _names(processes):
    return ",".join(sorted({p.get("name") or "?" for p in processes or []}))


def _addresses(addresses):
    return ",".join(sorted(f"{a.get('ip')}/{a.get('prefix')}" for a in addresses or []))


# Derived fields: element → comparable text.
DERIVED = {
    "processes": _names,
    "addresses": _addresses,
    "groups": lambda groups: ",".join(sorted(groups or [])),
    "members": lambda members: ",".join(sorted(members or [])),
    "names": lambda names: ",".join(names or []),
    "options": lambda options: ",".join(options or []),
}

# What is compared of each area. Fields left out change on their own (usage of a disk, the
# sub-state of a service, the time of a login) and would bury the real changes.
SPEC = {
    "system": [Scalar("distribution", "distribution.pretty_name"),
               Scalar("kernel release", "kernel.release"),
               Scalar("kernel version", "kernel.version"),
               Scalar("architecture", "kernel.machine"),
               Scalar("libc", "libc.version")],
    "hardware": [Scalar("CPU model", "cpu.model"), Scalar("logical CPUs", "cpu.logical"),
                 Scalar("memory", "memory.total"), Scalar("swap", "memory.swap_total"),
                 Collection("USB devices", "usb", ("idVendor", "idProduct", "device"),
                            ("manufacturer", "product"))],
    "packages": [Collection("packages", "packages", ("manager", "name", "arch"),
                            ("version",))],
    "storage": [Collection("devices", "devices", ("name",), ("kind", "size", "fstype")),
                Collection("mounts", "mounts", ("mountpoint",),
                           ("source", "fstype", "options")),
                Collection("swaps", "swaps", ("name",), ("type", "size"))],
    "permissions": [Collection("SUID binaries", "suid", ("path",), ("mode", "uid", "gid")),
                    Collection("SGID binaries", "sgid", ("path",), ("mode", "uid", "gid")),
                    Collection("world-writable files", "world_writable_files", ("path",),
                               ("mode",)),
                    Collection("world-writable directories without sticky bit",
                               "world_writable_dirs_no_sticky", ("path",), ("mode",)),
                    Collection("account files", "account_files", ("path",),
                               ("mode", "uid", "gid", "too_open"))],
    "identity": [Scalar("hostname", "hostname"), Scalar("DNS domain", "dns_domain"),
                 Scalar("NIS domain", "nis_domain"), Scalar("host id", "hostid"),
                 Collection("banners", "banners", ("path",), ("text",), mapping=True)],
    "users": [Collection("users", "users", ("name",),
                         ("uid", "gid", "home", "shell", "groups", "password", "algorithm")),
              Collection("groups", "groups", ("name",), ("gid", "members"))],
    "services": [Collection("services", "services", ("manager", "name"),
                            ("active", "enabled")),
                 Scalar("init", "init")],
    "network": [Collection("interfaces", "interfaces", ("name",),
                           ("mac", "mtu", "state", "addresses")),
                Collection("routes", "routes", ("family", "destination", "via", "dev")),
                Collection("name servers", "dns.nameservers", ()),
                Collection("hosts file", "hosts", ("ip",), ("names",)),
                Collection("listening sockets", "listening", ("proto", "address", "port"),
                           ("processes",))],
    "firewall": [Collection("engines", "engines", ()),
                 Collection("chains", "chains", ("family", "table", "name"), ("policy",)),
                 Collection("rules", "rules", ("engine", "family", "table", "chain",
                                               "direction", "action", "source",
                                               "destination", "protocol", "port"))],
    "timesync": [Collection("services", "services", ()),
                 Collection("configured servers", "configured",
                            ("service", "kind", "server"))],
    # Logins come and go between any two snapshots: only the sources are compared.
    "sessions": [Collection("sources", "sources", ())],
    "carving": [Collection("addresses in files", "addresses", ("ip",)),
                Collection("names in files", "names", ("name",))],
    # Volatile: compared only on request.
    "processes": [Collection("processes", "processes", ("user", "comm", "cmdline"))],
    "connections": [Collection("connections", "connections",
                               ("proto", "direction", "remote", "service"))],
    "neighbours": [Collection("neighbours", "neighbours", ("ip",), ("mac", "interface"))],
    "load": [],
}

# Users: without /etc/shadow the password state is unknown; it is not a change.
SHADOW_FIELDS = ("password", "algorithm")


@dataclass
class Change:
    collection: str
    key: str
    kind: str                  # added, removed, changed
    before: dict | None = None
    after: dict | None = None


@dataclass
class AreaDiff:
    area: str
    title: str
    volatile: bool
    before: str                # status of the area in each snapshot
    after: str
    state: str                 # same, changed, lost, regained, unavailable
    changes: list = field(default_factory=list)
    gaps_lost: list = field(default_factory=list)      # items that stopped being seen
    gaps_regained: list = field(default_factory=list)  # items seen again
    notes: list = field(default_factory=list)

    @property
    def interesting(self):
        return self.state != "same"


def _value(element, name):
    value = element.get(name) if isinstance(element, dict) else None
    if name in DERIVED and (value is None or isinstance(value, list)):
        return DERIVED[name](value)
    return value


def _elements(data, collection):
    """{key tuple: element} of COLLECTION in an area's DATA."""
    raw = _get(data, collection.path)
    if raw is None:
        return {}
    if collection.mapping and isinstance(raw, dict):
        raw = [dict(value, **{collection.key[0]: name}) for name, value in raw.items()]
    found = {}
    for element in raw if isinstance(raw, list) else []:
        if collection.key:
            key = tuple(_value(element, name) for name in collection.key)
        else:
            key = (element,)
        found.setdefault(key, element)
    return found


def _key_text(key):
    return " ".join(str(part) for part in key if part not in (None, ""))


def _compare_collection(collection, before, after, skip=()):
    old, new = _elements(before, collection), _elements(after, collection)
    fields = [name for name in collection.fields if name not in skip]
    changes = []
    for key in sorted(new.keys() - old.keys(), key=repr):
        changes.append(Change(collection.name, _key_text(key), "added",
                              after={f: _value(new[key], f) for f in fields}))
    for key in sorted(old.keys() - new.keys(), key=repr):
        changes.append(Change(collection.name, _key_text(key), "removed",
                              before={f: _value(old[key], f) for f in fields}))
    for key in sorted(old.keys() & new.keys(), key=repr):
        was = {f: _value(old[key], f) for f in fields}
        now = {f: _value(new[key], f) for f in fields}
        if was != now:
            differs = [f for f in fields if was[f] != now[f]]
            changes.append(Change(collection.name, _key_text(key), "changed",
                                  before={f: was[f] for f in differs},
                                  after={f: now[f] for f in differs}))
    return changes


def _section(snapshot, name):
    return ((snapshot or {}).get("sections") or {}).get(name) or {
        "status": "not_collected", "data": None, "gaps": []}


def _gap_items(section):
    return {f"{g.get('item')} ({g.get('status')})" for g in section.get("gaps") or []
            if g.get("status") not in ("ok", "na")}


def compare_area(area, before, after):
    """AreaDiff of AREA (an aridi.interpret.Area) between two snapshot dicts."""
    old, new = _section(before, area.name), _section(after, area.name)
    diff = AreaDiff(area.name, area.title, area.volatile, old["status"], new["status"],
                    "same")
    if old["status"] == OK and new["status"] != OK:
        diff.state = "lost"
        return diff
    if old["status"] != OK and new["status"] == OK:
        diff.state = "regained"
        return diff
    if old["status"] != OK:
        diff.state = "unavailable" if old["status"] == new["status"] else "changed"
        return diff

    old_gaps, new_gaps = _gap_items(old), _gap_items(new)
    diff.gaps_lost = sorted(new_gaps - old_gaps)
    diff.gaps_regained = sorted(old_gaps - new_gaps)
    skip = ()
    if area.name == "users":
        was, now = _get(old["data"], "shadow_read"), _get(new["data"], "shadow_read")
        if not (was and now):
            skip = SHADOW_FIELDS
            if was != now:
                diff.notes.append("password states not compared: /etc/shadow was read in "
                                  "only one of the two snapshots")
    for part in SPEC.get(area.name, []):
        if isinstance(part, Scalar):
            was, now = _get(old["data"], part.path), _get(new["data"], part.path)
            if was != now:
                diff.changes.append(Change(part.name, part.name, "changed",
                                           before={"value": was}, after={"value": now}))
        else:
            diff.changes += _compare_collection(part, old["data"], new["data"], skip)
    if diff.changes or diff.gaps_lost or diff.gaps_regained:
        diff.state = "changed"
    return diff


def compare(before, after, volatile=False):
    """[AreaDiff] of every area, in report order. BEFORE may be None (first snapshot)."""
    return [compare_area(area, before, after) for area in AREAS
            if volatile or not area.volatile]
