"""Area "carving": IP addresses and host names found in /etc, /var/log and the journal
(TODO.md 3.16).

The collector sends only the address, the file, the line number and the context marks
(never the text of the line). The filters of legacy/gathering4.py:36-55 are applied here:
commented lines, "version" before the address, an address glued to other digits or dots,
network prefixes, 169.254/16, multicast and reserved ranges, 0.x and .0 addresses. IPv6
gets the equivalent ones. Names are kept unresolved.
"""

import ipaddress

from aridi.interpret import AreaResult, register
from aridi.model import Relation, Role
from aridi.parsers._common import gap, text

SOURCES = (("carving.etc_ips", "etc"), ("carving.log_ips", "log"))
# Last labels that are file extensions, not top-level domains.
NOT_TLD = frozenset({
    "conf", "cfg", "cnf", "d", "so", "sh", "pl", "py", "pyc", "pem", "crt", "key", "csr",
    "list", "service", "target", "socket", "timer", "mount", "rules", "txt", "log", "gz",
    "xz", "bz", "xml", "json", "yaml", "yml", "ini", "lock", "pid", "sock", "img", "ko",
    "dpkg", "rpm", "deb", "html", "htm", "js", "css", "png", "jpg", "svg", "md", "mo", "lua",
    "rb", "php", "conffile", "bak", "old", "new", "orig", "dist", "sample", "example",
    "default", "repo", "keyring", "gpg", "asc", "pub", "db", "dat", "cache", "local",
})
# First labels of reversed names (org.freedesktop.systemd1): not host names.
REVERSED = frozenset({"org", "com", "net", "io", "de", "fr", "uk", "eu", "edu", "gov"})


def exclusion(address, prefix, before, after, flags):
    """Why ADDRESS is not a real mention (legacy filters), or None if it is."""
    if "c" in flags:
        return "commented line"
    if "v" in flags:
        return "version number"
    glued = {"d", "p"} if address.version == 4 else {"d", "l", "k", "p"}
    if before in glued or after in glued:
        return "part of a longer token"
    full = 32 if address.version == 4 else 128
    if prefix and prefix != str(full):
        return "network prefix"
    if address.version == 4:
        first, last = int(str(address).split(".")[0]), int(str(address).split(".")[3])
        if address.is_link_local:
            return "link-local"
        if first == 0 or first > 223:
            return "reserved or multicast"
        if last == 0:
            return "network address"
    elif address.is_multicast or address.is_unspecified or address.is_link_local \
            or (address.is_reserved and not address.is_loopback):
        return "reserved, multicast or link-local"
    return None


def parse_entries(content):
    """[(path, line, address, prefix, before, after, flags)] of a carving section."""
    entries = []
    for row in content.splitlines():
        fields = row.split("|")
        if len(fields) != 7:
            continue
        try:
            address = ipaddress.ip_address(fields[2])
        except ValueError:
            continue
        entries.append((fields[0], fields[1], address, fields[3], fields[4], fields[5],
                        fields[6]))
    return entries


def parse_journal(content):
    """[(count, address, prefix, before, after, flags)] of carving.journal_ips."""
    entries = []
    for row in content.splitlines():
        count, _, rest = row.strip().partition(" ")
        fields = rest.split("|")
        if not count.isdigit() or len(fields) != 5:
            continue
        try:
            address = ipaddress.ip_address(fields[0])
        except ValueError:
            continue
        entries.append((int(count), address, *fields[1:]))
    return entries


def is_host_name(name):
    labels = name.split(".")
    tld = labels[-1]
    return (len(labels) >= 3 and tld.isalpha() and 2 <= len(tld) <= 24
            and tld not in NOT_TLD and labels[0] not in REVERSED)


@register("carving")
def parse(sections):
    gaps, found, excluded = [], {}, {}
    counts = {}
    for name, label in SOURCES:
        content = text(sections, name)
        if content is None:
            gaps.append(gap(sections, f"{label} addresses", [name], f"no {name}"))
            continue
        accepted = set()
        for path, line, address, prefix, before, after, flags in parse_entries(content):
            why = exclusion(address, prefix, before, after, flags)
            if why:
                excluded[why] = excluded.get(why, 0) + 1
                continue
            item = found.setdefault(str(address), {"ip": str(address), "mentions": []})
            mention = {"source": label, "path": path, "line": int(line) if line.isdigit()
                       else None}
            if mention not in item["mentions"]:
                item["mentions"].append(mention)
            accepted.add(str(address))
        counts[label] = len(accepted)
        raw = sections.get(name)
        if raw is not None and raw.truncated:
            gaps.append(gap(sections, f"{label} addresses", [name], "output cut at the limit"))

    journal = text(sections, "carving.journal_ips")
    if journal is not None:
        accepted = set()
        for count, address, prefix, before, after, flags in parse_journal(journal):
            if exclusion(address, prefix, before, after, flags):
                continue
            item = found.setdefault(str(address), {"ip": str(address), "mentions": []})
            item["mentions"].append({"source": "journal", "path": None, "line": None,
                                     "count": count})
            accepted.add(str(address))
        counts["journal"] = len(accepted)

    names = {}
    for row in (text(sections, "carving.etc_names") or "").splitlines():
        path, _, name = row.partition("|")
        if name and is_host_name(name):
            names.setdefault(name, []).append(path)

    relations = []
    ordered = sorted(found.values(), key=lambda i: (ipaddress.ip_address(i["ip"]).version,
                                                    ipaddress.ip_address(i["ip"])))
    for item in ordered:
        first = item["mentions"][0]
        where = (f"{first['path']}:{first['line']}" if first["path"]
                 else f"journal ({first.get('count')} times)")
        extra = len(item["mentions"]) - 1
        relations.append(Relation(item["ip"], Role.NAMED_IN_FILE, "carving",
                                  where + (f" and {extra} more" if extra else "")))
    data = {"addresses": ordered, "counts": counts, "excluded": excluded,
            "names": [{"name": name, "files": sorted(set(paths))}
                      for name, paths in sorted(names.items())]}
    return AreaResult(data, relations=relations, gaps=gaps)
