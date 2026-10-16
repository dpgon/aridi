"""Area "neighbours" (volatile): the ARP and NDP tables of the kernel, read passively
(TODO.md 3.17). Nothing here generates network traffic.
"""

import ipaddress

from aridi.interpret import AreaResult, register
from aridi.model import Relation, Role
from aridi.parsers._common import gap, text

ARP_COMPLETE = 0x2


def parse_proc_arp(content):
    neighbours = []
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        flags = int(fields[2], 16)
        neighbours.append({"ip": str(ipaddress.ip_address(fields[0])), "mac": fields[3],
                           "interface": fields[5],
                           "state": "complete" if flags & ARP_COMPLETE else "incomplete"})
    return neighbours


def parse_ip_neigh(content):
    neighbours = []
    for line in content.splitlines():
        fields = line.split()
        if not fields:
            continue
        try:
            address = ipaddress.ip_address(fields[0].split("%")[0])
        except ValueError:
            continue
        item = {"ip": str(address), "mac": None, "interface": None,
                "state": fields[-1].lower() if fields[-1].isupper() else None}
        if "dev" in fields[:-1]:
            item["interface"] = fields[fields.index("dev") + 1]
        if "lladdr" in fields[:-1]:
            item["mac"] = fields[fields.index("lladdr") + 1]
        item["router"] = "router" in fields
        neighbours.append(item)
    return neighbours


@register("neighbours")
def parse(sections):
    gaps = []
    ip_neigh = text(sections, "neighbours.ip_neigh")
    if ip_neigh is not None:
        neighbours, source = parse_ip_neigh(ip_neigh), "ip neigh"
    else:
        arp = text(sections, "neighbours.proc_arp")
        if arp is None:
            cause = gap(sections, "neighbours", ["neighbours.ip_neigh", "neighbours.proc_arp"],
                        "neither ip nor /proc/net/arp")
            return AreaResult(None, status=cause.status, reason=cause.reason)
        neighbours, source = parse_proc_arp(arp), "/proc/net/arp (IPv4 only)"
    relations = [Relation(item["ip"], Role.NEIGHBOUR, "neighbours", item.get("interface") or "")
                 for item in neighbours
                 if item.get("mac") and item.get("state") not in ("failed", "incomplete")]
    return AreaResult({"source": source, "neighbours": neighbours}, relations=relations,
                      gaps=gaps)
