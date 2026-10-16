"""Relation map of a snapshot for the web (TODO.md 6.5), replacing the --graph of 2019.

The diagram is SVG drawn by the template from the shapes computed here: no JavaScript and
no third-party library. Three columns: the machine with its addresses, its local
subnets with the addresses seen inside them (the gateway marked), and the addresses
beyond the gateway. Text from the machine is escaped by the template like everything else.
"""

import ipaddress
from dataclasses import dataclass, field

from aridi.model import Role
from aridi.model import Snapshot as CoreSnapshot
from aridi.relations import consolidate

ROW = 18           # height of a line of text
COLUMNS = (16, 300, 690)
WIDTHS = (240, 340, 340)
MAX_DRAWN = 200    # addresses drawn; the table below lists them all, paged


@dataclass
class Subnet:
    network: object
    gateways: set = field(default_factory=set)
    nodes: list = field(default_factory=list)


@dataclass
class RelationMap:
    hostname: str
    local: list            # Node of the machine's own addresses
    subnets: list          # Subnet
    outside: list          # Node beyond every local subnet
    total: int             # remote addresses
    drawn: int
    width: int = 0
    height: int = 0
    shapes: dict = field(default_factory=lambda: {"rects": [], "lines": [], "texts": []})


def roles_text(node):
    return ", ".join(sorted({role.value for role, _, _ in node.roles
                             if role != Role.LOCAL}))


def _subnets(network_data):
    """Local subnets (not loopback) and the gateways of the routes, from area network."""
    subnets = {}
    for interface in (network_data or {}).get("interfaces") or []:
        for address in interface.get("addresses") or []:
            try:
                net = ipaddress.ip_interface(f"{address['ip']}/{address['prefix']}").network
            except (KeyError, TypeError, ValueError):
                continue
            if net.is_loopback:
                continue
            subnets.setdefault(net, Subnet(net))
    for route in (network_data or {}).get("routes") or []:
        try:
            via = ipaddress.ip_address(route.get("via") or "")
        except ValueError:
            continue
        for subnet in subnets.values():
            if via.version == subnet.network.version and via in subnet.network:
                subnet.gateways.add(via)
    return sorted(subnets.values(), key=lambda s: (s.network.version, s.network))


def build(snapshot_data, hostname, limit=MAX_DRAWN):
    """RelationMap of a snapshot (Snapshot.data), drawing at most LIMIT remote addresses."""
    core = CoreSnapshot.from_dict(snapshot_data)
    nodes = consolidate(core.relations)
    network = core.sections.get("network")
    subnets = _subnets(network.data if network is not None and isinstance(network.data, dict)
                       else None)
    local = [n for n in nodes if n.local]
    remote = [n for n in nodes if not n.local]
    outside = []
    for node in remote:
        for subnet in subnets:
            if node.ip.version == subnet.network.version and node.ip in subnet.network:
                subnet.nodes.append(node)
                break
        else:
            outside.append(node)
    result = RelationMap(hostname or "(no hostname)", local, subnets, outside, len(remote),
                         min(len(remote), limit))
    _layout(result, limit)
    return result


def _layout(result, limit):
    rects, lines, texts = (result.shapes[k] for k in ("rects", "lines", "texts"))
    budget = limit

    # Column 1: the machine.
    x, width = COLUMNS[0], WIDTHS[0]
    texts.append({"x": x + 10, "y": 40, "text": result.hostname, "cls": "title"})
    y = 40 + ROW
    for node in result.local:
        texts.append({"x": x + 10, "y": y, "text": str(node.ip), "cls": ""})
        y += ROW
    machine_box = {"x": x, "y": 16, "w": width, "h": y - 16, "cls": "machine"}
    rects.append(machine_box)
    anchor = (x + width, 16 + (y - 16) / 2)
    bottom = y

    # Column 2: local subnets with what was seen inside.
    x, width = COLUMNS[1], WIDTHS[1]
    y = 16
    gateway_points = []
    for subnet in result.subnets:
        top = y
        texts.append({"x": x + 10, "y": y + 24, "text": str(subnet.network), "cls": "title"})
        y += 24 + ROW
        for gateway in sorted(subnet.gateways):
            texts.append({"x": x + 10, "y": y, "text": f"gateway {gateway}", "cls": "gateway"})
            gateway_points.append((x + width, y - 5))
            y += ROW
        shown = subnet.nodes[:max(budget, 0)]
        budget -= len(shown)
        for node in shown:
            texts.append({"x": x + 10, "y": y, "text": f"{node.ip}  {roles_text(node)}",
                          "cls": ""})
            y += ROW
        if len(shown) < len(subnet.nodes):
            texts.append({"x": x + 10, "y": y, "cls": "muted",
                          "text": f"… {len(subnet.nodes) - len(shown)} more in the table"})
            y += ROW
        rects.append({"x": x, "y": top, "w": width, "h": y - top, "cls": "subnet"})
        lines.append({"x1": anchor[0], "y1": anchor[1], "x2": x, "y2": top + 18})
        y += 12
    bottom = max(bottom, y)

    # Column 3: beyond the local subnets.
    x, width = COLUMNS[2], WIDTHS[2]
    if result.outside:
        top = 16
        y = top + 24
        texts.append({"x": x + 10, "y": y, "text": "Beyond the local subnets",
                      "cls": "title"})
        y += ROW
        shown = result.outside[:max(budget, 0)]
        for node in shown:
            texts.append({"x": x + 10, "y": y, "text": f"{node.ip}  {roles_text(node)}",
                          "cls": ""})
            y += ROW
        if len(shown) < len(result.outside):
            texts.append({"x": x + 10, "y": y, "cls": "muted",
                          "text": f"… {len(result.outside) - len(shown)} more in the table"})
            y += ROW
        rects.append({"x": x, "y": top, "w": width, "h": y - top, "cls": "outside"})
        for point in gateway_points or [anchor]:
            lines.append({"x1": point[0], "y1": point[1], "x2": x, "y2": top + 18})
        bottom = max(bottom, y)

    result.width = COLUMNS[2] + WIDTHS[2] + 16
    result.height = int(bottom + 16)
