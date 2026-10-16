"""Relation map of a snapshot: every IP with all its roles, from every area (TODO.md 3.18).

Equivalent to the infrastructure view of 2019 (-oi), with IPv4 and IPv6 sorted
together (mixing them, or a null key, broke -oi in 2019).
"""

from dataclasses import dataclass, field

from aridi.model import Role


@dataclass
class Node:
    ip: object
    local: bool
    roles: list = field(default_factory=list)     # (role, source, detail)


def consolidate(relations):
    """Nodes sorted by version and address; local machine first."""
    nodes = {}
    for relation in relations:
        node = nodes.setdefault(relation.ip, Node(relation.ip, False))
        entry = (relation.role, relation.source, relation.detail)
        if entry not in node.roles:
            node.roles.append(entry)
        if relation.role == Role.LOCAL:
            node.local = True
    return sorted(nodes.values(), key=lambda n: (not n.local, n.ip.version, n.ip))
