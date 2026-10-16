"""Area "connections" (volatile): established TCP and connected UDP sockets, v4 and v6,
with their process (TODO.md 3.15). Reuses the /proc/net sections of "network".

A connection whose local port is a listening port is incoming (peer_in), any other is
outgoing (peer_out). Loopback and local peers are not relations.
"""

import ipaddress

from aridi import ports
from aridi.interpret import AreaResult, register
from aridi.model import Relation, Role
from aridi.parsers._common import gap, text, user_names
from aridi.parsers.network import SOCKET_TABLES, socket_owners, ip_from_proc

TCP_STATES = {"01": "established", "02": "syn_sent", "03": "syn_recv", "04": "fin_wait1",
              "05": "fin_wait2", "06": "time_wait", "07": "close", "08": "close_wait",
              "09": "last_ack", "0A": "listen", "0B": "closing"}


def parse_table(content, proto):
    """(connections, listening ports) of one /proc/net table."""
    connections, listening = [], set()
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local_hex, _, local_port = fields[1].partition(":")
        remote_hex, _, remote_port = fields[2].partition(":")
        state = fields[3]
        local, remote = ip_from_proc(local_hex), ip_from_proc(remote_hex)
        if proto.startswith("tcp") and state == "0A":
            listening.add(int(local_port, 16))
            continue
        if int(remote) == 0 and int(remote_port, 16) == 0:
            if not proto.startswith("tcp"):
                listening.add(int(local_port, 16))
            continue
        if proto.startswith("tcp") and state not in ("01", "02", "03", "08"):
            continue          # closing states: no longer a relation worth recording
        connections.append({
            "proto": proto, "local": str(local), "local_port": int(local_port, 16),
            "remote": str(remote), "remote_port": int(remote_port, 16),
            "state": TCP_STATES.get(state, state) if proto.startswith("tcp") else "connected",
            "uid": int(fields[7]), "inode": int(fields[9]),
        })
    return connections, listening


@register("connections", uses=("network", "users"), needs_own=False)
def parse(sections):
    gaps, connections, listening = [], [], set()
    for proto, name in SOCKET_TABLES:
        if proto.startswith("raw"):
            continue
        content = text(sections, name)
        if content is None:
            raw = sections.get(name)
            if raw is None or raw.status != "na":
                gaps.append(gap(sections, f"sockets {proto}", [name], f"no {name}"))
            continue
        found, ports_listening = parse_table(content, proto)
        connections += found
        listening |= ports_listening

    owners = socket_owners(sections)
    names = user_names(sections)
    relations = []
    for conn in connections:
        conn["processes"] = owners.get(conn["inode"], [])
        conn["user"] = names.get(conn["uid"], str(conn["uid"]))
        incoming = conn["local_port"] in listening
        conn["direction"] = "in" if incoming else "out"
        service_port = conn["local_port"] if incoming else conn["remote_port"]
        conn["service"] = ports.name(service_port, conn["proto"])
        remote = ipaddress.ip_address(conn["remote"])
        if remote.is_loopback or conn["remote"] == conn["local"]:
            continue
        mapped = getattr(remote, "ipv4_mapped", None)
        relations.append(Relation(mapped or remote, Role.PEER_IN if incoming else Role.PEER_OUT,
                                  "connections",
                                  f"{conn['proto']} port {service_port}"
                                  + (f" ({conn['service']})" if conn["service"] else "")))
    connections.sort(key=lambda c: (c["proto"], c["remote"], c["remote_port"]))
    return AreaResult({"connections": connections}, relations=relations, gaps=gaps)
