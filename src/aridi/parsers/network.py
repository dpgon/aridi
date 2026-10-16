"""Area "network": interfaces, addresses, routes, name resolution and listening sockets
(TODO.md 3.9).

Interface names like "eth0@if5" are normalized ("eth0", peer "if5"): in 2019 they broke
the whole area (docs/MVP.md n.º 15). A UDP socket "listens" when it is unconnected (state
07, no remote address), not in state LISTEN (n.º 16).
"""

import ipaddress
import re
import struct

from aridi.interpret import AreaResult, register
from aridi.model import Relation, Role
from aridi.parsers._common import gap, text

TCP_LISTEN = "0A"
UNCONNECTED = "07"
SOCKET_TABLES = (("tcp", "network.proc_tcp"), ("tcp6", "network.proc_tcp6"),
                 ("udp", "network.proc_udp"), ("udp6", "network.proc_udp6"),
                 ("raw", "network.proc_raw"), ("raw6", "network.proc_raw6"))
RESOLVED_STUB = ipaddress.ip_address("127.0.0.53")
RTF_REJECT = 0x0200

_MTU = re.compile(r"\bmtu (\d+)")
_STATE = re.compile(r"\bstate (\S+)")
_LINK = re.compile(r"link/(\S+)(?: (\S+))?")


def split_name(name):
    """("eth0", "if5") from "eth0@if5"; ("lo", None) from "lo"."""
    name = name.rstrip(":")
    base, _, peer = name.partition("@")
    return base, (peer or None)


def ip_from_proc(hex_address):
    """IP address of a /proc/net/{tcp,udp,raw}[6] field (host byte order words)."""
    if len(hex_address) == 8:
        return ipaddress.IPv4Address(struct.pack("<I", int(hex_address, 16)))
    if len(hex_address) == 32:
        words = (struct.pack("<I", int(hex_address[i:i + 8], 16)) for i in range(0, 32, 8))
        return ipaddress.IPv6Address(b"".join(words))
    raise ValueError(f"invalid address {hex_address!r}")


def parse_ip_link(content):
    interfaces = {}
    for line in content.splitlines():
        fields = line.split()
        if len(fields) < 3 or not fields[0].rstrip(":").isdigit():
            continue
        name, peer = split_name(fields[1])
        flags = fields[2].strip("<>").split(",") if fields[2].startswith("<") else []
        mtu, state, link = _MTU.search(line), _STATE.search(line), _LINK.search(line)
        interfaces[name] = {
            "name": name, "index": int(fields[0].rstrip(":")), "peer": peer,
            "flags": flags, "mtu": int(mtu.group(1)) if mtu else None,
            "state": state.group(1).lower() if state else None,
            "link_type": link.group(1) if link else None,
            "mac": link.group(2) if link and link.group(2) and ":" in link.group(2) else None,
            "addresses": [],
        }
    return interfaces


def parse_sys_class_net(content):
    interfaces = {}
    for line in content.splitlines():
        name, *fields = line.split()
        values = dict(field.partition("=")[::2] for field in fields)
        interfaces[name] = {
            "name": name, "index": int(values["ifindex"]) if values.get("ifindex", "").isdigit()
            else None, "peer": None, "flags": [],
            "mtu": int(values["mtu"]) if values.get("mtu", "").isdigit() else None,
            "state": values.get("operstate") or None, "link_type": None,
            "mac": values.get("address") or None, "addresses": [],
        }
    return interfaces


def parse_ip_addr(content):
    """[(interface, address, prefix, scope)] from "ip -o addr"."""
    found = []
    for line in content.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[2] not in ("inet", "inet6"):
            continue
        address, _, prefix = fields[3].partition("/")
        scope = fields[fields.index("scope") + 1] if "scope" in fields[:-1] else None
        found.append((split_name(fields[1])[0], ipaddress.ip_address(address),
                      int(prefix) if prefix.isdigit() else None, scope))
    return found


def parse_if_inet6(content):
    found = []
    for line in content.splitlines():
        fields = line.split()
        if len(fields) == 6 and len(fields[0]) == 32:
            found.append((fields[5], ipaddress.IPv6Address(bytes.fromhex(fields[0])),
                          int(fields[2], 16), None))
    return found


def parse_fib_trie_local(content):
    """IPv4 addresses of the machine from the "Local" table of /proc/net/fib_trie."""
    addresses, last = set(), None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("|--"):
            last = stripped[3:].strip()
        elif stripped == "/32 host LOCAL" and last:
            addresses.add(ipaddress.IPv4Address(last))
    return [(None, address, None, None) for address in sorted(addresses)]


def parse_ip_route(content):
    routes = []
    for line in content.splitlines():
        fields = line.split()
        if not fields:
            continue
        route = {"destination": fields[0]}
        for key in ("via", "dev", "src", "proto", "scope", "metric"):
            if key in fields[1:-1]:
                route[key] = fields[fields.index(key) + 1]
        routes.append(route)
    return routes


def parse_proc_route(content):
    routes = []
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        destination = ip_from_proc(fields[1])
        mask = ip_from_proc(fields[7])
        prefix = bin(int(mask)).count("1")
        route = {"destination": "default" if prefix == 0 else f"{destination}/{prefix}",
                 "dev": fields[0]}
        if int(fields[2], 16):
            route["via"] = str(ip_from_proc(fields[2]))
        routes.append(route)
    return routes


def parse_proc_ipv6_route(content):
    routes = []
    for line in content.splitlines():
        fields = line.split()
        if len(fields) != 10 or int(fields[8], 16) & RTF_REJECT:
            continue          # unreachable routes the kernel keeps on lo
        destination = ipaddress.IPv6Address(bytes.fromhex(fields[0]))
        prefix = int(fields[1], 16)
        route = {"destination": "default" if prefix == 0 and int(destination) == 0
                 else f"{destination}/{prefix}", "dev": fields[9]}
        if int(fields[4], 16):
            route["via"] = str(ipaddress.IPv6Address(bytes.fromhex(fields[4])))
        routes.append(route)
    return routes


def parse_resolv_conf(content):
    """{"nameservers": [...], "invalid": [...], "search": [...], "options": [...]}."""
    result = {"nameservers": [], "invalid": [], "search": [], "options": []}
    for line in content.splitlines():
        fields = line.split("#", 1)[0].split(";", 1)[0].split()
        if len(fields) < 2:
            continue
        if fields[0] == "nameserver":
            try:
                result["nameservers"].append(str(ipaddress.ip_address(fields[1].split("%")[0])))
            except ValueError:
                result["invalid"].append(fields[1])
        elif fields[0] in ("search", "domain"):
            result["search"].extend(fields[1:])
        elif fields[0] == "options":
            result["options"].extend(fields[1:])
    return result


def parse_hosts(content):
    entries = []
    for line in content.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        try:
            address = ipaddress.ip_address(fields[0].split("%")[0])
        except ValueError:
            continue
        entries.append({"ip": str(address), "names": fields[1:]})
    return entries


def parse_socket_table(content, proto):
    """Listening sockets of one /proc/net table."""
    sockets = []
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local, remote, state = fields[1], fields[2], fields[3]
        address, _, port = local.partition(":")
        remote_address, _, remote_port = remote.partition(":")
        if proto.startswith("tcp"):
            listening = state == TCP_LISTEN
        else:
            listening = (state == UNCONNECTED and int(remote_address, 16) == 0
                         and int(remote_port, 16) == 0)
        if not listening:
            continue
        sockets.append({"proto": proto, "address": str(ip_from_proc(address)),
                        "port": int(port, 16), "uid": int(fields[7]),
                        "inode": int(fields[9])})
    return sockets


def socket_owners(sections):
    """{inode: [(pid, name)]} and {pid: (uid, name)}."""
    names = {}
    for line in (text(sections, "network.process_names") or "").splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3 and fields[0].isdigit():
            names[int(fields[0])] = (int(fields[1]) if fields[1].isdigit() else None, fields[2])
    owners = {}
    for line in (text(sections, "network.socket_pids") or "").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0].isdigit() and fields[1].isdigit():
            pid = int(fields[0])
            owners.setdefault(int(fields[1]), []).append(
                {"pid": pid, "name": names.get(pid, (None, None))[1]})
    return owners


def _interfaces(sections, gaps):
    link = text(sections, "network.ip_link")
    interfaces = parse_ip_link(link) if link else {}
    sys_net = text(sections, "network.sys_class_net")
    if sys_net:
        for name, info in parse_sys_class_net(sys_net).items():
            if name in interfaces:
                interfaces[name]["mac"] = interfaces[name]["mac"] or info["mac"]
            else:
                interfaces[name] = info
    if not interfaces:
        gaps.append(gap(sections, "interfaces", ["network.ip_link", "network.sys_class_net"],
                        "neither ip nor /sys/class/net"))

    addr = text(sections, "network.ip_addr")
    if addr:
        addresses = parse_ip_addr(addr)
    else:
        addresses = parse_if_inet6(text(sections, "network.if_inet6") or "")
        addresses += parse_fib_trie_local(text(sections, "network.fib_trie") or "")
        if not addresses:
            gaps.append(gap(sections, "addresses", ["network.ip_addr", "network.if_inet6"],
                            "no address source"))
    unassigned = []
    for name, address, prefix, scope in addresses:
        item = {"ip": str(address), "version": address.version, "prefix": prefix,
                "scope": scope}
        if name in interfaces:
            interfaces[name]["addresses"].append(item)
        else:
            unassigned.append(item)
    return interfaces, addresses, unassigned


def _routes(sections, gaps):
    routes = []
    for family, ip_name, proc_name, proc_parser in (
            (4, "network.ip_route", "network.proc_route", parse_proc_route),
            (6, "network.ip_route6", "network.proc_ipv6_route", parse_proc_ipv6_route)):
        content = text(sections, ip_name)
        if content is not None:
            found = parse_ip_route(content)
        else:
            proc = text(sections, proc_name)
            if proc is None:
                gaps.append(gap(sections, f"routes v{family}", [ip_name, proc_name],
                                "no route source"))
                continue
            found = proc_parser(proc)
        for route in found:
            route["family"] = family
        routes.extend(found)
    return routes


def _dns(sections):
    resolv = text(sections, "network.resolv_conf")
    if resolv is None:
        return None
    dns = parse_resolv_conf(resolv)
    dns["upstream"] = None
    resolved = text(sections, "network.resolved_resolv_conf")
    if resolved is not None and str(RESOLVED_STUB) in dns["nameservers"]:
        # systemd-resolved stub: the real servers are in its own resolv.conf.
        dns["upstream"] = parse_resolv_conf(resolved)["nameservers"]
    return dns


@register("network")
def parse(sections):
    gaps = []
    interfaces, addresses, unassigned = _interfaces(sections, gaps)
    routes = _routes(sections, gaps)
    dns = _dns(sections)
    if dns is None:
        gaps.append(gap(sections, "dns", ["network.resolv_conf"], "no /etc/resolv.conf"))
    hosts_text = text(sections, "network.hosts")
    hosts = parse_hosts(hosts_text) if hosts_text is not None else None
    if hosts is None:
        gaps.append(gap(sections, "hosts", ["network.hosts"], "no /etc/hosts"))

    owners = socket_owners(sections)
    listening = []
    for proto, name in SOCKET_TABLES:
        content = text(sections, name)
        if content is None:
            raw = sections.get(name)
            if raw is None or raw.status != "na":
                gaps.append(gap(sections, f"sockets {proto}", [name], f"no {name}"))
            continue
        for sock in parse_socket_table(content, proto):
            sock["processes"] = owners.get(sock["inode"], [])
            listening.append(sock)
    listening.sort(key=lambda s: (s["proto"], s["port"], s["address"]))

    relations = []
    local = {str(address) for _, address, _, _ in addresses}
    for address in sorted(local, key=lambda a: (ipaddress.ip_address(a).version,
                                                ipaddress.ip_address(a))):
        relations.append(Relation(address, Role.LOCAL, "network"))
    if dns:
        servers = dns["upstream"] if dns["upstream"] is not None else dns["nameservers"]
        for server in servers:
            relations.append(Relation(server, Role.DNS_SERVER, "network", "resolv.conf"))
    for entry in hosts or []:
        address = ipaddress.ip_address(entry["ip"])
        if (entry["ip"] not in local and not address.is_loopback and not address.is_multicast
                and not address.is_link_local and not address.is_reserved):
            relations.append(Relation(address, Role.NAMED_IN_FILE, "network",
                                      f"/etc/hosts: {' '.join(entry['names'])}"[:200]))

    data = {"interfaces": sorted(interfaces.values(), key=lambda i: (i["index"] or 0, i["name"])),
            "unassigned_addresses": unassigned, "routes": routes, "dns": dns,
            "hosts": hosts, "listening": listening}
    return AreaResult(data, relations=relations, gaps=gaps)
