"""Human-readable report of a snapshot: summary or detail per area, then the gaps.

Every string that comes from the inspected machine is untrusted: clean() escapes control
characters, so a banner with ANSI sequences cannot rewrite the terminal.
"""

import re

from aridi.interpret import AREAS
from aridi.model import Status
from aridi.parsers.storage import PSEUDO_FS
from aridi.relations import consolidate

# Area renderers registered by phase 3: FUNC(data, detail) -> list of lines.
_renderers = {}

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

STATUS_TEXT = {
    Status.OK: "ok",
    Status.DENIED: "denied (no permission)",
    Status.MISSING: "missing tool",
    Status.NA: "not applicable",
    Status.TIMEOUT: "timed out",
    Status.ERROR: "error",
    Status.NOT_COLLECTED: "not collected",
    Status.NO_PARSER: "no analyzer",
}


def renderer(area):
    """Decorator: register the text renderer of AREA."""
    def decorator(func):
        _renderers[area] = func
        return func
    return decorator


def clean(value):
    """Text safe for a terminal: control characters become \\xNN; tabs and newlines too."""
    text = "" if value is None else str(value)
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text.replace("\t", "\\t")
                        .replace("\n", "\\n"))


def _title(text, char="="):
    return [text, char * len(text)]


def _area_lines(area, section, detail):
    lines = _title(area.title + (" (volatile)" if area.volatile else ""), "-")
    if section.status != Status.OK:
        lines.append(f"  [{STATUS_TEXT[section.status]}] {clean(section.reason)}")
        # A partial result (e.g. a search that timed out) is still shown.
        if section.data is None or area.name not in _renderers:
            return lines
    for gap in section.gaps:
        lines.append(f"  [{STATUS_TEXT[gap.status]}] {clean(gap.item)}: {clean(gap.reason)}")
    render = _renderers.get(area.name)
    if render is None:
        lines.append("  (no text view for this area yet)")
        return lines
    lines.extend("  " + clean(line) for line in render(section.data, detail))
    return lines


def area_lines(name, section, detail=False):
    """Lines of one area without its title, for other views (the central web pages)."""
    area = next(a for a in AREAS if a.name == name)
    return _area_lines(area, section, detail)[2:]


def _infrastructure(snapshot):
    """The relation map (-oi of 2019): local machine first, then remote addresses."""
    lines = _title("Infrastructure")
    nodes = consolidate(snapshot.relations)
    if not nodes:
        return lines + ["(no address found)"]
    for local in (True, False):
        group = [node for node in nodes if node.local == local]
        if not group:
            continue
        lines.append("Local machine:" if local else "Remote addresses:")
        for node in group:
            lines.append(f"  {node.ip}")
            lines.extend(f"    {role.value} ({source}{', ' + clean(detail) if detail else ''})"
                         for role, source, detail in node.roles if role.value != "local")
    return lines


def render(snapshot, detail=False):
    """The report as a string."""
    lines = _title(f"aridi report: {clean(snapshot.machine.hostname or '(unknown host)')}")
    lines += [
        f"Machine id:   {clean(snapshot.machine.machine_id or '(unknown)')}",
        f"Collected at: {clean(snapshot.collected_at or '(unknown)')}",
        f"Collector:    {clean(snapshot.collector_version)} "
        f"(bundle format {snapshot.bundle_format}, snapshot schema {snapshot.schema_version})",
        f"Result:       {'complete' if not snapshot.gaps() else 'with gaps'}",
        f"Level:        {'detail' if detail else 'summary'}",
        "",
    ]
    for area in AREAS:
        section = snapshot.sections.get(area.name)
        if section is None:
            continue
        lines += _area_lines(area, section, detail) + [""]

    lines += _infrastructure(snapshot) + [""]

    gaps = snapshot.gaps()
    lines += _title("What could not be seen")
    if not gaps:
        lines.append("Nothing: every area was collected and analyzed.")
    else:
        titles = {area.name: area.title for area in AREAS}
        rows = [(titles.get(name, name) + (f": {clean(item)}" if item else ""),
                 status.value, clean(reason)) for name, item, status, reason in gaps]
        width = max(len(row[0]) for row in rows)
        for what, status, reason in rows:
            lines.append(f"{what:<{width}}  {status:<13}  {reason}")
    return "\n".join(lines) + "\n"


def _value(value, missing="(unknown)"):
    return missing if value in (None, "", []) else value


@renderer("system")
def _system(data, detail):
    dist = data.get("distribution") or {}
    kernel = data.get("kernel") or {}
    libc = data.get("libc") or {}
    name = dist.get("pretty_name") or " ".join(
        part for part in (dist.get("name"), dist.get("version")) if part) or None
    ident = " ".join(part for part in (dist.get("id"), dist.get("version_id")) if part)
    lines = [
        f"Distribution: {_value(name)}" + (f" [{ident}]" if ident else ""),
        "Kernel:       " + " ".join(part for part in (kernel.get("ostype"),
                                                    _value(kernel.get("release"))) if part),
        f"Architecture: {_value(kernel.get('machine'))}",
        f"Libc:         {_value(libc.get('family'))} {libc.get('version') or ''}".rstrip(),
    ]
    if detail:
        lines += [
            f"Name:         {_value(dist.get('name'))}",
            f"Version:      {_value(dist.get('version'))}",
            f"Codename:     {_value(dist.get('version_codename'))}",
            f"Like:         {_value(' '.join(dist.get('id_like') or []), '(none)')}",
            f"Source:       {_value(dist.get('source'))}",
            f"Kernel build: {_value(kernel.get('version'))}",
            f"/proc/version: {_value(kernel.get('proc_version'))}",
        ]
        for name, line in sorted((data.get("release_files") or {}).items()):
            lines.append(f"{name}: {line}")
    return lines


def human_duration(seconds):
    """"2 days, 20:56:56" (the uptime format of 2019)."""
    days, rest = divmod(int(seconds), 86400)
    clock = f"{rest // 3600:02d}:{rest % 3600 // 60:02d}:{rest % 60:02d}"
    if not days:
        return clock
    return f"{days} day{'s' if days != 1 else ''}, {clock}"


def human_bytes(value):
    """1536 -> "1.5 KiB"; None -> "(unknown)". Binary units, computed from bytes."""
    if value is None:
        return "(unknown)"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if round(abs(size), 1) < 1024 or unit == "PiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


@renderer("hardware")
def _hardware(data, detail):
    cpu = data.get("cpu") or {}
    memory = data.get("memory") or {}
    usb = data.get("usb")
    topology = ", ".join(f"{value} {label}" for value, label in (
        (cpu.get("sockets"), "socket(s)"), (cpu.get("cores"), "core(s)"),
        (cpu.get("threads_per_core"), "thread(s) per core")) if value)
    lines = [
        f"CPU:    {_value(cpu.get('logical'))} x {_value(cpu.get('model'))}"
        f" ({_value(cpu.get('architecture'))})" + (f", {topology}" if topology else ""),
        f"Memory: {human_bytes(memory.get('total'))}, swap {human_bytes(memory.get('swap_total'))}",
    ]
    if usb is None:
        lines.append("USB:    (not available)")
    else:
        hubs = sum(1 for dev in usb if dev.get("hub"))
        lines.append(f"USB:    {len(usb) - hubs} device(s), {hubs} hub(s)")
    if detail:
        lines += [
            f"Vendor: {_value(cpu.get('vendor'))}",
            f"Online: {_value(','.join(str(n) for n in cpu.get('online') or []))}",
            f"Flags:  {_value(' '.join(cpu.get('flags') or []), '(none)')}",
            f"Bugs:   {_value(' '.join(cpu.get('bugs') or []), '(none)')}",
        ]
        if cpu.get("implementer"):
            lines.append(f"ARM:    implementer {cpu['implementer']}, part {cpu.get('part')}")
        for dev in usb or []:
            kind = "root hub" if dev.get("root_hub") else "hub" if dev.get("hub") else "device"
            lines.append(f"USB {dev.get('device')}: {dev.get('idVendor', '?')}:"
                         f"{dev.get('idProduct', '?')} {kind} "
                         f"{dev.get('manufacturer', '')} {dev.get('product', '')}".rstrip())
    return lines


@renderer("packages")
def _packages(data, detail):
    managers = data.get("managers") or {}
    per_manager = ", ".join(f"{name} {count}" for name, count in managers.items())
    lines = [f"Installed: {data.get('count', 0)}" + (f" ({per_manager})" if per_manager else "")]
    if data.get("gpg_pubkeys"):
        lines.append(f"RPM signing keys (gpg-pubkey, not counted): {data['gpg_pubkeys']}")
    if detail:
        for package in data.get("packages") or []:
            lines.append(f"{package.get('name')} {package.get('version') or '?'} "
                         f"{package.get('arch') or ''}".rstrip())
    return lines


@renderer("storage")
def _storage(data, detail):
    devices = data.get("devices") or []
    disks = [d for d in devices if d.get("kind") in ("disk", "raid", "unknown") and d.get("size")]
    lines = ["Disks:  " + (", ".join(f"{d['name']} {human_bytes(d['size'])}" for d in disks)
                           or "(none)")]
    mounts = data.get("mounts") or []
    real = [m for m in mounts if m.get("fstype") not in PSEUDO_FS]
    lines.append(f"Mounts: {len(mounts)} ({len(mounts) - len(real)} pseudo filesystems"
                 f"{'' if detail else ', not listed'})")
    for mount in mounts if detail else real:
        usage = mount.get("usage")
        used = (f"{human_bytes(usage['used'])} of {human_bytes(usage['size'])} "
                f"({usage['percent']}%)" if usage else "usage unknown")
        flags = [flag for flag, on in (("bind", mount.get("bind")),
                                       ("ro", "ro" in (mount.get("options") or [])),
                                       (f"subvol={mount.get('subvolume')}",
                                        mount.get("subvolume"))) if on]
        lines.append(f"  {mount.get('mountpoint')}  {mount.get('fstype')} "
                     f"{mount.get('source')}  {used}"
                     + (f"  [{', '.join(flags)}]" if flags else ""))
        if detail:
            lines.append(f"      options {','.join(mount.get('options') or [])}"
                         f"  root {mount.get('root')}  dev {mount.get('dev')}")
    swaps = data.get("swaps")
    if swaps is None:
        lines.append("Swap:   (unknown)")
    else:
        lines.append("Swap:   " + (", ".join(f"{s['device']} {human_bytes(s['size'])}"
                                             for s in swaps) or "(none)"))
    if detail:
        for device in devices:
            extra = " ".join(f"{key}={value}" for key, value in (
                ("dm", device.get("dm_name")), ("fstype", device.get("fstype")),
                ("holders", ",".join(device.get("holders") or [])),
                ("slaves", ",".join(device.get("slaves") or []))) if value)
            lines.append(f"Device {device.get('name')} {device.get('kind')} "
                         f"{human_bytes(device.get('size'))} {extra}".rstrip())
    return lines


@renderer("permissions")
def _permissions(data, detail):
    if not data.get("searched"):
        lines = ["Search: (not done)"]
    else:
        suid, sgid = data.get("suid") or [], data.get("sgid") or []
        lines = [
            f"SUID files: {len(suid)} ({sum(1 for f in suid if not f.get('root_owned'))} "
            "not owned by root)",
            f"SGID files: {len(sgid)}",
            f"World-writable files: {len(data.get('world_writable_files') or [])}",
            "World-writable dirs without sticky bit: "
            f"{len(data.get('world_writable_dirs_no_sticky') or [])}"
            f" (with sticky bit: {data.get('world_writable_dirs_sticky', 0)})",
        ]
        listed = [("dir without sticky bit", data.get("world_writable_dirs_no_sticky")),
                  ("world-writable file", data.get("world_writable_files"))]
        if detail:
            listed += [("suid", suid), ("sgid", sgid)]
        for label, items in listed:
            for item in items or []:
                lines.append(f"  {label}: {item['path']} {item['mode']} "
                             f"uid={item['uid']} gid={item['gid']}")
    for item in data.get("account_files") or []:
        verdict = (f"more open than {item['recommended']}" if item.get("too_open")
                   else "ok")
        if detail or item.get("too_open"):
            lines.append(f"Account file {item['path']}: {item['mode']} "
                         f"uid={item['uid']} gid={item['gid']} ({verdict})")
    return lines


@renderer("identity")
def _identity(data, detail):
    domain = data.get("dns_domain")
    lines = [
        f"Hostname:   {_value(data.get('hostname'))}",
        "DNS domain: " + ("(none)" if domain == ""
                          else _value(domain, "(the hostname does not resolve)")),
        f"NIS domain: {_value(data.get('nis_domain'), '(none)')}",
        f"Host id:    {_value(data.get('hostid'))}",
    ]
    banners = data.get("banners") or {}
    lines.append("Banners:    " + (", ".join(sorted(banners)) or "(none)"))
    if detail:
        if data.get("etc_hostname") and data.get("etc_hostname") != data.get("hostname"):
            lines.append(f"/etc/hostname differs: {data['etc_hostname']}")
        # Untrusted text: every line goes through clean() in _area_lines.
        for path in sorted(banners):
            lines.append(f"--- {path}" + (" (cut)" if banners[path].get("truncated") else ""))
            lines.extend(f"| {line}" for line in banners[path].get("text", "").splitlines())
    return lines


@renderer("users")
def _users(data, detail):
    users = data.get("users") or []
    states = data.get("password_states") or {}
    algorithms = data.get("algorithms") or {}
    lines = [
        f"Accounts: {len(users)}, groups: {len(data.get('groups') or [])}",
        "Passwords: " + (", ".join(f"{count} {state}" for state, count in sorted(states.items()))
                         or "(none)"),
        "Algorithms: " + (", ".join(f"{name} {count}" for name, count in
                                    sorted(algorithms.items())) or "(none)"),
    ]
    if not data.get("shadow_read"):
        lines.append("Password state unknown: /etc/shadow could not be read")
    empty = [u["name"] for u in users if u.get("password") == "empty"]
    if empty:
        lines.append("WITHOUT PASSWORD: " + ", ".join(empty))
    shells = [u for u in users if u.get("password") == "set"]
    # One account per line: 2019 cut names at the line width.
    lines.append("Accounts with a password:" + ("" if shells else " (none)"))
    lines.extend(f"  {u['name']} (uid {u['uid']}, {u['algorithm']}, {u['shell']})"
                 for u in shells)
    for orphan in data.get("members_without_account") or []:
        lines.append(f"Group {orphan['group']}: member {orphan['member']} has no local account")
    if detail:
        for user in users:
            lines.append(f"  user {user['name']} uid={user['uid']} gid={user['gid']} "
                         f"password={user['password']} algorithm={user['algorithm']} "
                         f"home={user['home']} shell={user['shell']} "
                         f"groups={','.join(user['groups'])}")
        for group in data.get("groups") or []:
            lines.append(f"  group {group['name']} gid={group['gid']} "
                         f"members={','.join(group['members'])}")
    return lines


@renderer("services")
def _services(data, detail):
    services = data.get("services") or []
    running = [s for s in services if s.get("active") in ("active", "started", "run")]
    lines = [
        f"Managers: {', '.join(data.get('managers') or []) or '(none found)'}"
        f" (init: {_value(data.get('init'))}, systemd running: "
        f"{'yes' if data.get('systemd_running') else 'no'})",
        f"Services: {len(services)}, running {len(running)}, failed "
        f"{len(data.get('failed') or [])}",
    ]
    # Failed services first: they are what needs attention.
    lines.extend(f"  FAILED {name}" for name in data.get("failed") or [])
    if detail:
        by_state = {}
        for service in services:
            by_state.setdefault(service.get("active") or "unknown", []).append(service)
        for state in sorted(by_state):
            lines.append(f"{state}:")
            for service in sorted(by_state[state], key=lambda s: s["name"]):
                levels = service.get("runlevels")
                lines.append(f"  {service['name']} [{service['manager']}] "
                             f"enabled={service.get('enabled')}"
                             + (f" runlevels={''.join(levels)}" if levels else ""))
    return lines


@renderer("network")
def _network(data, detail):
    lines = []
    for iface in data.get("interfaces") or []:
        addresses = [f"{a['ip']}/{a['prefix']}" if a.get("prefix") is not None else a["ip"]
                     for a in iface.get("addresses") or []]
        if not detail and not addresses:
            continue
        peer = f" (peer {iface['peer']})" if iface.get("peer") else ""
        lines.append(f"Interface {iface['name']}{peer}: {iface.get('state') or '?'} "
                     f"mac {iface.get('mac') or '-'}  " + (" ".join(addresses) or "(no address)"))
    for item in data.get("unassigned_addresses") or []:
        lines.append(f"Address without interface: {item['ip']}")
    defaults = [r for r in data.get("routes") or [] if r.get("destination") == "default"]
    lines.append("Default route: " + (", ".join(f"via {r.get('via', '-')} dev {r.get('dev', '?')}"
                                                for r in defaults) or "(none)"))
    dns = data.get("dns")
    if dns is None:
        lines.append("DNS: (unknown)")
    else:
        servers = ", ".join(dns.get("nameservers") or []) or "(none)"
        if dns.get("upstream") is not None:
            servers += f" -> systemd-resolved upstream {', '.join(dns['upstream']) or '(none)'}"
        lines.append(f"DNS: {servers}" + (f"  search {' '.join(dns['search'])}"
                                          if dns.get("search") else ""))
        for invalid in dns.get("invalid") or []:
            lines.append(f"DNS entry that is not an IP: {invalid}")
    listening = data.get("listening") or []
    lines.append(f"Listening sockets: {len(listening)}")
    for sock in listening:
        if sock["proto"].startswith("raw") and not detail:
            continue
        who = ", ".join(f"{p['name'] or '?'}[{p['pid']}]" for p in sock.get("processes") or [])
        address = f"[{sock['address']}]" if ":" in sock["address"] else sock["address"]
        lines.append(f"  {sock['proto']:<5} {address}:{sock['port']}  uid {sock['uid']}  "
                     f"{who or '(process unknown)'}")
    if detail:
        for route in data.get("routes") or []:
            extra = " ".join(f"{k} {v}" for k, v in route.items()
                             if k not in ("destination", "family"))
            lines.append(f"Route v{route.get('family')}: {route['destination']} {extra}")
        for entry in data.get("hosts") or []:
            lines.append(f"/etc/hosts: {entry['ip']} {' '.join(entry['names'])}")
    return lines


@renderer("firewall")
def _firewall(data, detail):
    rules = data.get("rules") or []
    lines = [f"Engines: {', '.join(data.get('engines') or []) or '(none found)'}"]
    policies = [c for c in data.get("chains") or [] if c.get("hook") and c.get("policy")]
    for chain in policies:
        lines.append(f"Policy {chain['family']} {chain['table']} {chain['name']} "
                     f"({chain['hook']}): {chain['policy']}")
    shown = rules if detail else [r for r in rules if r.get("action") == "accept"
                                  and (r.get("source") or r.get("destination") or r.get("port"))]
    lines.append(f"Rules: {len(rules)}" + ("" if detail else
                                           f", {len(shown)} specific accept rule(s) listed"))
    for rule in shown:
        parts = [f"{k} {rule[k]}" for k in ("source", "destination", "protocol", "port")
                 if rule.get(k)]
        lines.append(f"  {rule['engine']} {rule.get('family')} {rule.get('chain')}"
                     f" [{rule.get('direction') or '-'}] {rule.get('action') or '-'}: "
                     + (", ".join(parts) or "any"))
    for zone in data.get("firewalld_zones") or []:
        if zone.get("active") or detail:
            lines.append(f"firewalld zone {zone['zone']}{' (active)' if zone.get('active') else ''}"
                         f": services {' '.join(zone.get('services') or []) or '-'}, "
                         f"ports {' '.join(zone.get('ports') or []) or '-'}")
            lines.extend(f"    {rich}" for rich in zone.get("rich_rules") or [])
    ufw = data.get("ufw")
    if ufw:
        lines.append(f"ufw: {'active' if ufw.get('active') else 'inactive'}, "
                     f"{ufw.get('defaults') or ''}".rstrip(", "))
        lines.extend("    " + "  ".join(rule) for rule in ufw.get("rules") or [])
    return lines


@renderer("timesync")
def _timesync(data, detail):
    lines = [f"Services: {', '.join(data.get('services') or []) or '(none)'}"]
    for item in data.get("configured") or []:
        lines.append(f"Configured ({item['service']}, {item['kind']}): {item['server']}")
    for item in data.get("in_use") or []:
        mark = " (selected)" if item.get("selected") else ""
        name = f" [{item['name']}]" if item.get("name") else ""
        lines.append(f"In use ({item['service']}): {item['server']}{name}{mark}")
    return lines


def _process_line(proc):
    # A process can end between the reads of stat and status: its user is then unknown.
    return (f"{proc['pid']:>7} {proc.get('user') or '?':<10} {proc.get('state')} "
            f"cpu {proc['cpu'] if proc.get('cpu') is not None else '?':>6}% "
            f"rss {human_bytes(proc.get('rss')):>10}  {proc.get('cmdline') or proc.get('comm')}")


@renderer("processes")
def _processes(data, detail):
    by_pid = {p["pid"]: p for p in data.get("processes") or []}
    states = ", ".join(f"{state} {count}" for state, count in sorted(
        (data.get("by_state") or {}).items()))
    lines = [f"Processes: {data.get('count', 0)} ({states})"]
    if data.get("zombies"):
        lines.append("Zombies: " + ", ".join(str(pid) for pid in data["zombies"]))
    top = 10 if detail else 5
    for title, key in (("Top memory", "top_memory"), ("Top CPU since start", "top_cpu")):
        lines.append(f"{title}:")
        lines.extend("  " + _process_line(by_pid[pid])
                     for pid in (data.get(key) or [])[:top] if pid in by_pid)
    if data.get("clk_tck_source") == "default":
        lines.append(f"(CPU computed with USER_HZ {data.get('clk_tck')}: getconf not available)")
    if detail:
        lines.append("All processes:")
        lines.extend("  " + _process_line(proc) for proc in data.get("processes") or [])
    return lines


@renderer("load")
def _load(data, detail):
    lines = []
    mem = data.get("memory")
    if mem:
        lines.append(f"Memory: {human_bytes(mem['used'])} used, {human_bytes(mem['cache'])} "
                     f"cache, {human_bytes(mem['buffers'])} buffers, "
                     f"{human_bytes(mem['free'])} free of {human_bytes(mem['total'])}")
        lines.append(f"Swap:   {human_bytes(mem.get('swap_used'))} used of "
                     f"{human_bytes(mem.get('swap_total'))}")
    if data.get("uptime_seconds") is not None:
        lines.append(f"Uptime: {human_duration(data['uptime_seconds'])}")
    load = data.get("load")
    if load:
        lines.append(f"Load:   {load['1']} {load['5']} {load['15']} (1, 5, 15 min)")
    cpu = data.get("cpu") or {}
    for label, key in (("CPU since boot", "since_boot"), ("CPU last second", "last_second")):
        if cpu.get(key):
            values = cpu[key]
            lines.append(f"{label}: {values['user']}% user, {values['system']}% system, "
                         f"{values['iowait']}% iowait, {values['idle']}% idle")
    for disk in data.get("disks") or []:
        if detail or disk["busy_percent"] or disk["reads_per_second"] or disk["writes_per_second"]:
            lines.append(f"Disk {disk['device']}: {disk['busy_percent']}% busy, "
                         f"{disk['reads_per_second']} reads/s, "
                         f"{disk['writes_per_second']} writes/s")
    files, inodes = data.get("files"), data.get("inodes")
    if files:
        lines.append(f"Open files: {files['allocated']} of {files['max']}")
    if inodes and detail:
        lines.append(f"Inodes in cache: {inodes['count']} ({inodes['free']} free)")
    return lines


@renderer("sessions")
def _sessions(data, detail):
    lines = [f"Sources: {', '.join(data.get('sources') or []) or '(none)'}"]
    active = data.get("active")
    if active is None:
        lines.append("Active sessions: (unknown)")
    else:
        lines.append(f"Active sessions: {len(active)}")
        lines.extend(f"  {s['user']} {s['line']} from {s.get('host') or '-'} since "
                     f"{s.get('since') or '?'}" for s in active)
    for label, key in (("Logins", "login_counts"), ("Failed logins", "failed_counts")):
        counts = data.get(key)
        if counts:
            lines.append(f"{label}: {counts['day']} last day, {counts['week']} last week, "
                         f"{counts['month']} last month")
    failed = data.get("failed") or []
    sources = {}
    for event in failed:
        sources[event.get("host") or "-"] = sources.get(event.get("host") or "-", 0) + 1
    if sources:
        lines.append("Failed login sources: " + ", ".join(
            f"{host} ({count})" for host, count in sorted(sources.items(), key=lambda i: -i[1])))
    if detail:
        for event in data.get("logins") or []:
            lines.append(f"  login {event.get('time')} {event['user']} {event.get('line')} "
                         f"from {event.get('host') or '-'}")
        for event in failed:
            lines.append(f"  failed {event.get('time')} {event['user']} from "
                         f"{event.get('host')} ({event.get('method')})")
    return lines


@renderer("connections")
def _connections(data, detail):
    connections = data.get("connections") or []
    incoming = [c for c in connections if c["direction"] == "in"]
    lines = [f"Connections: {len(connections)} ({len(incoming)} incoming, "
             f"{len(connections) - len(incoming)} outgoing)"]
    for conn in connections:
        who = ", ".join(f"{p['name'] or '?'}[{p['pid']}]" for p in conn.get("processes") or [])
        service = f" {conn['service']}" if conn.get("service") else ""
        arrow = "<-" if conn["direction"] == "in" else "->"
        lines.append(f"  {conn['proto']} {conn['local']}:{conn['local_port']} {arrow} "
                     f"{conn['remote']}:{conn['remote_port']}{service} {conn['state']} "
                     f"{conn['user']} {who}".rstrip())
    return lines


@renderer("carving")
def _carving(data, detail):
    counts = data.get("counts") or {}
    lines = ["Addresses: " + (", ".join(f"{count} in {source}" for source, count in
                                        counts.items()) or "(none)")]
    for item in data.get("addresses") or []:
        where = ", ".join(f"{m['path']}:{m['line']}" if m.get("path")
                          else f"journal x{m.get('count')}" for m in item["mentions"][:3])
        more = len(item["mentions"]) - 3
        lines.append(f"  {item['ip']}  {where}" + (f" (+{more})" if more > 0 else ""))
    names = data.get("names") or []
    lines.append(f"Possible host names in /etc (not resolved): {len(names)}")
    if detail:
        lines.extend(f"  {n['name']}  {', '.join(n['files'])}" for n in names)
        for why, count in sorted((data.get("excluded") or {}).items()):
            lines.append(f"Excluded ({why}): {count}")
    return lines


@renderer("neighbours")
def _neighbours(data, detail):
    neighbours = data.get("neighbours") or []
    lines = [f"Neighbours: {len(neighbours)} (from {data.get('source')})"]
    lines.extend(f"  {n['ip']}  {n.get('mac') or '-'}  {n.get('interface') or '-'}  "
                 f"{n.get('state') or '-'}" + ("  router" if n.get("router") else "")
                 for n in neighbours)
    return lines
