"""From Snapshot.data (snapshot v1 of the core) to the gap and search index rows.

Only non-volatile areas are indexed (TODO.md 5.2): a process or a connection says what
happened at one instant, not what the machine is. Gaps are stored for every area.
"""

import ipaddress

from aridi.model import Snapshot as CoreSnapshot

from aridi_central.inventory.models import (Gap, Relation, SnapshotPackage, SnapshotPort,
                                            SnapshotService, SnapshotUser)


def _section_data(core, name):
    """Data of a non-volatile area, or None if it is volatile or has no data."""
    section = core.sections.get(name)
    if section is None or section.volatile or not isinstance(section.data, dict):
        return None
    return section.data


def _text(value, limit=255):
    return "" if value is None else str(value)[:limit]


def rows_for(snapshot, core):
    """{model: [unsaved rows]} for SNAPSHOT from its core snapshot CORE."""
    rows = {Gap: [], SnapshotPackage: [], SnapshotUser: [], SnapshotPort: [],
            SnapshotService: [], Relation: []}
    for area, item, status, reason in core.gaps():
        rows[Gap].append(Gap(snapshot=snapshot, area=area, item=_text(item, 200),
                             status=status.value, reason=reason or ""))

    packages = _section_data(core, "packages")
    for package in (packages or {}).get("packages") or []:
        rows[SnapshotPackage].append(SnapshotPackage(
            snapshot=snapshot, name=_text(package.get("name")),
            version=_text(package.get("version")), arch=_text(package.get("arch"), 32),
            manager=_text(package.get("manager"), 16)))

    users = _section_data(core, "users")
    for user in (users or {}).get("users") or []:
        rows[SnapshotUser].append(SnapshotUser(
            snapshot=snapshot, name=_text(user.get("name")), uid=user.get("uid"),
            shell=_text(user.get("shell")), password_algo=_text(user.get("algorithm"), 32),
            groups=",".join(user.get("groups") or [])))

    network = _section_data(core, "network")
    for sock in (network or {}).get("listening") or []:
        try:
            family = ipaddress.ip_address(sock.get("address")).version
        except ValueError:
            family = 0
        processes = ",".join(sorted({p.get("name") or str(p.get("pid"))
                                     for p in sock.get("processes") or []}))
        rows[SnapshotPort].append(SnapshotPort(
            snapshot=snapshot, proto=_text(sock.get("proto"), 8), family=family,
            address=_text(sock.get("address"), 64), port=sock.get("port"),
            process=_text(processes)))

    services = _section_data(core, "services")
    for service in (services or {}).get("services") or []:
        rows[SnapshotService].append(SnapshotService(
            snapshot=snapshot, manager=_text(service.get("manager"), 16),
            name=_text(service.get("name")), state=_text(service.get("active"), 32),
            enabled=_text(service.get("enabled"), 32)))

    volatile = {name for name, section in core.sections.items() if section.volatile}
    for relation in core.relations:
        if relation.source in volatile:
            continue
        rows[Relation].append(Relation(snapshot=snapshot, ip=str(relation.ip),
                                       role=relation.role.value, source=relation.source,
                                       detail=relation.detail))
    return rows


def index_snapshot(snapshot):
    """Create the gap and index rows of a saved Snapshot that has data."""
    core = CoreSnapshot.from_dict(snapshot.data)
    for model, objects in rows_for(snapshot, core).items():
        model.objects.bulk_create(objects, batch_size=500)
    return core
