"""Scan jobs: from an AuthorizedNetwork to ScanResult rows and to the inventory
(TODO.md 7.3). Called by the worker for jobs of kind "scan".

Open ports of an address that belongs to an inventoried machine (one of the local
addresses of its latest snapshot, or its SSH target when it is an address) become
relations with the role scan_open_port on that snapshot.
"""

import ipaddress
import logging
from dataclasses import dataclass

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from aridi import ports as port_names

from aridi_central.discovery.models import AuthorizedNetwork, ScanResult
from aridi_central.discovery.scanner import (ALL_PORTS, COMMON_PORTS, OutsidePerimeter,
                                             Perimeter, Scanner, tcp_connect)
from aridi_central.inventory.models import Machine, Relation

log = logging.getLogger(__name__)

SOURCE = "scan"


@dataclass
class Outcome:
    ok: bool
    reason: str = ""
    found: int = 0


def active_networks():
    return [network.network for network in AuthorizedNetwork.objects.filter(active=True)]


def machine_addresses():
    """{ip: Machine} of the inventoried machines, from their latest snapshot."""
    found = {}
    for machine in Machine.objects.all():
        snapshot = machine.latest_snapshot()
        if snapshot is not None:
            for ip in snapshot.relations.filter(role="local").values_list("ip", flat=True):
                found.setdefault(ipaddress.ip_address(ip), machine)
        host = machine.ssh_target.rpartition("@")[2].strip("[]")
        try:
            found.setdefault(ipaddress.ip_address(host), machine)
        except ValueError:
            pass
    return found


def integrate(found, when):
    """Relations scan_open_port on the latest snapshot of the machines found."""
    owners = machine_addresses()
    by_machine = {}
    for ip, port in found:
        machine = owners.get(ip)
        if machine is not None:
            by_machine.setdefault(machine, []).append((ip, port))
    for machine, opened in by_machine.items():
        snapshot = machine.latest_snapshot()
        if snapshot is None:
            continue
        with transaction.atomic():
            Relation.objects.filter(snapshot=snapshot, source=SOURCE,
                                    ip__in=[str(ip) for ip, _ in opened]).delete()
            Relation.objects.bulk_create(
                Relation(snapshot=snapshot, ip=str(ip), role="scan_open_port", source=SOURCE,
                         detail=" ".join(filter(None, (f"tcp/{port}", port_names.name(port))))
                         + f", scan of {when:%Y-%m-%d %H:%M} UTC")
                for ip, port in opened)
    return by_machine


def run_scan(job, stop=None, connect=tcp_connect):
    """Scan the network of JOB. Refuses when scanning is off or the network inactive."""
    if not settings.ARIDI_SCAN_ENABLED:
        return Outcome(False, "scanning is disabled (ARIDI_SCAN_ENABLED is not 1)")
    network = AuthorizedNetwork.objects.filter(id=job.network_id).first()
    if network is None or not network.active:
        return Outcome(False, "the network is not an active authorized network")
    ports = ALL_PORTS if network.ports == AuthorizedNetwork.Ports.ALL else COMMON_PORTS
    scanner = Scanner(Perimeter(active_networks), rate=settings.ARIDI_SCAN_RATE,
                      timeout=settings.ARIDI_SCAN_TIMEOUT, threads=settings.ARIDI_SCAN_THREADS,
                      stop=stop, connect=connect)
    log.info("scanning %s: %d addresses x %d ports, %d per second", network,
             network.network.num_addresses, len(ports), settings.ARIDI_SCAN_RATE)
    try:
        found = scanner.scan(network.network, ports)
    except OutsidePerimeter as exc:
        return Outcome(False, f"stopped: {exc} (deactivated during the scan?)")
    if scanner.stop.is_set():
        return Outcome(False, "interrupted by the worker shutdown")
    when = timezone.now()
    ScanResult.objects.bulk_create(
        ScanResult(network=network, job=job, ip=str(ip), port=port, scanned_at=when,
                   service=port_names.name(port) or "")
        for ip, port in found)
    integrate(found, when)
    log.info("scan of %s: %d open ports in %d attempts", network, len(found),
             scanner.attempts)
    return Outcome(True, found=len(found))


def latest_results(addresses):
    """Open ports of the latest scan of each network that covered ADDRESSES."""
    rows = list(ScanResult.objects.filter(ip__in=[str(ip) for ip in addresses])
                .select_related("network").order_by("-scanned_at"))
    latest = {}
    for row in rows:
        latest.setdefault(row.network_id, row.scanned_at)
    return [row for row in rows if row.scanned_at == latest[row.network_id]]
