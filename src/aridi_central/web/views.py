"""Views of the web interface (TODO.md 5.6, 5.7, 6.1, 6.3, 6.5).

Every page needs a logged-in user; changes need the permissions of the administration
role (roles.py). Text that comes from machines is only ever output through the template
autoescape, never marked safe.
"""

import ipaddress
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import OuterRef, Subquery
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from aridi.interpret import AREAS
from aridi.model import Snapshot as CoreSnapshot
from aridi.relations import consolidate
from aridi.views.text import area_lines

from aridi_central.changes.diff import compare
from aridi_central.changes.models import Alert, Channel, Delivery, RuleOverride
from aridi_central.changes.rules import BY_CODE, RULES
from aridi_central.collection.models import Job, Schedule
from aridi_central.collection.worker import enqueue, enqueue_scan
from aridi_central.discovery.models import AuthorizedNetwork
from aridi_central.discovery.scanning import latest_results
from aridi_central.inventory.importing import ImportRefused, NeedsConfirmation, import_bundle
from aridi_central.inventory.models import (Group, Machine, Relation, Snapshot,
                                            SnapshotPackage, SnapshotPort, SnapshotService,
                                            SnapshotUser)
from aridi_central.web.forms import (AlertFilterForm, AlertStateForm,
                                     AuthorizedNetworkForm, ChannelForm, GroupForm,
                                     ImportForm, MachineForm, RuleOverrideForm, ScheduleForm,
                                     SearchForm)
from aridi_central.web.relation_map import build as build_map


def permission(code):
    """Login required (redirect), then permission CODE required (403)."""
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect_to_login(request.get_full_path())
            if not request.user.has_perm(code):
                raise PermissionDenied
            return view(request, *args, **kwargs)
        return wrapper
    return decorator


def healthz(request):
    """Container healthcheck: the database answers."""
    Machine.objects.exists()
    return HttpResponse("ok\n", content_type="text/plain")


# Machines

@permission("inventory.view_machine")
def machine_list(request):
    latest = Snapshot.objects.filter(machine=OuterRef("pk")).order_by("-collected_at", "-id")
    machines = Machine.objects.annotate(last_id=Subquery(latest.values("id")[:1]))
    snapshots = Snapshot.objects.in_bulk([m.last_id for m in machines if m.last_id])
    rows = []
    for machine in machines.prefetch_related("groups"):
        last = snapshots.get(machine.last_id)
        rows.append({"machine": machine, "last": last,
                     "gaps": last.gaps.count() if last else None,
                     "alerts": machine.alerts.exclude(state=Alert.State.RESOLVED).count()})
    return render(request, "web/machine_list.html", {"rows": rows})


def _areas(snapshot, detail):
    """[(title, volatile, lines)] and the relation map of a snapshot with data."""
    core = CoreSnapshot.from_dict(snapshot.data)
    areas = [(area.title, area.volatile,
              area_lines(area.name, core.sections[area.name], detail))
             for area in AREAS if area.name in core.sections]
    nodes = consolidate(core.relations)
    return areas, nodes


def _snapshot_page(request, machine, snapshot):
    detail = request.GET.get("detail") == "1"
    context = {"machine": machine, "snapshot": snapshot, "detail": detail}
    if snapshot is not None and snapshot.data is not None:
        context["areas"], context["nodes"] = _areas(snapshot, detail)
        context["gaps"] = snapshot.gaps.all()
    context["last_failure"] = (machine.snapshots.filter(result=Snapshot.Result.FAILED)
                               .order_by("-collected_at").first())
    context["jobs"] = machine.jobs.all()[:5]
    context["open_alerts"] = machine.alerts.exclude(state=Alert.State.RESOLVED).count()
    context["scanned"] = latest_results(machine_ips(machine, snapshot))
    return render(request, "web/machine_detail.html", context)


def machine_ips(machine, snapshot):
    """The machine's own addresses: local relations of SNAPSHOT and an SSH target address."""
    found = set()
    if snapshot is not None:
        found |= set(snapshot.relations.filter(role="local").values_list("ip", flat=True))
    host = machine.ssh_target.rpartition("@")[2].strip("[]")
    try:
        found.add(str(ipaddress.ip_address(host)))
    except ValueError:
        pass
    return found


@permission("inventory.view_machine")
def machine_detail(request, pk):
    machine = get_object_or_404(Machine, pk=pk)
    return _snapshot_page(request, machine, machine.latest_snapshot())


@permission("inventory.view_snapshot")
def snapshot_detail(request, pk):
    snapshot = get_object_or_404(Snapshot, pk=pk)
    return _snapshot_page(request, snapshot.machine, snapshot)


@permission("inventory.view_snapshot")
def machine_history(request, pk):
    machine = get_object_or_404(Machine, pk=pk)
    snapshots = machine.snapshots.all()[:500]
    return render(request, "web/machine_history.html",
                  {"machine": machine, "snapshots": snapshots})


def gaps_since(machine):
    """Gaps of the latest snapshot, each with the first snapshot of its unbroken run."""
    snapshots = list(machine.snapshots.exclude(result=Snapshot.Result.FAILED)
                     .order_by("-collected_at", "-id").prefetch_related("gaps")[:500])
    if not snapshots:
        return []
    rows = []
    for gap in snapshots[0].gaps.all():
        key = (gap.area, gap.item, gap.status)
        since = snapshots[0]
        for older in snapshots[1:]:
            if key not in {(g.area, g.item, g.status) for g in older.gaps.all()}:
                break
            since = older
        rows.append({"gap": gap, "since": since})
    return rows


@permission("inventory.view_snapshot")
def machine_gaps(request, pk):
    machine = get_object_or_404(Machine, pk=pk)
    return render(request, "web/machine_gaps.html",
                  {"machine": machine, "rows": gaps_since(machine)})


def _edit(request, form_class, instance, template, done):
    form = form_class(request.POST or None, instance=instance)
    if request.method == "POST" and form.is_valid():
        saved = form.save()
        messages.success(request, f"Saved {saved}.")
        return redirect(done)
    return render(request, template, {"form": form, "instance": instance})


@permission("inventory.add_machine")
def machine_create(request):
    return _edit(request, MachineForm, None, "web/form.html", "machine-list")


@permission("inventory.change_machine")
def machine_edit(request, pk):
    machine = get_object_or_404(Machine, pk=pk)
    return _edit(request, MachineForm, machine, "web/form.html", "machine-list")


# Groups and schedules

@permission("inventory.view_group")
def group_list(request):
    return render(request, "web/group_list.html", {
        "groups": Group.objects.prefetch_related("machines"),
        "schedules": Schedule.objects.select_related("machine", "group"),
    })


@permission("inventory.add_group")
def group_create(request):
    return _edit(request, GroupForm, None, "web/form.html", "group-list")


@permission("inventory.change_group")
def group_edit(request, pk):
    return _edit(request, GroupForm, get_object_or_404(Group, pk=pk), "web/form.html",
                 "group-list")


@permission("collection.add_schedule")
def schedule_create(request):
    return _edit(request, ScheduleForm, None, "web/form.html", "group-list")


@permission("collection.change_schedule")
def schedule_edit(request, pk):
    return _edit(request, ScheduleForm, get_object_or_404(Schedule, pk=pk), "web/form.html",
                 "group-list")


@require_POST
@permission("collection.delete_schedule")
def schedule_delete(request, pk):
    get_object_or_404(Schedule, pk=pk).delete()
    messages.success(request, "Schedule deleted.")
    return redirect("group-list")


# Collection

@require_POST
@permission("collection.add_job")
def collect(request):
    """Collect now: machine ids (machine=…) and/or a group (group=…)."""
    machines = list(Machine.objects.filter(id__in=request.POST.getlist("machine")))
    if request.POST.get("group"):
        group = get_object_or_404(Group, pk=request.POST["group"])
        machines += list(group.machines.all())
    jobs = enqueue(machines, origin=Snapshot.Origin.ON_DEMAND, user=request.user)
    messages.info(request, f"{len(jobs)} collection(s) queued; machines with a pending "
                           f"collection, inactive or without SSH target are skipped.")
    target = request.POST.get("next", "")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()},
                                           require_https=request.is_secure()):
        target = "job-list"
    return redirect(target)


@permission("collection.view_job")
def job_list(request):
    return render(request, "web/job_list.html",
                  {"jobs": Job.objects.select_related("machine", "network")[:200]})


@permission("inventory.add_snapshot")
def import_view(request):
    form = ImportForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        upload = form.cleaned_data["bundle"]
        if upload.size > settings.ARIDI_MAX_BUNDLE_BYTES:
            form.add_error("bundle", "The file is too large.")
        else:
            try:
                stored = import_bundle(upload.read(), machine=form.cleaned_data["machine"],
                                       create=form.cleaned_data["create"])
            except NeedsConfirmation as exc:
                form.add_error("machine", f"{exc}. Choose it above to confirm.")
            except ImportRefused as exc:
                form.add_error("bundle", str(exc))
            else:
                state = "Imported" if stored.created else "Already imported"
                messages.success(request, f"{state}: {stored.snapshot}.")
                return redirect("snapshot-detail", pk=stored.snapshot.pk)
    return render(request, "web/import.html", {"form": form})


# Search over the latest snapshot of every machine (TODO.md 5.7)

def latest_snapshot_ids():
    latest = (Snapshot.objects.filter(machine=OuterRef("machine"))
              .exclude(result=Snapshot.Result.FAILED).order_by("-collected_at", "-id"))
    return (Snapshot.objects.exclude(result=Snapshot.Result.FAILED)
            .filter(id=Subquery(latest.values("id")[:1])).values("id"))


def search_rows(kind, query):
    """Rows matching QUERY of KIND in the latest snapshot of each machine."""
    query = query.strip()
    latest = latest_snapshot_ids()
    if kind == "package":
        name, _, version = query.partition("=")
        rows = SnapshotPackage.objects.filter(snapshot__in=latest, name=name.strip())
        if version.strip():
            rows = rows.filter(version=version.strip())
    elif kind == "port":
        proto, _, number = query.rpartition("/")
        if not number.isdigit():
            return None
        rows = SnapshotPort.objects.filter(snapshot__in=latest, port=int(number))
        if proto:
            rows = rows.filter(proto__in=[proto.lower(), proto.lower() + "6"])
    elif kind == "user":
        rows = SnapshotUser.objects.filter(snapshot__in=latest, name=query)
    elif kind == "service":
        rows = SnapshotService.objects.filter(snapshot__in=latest, name=query)
    elif kind == "ip":
        try:
            address = str(ipaddress.ip_address(query))
        except ValueError:
            return None
        rows = Relation.objects.filter(snapshot__in=latest, ip=address)
    else:
        return None
    return rows.select_related("snapshot__machine").order_by("snapshot__machine__name")


@permission("inventory.view_snapshot")
def search(request):
    form = SearchForm(request.GET or None)
    rows = None
    if form.is_valid():
        rows = search_rows(form.cleaned_data["kind"], form.cleaned_data["query"])
        if rows is None:
            form.add_error("query", "This query does not fit the chosen kind.")
    return render(request, "web/search.html", {"form": form, "rows": rows,
                                               "kind": form.data.get("kind")})


# Changes and alerts (phase 6)

def _with_data(machine):
    return machine.snapshots.exclude(result=Snapshot.Result.FAILED).order_by(
        "-collected_at", "-id")


@permission("inventory.view_snapshot")
def machine_compare(request, pk):
    """Comparison of two snapshots of a machine (TODO.md 6.1): ?a=older&b=newer."""
    machine = get_object_or_404(Machine, pk=pk)
    choices = list(_with_data(machine).only("id", "collected_at", "origin")[:200])
    volatile = request.GET.get("volatile") == "1"
    context = {"machine": machine, "choices": choices, "volatile": volatile}
    ids = [choice.id for choice in choices]
    try:
        b_id = int(request.GET.get("b") or (ids[0] if ids else 0))
        if request.GET.get("a"):
            a_id = int(request.GET["a"])
        else:
            # The snapshot just before B.
            position = ids.index(b_id) + 1 if b_id in ids else len(ids)
            a_id = ids[position] if position < len(ids) else 0
    except ValueError:
        raise Http404("snapshot ids are numbers") from None
    if a_id and b_id:
        a = get_object_or_404(_with_data(machine), pk=a_id)
        b = get_object_or_404(_with_data(machine), pk=b_id)
        context.update(a=a, b=b, areas=compare(a.data, b.data, volatile=volatile))
    return render(request, "web/compare.html", context)


ALERT_PAGE = 100


@permission("changes.view_alert")
def alert_list(request):
    form = AlertFilterForm(request.GET or {"state": "open"})
    alerts = Alert.objects.select_related("machine")
    if form.is_valid():
        data = form.cleaned_data
        if data["state"] == "open":
            alerts = alerts.exclude(state=Alert.State.RESOLVED)
        elif data["state"]:
            alerts = alerts.filter(state=data["state"])
        for name in ("severity", "rule", "machine"):
            if data[name]:
                alerts = alerts.filter(**{name: data[name]})
    page = Paginator(alerts, ALERT_PAGE).get_page(request.GET.get("page"))
    query = request.GET.copy()
    query.pop("page", None)
    return render(request, "web/alert_list.html",
                  {"form": form, "page": page, "query": query.urlencode()})


@permission("changes.view_alert")
def alert_detail(request, pk):
    alert = get_object_or_404(Alert.objects.select_related("machine", "snapshot", "previous",
                                                           "changed_by"), pk=pk)
    areas = None
    if (alert.previous is not None and alert.snapshot is not None
            and alert.previous.data is not None and alert.snapshot.data is not None):
        areas = [area for area in compare(alert.previous.data, alert.snapshot.data)
                 if area.interesting]
    return render(request, "web/alert_detail.html", {
        "alert": alert, "rule": BY_CODE.get(alert.rule), "areas": areas,
        "deliveries": alert.deliveries.select_related("channel"),
        "state_form": AlertStateForm(initial={"state": alert.state, "note": alert.note})})


@require_POST
@permission("changes.change_alert")
def alert_state(request, pk):
    alert = get_object_or_404(Alert, pk=pk)
    form = AlertStateForm(request.POST)
    if form.is_valid():
        alert.state = form.cleaned_data["state"]
        alert.note = form.cleaned_data["note"]
        alert.changed_by = request.user
        alert.save(update_fields=["state", "note", "changed_by", "updated_at"])
        messages.success(request, f"Alert marked {alert.state}.")
    else:
        messages.error(request, "Invalid state.")
    return redirect("alert-detail", pk=alert.pk)


@permission("changes.view_ruleoverride")
def rule_list(request):
    return render(request, "web/rule_list.html", {
        "rules": RULES,
        "overrides": RuleOverride.objects.select_related("machine", "group")})


@permission("changes.add_ruleoverride")
def override_create(request):
    return _edit(request, RuleOverrideForm, None, "web/form.html", "rule-list")


@permission("changes.change_ruleoverride")
def override_edit(request, pk):
    return _edit(request, RuleOverrideForm, get_object_or_404(RuleOverride, pk=pk),
                 "web/form.html", "rule-list")


@require_POST
@permission("changes.delete_ruleoverride")
def override_delete(request, pk):
    get_object_or_404(RuleOverride, pk=pk).delete()
    messages.success(request, "Override deleted.")
    return redirect("rule-list")


@permission("changes.view_channel")
def channel_list(request):
    return render(request, "web/channel_list.html", {
        "channels": Channel.objects.prefetch_related("groups"),
        # Names only: the URLs are secrets of the environment.
        "webhooks": sorted(settings.ARIDI_WEBHOOKS),
        "smtp": bool(settings.EMAIL_HOST),
        "recent": Delivery.objects.select_related("alert__machine", "channel")
                  .order_by("-id")[:50]})


@permission("changes.add_channel")
def channel_create(request):
    return _edit(request, ChannelForm, None, "web/form.html", "channel-list")


@permission("changes.change_channel")
def channel_edit(request, pk):
    return _edit(request, ChannelForm, get_object_or_404(Channel, pk=pk), "web/form.html",
                 "channel-list")


@require_POST
@permission("changes.delete_channel")
def channel_delete(request, pk):
    get_object_or_404(Channel, pk=pk).delete()
    messages.success(request, "Channel deleted.")
    return redirect("channel-list")


# Relation map (TODO.md 6.5)

MAP_PAGE = 100


@permission("inventory.view_snapshot")
def machine_map(request, pk):
    machine = get_object_or_404(Machine, pk=pk)
    snapshot = machine.latest_snapshot()
    context = {"machine": machine, "snapshot": snapshot}
    if snapshot is not None:
        # The open ports found by scanning (phase 7) join the relations of the snapshot.
        data = dict(snapshot.data, relations=snapshot.data.get("relations", []) + [
            {"ip": r.ip, "role": r.role, "source": r.source, "detail": r.detail}
            for r in snapshot.relations.filter(source="scan")])
        relation_map = build_map(data, snapshot.data["machine"].get("hostname"))
        rows = (relation_map.local
                + [node for subnet in relation_map.subnets for node in subnet.nodes]
                + relation_map.outside)
        context.update(map=relation_map,
                       page=Paginator(rows, MAP_PAGE).get_page(request.GET.get("page")))
    return render(request, "web/machine_map.html", context)


# Network discovery (TODO.md 7.2 and 7.3)

@permission("discovery.view_authorizednetwork")
def network_list(request):
    return render(request, "web/network_list.html", {
        "networks": AuthorizedNetwork.objects.select_related("authorized_by"),
        "enabled": settings.ARIDI_SCAN_ENABLED,
        "max_v4": settings.ARIDI_SCAN_MAX_PREFIX_V4,
        "max_v6": settings.ARIDI_SCAN_MAX_PREFIX_V6})


@permission("discovery.add_authorizednetwork")
def network_create(request):
    form = AuthorizedNetworkForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        network = form.save(commit=False)
        network.authorized_by = request.user
        network.save()
        messages.success(request, f"Network {network} authorized.")
        return redirect("network-list")
    return render(request, "web/form.html", {"form": form, "instance": None})


@permission("discovery.change_authorizednetwork")
def network_edit(request, pk):
    network = get_object_or_404(AuthorizedNetwork, pk=pk)
    form = AuthorizedNetworkForm(request.POST or None, instance=network)
    if request.method == "POST" and form.is_valid():
        changed = form.save(commit=False)
        # Changing a network is authorizing it again.
        changed.authorized_by, changed.authorized_at = request.user, timezone.now()
        changed.save()
        messages.success(request, f"Saved {changed}.")
        return redirect("network-list")
    return render(request, "web/form.html", {"form": form, "instance": network})


@require_POST
@permission("discovery.delete_authorizednetwork")
def network_delete(request, pk):
    get_object_or_404(AuthorizedNetwork, pk=pk).delete()
    messages.success(request, "Network removed: it will not be scanned any more.")
    return redirect("network-list")


@permission("discovery.view_scanresult")
def network_detail(request, pk):
    network = get_object_or_404(AuthorizedNetwork, pk=pk)
    last = network.results.order_by("-scanned_at").values_list("scanned_at", flat=True).first()
    results = network.results.filter(scanned_at=last) if last else []
    return render(request, "web/network_detail.html", {
        "network": network, "last": last, "results": results,
        "jobs": network.jobs.all()[:20], "enabled": settings.ARIDI_SCAN_ENABLED})


@require_POST
@permission("collection.add_job")
def network_scan(request, pk):
    network = get_object_or_404(AuthorizedNetwork, pk=pk)
    if not settings.ARIDI_SCAN_ENABLED:
        messages.error(request, "Scanning is disabled in this central (ARIDI_SCAN_ENABLED).")
    elif enqueue_scan(network, user=request.user) is None:
        messages.info(request, "Not queued: the network is inactive or already has a scan "
                               "pending.")
    else:
        messages.info(request, f"Scan of {network} queued.")
    return redirect("network-detail", pk=network.pk)
