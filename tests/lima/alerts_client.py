"""Web client of the phase 6 acceptance (tests/lima/central-acceptance.sh alerts), run in
"web". One stage per call; the script changes the VM between stages.

Arguments: STAGE SSH_TARGET SSH_PORT ADMIN_PASSWORD
  baseline   add the VM and a webhook channel; two collections; the second raises nothing
  changes    collect: a user with a shell and a new port give two alerts, in the web and
             in the webhook
  silenced   silence both rules for the VM; collect: a second user and port raise nothing
  stopped    the VM is off: three failed collections give "does not respond"
"""

import json
import re
import sys
import time
import urllib.request

sys.path.insert(0, "/t")
from acceptance_client import Browser, check  # noqa: E402

STAGE, TARGET, PORT, ADMIN_PASSWORD = sys.argv[1:5]
NAME = "debian12-arm64"

admin = Browser()
admin.login("admin", ADMIN_PASSWORD)


def machine_id():
    _, _, body = admin.request("GET", "/")
    found = re.search(rf'href="/machines/(\d+)/">{NAME}<', body)
    return found.group(1) if found else None


def collect(machine, expect="done", seconds=420):
    """Ask for a collection and wait for its job to end in EXPECT."""
    before = finished(machine)
    status, _, _ = admin.request("POST", "/collect/", {"machine": machine})
    check(status == 302, "collection queued")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        now = finished(machine)
        if now[expect] > before[expect]:
            return
        if expect == "done" and now["failed"] > before["failed"]:
            sys.exit("acceptance: FAIL the collection failed")
        time.sleep(3)
    sys.exit(f"acceptance: FAIL no {expect} collection after {seconds} s")


def finished(machine):
    _, _, body = admin.request("GET", "/jobs/")
    rows = re.findall(rf'href="/machines/{machine}/">[^<]*</a></td>\s*<td>[^<]*</td>'
                      rf'<td class="(\w+)">', body)
    return {"done": rows.count("done"), "failed": rows.count("failed")}


def alerts(state="open"):
    """[(id, title)] of the alerts of the VM in the web."""
    _, _, body = admin.request("GET", f"/alerts/?state={state}&machine={machine_id()}")
    return re.findall(r'<a href="/alerts/(\d+)/">([^<]*)</a>', body)


def hook():
    with urllib.request.urlopen("http://hook:8080/", timeout=10) as response:
        return json.load(response)


def wait_hook(ids, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        got = {body["alert"]["id"] for body in hook()}
        if set(ids) <= got:
            return
        time.sleep(3)
    sys.exit(f"acceptance: FAIL the webhook did not receive alerts {sorted(ids)}")


def new_since(known):
    return [(i, t) for i, t in alerts("") if i not in known]


def report(found):
    for alert_id, title in found:
        print(f"acceptance:    alert {alert_id}: {title}")


if STAGE == "baseline":
    status, _, _ = admin.request("POST", "/machines/new/", {
        "name": NAME, "ssh_target": TARGET, "ssh_port": PORT, "privilege": "sudo",
        "active": "on"})
    check(status == 302, "the administrator adds the Lima VM")
    status, _, body = admin.request("POST", "/channels/new/", {
        "name": "test-hook", "kind": "webhook", "target": "test", "min_severity": "low",
        "active": "on"})
    check(status == 302, "a webhook channel (ARIDI_WEBHOOK_URL_TEST)")
    machine = machine_id()
    collect(machine)
    first = alerts("")
    print(f"acceptance: ok first collection ({len(first)} alert(s) about its state)")
    report(first)
    collect(machine)
    second = new_since({i for i, _ in first})
    report(second)
    check(not second, "a second collection without changes raises no alert")

elif STAGE == "changes":
    machine = machine_id()
    known = {i for i, _ in alerts("")}
    collect(machine)
    found = new_since(known)
    report(found)
    titles = [t for _, t in found]
    check(any(re.match(r"New user mallory with login shell /bin/bash", t) for t in titles),
          "alert: new user with a shell, in the web")
    check(any(re.match(r"New listening socket tcp6? \S+ port 4444", t) for t in titles),
          "alert: new listening port 4444, in the web")
    check(len(found) == 2, "exactly those two alerts")
    wait_hook([int(i) for i, _ in found])
    check(True, "both alerts delivered to the test webhook")
    _, _, body = admin.request("GET", f"/alerts/{found[0][0]}/")
    check("What changed" in body, "the alert shows the comparison")

elif STAGE == "silenced":
    machine = machine_id()
    for rule in ("privileged_user", "new_listening_port"):
        status, _, _ = admin.request("POST", "/rules/overrides/new/", {
            "rule": rule, "machine": machine, "silenced": "on"})
        check(status == 302, f"rule {rule} silenced for the VM")
    known = {i for i, _ in alerts("")}
    delivered = len(hook())
    collect(machine)
    found = new_since(known)
    report(found)
    check(not [t for _, t in found if "trudy" in t or "4445" in t],
          "the silenced rules raise nothing for the new user and port")
    _, _, body = admin.request("GET", f"/machines/{machine}/compare/")
    check("trudy" in body and "4445" in body, "the comparison still shows the changes")
    time.sleep(10)
    check(len(hook()) == delivered + len(found), "nothing more reached the webhook")

elif STAGE == "stopped":
    machine = machine_id()
    for n in range(3):
        collect(machine, expect="failed", seconds=180)
        print(f"acceptance: ok failed collection {n + 1} of 3")
    found = [(i, t) for i, t in alerts() if "does not respond" in t]
    report(found)
    check(len(found) == 1, "alert: the machine does not respond, in the web")
    wait_hook([int(found[0][0])])
    check(True, "the alert reached the webhook")

else:
    sys.exit(f"unknown stage {STAGE}")
