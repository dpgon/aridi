"""Comparison of two snapshots, area by area (TODO.md 6.1), with synthetic pairs."""

from django.test import SimpleTestCase

from aridi.interpret import AREAS

from aridi_central.changes.diff import SPEC, compare
from aridi_central.changes.tests.helpers import (add_listening, add_user, data, set_status,
                                                 snapshot)


def by_area(diffs):
    return {d.area: d for d in diffs}


def changes(diff, collection=None):
    return [(c.collection, c.key, c.kind) for c in diff.changes
            if collection is None or c.collection == collection]


class CompareTest(SimpleTestCase):

    def test_same_snapshot_has_no_changes(self):
        for name, variant in (("vm-debian12-arm64", "vm"), ("alpine320", "server"),
                              ("centos6", "server")):
            with self.subTest(sample=name):
                snap = snapshot(name, variant)
                diffs = compare(snap, snapshot(name, variant), volatile=True)
                self.assertEqual([d.area for d in diffs if d.interesting], [])

    def test_every_area_has_a_specification(self):
        self.assertEqual(set(SPEC), {area.name for area in AREAS})

    def test_volatile_areas_only_on_request(self):
        stable = {d.area for d in compare(snapshot(), snapshot())}
        everything = {d.area for d in compare(snapshot(), snapshot(), volatile=True)}
        self.assertEqual(everything - stable,
                         {a.name for a in AREAS if a.volatile})

    def test_ok_to_denied_is_lost_not_everything_removed(self):
        before = snapshot()
        after = set_status(snapshot(), "users", "denied", "cannot read /etc/passwd")
        users = by_area(compare(before, after))["users"]
        self.assertEqual(users.state, "lost")
        self.assertEqual(users.after, "denied")
        self.assertEqual(users.changes, [])
        back = by_area(compare(after, before))["users"]
        self.assertEqual(back.state, "regained")
        self.assertEqual(back.changes, [])

    def test_not_seen_in_either(self):
        before = set_status(snapshot(), "firewall", "denied")
        after = set_status(snapshot(), "firewall", "denied")
        self.assertEqual(by_area(compare(before, after))["firewall"].state, "unavailable")

    def test_packages_added_removed_and_upgraded(self):
        before, after = snapshot(), snapshot()
        packages = data(after, "packages")["packages"]
        removed = packages.pop(0)
        packages[0]["version"] = "99.0"
        packages.append({"name": "netcat", "version": "1.0", "arch": "arm64",
                         "manager": "dpkg"})
        diff = by_area(compare(before, after))["packages"]
        self.assertEqual(diff.state, "changed")
        kinds = {key: kind for _, key, kind in changes(diff)}
        self.assertEqual(kinds["dpkg netcat arm64"], "added")
        self.assertEqual(kinds[f"dpkg {removed['name']} {removed['arch']}"], "removed")
        upgraded = [c for c in diff.changes if c.kind == "changed"]
        self.assertEqual(len(upgraded), 1)
        self.assertEqual(upgraded[0].after, {"version": "99.0"})

    def test_users_by_name_and_groups(self):
        before, after = snapshot(), add_user(snapshot())
        root = data(after, "users")["users"][0]
        root["shell"] = "/bin/zsh"
        diff = by_area(compare(before, after))["users"]
        self.assertIn(("users", "mallory", "added"), changes(diff))
        change = [c for c in diff.changes if c.key == "root"][0]
        self.assertEqual((change.before, change.after), ({"shell": "/bin/bash"},
                                                         {"shell": "/bin/zsh"}))

    def test_password_states_ignored_when_shadow_was_not_read(self):
        before, after = snapshot(), snapshot()
        users = data(after, "users")
        users["shadow_read"] = False
        for user in users["users"]:
            user["password"], user["algorithm"] = "unknown", None
        diff = by_area(compare(before, after))["users"]
        self.assertEqual(diff.changes, [])
        self.assertTrue(diff.notes)

    def test_listening_socket_key(self):
        before, after = snapshot(), add_listening(snapshot())
        diff = by_area(compare(before, after))["network"]
        self.assertEqual(changes(diff, "listening sockets"),
                         [("listening sockets", "tcp 0.0.0.0 4444", "added")])

    def test_service_state_and_kernel_scalar(self):
        before, after = snapshot(), snapshot()
        service = data(after, "services")["services"][0]
        service["active"] = "failed"
        data(after, "system")["kernel"]["release"] = "6.12.0-new"
        diffs = by_area(compare(before, after))
        self.assertEqual([c.after for c in diffs["services"].changes], [{"active": "failed"}])
        self.assertEqual(changes(diffs["system"]), [("kernel release", "kernel release",
                                                     "changed")])

    def test_suid_and_banners(self):
        before, after = snapshot(), snapshot()
        data(after, "permissions")["suid"].append(
            {"path": "/tmp/.x", "mode": "4755", "uid": 0, "gid": 0, "root_owned": True})
        data(after, "identity")["banners"]["/etc/motd"]["text"] = "changed"
        diffs = by_area(compare(before, after))
        self.assertIn(("SUID binaries", "/tmp/.x", "added"), changes(diffs["permissions"]))
        self.assertIn(("banners", "/etc/motd", "changed"), changes(diffs["identity"]))

    def test_item_gap_that_appears(self):
        before, after = snapshot(), snapshot()
        after["sections"]["storage"]["gaps"].append(
            {"item": "usage", "status": "missing", "reason": "no df"})
        diff = by_area(compare(before, after))["storage"]
        self.assertEqual(diff.state, "changed")
        self.assertEqual(diff.gaps_lost, ["usage (missing)"])

    def test_volatile_processes_compared_on_request(self):
        before, after = snapshot(), snapshot()
        data(after, "processes")["processes"].append(
            {"pid": 4242, "ppid": 1, "comm": "miner", "state": "R", "user": "nobody",
             "cmdline": "/tmp/miner"})
        diff = by_area(compare(before, after, volatile=True))["processes"]
        self.assertIn(("processes", "nobody miner /tmp/miner", "added"), changes(diff))
