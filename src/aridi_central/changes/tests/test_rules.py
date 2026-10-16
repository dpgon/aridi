"""Each built-in rule with a pair that raises it and one that does not (TODO.md 6.2)."""

from django.test import SimpleTestCase

from aridi_central.changes import rules
from aridi_central.changes.tests.helpers import (add_listening, add_user, data, set_status,
                                                 snapshot)


def keys(rule, before, after, threshold=None):
    found = getattr(rules, rule)(before, after, threshold or rules.BY_CODE[rule].threshold)
    return [f.key for f in found]


def mount(after, mountpoint, percent, fstype="ext4", options=("rw",)):
    data(after, "storage")["mounts"].append({
        "mountpoint": mountpoint, "fstype": fstype, "source": "/dev/vdb",
        "options": list(options), "usage": {"filesystem": "/dev/vdb", "size": 1000,
                                            "used": percent * 10,
                                            "available": 1000 - percent * 10,
                                            "percent": percent}})
    return after


class RuleTest(SimpleTestCase):

    def test_registry(self):
        self.assertEqual(len(rules.RULES), 9)
        self.assertEqual(len(rules.BY_CODE), 9)
        for rule in rules.RULES:
            self.assertIn(rule.severity, rules.Severity.values)
            self.assertEqual(rule.check is None, rule.code == rules.UNRESPONSIVE)

    def test_nothing_fires_between_equal_snapshots(self):
        for rule in rules.RULES:
            if rule.check is None:
                continue
            with self.subTest(rule=rule.code):
                self.assertEqual(rule.check(snapshot(), snapshot(), rule.threshold), [])

    def test_privileged_user(self):
        before = snapshot()
        self.assertEqual(keys("privileged_user", before, add_user(snapshot())),
                         ["mallory:new"])
        self.assertEqual(keys("privileged_user", before,
                              add_user(snapshot(), shell="/usr/sbin/nologin")), [])
        self.assertEqual(keys("privileged_user", before,
                              add_user(snapshot(), shell="/usr/sbin/nologin", uid=0)),
                         ["mallory:new"])
        self.assertEqual(keys("privileged_user", before,
                              add_user(snapshot(), shell="/bin/false",
                                       groups=["mallory", "wheel"])), ["mallory:new"])

    def test_existing_user_gains_privileges(self):
        before, after = snapshot(), snapshot()
        users = {u["name"]: u for u in data(after, "users")["users"]}
        daemon = users["daemon"]
        self.assertFalse(rules._privileges(daemon))
        daemon["shell"] = "/bin/sh"
        daemon["groups"] = daemon["groups"] + ["sudo"]
        self.assertEqual(keys("privileged_user", before, after),
                         ["daemon:group:sudo", "daemon:shell"])

    def test_first_snapshot_raises_no_change_alerts(self):
        for code in ("privileged_user", "new_listening_port", "service_failed",
                     "new_privileged_binary", "kernel_changed", "area_lost"):
            with self.subTest(rule=code):
                self.assertEqual(keys(code, None, add_user(add_listening(snapshot()))), [])

    def test_new_listening_port(self):
        self.assertEqual(keys("new_listening_port", snapshot(), add_listening(snapshot())),
                         ["tcp/0.0.0.0/4444"])
        # Same socket on both: nothing.
        self.assertEqual(keys("new_listening_port", add_listening(snapshot()),
                              add_listening(snapshot())), [])

    def test_service_failed(self):
        before = snapshot()
        self.assertIn("aridi-fails", data(before, "services")["failed"])
        after = snapshot()
        data(after, "services")["failed"].append("nginx")
        self.assertEqual(keys("service_failed", before, after), ["nginx"])
        # Already failed before: nothing new.
        self.assertEqual(keys("service_failed", after, after), [])

    def test_new_privileged_binary(self):
        before, after = snapshot(), snapshot()
        data(after, "permissions")["sgid"].append(
            {"path": "/usr/local/bin/x", "mode": "2755", "uid": 0, "gid": 0})
        self.assertEqual(keys("new_privileged_binary", before, after),
                         ["sgid:/usr/local/bin/x"])
        # A partial search before: what it missed is not "new".
        before["sections"]["permissions"]["gaps"].append(
            {"item": "search", "status": "timeout", "reason": "find ran out of time"})
        self.assertEqual(keys("new_privileged_binary", before, after), [])

    def test_kernel_changed(self):
        after = snapshot()
        data(after, "system")["kernel"]["release"] = "6.12.0-new"
        self.assertEqual(len(keys("kernel_changed", snapshot(), after)), 1)

    def test_disk_full_threshold_and_transition(self):
        before = snapshot()
        after = mount(snapshot(), "/srv", 95)
        self.assertEqual(keys("disk_full", before, after), ["/srv"])
        self.assertEqual(keys("disk_full", before, after, threshold=96), [])
        self.assertEqual(keys("disk_full", None, after), ["/srv"])     # a state: first too
        self.assertEqual(keys("disk_full", after, mount(snapshot(), "/srv", 97)), [])
        for fstype, options in (("squashfs", ("ro",)), ("ext4", ("ro",)), ("tmpfs", ("rw",))):
            with self.subTest(fstype=fstype, options=options):
                self.assertEqual(keys("disk_full", before,
                                      mount(snapshot(), "/x", 100, fstype, options)), [])

    def test_account_file_permissions(self):
        # Debian ships /etc/shadow 0640 root:shadow: the core's 0400 says "too open", the
        # rule does not.
        shipped = {e["path"]: e for e in data(snapshot(), "permissions")["account_files"]}
        self.assertEqual(shipped["/etc/shadow"]["mode"], "0640")
        self.assertTrue(shipped["/etc/shadow"]["too_open"])
        self.assertEqual(keys("account_file_permissions", None, snapshot()), [])
        for mode, gid, uid, raised in (("0644", 42, 0, True), ("0660", 42, 0, True),
                                       ("0640", 1000, 0, True), ("0640", 0, 0, False),
                                       ("0000", 0, 0, False), ("0400", 0, 1000, True)):
            with self.subTest(mode=mode, gid=gid, uid=uid):
                after = snapshot()
                shadow = [e for e in data(after, "permissions")["account_files"]
                          if e["path"] == "/etc/shadow"][0]
                shadow.update(mode=mode, gid=gid, uid=uid)
                expected = ["/etc/shadow"] if raised else []
                self.assertEqual(keys("account_file_permissions", snapshot(), after),
                                 expected)
                self.assertEqual(keys("account_file_permissions", None, after), expected)
                self.assertEqual(keys("account_file_permissions", after, after), [])
        after = snapshot()
        passwd = [e for e in data(after, "permissions")["account_files"]
                  if e["path"] == "/etc/passwd"][0]
        passwd.update(mode="0666", too_open=True)
        self.assertEqual(keys("account_file_permissions", snapshot(), after), ["/etc/passwd"])

    def test_area_lost(self):
        before = snapshot()
        self.assertEqual(keys("area_lost", before, set_status(snapshot(), "packages",
                                                              "timeout")), ["packages"])
        self.assertEqual(keys("area_lost", before, set_status(snapshot(), "firewall", "na")),
                         [])

    def test_volatile_areas_raise_nothing(self):
        before, after = snapshot(), snapshot()
        data(after, "processes")["processes"].append({"pid": 1, "comm": "x", "user": "root"})
        data(after, "connections")["connections"] = []
        set_status(after, "load", "timeout")
        set_status(after, "neighbours", "denied")
        for rule in rules.RULES:
            if rule.check is not None:
                with self.subTest(rule=rule.code):
                    self.assertEqual(rule.check(before, after, rule.threshold), [])
