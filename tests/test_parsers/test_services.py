"""Area "services" (src/aridi/parsers/services.py), TODO.md 3.8."""

import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Status
from aridi.parsers import services
from tests.helpers import CORPUS, SYSTEMD_VMS, facts, make_bundle, sample_name, samples


def services_of(sample_dir):
    return interpret(bundle.read(sample_dir / "bundle.aridi")).sections["services"]


def parse(*sections):
    return services.parse(dict(bundle.parse(make_bundle(sections)).sections))


class CorpusTest(unittest.TestCase):

    def test_area_never_fails(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = services_of(sample)
                self.assertEqual(section.status, Status.OK)
                self.assertEqual([g for g in section.gaps if g.status != Status.NA], [])

    def test_vms_with_systemd_show_the_failed_service(self):
        for name in SYSTEMD_VMS:
            with self.subTest(sample=name):
                sample = CORPUS / name / "vm"
                data = services_of(sample).data
                self.assertTrue(data["systemd_running"])
                self.assertIn("aridi-fails", data["failed"])
                el = ("vm-rocky9-arm64", "vm-alma10-arm64", "vm-centos7-amd64")
                ssh = "sshd" if name in el else "ssh"
                running = {s["name"] for s in data["services"] if s["active"] == "active"}
                self.assertIn(ssh, running)
                # Same failed units as systemctl in facts.txt (UNIT LOAD ACTIVE SUB ...;
                # "failed" can also be a word of the description).
                rows = [line.split() for line in
                        facts(sample)["services_systemctl"].splitlines()]
                failed = sorted(row[0].removesuffix(".service") for row in rows
                                if len(row) >= 3 and row[0].endswith(".service")
                                and row[2] == "failed")
                self.assertEqual(data["failed"], failed)

    def test_centos7_container_systemctl_without_systemd(self):
        """docs/MVP.md n.º 19: systemctl present, systemd not running."""
        section = services_of(CORPUS / "centos7" / "minimal")
        self.assertEqual(section.status, Status.OK)
        self.assertFalse(section.data["systemd_running"])
        self.assertIn("sysv", section.data["managers"])
        self.assertNotIn("systemd", section.data["managers"])

    def test_centos6_sysv(self):
        data = services_of(CORPUS / "centos6" / "minimal").data
        self.assertEqual(data["managers"], ["sysv"])

    def test_centos6_vm_sysv_runlevels(self):
        """A booted SysV machine: the runlevels of chkconfig, and no guessed state.

        Knowing whether a SysV service runs means running its init script ("service X
        status"), which aridi never does; so "active" is unknown, not "inactive".
        """
        sample = CORPUS / "vm-centos6-amd64" / "vm"
        data = services_of(sample).data
        self.assertEqual(data["managers"], ["sysv"])
        self.assertFalse(data["systemd_running"])
        by_name = {s["name"]: s for s in data["services"]}
        for name in ("sshd", "ntpd"):
            self.assertEqual(by_name[name]["enabled"], "enabled")
            self.assertIn("3", by_name[name]["runlevels"])
        self.assertEqual({s["active"] for s in data["services"]}, {None})
        # Same runlevels as chkconfig in facts.txt.
        for line in facts(sample)["services_chkconfig"].splitlines():
            fields = line.split()
            if len(fields) == 8 and fields[0] in by_name:
                levels = [f.split(":")[0] for f in fields[1:] if f.endswith(":on")]
                self.assertEqual(by_name[fields[0]]["runlevels"], levels, fields[0])

    def test_alpine_openrc(self):
        """OpenRC is installed in the server variant; the image enables no service."""
        data = services_of(CORPUS / "alpine320" / "server").data
        self.assertIn("openrc", data["managers"])
        self.assertIn("default", data["openrc_runlevels"])
        self.assertNotIn("openrc", services_of(CORPUS / "alpine320" / "minimal").data["managers"])


class SyntheticTest(unittest.TestCase):

    def test_systemd_units_and_unit_files(self):
        units = (b"ssh.service loaded active running OpenBSD Secure Shell server\n"
                 b"\xe2\x97\x8f broken.service loaded failed failed Broken thing\n"
                 b"systemd-journald.socket loaded active running Journal Socket\n")
        files = (b"ssh.service enabled enabled\nbroken.service enabled enabled\n"
                 b"cron.service disabled enabled\ngetty@.service enabled enabled\n")
        data = parse(("services.systemd_units", units),
                     ("services.systemd_unit_files", files)).data
        by_name = {s["name"]: s for s in data["services"]}
        self.assertEqual(sorted(by_name), ["broken", "cron", "ssh"])
        self.assertEqual(by_name["ssh"]["enabled"], "enabled")
        self.assertEqual(by_name["cron"]["active"], "inactive")
        self.assertEqual(data["failed"], ["broken"])

    def test_chkconfig_and_rc_links(self):
        chkconfig = (b"crond          \t0:off\t1:off\t2:on\t3:on\t4:on\t5:on\t6:off\n"
                     b"netconsole     \t0:off\t1:off\t2:off\t3:off\t4:off\t5:off\t6:off\n"
                     b"\nxinetd based services:\n\tchargen-dgram:\toff\n")
        rc_d = b"/etc/rc.d/rc3.d:\nK10network\nS90sshd\n/etc/rc.d/rc5.d:\nS90sshd\n"
        data = parse(("services.chkconfig", chkconfig), ("services.rc_d", rc_d)).data
        by_name = {s["name"]: s for s in data["services"]}
        self.assertEqual(by_name["crond"]["runlevels"], ["2", "3", "4", "5"])
        self.assertEqual(by_name["netconsole"]["enabled"], "disabled")
        self.assertEqual(by_name["sshd"]["runlevels"], ["3", "5"])
        self.assertEqual(by_name["network"]["enabled"], "disabled")

    def test_openrc_and_runit(self):
        levels = b"boot:\nhostname\ndefault:\nsshd\ncrond\n"
        status = (b"Runlevel: default\n sshd       [  started  ]\n crond     [  stopped  ]\n"
                  b"Dynamic Runlevel: hotplugged\n")
        runit = b"run: /var/service/sshd: (pid 99) 600s; run: log: (pid 98) 600s\n"
        data = parse(("services.openrc_runlevels", levels), ("services.openrc_status", status),
                     ("services.runit", runit)).data
        by_name = {(s["manager"], s["name"]): s for s in data["services"]}
        self.assertEqual(by_name[("openrc", "sshd")]["active"], "started")
        self.assertEqual(by_name[("openrc", "hostname")]["runlevels"], ["boot"])
        self.assertEqual(by_name[("runit", "sshd")]["active"], "run")

    def test_no_manager_is_not_applicable(self):
        result = parse(("services.systemd_units", b"", "na", "-", "systemd is not running"))
        self.assertEqual([(g.item, g.status) for g in result.gaps],
                         [("service manager", Status.NA)])


if __name__ == "__main__":
    unittest.main()
