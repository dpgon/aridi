"""Area "storage" (src/aridi/parsers/storage.py), TODO.md 3.4."""

import re
import unittest

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Status
from aridi.parsers import storage
from tests.helpers import (CORPUS, VMS, facts, legacy_bundle, legacy_report, make_bundle,
                           sample_name, samples)


def storage_of(path):
    return interpret(bundle.read(path)).sections["storage"]


def parse(*sections):
    return storage.parse(dict(bundle.parse(make_bundle(sections)).sections))


class CorpusTest(unittest.TestCase):

    def test_mounts_and_usage_match_facts(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = storage_of(sample / "bundle.aridi")
                ref = facts(sample)
                self.assertEqual(section.status, Status.OK)
                self.assertEqual(section.gaps, [])
                expected = [(storage.unescape(line.split(" - ")[0].split()[4]),
                             line.split(" - ")[1].split()[0])
                            for line in ref["mountinfo"].splitlines() if " - " in line]
                got = [(m["mountpoint"], m["fstype"]) for m in section.data["mounts"]]
                self.assertEqual(got, expected)
                for line in ref["df"].splitlines()[1:]:
                    fields = line.split()
                    mount = next(m for m in section.data["mounts"]
                                 if m["mountpoint"] == fields[5] and m["usage"])
                    self.assertEqual(mount["usage"]["size"], int(fields[1]) * 1024)
                    # df prints KiB: below 1 MiB its own rounding exceeds one point.
                    if int(fields[1]) >= 1024:
                        self.assertLessEqual(
                            abs(mount["usage"]["percent"] - int(fields[4][:-1])), 1, fields[5])

    def test_no_host_directory_in_any_sample(self):
        """Lima VMs used to mount the host home directory (tests/corpus/README.md)."""
        paths = [sample / "bundle.aridi" for sample in samples()]
        paths += [legacy_bundle("debian12"), legacy_bundle("centos7")]
        for path in paths:
            with self.subTest(bundle=str(path)):
                for mount in storage_of(path).data["mounts"]:
                    self.assertNotIn(mount["fstype"], ("virtiofs", "9p", "fuse.sshfs"))
                    self.assertFalse(mount["mountpoint"].startswith("/Users/"))

    def test_bind_and_tmpfs_of_the_scenario(self):
        for sample in samples():
            if sample.name == "vm":
                continue
            with self.subTest(sample=sample_name(sample)):
                mounts = {m["mountpoint"]: m for m in
                          storage_of(sample / "bundle.aridi").data["mounts"]}
                self.assertTrue(mounts["/srv/bind"]["bind"])
                self.assertIn("ro", mounts["/srv/bind"]["options"])
                self.assertEqual(mounts["/srv/scratch"]["fstype"], "tmpfs")
                self.assertFalse(mounts["/srv/scratch"]["bind"])

    def test_current_lsblk_does_not_break(self):
        """docs/MVP.md n.º 13: the lsblk of current distributions broke the area in 2019."""
        for name in ("debian12", "ubuntu2404", "rocky9", "fedora44"):
            with self.subTest(sample=name):
                section = storage_of(CORPUS / name / "server" / "bundle.aridi")
                self.assertEqual(section.status, Status.OK)
                self.assertTrue(section.data["lsblk"])

    def test_centos6_without_lsblk(self):
        section = storage_of(CORPUS / "centos6" / "minimal" / "bundle.aridi")
        self.assertEqual(section.status, Status.OK)
        self.assertIsNone(section.data["lsblk"])
        self.assertEqual(section.gaps, [])
        self.assertTrue(section.data["devices"])

    def test_vm_root_filesystem(self):
        for name in VMS:
            with self.subTest(sample=name):
                data = storage_of(CORPUS / name / "vm" / "bundle.aridi").data
                root = next(m for m in data["mounts"] if m["mountpoint"] == "/")
                self.assertIn(root["fstype"], ("ext4", "xfs", "btrfs"))
                self.assertGreater(root["usage"]["size"], 1 << 30)
                self.assertTrue(any(d["kind"] == "part" for d in data["devices"]))


class LegacyRegressionTest(unittest.TestCase):

    def test_centos7_same_disks_and_mounted_partition(self):
        report = legacy_report("centos7")
        disks = re.findall(r"^(\w+)\s+- Size: (\S+)$", report, re.M)
        data = storage_of(legacy_bundle("centos7")).data
        devices = {d["name"]: d for d in data["devices"]}
        for name, _ in disks:
            self.assertEqual(devices[name]["kind"], "disk")
        mount = re.search(r"Mounted partitions:.*?\n\n(\w+)\s*\n \|__(\S+)\n \|__Filesystem: (\w+)",
                          report, re.S)
        part, mountpoint, fstype = mount.groups()
        found = [m for m in data["mounts"] if m["mountpoint"] == mountpoint]
        self.assertEqual([(m["source"], m["fstype"]) for m in found],
                         [(f"/dev/{part}", fstype)])


class SyntheticTest(unittest.TestCase):

    def test_mountinfo_escapes_btrfs_subvolumes_and_repeats(self):
        mountinfo = (
            b"22 1 0:30 /@ / rw,relatime shared:1 - btrfs /dev/sda2 rw,subvol=/@\n"
            b"23 22 0:30 /@home /home rw,relatime shared:2 - btrfs /dev/sda2 rw,subvol=/@home\n"
            b"24 22 8:1 / /boot rw - ext4 /dev/sda1 rw\n"
            b"25 22 8:1 / /mnt/boot\\040copy rw - ext4 /dev/sda1 rw\n"
            b"26 22 8:1 /grub /srv/grub ro - ext4 /dev/sda1 rw\n"
            b"broken line\n")
        mounts = parse(("storage.mountinfo", mountinfo)).data["mounts"]
        self.assertEqual([m["mountpoint"] for m in mounts],
                         ["/", "/home", "/boot", "/mnt/boot copy", "/srv/grub"])
        self.assertEqual([m["subvolume"] for m in mounts[:2]], ["/@", "/@home"])
        self.assertEqual([m["bind"] for m in mounts], [False, False, False, True, True])

    def test_df_percent_like_df(self):
        df = (b"Filesystem 1024-blocks Used Available Capacity Mounted on\n"
              b"/dev/sda1 1000 333 667 34% /\n"
              b"/dev/sdb1 1000 0 0 0% /full of spaces\n")
        usage = storage.parse_df(df.decode())
        self.assertEqual(usage["/"]["percent"], 34)
        self.assertEqual(usage["/"]["used"], 333 * 1024)
        self.assertEqual(usage["/full of spaces"]["percent"], 0)

    def test_lsblk_pairs_with_quotes_and_empty_values(self):
        rows = storage.parse_lsblk('NAME="sda" TYPE="disk" SIZE="100" MOUNTPOINT=""\n'
                                   'NAME="sda1" TYPE="part" MOUNTPOINT="/a \\"b\\""\n')
        self.assertEqual(rows[0]["mountpoint"], "")
        self.assertEqual(rows[1]["mountpoint"], '/a "b"')

    def test_block_kinds_and_partitions_fallback(self):
        block = (b"sda kind=disk size=2048 removable=0 ro=0 dev=8:0 dm= holders= slaves=\n"
                 b"sda1 kind=part size=1024 removable=0 ro=0 dev=8:1 dm= holders=dm-0, slaves=\n"
                 b"dm-0 kind=disk size=1024 removable=0 ro=0 dev=253:0 dm=vg-root holders= "
                 b"slaves=sda1,\n")
        devices = parse(("storage.block", block)).data["devices"]
        self.assertEqual([(d["name"], d["kind"], d["size"]) for d in devices],
                         [("sda", "disk", 1048576), ("sda1", "part", 524288),
                          ("dm-0", "dm", 524288)])
        self.assertEqual(devices[1]["holders"], ["dm-0"])
        self.assertEqual(devices[2]["dm_name"], "vg-root")
        partitions = b"major minor  #blocks  name\n\n   8        0   1048576 sda\n"
        result = parse(("storage.block", b"", "na", "-", "no /sys/class/block"),
                       ("storage.partitions", partitions))
        self.assertEqual(result.data["devices"][0]["size"], 1048576 * 1024)

    def test_nothing_readable_declares_gaps(self):
        result = parse(("storage.mountinfo", b"", "denied", 1, "Permission denied"))
        items = {g.item: g.status for g in result.gaps}
        self.assertEqual(items["mounts"], Status.DENIED)
        self.assertIn("usage", items)
        self.assertIn("swap", items)


if __name__ == "__main__":
    unittest.main()
