"""Area "hardware" (src/aridi/parsers/hardware.py), TODO.md 3.2."""

import re
import unittest
from pathlib import Path

from aridi import bundle
from aridi.interpret import interpret
from aridi.model import Status
from aridi.parsers import hardware
from tests.helpers import (CORPUS, facts, legacy_bundle, legacy_report, make_bundle,
                           sample_name, samples)

DATA = Path(__file__).parent / "data"


def hardware_of(sample_dir):
    return interpret(bundle.read(sample_dir / "bundle.aridi")).sections["hardware"]


def parse(*sections):
    return hardware.parse(dict(bundle.parse(make_bundle(sections)).sections))


class CorpusTest(unittest.TestCase):

    def test_matches_facts_in_every_sample(self):
        for sample in samples():
            with self.subTest(sample=sample_name(sample)):
                section = hardware_of(sample)
                ref = facts(sample)
                self.assertEqual(section.status, Status.OK)
                self.assertEqual([g for g in section.gaps if g.status != Status.NA], [])
                cpu = section.data["cpu"]
                self.assertEqual(cpu["logical"], int(ref["cpu_count"]))
                self.assertEqual(cpu["architecture"], ref["arch"].strip())
                mem_total = re.search(r"MemTotal:\s+(\d+) kB", ref["meminfo"]).group(1)
                self.assertEqual(section.data["memory"]["total"], int(mem_total) * 1024)

    def test_arm64_has_cores_and_model(self):
        """docs/MVP.md n.º 11: arm64 gave "0 cores" and an empty model in 2019."""
        for name in ("debian12/minimal", "alpine320/minimal", "vm-rocky9-arm64/vm"):
            with self.subTest(sample=name):
                cpu = hardware_of(CORPUS / name).data["cpu"]
                self.assertEqual(cpu["architecture"], "aarch64")
                self.assertGreater(cpu["cores"], 0)
                self.assertGreater(cpu["sockets"], 0)
                self.assertTrue(cpu["model"])
                self.assertTrue(cpu["vendor"])
                self.assertEqual(cpu["model_source"], "cpuinfo-arm")

    def test_x86_64_vm(self):
        cpu = hardware_of(CORPUS / "vm-debian12-amd64" / "vm").data["cpu"]
        self.assertEqual(cpu["architecture"], "x86_64")
        self.assertEqual(cpu["model_source"], "cpuinfo")
        self.assertTrue(cpu["vendor"])
        self.assertTrue(cpu["model"])
        self.assertIn("sse2", cpu["flags"])
        self.assertGreater(cpu["cores"], 0)


class LegacyRegressionTest(unittest.TestCase):

    def test_memory_total_same_as_legacy(self):
        for distro in ("debian12", "centos7"):
            with self.subTest(distro=distro):
                legacy_kb = re.search(r"Memory:\s+(\d+) kB", legacy_report(distro)).group(1)
                data = interpret(bundle.read(legacy_bundle(distro))).sections["hardware"].data
                memory = data["memory"]
                self.assertEqual(memory["total"], int(legacy_kb) * 1024)


class SyntheticTest(unittest.TestCase):

    def test_usb_devices_and_hubs(self):
        usb = (DATA / "usb" / "laptop.txt").read_bytes()
        devices = parse(("hardware.usb", usb)).data["usb"]
        self.assertEqual([d["device"] for d in devices], ["usb1", "1-2", "1-2.1", "1-4"])
        self.assertEqual([(d["hub"], d["root_hub"]) for d in devices],
                         [(True, True), (True, False), (False, False), (False, False)])
        self.assertEqual(devices[2]["product"], "USB Receiver")
        self.assertNotIn("product", devices[3])

    def test_without_sys_bus_usb_is_na_not_error(self):
        result = parse(("hardware.usb", b"", "na", "-", "no /sys/bus/usb/devices"))
        self.assertIsNone(result.data["usb"])
        [usb_gap] = [g for g in result.gaps if g.item == "usb"]
        self.assertEqual(usb_gap.status, Status.NA)

    def test_x86_cpuinfo_and_topology(self):
        cpuinfo = b"".join(
            b"processor\t: %d\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) "
            b"Gold 6230 CPU @ 2.10GHz\nflags\t\t: fpu sse2 ht\nbugs\t\t: spectre_v1\n\n" % n
            for n in range(4))
        topology = (b"cpu0 package=0 core=0 die=0 cluster=0 threads=0,2 online=\n"
                    b"cpu1 package=0 core=1 die=0 cluster=0 threads=1,3 online=1\n"
                    b"cpu2 package=0 core=0 die=0 cluster=0 threads=0,2 online=1\n"
                    b"cpu3 package=0 core=1 die=0 cluster=0 threads=1,3 online=1\n")
        cpu = parse(("hardware.cpuinfo", cpuinfo), ("hardware.cpu_online", b"0-3\n"),
                    ("hardware.cpu_topology", topology)).data["cpu"]
        self.assertEqual((cpu["logical"], cpu["sockets"], cpu["cores"], cpu["threads_per_core"]),
                         (4, 1, 2, 2))
        self.assertEqual(cpu["vendor"], "GenuineIntel")
        self.assertEqual(cpu["bugs"], ["spectre_v1"])

    def test_arm_known_and_unknown_parts(self):
        def model(implementer, part):
            info = (b"processor\t: 0\nCPU implementer\t: %s\nCPU part\t: %s\n"
                    % (implementer, part))
            return parse(("hardware.cpuinfo", info)).data["cpu"]

        self.assertEqual(model(b"0x41", b"0xd0c")["model"], "Neoverse-N1")
        cpu = model(b"0x41", b"0xfff")
        self.assertEqual((cpu["vendor"], cpu["model"]), ("ARM", "ARM part 0xfff"))
        self.assertEqual(model(b"0x99", b"0x001")["vendor"], "implementer 0x99")

    def test_unknown_package_id_is_not_a_socket(self):
        topology = b"cpu0 package=-1 core=0 die= cluster=-1 threads=0 online=\n"
        cpu = parse(("hardware.cpu_topology", topology)).data["cpu"]
        self.assertIsNone(cpu["sockets"])
        self.assertEqual(cpu["cores"], 1)

    def test_cpu_list_and_bad_values(self):
        self.assertEqual(hardware.cpu_list("0-2,5,7-8"), {0, 1, 2, 5, 7, 8})
        result = parse(("hardware.cpu_online", b"0-x\n"))
        self.assertIn("online cpus", [g.item for g in result.gaps])

    def test_nothing_readable(self):
        result = parse(("hardware.cpuinfo", b"", "denied", "-", "not readable"))
        self.assertEqual({g.item: g.status for g in result.gaps}["cpuinfo"], Status.DENIED)
        self.assertIn("memory", [g.item for g in result.gaps])


if __name__ == "__main__":
    unittest.main()
