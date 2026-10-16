"""tests/parity.md is complete and every test it names exists (TODO.md 4.1).

Running the named tests is "tests/run.sh all"; this only keeps the table honest: no
functionality of docs/MVP.md without a row, no row pointing at a test that is not there.
"""

import importlib
import re
import unittest

from tests.helpers import REPO

PARITY = REPO / "tests" / "parity.md"
# First column of the "Implementadas, sin verificar" and "Abandonadas" tables of the 2019
# measurement (docs/MVP.md up to commit b155e0a; the file now measures the new collector).
MVP_2019 = {
    "Implementadas, sin verificar": [
        "Barrido ARP de la red local", "Servicios con systemd en marcha o con SysV",
        "Sesiones activas, últimos accesos y accesos fallidos",
        "`iptables` con reglas, como root y con permisos", "USB con `lsusb` presente",
        "Grafo de red con `graphviz` instalado", "Paquetes con zypper o pacman",
        "Datos de CPU en x86_64", "RHEL/CentOS 6"],
    "Abandonadas": [
        "Lectura de NTP", "Comprobación de permisos de `passwd`, `group`, `shadow` y `gshadow`",
        "Registro de vulnerabilidades", "Categorías de ficheros interesantes (0 a 18)",
        "Uso como paquete importable"],
}
TEST_REF = re.compile(r"`(test_\w+):(\w+)\.(test_\w+)`")


def table_rows(text, heading):
    """Rows (lists of cells) of the first table after the "## heading" line."""
    section = text.split(f"## {heading}", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("|")]
    return [[cell.strip() for cell in row.strip("|").split("|")] for row in rows[2:]]


def module_path(name):
    """Dotted path of tests/**/NAME.py."""
    [path] = (REPO / "tests").rglob(f"{name}.py")
    return ".".join(path.relative_to(REPO).with_suffix("").parts)


class ParityDocTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.parity = PARITY.read_text(encoding="utf-8")

    def test_every_numbered_functionality(self):
        numbers = [row[0] for row in table_rows(self.parity, "Funcionalidades que funcionaban")]
        numbers += [row[0] for row in table_rows(self.parity, "Funcionalidades a medias")]
        self.assertEqual(numbers, [str(n) for n in range(1, 22)])

    def test_every_unverified_and_abandoned_row(self):
        for heading, mvp_heading in (("Implementadas, sin verificar",
                                      "Implementadas, sin verificar"),
                                     ("Abandonadas en 2019", "Abandonadas")):
            with self.subTest(table=heading):
                ours = [row[0] for row in table_rows(self.parity, heading)]
                self.assertEqual(len(ours), len(MVP_2019[mvp_heading]))

    def test_every_row_has_tests_or_is_abandoned(self):
        for heading in ("Funcionalidades que funcionaban", "Funcionalidades a medias",
                        "Implementadas, sin verificar", "Abandonadas en 2019"):
            for row in table_rows(self.parity, heading):
                with self.subTest(row=row[0]):
                    tests = row[-1]
                    if tests == "—":
                        self.assertIn("Se abandona", row[-2])
                    else:
                        self.assertTrue(TEST_REF.search(tests) or "run.sh collector" in tests)

    def test_named_tests_exist(self):
        refs = TEST_REF.findall(self.parity)
        self.assertGreater(len(refs), 50)
        for module, cls, method in refs:
            with self.subTest(test=f"{module}:{cls}.{method}"):
                loaded = importlib.import_module(module_path(module))
                self.assertTrue(hasattr(getattr(loaded, cls), method))


if __name__ == "__main__":
    unittest.main()
