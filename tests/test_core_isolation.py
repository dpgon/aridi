"""The core (src/aridi) may only import the standard library and itself.

This guards the founding rule of the project: no third-party code in the collector
(CLAUDE.md, docs/CAMBIO.md).
"""

import ast
import sys
import unittest
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "src" / "aridi"
ALLOWED = set(sys.stdlib_module_names) | {"aridi", "__future__"}


def imported_modules(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.lineno, node.module


class CoreIsolationTest(unittest.TestCase):

    def test_core_exists(self):
        self.assertTrue((CORE / "__init__.py").is_file(), CORE)

    def test_detects_foreign_imports(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.py"
            sample.write_text("import os\nfrom django.db import models\nfrom . import x\n")
            found = [m for _, m in imported_modules(sample)
                     if m.split(".")[0] not in ALLOWED]
        self.assertEqual(found, ["django.db"])

    def test_only_stdlib_imports(self):
        offending = []
        for path in sorted(CORE.rglob("*.py")):
            for lineno, module in imported_modules(path):
                if module.split(".")[0] not in ALLOWED:
                    offending.append(f"{path.relative_to(CORE.parent)}:{lineno}: {module}")
        self.assertEqual(offending, [], "non-stdlib imports in the core")


if __name__ == "__main__":
    unittest.main()
