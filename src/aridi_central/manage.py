#!/usr/bin/env python3
"""Django administrative commands of the aridi central component.

Runs as "python src/aridi_central/manage.py …" from the repository or as
"python -m aridi_central.manage …" once installed.
"""

import os
import sys
from pathlib import Path


def main():
    # From the repository, src/ holds both aridi and aridi_central.
    src = str(Path(__file__).resolve().parent.parent)
    if src not in sys.path:
        sys.path.insert(0, src)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aridi_central.settings")
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
