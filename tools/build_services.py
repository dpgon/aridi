"""Build src/aridi/data/services.csv from the IANA port registry (TODO.md 7.1).

    python tools/build_services.py [--input FILE] [--output PATH]

Without --input it downloads service-names-port-numbers.csv from IANA. Standard library
only. The output is "name|port|protocol|description", one line per (port, protocol) with
the first service name IANA lists for it, after a header of "#" lines with the source
and the date. Port ranges ("6000-6063") and entries without a name are left out.
"""

import argparse
import csv
import datetime
import io
import logging
import re
import sys
import urllib.request
from pathlib import Path

URL = ("https://www.iana.org/assignments/service-names-port-numbers/"
       "service-names-port-numbers.csv")
OUTPUT = Path(__file__).resolve().parent.parent / "src" / "aridi" / "data" / "services.csv"
PROTOCOLS = ("tcp", "udp", "sctp", "dccp")
# A name is one token: no spaces and no field separator.
NAME = re.compile(r"^[^\s|]+$")

log = logging.getLogger("build_services")


def clean(text):
    """One line, without the field separator."""
    return " ".join(text.replace("|", "/").split())


def build(text):
    """[(name, port, protocol, description)] from the IANA CSV TEXT, sorted."""
    rows = {}
    reader = csv.DictReader(io.StringIO(text))
    required = {"Service Name", "Port Number", "Transport Protocol", "Description"}
    if not required <= set(reader.fieldnames or []):
        raise ValueError(f"not the IANA registry: columns {reader.fieldnames}")
    for record in reader:
        name = record["Service Name"].strip()
        port = record["Port Number"].strip()
        protocol = record["Transport Protocol"].strip().lower()
        if not name or not port.isdigit() or protocol not in PROTOCOLS:
            continue
        if not NAME.match(name):
            log.warning("ignored service name %r", name)
            continue
        rows.setdefault((int(port), protocol),
                        (name, int(port), protocol, clean(record["Description"])))
    return [rows[key] for key in sorted(rows)]


def render(rows, source, when):
    header = [
        "# Port names: name|port|protocol|description",
        f"# Source: {source}",
        f"# Generated: {when} by tools/build_services.py (first name per port and protocol)",
    ]
    return "\n".join(header + ["|".join(map(str, row)) for row in rows]) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, help="a local copy of the IANA CSV")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.input:
        text, source = args.input.read_text(encoding="utf-8"), f"{URL} (local copy)"
    else:
        log.info("downloading %s", URL)
        with urllib.request.urlopen(URL, timeout=60) as response:
            text, source = response.read().decode("utf-8"), URL
    rows = build(text)
    if len(rows) < 1000:
        log.error("only %d entries: the registry looks wrong, nothing written", len(rows))
        return 1
    today = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
    args.output.write_text(render(rows, source, today), encoding="utf-8")
    log.info("%d entries written to %s", len(rows), args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
