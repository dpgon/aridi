"""Command line interface: aridi report|interpret|validate <bundle>."""

import argparse
import logging
import os
import sys

from aridi import __version__
from aridi.bundle import BundleError, read
from aridi.interpret import interpret
from aridi.model import Outcome
from aridi.views import text

log = logging.getLogger("aridi")

# Exit codes (docs/CAMBIO.md): 0 complete, 1 complete with gaps, 2 failed or invalid.
EXIT_COMPLETE = 0
EXIT_GAPS = 1
EXIT_FAILED = 2


def build_parser():
    parser = argparse.ArgumentParser(
        prog="aridi",
        description="Interpret raw bundles produced by aridi-collect.sh.",
    )
    parser.add_argument("--version", action="version", version=f"aridi {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="more log messages on stderr (-vv for debug)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    report = subparsers.add_parser("report", help="print a human-readable report")
    report.add_argument("bundle", help="raw bundle file")
    report.add_argument("--detail", action="store_true", help="detailed report")

    interpret_cmd = subparsers.add_parser("interpret", help="write the snapshot as JSON")
    interpret_cmd.add_argument("bundle", help="raw bundle file")
    interpret_cmd.add_argument("-o", "--output",
                               help="new output file, mode 0600 (default: stdout)")

    validate = subparsers.add_parser("validate", help="check the bundle format")
    validate.add_argument("bundle", help="raw bundle file")

    return parser


def write_new_file(path, content):
    """Create PATH with mode 0600; fail if it exists or is a symbolic link."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


def _exit_code(snapshot):
    return EXIT_COMPLETE if snapshot.outcome() == Outcome.COMPLETE else EXIT_GAPS


def _validate(args, bundle):
    statuses = {}
    for section in bundle.sections.values():
        statuses[section.status] = statuses.get(section.status, 0) + 1
    summary = ", ".join(f"{count} {status}" for status, count in sorted(statuses.items()))
    print(f"{args.bundle}: valid bundle format {bundle.format_version}, collector "
          f"{bundle.collector_version}, {len(bundle.sections)} sections ({summary})")
    return EXIT_COMPLETE


def _interpret(args, bundle):
    snapshot = interpret(bundle)
    content = snapshot.to_json()
    if args.output:
        try:
            write_new_file(args.output, content)
        except OSError as exc:
            log.error("cannot create %s: %s", args.output, exc.strerror or exc)
            return EXIT_FAILED
    else:
        sys.stdout.write(content)
    return _exit_code(snapshot)


def _report(args, bundle):
    snapshot = interpret(bundle)
    sys.stdout.write(text.render(snapshot, detail=args.detail))
    return _exit_code(snapshot)


COMMANDS = {"validate": _validate, "interpret": _interpret, "report": _report}


def main(argv=None):
    args = build_parser().parse_args(argv)
    level = {0: logging.WARNING, 1: logging.INFO}.get(args.verbose, logging.DEBUG)
    logging.basicConfig(level=level, stream=sys.stderr, force=True,
                        format="aridi: %(levelname)s: %(message)s")
    try:
        bundle = read(args.bundle)
    except OSError as exc:
        log.error("cannot read %s: %s", args.bundle, exc.strerror or exc)
        return EXIT_FAILED
    except BundleError as exc:
        log.error("%s: invalid bundle: %s", args.bundle, exc)
        return EXIT_FAILED
    return COMMANDS[args.command](args, bundle)


if __name__ == "__main__":
    sys.exit(main())
