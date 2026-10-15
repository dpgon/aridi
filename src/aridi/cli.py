"""Command line interface: aridi report|interpret|validate <bundle>."""

import argparse
import sys

from aridi import __version__

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
    subparsers = parser.add_subparsers(dest="command", required=True)

    report = subparsers.add_parser("report", help="print a human-readable report")
    report.add_argument("bundle", help="raw bundle file")
    report.add_argument("--detail", action="store_true", help="detailed report")

    interpret = subparsers.add_parser("interpret", help="write the snapshot as JSON")
    interpret.add_argument("bundle", help="raw bundle file")
    interpret.add_argument("-o", "--output", help="output file (default: stdout)")

    validate = subparsers.add_parser("validate", help="check the bundle format")
    validate.add_argument("bundle", help="raw bundle file")

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    print(f"aridi {args.command}: not implemented yet", file=sys.stderr)
    return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
