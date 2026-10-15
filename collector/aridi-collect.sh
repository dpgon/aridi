#!/bin/sh
# aridi-collect.sh: raw collector of aridi.
#
# Runs on the inventoried machine (POSIX sh, no other requirement), reads what it can
# and writes a raw bundle to stdout. It never writes to disk and never sends secrets:
# sensitive data is filtered at the source. The bundle format is specified in
# docs/FORMATO.md (TODO.md, phase 2).
#
# Copyright (C) 2019-2026 the aridi authors
# License: GNU General Public License v3.0 only (see LICENSE)

ARIDI_COLLECTOR_VERSION="2.0.0.dev0"
