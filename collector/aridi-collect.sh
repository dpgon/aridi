#!/bin/sh
# aridi-collect.sh: raw collector of aridi.
#
# Runs on the inventoried machine (POSIX sh, no other requirement), reads what it can
# and writes a raw bundle to stdout. It never writes to disk and never sends secrets:
# sensitive data is filtered at the source. The bundle format is specified in
# docs/FORMATO.md.
#
# Usage: sh aridi-collect.sh > machine.aridi      or      ssh host sh -s < aridi-collect.sh
#
# The script may arrive through stdin ("sh -s"), so every command runs with </dev/null:
# a command that reads stdin would eat the rest of the script (bash reads it line by line).
#
# Copyright (C) 2019-2026 the aridi authors
# License: GNU General Public License v3.0 only (see LICENSE)

ARIDI_COLLECTOR_VERSION="2.0.0.dev0"
ARIDI_BUNDLE_FORMAT=1

# Limits per section. They can be lowered by the tests (tests/collector/).
ARIDI_SECTION_LIMIT=${ARIDI_SECTION_LIMIT:-4194304}
ARIDI_SECTION_TIMEOUT=${ARIDI_SECTION_TIMEOUT:-60}

# System directories first: a writable /usr/local must not shadow the base tools.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
LC_ALL=C
export PATH LC_ALL
umask 077

# fd 3 is the bundle stream: section content is written there from inside the command
# substitutions that capture exit codes and stderr.
exec 3>&1

_count=0

have() { command -v "$1" >/dev/null 2>&1; }

_line() { printf '%s\n' "--$_boundary $*"; }

_detect_timeout() {
    # Sets _timeout to the prefix that limits a command, or leaves it empty.
    _timeout=""
    _timeout_kind=none
    if timeout 5 true </dev/null >/dev/null 2>&1; then
        _timeout="timeout"
        _timeout_kind=timeout
    elif timeout -t 5 true </dev/null >/dev/null 2>&1; then
        _timeout="timeout -t"
        _timeout_kind=timeout-t
    fi
}

_new_boundary() {
    _boundary=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null </dev/null | tr -d ' \n')
    _boundary_source=urandom
    case $_boundary in
        ????????????????????????????????) ;;
        *)
            # Weak fallback, declared in meta.env: time and pid only.
            _boundary="weak$(date +%s 2>/dev/null </dev/null)x$$"
            _boundary_source=weak
            ;;
    esac
}

_limited() {
    # Runs "$@" with the section time limit when a timeout tool exists.
    if [ -n "$_timeout" ]; then
        $_timeout "$ARIDI_SECTION_TIMEOUT" "$@"
    else
        "$@"
    fi
}

_stderr_line() {
    # One printable line of at most 400 bytes from stdin, prefixed with "err ". It reads
    # all its input: closing the pipe early would kill the command with SIGPIPE.
    # Control and non-ASCII bytes become "?" (busybox tr has no character classes).
    _e=$(awk 'length(s) < 400 { s = s " " $0 } END { s = substr(s, 2, 400)
        gsub(/[^ -~]/, "?", s); print s }')
    [ -n "$_e" ] && printf 'err %s\n' "$_e"
    return 0
}

_run() {
    # _run NAME FIELDS COMMAND...: one section with the output of COMMAND.
    _name=$1
    _fields=$2
    shift 2
    _count=$((_count + 1))
    _line "begin $_name $_fields limit=$ARIDI_SECTION_LIMIT"
    # Content goes to fd 3 (limit + 1 bytes, so the reader can tell it was cut); the exit
    # code and the first stderr bytes are captured.
    _res=$( { { { _limited "$@" </dev/null 2>&5; echo "rc $?" >&4; } |
        head -c "$((ARIDI_SECTION_LIMIT + 1))" >&3; } 5>&1 | _stderr_line; } 4>&1 )
    printf '\n'
    _rc=$(printf '%s\n' "$_res" | sed -n 's/^rc //p')
    _err=$(printf '%s\n' "$_res" | sed -n 's/^err //p')
    case $_rc in
        0) _status=ok ;;
        124|137|143) if [ -n "$_timeout" ]; then _status=timeout; else _status=error; fi ;;
        141) _status=ok ;;  # SIGPIPE: the output exceeded the limit (marked by the reader)
        127) _status=missing ;;
        *)
            case $_err in
                *"ermission denied"*|*"peration not permitted"*) _status=denied ;;
                *) _status=error ;;
            esac
            ;;
    esac
    _line "end $_name status=$_status rc=${_rc:--}"
    [ -n "$_err" ] && _line "note $_name $_err"
    return 0
}

_empty() {
    # _empty NAME FIELDS STATUS NOTE: a section that was not run.
    _count=$((_count + 1))
    _line "begin $1 $2 limit=$ARIDI_SECTION_LIMIT"
    printf '\n'
    _line "end $1 status=$3 rc=-"
    _line "note $1 $4"
}

section() {
    # section NAME TOOL [ARGS...]: output of a command; "missing" if TOOL does not exist.
    _sname=$1
    shift
    if have "$1"; then
        _run "$_sname" "kind=cmd tool=${1##*/}" "$@"
    else
        _empty "$_sname" "kind=cmd tool=${1##*/}" missing "tool not found: $1"
    fi
}

section_file() {
    # section_file NAME PATH: content of a file; "na" if it does not exist, "denied" if
    # it cannot be read.
    if [ ! -e "$2" ]; then
        _empty "$1" "kind=file path=$2" na "not found: $2"
    elif [ ! -r "$2" ]; then
        _empty "$1" "kind=file path=$2" denied "not readable: $2"
    else
        _run "$1" "kind=file path=$2" cat "$2"
    fi
}

section_text() {
    # section_text NAME TEXT: a value computed by the script itself.
    _count=$((_count + 1))
    _line "begin $1 kind=text limit=$ARIDI_SECTION_LIMIT"
    printf '%s\n\n' "$2"
    _line "end $1 status=ok rc=0"
}

bundle_begin() {
    _new_boundary
    _detect_timeout
    printf 'ARIDI-BUNDLE %s %s\n' "$ARIDI_BUNDLE_FORMAT" "$ARIDI_COLLECTOR_VERSION"
    printf 'boundary %s\n' "$_boundary"
}

bundle_end() {
    _line "close sections=$_count"
}

collect_meta() {
    # Identity of the machine and of this run (snapshot header, docs/FORMATO.md).
    _shell=$(readlink "/proc/$$/exe" 2>/dev/null </dev/null)
    section_text meta.env "shell=${_shell:-unknown}
timeout=$_timeout_kind
section_timeout=$ARIDI_SECTION_TIMEOUT
section_limit=$ARIDI_SECTION_LIMIT
boundary_source=$_boundary_source
path=$PATH"
    section meta.date_utc date -u +%Y-%m-%dT%H:%M:%SZ
    section meta.uid id -u
    section_file meta.machine_id /etc/machine-id
    section_file meta.dbus_machine_id /var/lib/dbus/machine-id
    section_file meta.hostname /proc/sys/kernel/hostname
    section meta.uname uname -a
}

main() {
    bundle_begin
    collect_meta
    bundle_end
}

# ARIDI_COLLECT_LIB=1 only defines the functions (used by tests/collector/).
if [ "${ARIDI_COLLECT_LIB:-}" != 1 ]; then
    main
    exit 0
fi
