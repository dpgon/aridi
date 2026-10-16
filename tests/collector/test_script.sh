#!/bin/sh
# Tests of collector/aridi-collect.sh in every image of tests/corpus/images.txt, minimal
# variant, network "none" (TODO.md, phase 2.2). Run by "tests/run.sh collector".
#
# In each image:
#   - the script runs with every shell present (sh, dash, bash, busybox ash) through
#     "SHELL -s", as root: exit code 0, header "ARIDI-BUNDLE 1", and no file created or
#     modified (find / -xdev -newer MARKER);
#   - with bash, data after the script in stdin is never executed;
#   - as uid 65534 (nobody): the script still ends with 0, and a probe of the section
#     functions (ARIDI_COLLECT_LIB=1) yields denied, missing, na, timeout, error and a
#     truncated section. The probe is read line by line by bash (sh on the Red Hat family
#     and Arch), so a section command that read stdin would eat the following lines.
# The bundles are then checked with the core reader (tests/collector/check_bundles.py).
#
# Usage: tests/collector/test_script.sh [NAME...]     (default: every image)

set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
images="$repo/tests/corpus/images.txt"
script="$repo/collector/aridi-collect.sh"
python_image=python:3.12-slim

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT INT TERM
failures=0

fail() {
    echo "FAIL $*"
    failures=$((failures + 1))
}

probe() {
    # The section functions with low limits, on cases with a known status.
    printf 'ARIDI_COLLECT_LIB=1\nARIDI_SECTION_TIMEOUT=2\nARIDI_SECTION_LIMIT=1000\n'
    cat "$script"
    cat <<'EOF'
bundle_begin
section t.stdin cat
section_file t.shadow_file /etc/shadow
section t.shadow_cmd cat /etc/shadow
section t.slow sleep 10
section t.nosuch aridi-no-such-tool
section_file t.nofile /aridi/no/such/file
section t.big sh -c 'i=0; while [ $i -lt 300 ]; do echo 0123456789; i=$((i + 1)); done'
section t.fail sh -c 'echo partial; printf "boom\033[31m\n" >&2; exit 3'
section_text t.text "computed value"
bundle_end
EOF
}

emulator_touches_tmp() {
    # True if reading a process command line, alone, changes /tmp in this container.
    docker exec "$1" sh -c '
        touch /tmp/.aridi-probe; sleep 1; cat /proc/1/cmdline >/dev/null
        changed=$(find /tmp -newer /tmp/.aridi-probe ! -path /tmp/.aridi-probe)
        rm -f /tmp/.aridi-probe; [ "$changed" = /tmp ]'
}

test_image() {
    name=$1
    image=$2
    platform=$3
    container="aridi-collector-test-$name"
    docker rm -f "$container" >/dev/null 2>&1
    if ! docker run -d --name "$container" --platform "$platform" --network none \
        "$image" sh -c 'while :; do sleep 3600; done' >/dev/null; then
        fail "$name: docker run"
        return
    fi

    shells=$(docker exec "$container" sh -c '
        echo sh
        for s in dash bash; do command -v $s >/dev/null 2>&1 && echo $s; done
        command -v busybox >/dev/null 2>&1 && busybox ash -c true 2>/dev/null && echo busybox-ash
        true')

    for shell in $shells; do
        run=$shell
        [ "$shell" = busybox-ash ] && run="busybox ash"
        docker exec "$container" sh -c 'rm -f /tmp/.aridi-marker; touch /tmp/.aridi-marker'
        sleep 1
        bundle="$out/$name.root.$shell.aridi"
        # shellcheck disable=SC2086
        docker exec -i "$container" $run -s < "$script" > "$bundle" 2> "$bundle.stderr"
        rc=$?
        [ $rc -eq 0 ] || fail "$name/$shell: exit code $rc"
        head -n 1 "$bundle" | grep -q '^ARIDI-BUNDLE 1 ' ||
            fail "$name/$shell: no ARIDI-BUNDLE 1 header"
        [ -s "$bundle.stderr" ] && fail "$name/$shell: stderr: $(head -c 200 "$bundle.stderr")"
        changed=$(docker exec "$container" \
            find / -xdev -newer /tmp/.aridi-marker ! -path /tmp/.aridi-marker 2>/dev/null)
        if [ "$changed" = /tmp ] && emulator_touches_tmp "$container"; then
            # Under amd64 emulation on an arm64 host, reading /proc/PID/cmdline (even with
            # cat) creates and removes a file in /tmp: an artifact of the emulator, proved
            # in this same image by emulator_touches_tmp. Any other change still fails.
            echo "ok $name/$shell: only /tmp changed, as plain cat of /proc/1/cmdline does here"
        elif [ -n "$changed" ]; then
            fail "$name/$shell: files created or modified: $changed"
        fi
        echo "ok $name/$shell: $(grep -c ' begin ' "$bundle") sections"
    done

    if docker exec "$container" sh -c 'command -v bash' >/dev/null 2>&1; then
        trailer=$( { cat "$script"; echo 'echo ARIDI-TRAILER-EXECUTED'; } |
            docker exec -i "$container" bash -s)
        case $trailer in
            *ARIDI-TRAILER-EXECUTED*) fail "$name/bash: data after the script was executed" ;;
            *" close sections="*) echo "ok $name/bash: stdin after the script ignored" ;;
            *) fail "$name/bash: bundle without close line when fed through stdin" ;;
        esac
    fi

    bundle="$out/$name.nobody.aridi"
    docker exec -i -u 65534:65534 "$container" sh -s < "$script" > "$bundle" 2> "$bundle.stderr"
    rc=$?
    [ $rc -eq 0 ] || fail "$name/nobody: exit code $rc"
    [ -s "$bundle.stderr" ] && fail "$name/nobody: stderr: $(head -c 200 "$bundle.stderr")"
    probe | docker exec -i -u 65534:65534 "$container" sh -s > "$out/$name.probe.aridi" 2>&1 ||
        fail "$name/probe: exit code $?"
    echo "ok $name/nobody: full run and probe captured"

    docker rm -f "$container" >/dev/null
}

if [ $# -eq 0 ]; then
    set -- $(awk '!/^#/ && NF { print $1 }' "$images")
fi
for name in "$@"; do
    line=$(awk -v n="$name" '$1 == n' "$images")
    [ -n "$line" ] || { fail "unknown image $name"; continue; }
    # shellcheck disable=SC2086
    test_image $(echo "$line" | awk '{ print $1, $2, $3 }')
done

if ! docker run --rm --network none -v "$repo":/repo:ro -v "$out":/bundles:ro -w /repo \
    -e PYTHONPATH=src:. -e PYTHONDONTWRITEBYTECODE=1 \
    "$python_image" python tests/collector/check_bundles.py /bundles; then
    fail "check_bundles.py"
fi

if [ $failures -ne 0 ]; then
    echo "collector: $failures failure(s)"
    exit 1
fi
echo "collector: all checks passed"
