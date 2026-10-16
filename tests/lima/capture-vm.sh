#!/bin/sh
# Captures one corpus sample in a disposable Lima VM (TODO.md, phase 1.2).
#
# Usage: tests/lima/capture-vm.sh VM | all
#   VM  debian12-arm64 | rocky9-arm64 | debian12-amd64  (tests/lima/VM.yaml)
#
# Creates the VM, applies tests/corpus/scenario.sh (static part) and
# tests/lima/scenario-vm.sh, runs collector/aridi-collect.sh through "sudo sh -s",
# runs tests/corpus/facts.sh, saves everything in tests/corpus/vm-VM/vm/ (same files as
# tests/corpus/capture.sh) and deletes the VM. Requires Lima 2.x; the amd64 VM also needs
# the lima-additional-guestagents formula and is slow (QEMU emulation).

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
corpus="$repo/tests/corpus"
collector="$repo/collector/aridi-collect.sh"

capture() {
    vm=$1
    template="$here/$vm.yaml"
    [ -f "$template" ] || { echo "unknown VM: $vm" >&2; return 2; }
    instance="aridi-corpus-$vm"
    out="$corpus/vm-$vm/vm"

    limactl delete --force "$instance" >/dev/null 2>&1 || true
    # --mount-none: Lima appends the mounts of the base template (the host home directory)
    # to ours, so "mounts: []" in the YAML is not enough.
    limactl start --tty=false --mount-none --name "$instance" "$template" \
        > "$corpus/.lima-$vm.log" 2>&1 || {
        echo "$vm: limactl start failed, see tests/corpus/.lima-$vm.log" >&2
        return 1
    }

    vmsh() { limactl shell --workdir / "$instance" "$@"; }

    # Never collect in a VM that sees host directories.
    host_mounts=$(vmsh sh -c "grep -E ' - (virtiofs|9p|fuse\.sshfs) ' /proc/self/mountinfo" || true)
    if [ -n "$host_mounts" ]; then
        echo "$vm: the VM has host directories mounted, aborting:" >&2
        echo "$host_mounts" >&2
        limactl delete --force "$instance" >/dev/null 2>&1
        return 1
    fi

    rm -rf "$out"
    mkdir -p "$out"
    vmsh sudo sh -c 'cat > /usr/local/sbin/aridi-scenario.sh' < "$corpus/scenario.sh"
    vmsh sudo sh /usr/local/sbin/aridi-scenario.sh static < /dev/null > "$out/scenario.txt" 2>&1 || true
    vmsh sudo sh -c 'cat > /usr/local/sbin/aridi-scenario-vm.sh' < "$here/scenario-vm.sh"
    vmsh sudo sh /usr/local/sbin/aridi-scenario-vm.sh < /dev/null >> "$out/scenario.txt" 2>&1 || true
    sleep 2

    set +e
    started=$(date +%s)
    vmsh sudo sh -s < "$collector" > "$out/bundle.aridi" 2> "$out/collector.stderr"
    collector_rc=$?
    collector_seconds=$(( $(date +%s) - started ))
    vmsh sudo sh -s < "$corpus/facts.sh" > "$out/facts.txt" 2>&1
    facts_rc=$?
    set -e
    [ -s "$out/collector.stderr" ] || rm -f "$out/collector.stderr"

    {
        echo "name=vm-$vm"
        echo "variant=vm"
        echo "image=lima:$(sed -n 's/^base: //p' "$template")"
        echo "platform=lima/$(sed -n 's/^arch: //p' "$template")"
        echo "arch=$(vmsh uname -m)"
        echo "network=lima-user"
        echo "captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "collector_version=$(sed -n 's/^ARIDI_COLLECTOR_VERSION="\(.*\)"/\1/p' "$collector")"
        echo "collector_exit=$collector_rc"
        echo "collector_seconds=$collector_seconds"
        echo "facts_exit=$facts_rc"
        echo "lima_version=$(limactl --version | awk '{print $3}')"
    } > "$out/meta.txt"

    limactl delete --force "$instance" >/dev/null 2>&1
    rm -f "$corpus/.lima-$vm.log"
    echo "vm-$vm: collector exit $collector_rc, $(wc -c < "$out/bundle.aridi" | tr -d ' ') bytes, $(grep -c '^ok' "$out/scenario.txt") ok / $(grep -c '^skip' "$out/scenario.txt") skipped"
}

if [ "${1:-}" = all ]; then
    status=0
    for vm in debian12-arm64 rocky9-arm64 debian12-amd64; do
        capture "$vm" || { echo "vm-$vm: FAILED"; status=1; }
    done
    exit $status
fi

if [ $# -ne 1 ]; then
    echo "usage: $0 VM | all" >&2
    exit 2
fi
capture "$1"
