#!/bin/sh
# Captures one corpus sample in a disposable QEMU VM, for the systems that Lima cannot
# start (FUTURE.md 1.6: CentOS 6 and 7 in a VM). CentOS 6 has no systemd and a 2.6.32
# kernel, older than what Lima's guest agent needs; Lima has no CentOS 7 template.
#
# Usage: tests/qemu/capture-vm.sh VM | all
#   VM  centos7-amd64 | centos6-amd64
#
# Same steps and files as tests/lima/capture-vm.sh: downloads the official cloud image
# once (checked against its pinned SHA-256), boots a throw-away overlay of it with a
# cloud-init seed that only adds a one-time SSH key, prepares it over SSH, applies
# tests/corpus/scenario.sh (static part) and tests/lima/scenario-vm.sh, runs
# collector/aridi-collect.sh through "sudo sh -s", runs tests/corpus/facts.sh, saves
# everything in tests/corpus/vm-VM/vm/ and deletes the VM.
#
# The VM shares no host directory (no virtfs, no 9p) and reaches the network through
# QEMU user networking, like the Lima VMs. On arm64 hosts x86_64 is emulated (TCG) and
# each VM takes several minutes. Requires qemu-system-x86_64, qemu-img, curl, ssh and
# hdiutil (macOS) or mkisofs/genisoimage/xorriso. Images are cached in
# ${ARIDI_QEMU_CACHE:-$HOME/.cache/aridi-qemu}.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
corpus="$repo/tests/corpus"
collector="$repo/collector/aridi-collect.sh"
cache=${ARIDI_QEMU_CACHE:-$HOME/.cache/aridi-qemu}

define() {
    case $1 in
        centos7-amd64)
            image=CentOS-7-x86_64-GenericCloud-2211.qcow2
            url=https://cloud.centos.org/centos/7/images/$image
            sha256=284aab2b23d91318f169ff464bce4d53404a15a0618ceb34562838c59af4adea
            port=60227
            # Vault: CentOS 7 is out of support and its mirrors are gone.
            prepare='
                sed -i -e "s|^mirrorlist=|#mirrorlist=|" \
                    -e "s|^#\?baseurl=.*/\$releasever/|baseurl=http://vault.centos.org/7.9.2009/|" \
                    /etc/yum.repos.d/CentOS-*.repo
                yum install -y sudo iproute procps-ng util-linux iptables socat chrony \
                    openssh-server openssh-clients python
                systemctl enable chronyd
                systemctl start chronyd'
            ;;
        centos6-amd64)
            image=CentOS-6-x86_64-GenericCloud-1907.qcow2
            url=https://cloud.centos.org/centos/6/images/$image
            sha256=5350c20875a3fec28157abbc7db5dc635911212804f892b751f94fcf3f285aec
            port=60226
            # No socat in CentOS 6: the scenario listens with nc. ntpd instead of chrony.
            prepare='
                sed -i -e "s|^mirrorlist=|#mirrorlist=|" \
                    -e "s|^#\?baseurl=.*/\$releasever/|baseurl=http://vault.centos.org/6.10/|" \
                    /etc/yum.repos.d/CentOS-*.repo
                yum install -y sudo iproute procps util-linux-ng iptables nc ntp \
                    openssh-server openssh-clients python
                chkconfig ntpd on
                service ntpd start'
            ;;
        *) return 2 ;;
    esac
}

fetch() {
    mkdir -p "$cache"
    if [ ! -f "$cache/$image" ]; then
        echo "downloading $url" >&2
        curl -fsSL --retry 3 -o "$cache/$image.part" "$url"
        mv "$cache/$image.part" "$cache/$image"
    fi
    actual=$(shasum -a 256 "$cache/$image" | awk '{print $1}')
    if [ "$actual" != "$sha256" ]; then
        echo "$image: SHA-256 $actual, expected $sha256; deleting it" >&2
        rm -f "$cache/$image"
        return 1
    fi
}

seed_iso() {
    # seed_iso DIR ISO: NoCloud seed (volume "cidata") from DIR.
    if command -v hdiutil >/dev/null 2>&1; then
        hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o "$2" "$1"
    elif command -v xorriso >/dev/null 2>&1; then
        xorriso -as mkisofs -quiet -V cidata -J -r -o "$2" "$1"
    else
        "$(command -v mkisofs || command -v genisoimage)" -quiet -V cidata -J -r -o "$2" "$1"
    fi
}

capture() {
    vm=$1
    define "$vm" || { echo "unknown VM: $vm" >&2; return 2; }
    out="$corpus/vm-$vm/vm"
    log="$corpus/.qemu-$vm.log"
    fetch

    work=$(mktemp -d "$cache/run-$vm.XXXXXX")
    pidfile="$work/qemu.pid"
    # Always stop the VM and delete its disk, whatever happens.
    trap 'stop' EXIT INT TERM
    stop() {
        if [ -f "$pidfile" ]; then
            kill "$(cat "$pidfile")" 2>/dev/null || true
            sleep 2
        fi
        rm -rf "$work"
    }

    # One-time key: the VM accepts only this key, which is deleted with the VM. CentOS
    # 6 (OpenSSH 5.3) knows neither ed25519 nor rsa-sha2, hence RSA and +ssh-rsa.
    ssh-keygen -q -t rsa -b 3072 -N '' -C aridi-corpus -f "$work/key"
    mkdir "$work/seed"
    printf 'instance-id: aridi-corpus-%s\nlocal-hostname: %s-corpus\n' "$vm" "${vm%-*}" \
        > "$work/seed/meta-data"
    {
        echo "#cloud-config"
        echo "ssh_authorized_keys:"
        echo "  - $(cat "$work/key.pub")"
        echo "ssh_pwauth: false"
    } > "$work/seed/user-data"
    seed_iso "$work/seed" "$work/seed.iso"
    qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$image" "$work/disk.qcow2" 12G

    if [ "$(uname -m)" = x86_64 ] && [ "$(uname -s)" = Darwin ]; then
        accel=hvf
    elif [ "$(uname -m)" = x86_64 ] && [ -w /dev/kvm ]; then
        accel=kvm
    else
        accel=tcg,thread=multi
    fi
    qemu-system-x86_64 -machine pc -accel "$accel" -cpu max -smp 2 -m 2048 \
        -drive "file=$work/disk.qcow2,if=virtio,format=qcow2" \
        -drive "file=$work/seed.iso,if=virtio,format=raw,readonly=on" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" \
        -device virtio-net-pci,netdev=net0 \
        -display none -serial "file:$work/console.log" \
        -daemonize -pidfile "$pidfile" > "$log" 2>&1

    sshopts="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa
        -o PubkeyAcceptedAlgorithms=+ssh-rsa -o IdentitiesOnly=yes -i $work/key -p $port"
    # shellcheck disable=SC2086  # sshopts is a list of options
    vmsh() { ssh $sshopts centos@127.0.0.1 "$@"; }
    # shellcheck disable=SC2086
    vmsh_tty() { ssh -tt $sshopts centos@127.0.0.1 "$@"; }

    started=$(date +%s)
    until vmsh true < /dev/null 2>/dev/null; do
        if [ $(( $(date +%s) - started )) -gt 1500 ]; then
            echo "$vm: no SSH after 25 minutes; console in $log" >&2
            cp "$work/console.log" "$log"
            return 1
        fi
        sleep 10
    done
    echo "$vm: SSH up after $(( $(date +%s) - started )) s" >&2

    # Never collect in a VM that sees host directories.
    host_mounts=$(vmsh "grep -E ' - (virtiofs|9p|fuse\.sshfs) ' /proc/self/mountinfo" \
        < /dev/null || true)
    if [ -n "$host_mounts" ]; then
        echo "$vm: the VM has host directories mounted, aborting:" >&2
        echo "$host_mounts" >&2
        return 1
    fi

    # CentOS sudoers has "Defaults requiretty": the first sudo gets a terminal and lifts
    # it, so that the collector can be fed through stdin like in every other sample.
    vmsh_tty "sudo sed -i 's/^Defaults *requiretty/# &/' /etc/sudoers" < /dev/null >> "$log" 2>&1
    {
        echo "set -eux"
        echo "$prepare"
        echo "useradd -m -s /bin/bash aridi || true"
        echo "# The sudo rule decided in TODO.md 5.0: only the installed collector."
        echo "echo 'aridi ALL=(root) NOPASSWD: /usr/local/libexec/aridi-collect.sh \"\"' > /etc/sudoers.d/aridi"
        echo "chmod 0440 /etc/sudoers.d/aridi"
    } | vmsh sudo sh -s >> "$log" 2>&1 || {
        echo "$vm: preparing the VM failed, see $log" >&2
        return 1
    }

    rm -rf "$out"
    mkdir -p "$out"
    vmsh "sudo sh -c 'cat > /usr/local/sbin/aridi-scenario.sh'" < "$corpus/scenario.sh"
    vmsh sudo sh /usr/local/sbin/aridi-scenario.sh static < /dev/null > "$out/scenario.txt" 2>&1 || true
    vmsh "sudo sh -c 'cat > /usr/local/sbin/aridi-scenario-vm.sh'" < "$repo/tests/lima/scenario-vm.sh"
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
        echo "image=qemu:$image@sha256:$sha256"
        echo "platform=qemu/x86_64"
        echo "arch=$(vmsh uname -m < /dev/null)"
        echo "network=qemu-user"
        echo "captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "collector_version=$(sed -n 's/^ARIDI_COLLECTOR_VERSION="\(.*\)"/\1/p' "$collector")"
        echo "collector_exit=$collector_rc"
        echo "collector_seconds=$collector_seconds"
        echo "facts_exit=$facts_rc"
        echo "qemu_version=$(qemu-system-x86_64 --version | sed -n '1s/.*version \([^ ]*\).*/\1/p')"
        echo "qemu_accel=${accel%%,*}"
    } > "$out/meta.txt"

    stop
    trap - EXIT INT TERM
    rm -f "$log"
    echo "vm-$vm: collector exit $collector_rc, $(wc -c < "$out/bundle.aridi" | tr -d ' ') bytes, $(grep -c '^ok' "$out/scenario.txt") ok / $(grep -c '^skip' "$out/scenario.txt") skipped"
}

if [ "${1:-}" = all ]; then
    status=0
    for vm in centos7-amd64 centos6-amd64; do
        ( capture "$vm" ) || { echo "vm-$vm: FAILED"; status=1; }
    done
    exit $status
fi

if [ $# -ne 1 ]; then
    echo "usage: $0 VM | all" >&2
    exit 2
fi
capture "$1"
