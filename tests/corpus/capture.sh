#!/bin/sh
# Captures one corpus sample in a disposable container (TODO.md, phase 1.1).
#
# Usage: tests/corpus/capture.sh NAME VARIANT
#        tests/corpus/capture.sh all            every image of images.txt, every variant
#
#   NAME     a name from tests/corpus/images.txt (debian12, alpine320, centos6...)
#   VARIANT  minimal  the image as is, without Python, network "none"
#            server   image + iproute2/procps/util-linux/nftables/iptables/socat, network "none"
#            bridge   the server image on an internal bridge network (eth0@ifN interfaces)
#
# Steps: start the container, apply scenario.sh (users, groups, files, listeners, a
# process with a uid that has no account), run collector/aridi-collect.sh through
# "sh -s" as root, run facts.sh, and save everything in tests/corpus/NAME/VARIANT/:
#   bundle.aridi   raw bundle written by the collector to stdout
#   facts.txt      reference facts (facts.sh)
#   scenario.txt   what the scenario could and could not set up
#   meta.txt       image, digest, platform, variant, date, exit codes
#
# Server images are built with network access; the samples themselves never have
# Internet access.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
collector="$repo/collector/aridi-collect.sh"
network_name=aridi-corpus

image_line() {
    awk -v n="$1" '$1 == n { print; found = 1 } END { exit !found }' "$here/images.txt"
}

server_install() {
    # Install command of the "server" variant per package family.
    case $1 in
        apt) echo "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 procps util-linux nftables iptables socat && rm -rf /var/lib/apt/lists/*" ;;
        dnf) echo "dnf install -y iproute procps-ng util-linux nftables iptables-nft socat && dnf clean all" ;;
        apk) echo "apk add --no-cache iproute2 procps util-linux nftables iptables socat" ;;
        zypper) echo "zypper -n install --no-recommends iproute2 procps util-linux nftables iptables socat && zypper clean -a" ;;
        # pacman 7 sandboxing fails under amd64 emulation (seccomp error 22).
        pacman) echo "pacman -Sy --noconfirm --needed --disable-sandbox iproute2 procps-ng util-linux nftables iptables socat && pacman -Scc --noconfirm" ;;
        yum7) echo "base=http://vault.centos.org/altarch/7.9.2009; [ \"\$(uname -m)\" = x86_64 ] && base=http://vault.centos.org/7.9.2009; sed -i -e 's|^mirrorlist=|#mirrorlist=|' -e \"s|^#\\?baseurl=.*/\\\$releasever/|baseurl=\$base/|\" /etc/yum.repos.d/*.repo && yum install -y iproute procps-ng util-linux nftables iptables socat && yum clean all" ;;
        yum6) echo "sed -i -e 's|^mirrorlist=|#mirrorlist=|' -e 's|^#\\?baseurl=.*/\$releasever/|baseurl=http://vault.centos.org/6.10/|' /etc/yum.repos.d/*.repo && yum install -y iproute procps util-linux-ng iptables nc && yum clean all" ;;
        *) echo "false" ;;
    esac
}

capture() {
    name=$1
    variant=$2
    line=$(image_line "$name") || { echo "unknown image name: $name" >&2; return 2; }
    image=$(echo "$line" | awk '{print $2}')
    platform=$(echo "$line" | awk '{print $3}')
    family=$(echo "$line" | awk '{print $4}')

    case $variant in
        minimal)
            run_image=$image
            net="--network none"
            ;;
        server|bridge)
            run_image="aridi-corpus:$name-server"
            if ! docker image inspect "$run_image" >/dev/null 2>&1; then
                printf 'FROM %s\nRUN %s\n' "$image" "$(server_install "$family")" |
                    docker build -q --platform "$platform" -t "$run_image" - >/dev/null ||
                    { echo "$name/$variant: building $run_image failed" >&2; return 1; }
            fi
            if [ "$variant" = server ]; then
                net="--network none"
            else
                docker network inspect "$network_name" >/dev/null 2>&1 ||
                    docker network create --internal "$network_name" >/dev/null
                net="--network $network_name"
            fi
            ;;
        *)
            echo "unknown variant: $variant" >&2
            return 2
            ;;
    esac

    out="$here/$name/$variant"
    container="aridi-corpus-$name-$variant"
    bind_dir=$(mktemp -d)
    echo "corpus bind mount" > "$bind_dir/README"
    docker rm -f "$container" >/dev/null 2>&1 || true

    # shellcheck disable=SC2086
    docker run -d --name "$container" --platform "$platform" $net \
        --hostname "corpus-$name" \
        --mount type=tmpfs,destination=/srv/scratch \
        -v "$bind_dir":/srv/bind:ro \
        "$run_image" sh -c 'while :; do sleep 3600; done' >/dev/null ||
        { echo "$name/$variant: docker run failed" >&2; rm -rf "$bind_dir"; return 1; }

    rm -rf "$out"
    mkdir -p "$out"

    docker exec "$container" mkdir -p /usr/local/sbin
    docker cp "$here/scenario.sh" "$container:/usr/local/sbin/aridi-scenario.sh" >/dev/null ||
        { echo "$name/$variant: copying scenario.sh failed" >&2; docker rm -f "$container" >/dev/null; return 1; }
    docker exec "$container" sh /usr/local/sbin/aridi-scenario.sh static > "$out/scenario.txt" 2>&1 || true
    for spec in "tcp6-any 8080" "tcp4-local 8081" "udp4-any 5514"; do
        docker exec -d "$container" sh /usr/local/sbin/aridi-scenario.sh listen $spec
    done
    docker exec -d -u 4242:4242 "$container" sleep 3600
    sleep 2
    for spec in "tcp6-any 8080" "tcp4-local 8081" "udp4-any 5514"; do
        port=${spec#* }
        hex=$(printf '%04X' "$port")
        if docker exec "$container" sh -c "grep -q ':$hex ' /proc/net/tcp /proc/net/tcp6 /proc/net/udp 2>/dev/null"; then
            echo "ok listener $spec" >> "$out/scenario.txt"
        else
            echo "skip listener $spec (no socat, python3 or busybox nc)" >> "$out/scenario.txt"
        fi
    done
    echo "ok process with uid 4242 without account (sleep)" >> "$out/scenario.txt"

    set +e
    docker exec -i "$container" sh -s < "$collector" > "$out/bundle.aridi" 2> "$out/collector.stderr"
    collector_rc=$?
    docker exec -i "$container" sh -s < "$here/facts.sh" > "$out/facts.txt" 2>&1
    facts_rc=$?
    set -e
    [ -s "$out/collector.stderr" ] || rm -f "$out/collector.stderr"

    {
        echo "name=$name"
        echo "variant=$variant"
        echo "image=$image"
        echo "run_image=$run_image"
        echo "platform=$platform"
        echo "arch=$(docker exec "$container" uname -m)"
        echo "network=${net#--network }"
        echo "captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "collector_version=$(sed -n 's/^ARIDI_COLLECTOR_VERSION="\(.*\)"/\1/p' "$collector")"
        echo "collector_exit=$collector_rc"
        echo "facts_exit=$facts_rc"
        echo "docker_version=$(docker version --format '{{.Server.Version}}')"
    } > "$out/meta.txt"

    docker rm -f "$container" >/dev/null
    rm -rf "$bind_dir"
    echo "$name/$variant: collector exit $collector_rc, $(wc -c < "$out/bundle.aridi" | tr -d ' ') bytes, $(grep -c '^ok' "$out/scenario.txt") ok / $(grep -c '^skip' "$out/scenario.txt") skipped"
}

if [ "${1:-}" = all ]; then
    status=0
    for name in $(awk '!/^#/ && NF { print $1 }' "$here/images.txt"); do
        for variant in minimal server bridge; do
            capture "$name" "$variant" || { echo "$name/$variant: FAILED"; status=1; }
        done
    done
    exit $status
fi

if [ $# -ne 2 ]; then
    echo "usage: $0 NAME VARIANT | all" >&2
    exit 2
fi
capture "$1" "$2"
