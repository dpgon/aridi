#!/bin/sh
# Final regression of the 2019 aridi against the new collector (TODO.md 4.1).
#
# In one disposable container per distro and variant (the images of
# tests/legacy/baseline.sh), it applies the corpus scenario except in "plain"
# (tests/corpus/scenario.sh: users, groups, banners, carving data, listeners and a process
# with a uid that has no account), runs the unmodified legacy program (without --scan) and right after it
# collector/aridi-collect.sh, so both describe the same machine at the same moment:
#   tests/parity/<distro>-<variant>/report.txt    full report of the 2019 aridi
#   tests/parity/<distro>-<variant>/bundle.aridi  raw bundle of the new collector
#   tests/parity/<distro>-<variant>/badfiles.txt  aridi.badfiles of the 2019 aridi
#   tests/parity/<distro>-<variant>/scenario.txt  what the scenario could set up
# Variants: "plain" (the image without the scenario, network "none": the cases that break
# 2019 are absent, so its users area survives), "none" and "bridge" (an internal Docker
# network: eth0@ifN, no Internet), both with the scenario.
# tests/test_parity.py compares both programs. The images must exist: "tests/legacy/baseline.sh
# compare" builds them. This script goes away with legacy/ (phase 4.2); its output stays
# as frozen reference data.
#
# Usage: tests/legacy/reference.sh

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
network_name=aridi-parity

docker network inspect "$network_name" >/dev/null 2>&1 ||
    docker network create --internal "$network_name" >/dev/null

for d in debian12 centos7; do
    for net in plain none bridge; do
        out="$repo/tests/parity/$d-$net"
        container="aridi-parity-$d-$net"
        case $net in
            plain|none) network=none ;;
            bridge) network=$network_name ;;
        esac
        rm -rf "$out"
        mkdir -p "$out"
        docker rm -f "$container" >/dev/null 2>&1 || true
        # The code is copied, not mounted: a bind mount would put host paths in the bundle
        # (mountinfo).
        docker run -d --name "$container" --network "$network" --hostname "parity-$d" \
            "aridi-legacy-test:$d" sh -c 'while :; do sleep 3600; done' >/dev/null
        docker exec "$container" mkdir -p /tmp/w /usr/local/sbin
        docker cp "$repo/legacy/." "$container:/tmp/w/" >/dev/null
        if [ "$net" = plain ]; then
            echo "skip scenario (plain image, like the phase 3 reference)" > "$out/scenario.txt"
        else
            docker cp "$repo/tests/corpus/scenario.sh" \
                "$container:/usr/local/sbin/aridi-scenario.sh" >/dev/null
            docker exec "$container" sh /usr/local/sbin/aridi-scenario.sh static \
                > "$out/scenario.txt" 2>&1 || true
            # The IPv6 nameserver becomes a None key in the 2019 relation map, and sorting it
            # aborts the whole report (docs/MVP.md n.º 9; observed here in phase 4). Without
            # it there is a report to compare against. resolv.conf may be a bind mount, so it
            # is rewritten in place.
            docker exec "$container" sh -c 'grep -v "^nameserver 2001:db8::53" /etc/resolv.conf \
                > /tmp/resolv && cat /tmp/resolv > /etc/resolv.conf && rm /tmp/resolv'
            echo "skip IPv6 nameserver removed again (it aborts the 2019 report)" >> "$out/scenario.txt"
            for spec in "tcp6-any 8080" "tcp4-local 8081" "udp4-any 5514"; do
                docker exec -d "$container" sh /usr/local/sbin/aridi-scenario.sh listen $spec
            done
            docker exec -d -u 4242:4242 "$container" sleep 3600
            sleep 2
        fi
        docker exec "$container" sh -c '
            cd /tmp/w
            printf "y\nn\nn\nn\nm\n" | python3 aridi.py -a -V 3 -of report.txt >/dev/null 2>&1
            cat report.txt' > "$out/report.txt"
        docker exec "$container" cat /tmp/w/aridi.badfiles > "$out/badfiles.txt"
        docker exec -i "$container" sh -s < "$repo/collector/aridi-collect.sh" \
            > "$out/bundle.aridi"
        docker rm -f "$container" >/dev/null
        echo "$d-$net: report $(wc -l < "$out/report.txt" | tr -d ' ') lines," \
            "bundle $(wc -c < "$out/bundle.aridi" | tr -d ' ') bytes"
    done
done
