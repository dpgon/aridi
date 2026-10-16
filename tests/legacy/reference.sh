#!/bin/sh
# Reference values of the 2019 aridi for the phase 3 regression tests (TODO.md, step
# "(e)" of every area).
#
# In one disposable container per distro (the images of tests/legacy/baseline.sh, network
# "none"), it runs the unmodified legacy program (without --scan) and right after it
# collector/aridi-collect.sh, so both describe the same machine at the same moment:
#   tests/legacy/reference/<distro>/report.txt    full report of the 2019 aridi
#   tests/legacy/reference/<distro>/bundle.aridi  raw bundle of the new collector
# Run it again whenever the collector changes, like the corpus capture. The images must
# exist: "tests/legacy/baseline.sh compare" builds them.
#
# Usage: tests/legacy/reference.sh

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

for d in debian12 centos7; do
    out="$here/reference/$d"
    container="aridi-legacy-reference-$d"
    mkdir -p "$out"
    docker rm -f "$container" >/dev/null 2>&1 || true
    # The legacy code is copied, not mounted: a bind mount would put host paths in the
    # bundle (mountinfo).
    docker run -d --name "$container" --network none \
        "aridi-legacy-test:$d" sh -c 'while :; do sleep 3600; done' >/dev/null
    docker exec "$container" mkdir -p /tmp/w
    docker cp "$repo/legacy/." "$container:/tmp/w/" >/dev/null
    docker exec "$container" sh -c '
        cd /tmp/w
        printf "y\nn\nn\nn\nm\n" | python3 aridi.py -a -V 3 -of report.txt >/dev/null 2>&1
        cat report.txt' > "$out/report.txt"
    docker exec -i "$container" sh -s < "$repo/collector/aridi-collect.sh" > "$out/bundle.aridi"
    docker rm -f "$container" >/dev/null
    echo "$d: report $(wc -l < "$out/report.txt" | tr -d ' ') lines, bundle $(wc -c < "$out/bundle.aridi" | tr -d ' ') bytes"
done
