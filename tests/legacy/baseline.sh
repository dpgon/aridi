#!/bin/sh
# Baseline of the 2019 aridi (TODO.md, phase 0.1).
#
# Runs the unmodified legacy program inside disposable containers without network,
# and records what it produces: the ERROR lines of aridi.log, the section headers of
# the report and the exit code. Those three things must not change while the legacy
# code is moved or kept around during the rewrite.
#
# Usage:
#   tests/legacy/baseline.sh record  [SRC_DIR]   write tests/legacy/baseline/<distro>/
#   tests/legacy/baseline.sh compare [SRC_DIR]   compare against the recorded baseline
#
# SRC_DIR is the directory holding aridi.py, relative to the repository root
# (default: "legacy" if it exists, "." otherwise).

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
baseline_dir="$here/baseline"
distros="debian12 centos7"

mode=${1:-}
if [ -d "$repo/legacy" ]; then default_src=legacy; else default_src=.; fi
src=${2:-$default_src}

case $mode in
    record|compare) ;;
    *) echo "usage: $0 record|compare [SRC_DIR]" >&2; exit 2 ;;
esac

if [ ! -f "$repo/$src/aridi.py" ]; then
    echo "error: $repo/$src/aridi.py not found" >&2
    exit 2
fi

# Builds a test image with python3 for the given distro (only needs network here).
build_image() {
    case $1 in
        debian12)
            docker build -q -t aridi-legacy-test:debian12 - >/dev/null <<'EOF'
FROM debian:12
RUN apt-get update && apt-get install -y --no-install-recommends python3 iproute2 procps iptables dnsutils && rm -rf /var/lib/apt/lists/*
EOF
            ;;
        centos7)
            # CentOS 7 is EOL: use the vault (altarch for non-x86_64 architectures).
            docker build -q -t aridi-legacy-test:centos7 - >/dev/null <<'EOF'
FROM centos:7
RUN if [ "$(uname -m)" = x86_64 ]; then base=http://vault.centos.org/7.9.2009; else base=http://vault.centos.org/altarch/7.9.2009; fi \
 && sed -i -e 's|^mirrorlist=|#mirrorlist=|' -e "s|^#\?baseurl=.*/\$releasever/|baseurl=$base/|" /etc/yum.repos.d/*.repo \
 && yum install -y python3 iproute && yum clean all
EOF
            ;;
    esac
}

# Runs legacy aridi in the container and prints three marked blocks on stdout.
run_legacy() {
    docker run --rm --network none -v "$repo/$src":/src:ro "aridi-legacy-test:$1" sh -c '
        mkdir -p /tmp/w && cp -r /src/. /tmp/w/ && cd /tmp/w
        printf "y\nn\nn\nn\nm\n" | python3 aridi.py -a --scan -V 3 -of report.txt >/dev/null 2>&1
        rc=$?
        echo "@@exit"; echo "$rc"
        echo "@@errors"; sed -n "s/^.* - ERROR - //p" aridi.log
        echo "@@sections"; grep -E "^(\*\*.*\*\*|\|\|.*\|\|)\$" report.txt | sed "s/  */ /g"
    '
}

# Splits the marked output into exit.txt, errors.txt and sections.txt in $2.
split_output() {
    mkdir -p "$2"
    awk -v dir="$2" '
        /^@@exit$/     { out = dir "/exit.txt";     printf "" > out; next }
        /^@@errors$/   { out = dir "/errors.txt";   printf "" > out; next }
        /^@@sections$/ { out = dir "/sections.txt"; printf "" > out; next }
        out != ""      { print >> out }
    ' "$1"
}

status=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

for d in $distros; do
    build_image "$d"
    run_legacy "$d" > "$tmp/$d.out"
    split_output "$tmp/$d.out" "$tmp/$d"
    case $mode in
        record)
            rm -rf "${baseline_dir:?}/$d"
            mkdir -p "$baseline_dir"
            cp -R "$tmp/$d" "$baseline_dir/$d"
            echo "$d: recorded (exit $(cat "$tmp/$d/exit.txt"), $(wc -l < "$tmp/$d/errors.txt" | tr -d ' ') errors, $(wc -l < "$tmp/$d/sections.txt" | tr -d ' ') sections)"
            ;;
        compare)
            if diff -r "$baseline_dir/$d" "$tmp/$d" > "$tmp/$d.diff"; then
                echo "$d: OK, identical to baseline"
            else
                echo "$d: DIFFERENT from baseline"
                cat "$tmp/$d.diff"
                status=1
            fi
            ;;
    esac
done

exit $status
