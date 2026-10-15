#!/bin/sh
# Runs the aridi test suites. Everything runs in Docker, so the host only needs a POSIX
# shell and Docker (the host Python is never used).
#
# Usage: tests/run.sh [unit|collector|central|legacy|all|golden]    (default: all)
#
#   unit       core unit tests (python -m unittest) in python:3.12-slim
#   collector  tests of collector/aridi-collect.sh in every corpus image
#   central    tests of the central component (phase 5)
#   legacy     regression of the 2019 aridi against tests/legacy/baseline/
#   all        all of the above; exit code is non-zero if any part fails
#   golden     regenerate the golden report of tests/test_core/test_text.py (review the diff)

set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
python_image=python:3.12-slim

run_unit() {
    docker run --rm --network none \
        -v "$repo":/repo:ro -w /repo \
        -e PYTHONPATH=src -e PYTHONDONTWRITEBYTECODE=1 \
        "$python_image" python -m unittest discover -s tests -t . "$@"
}

run_collector() {
    "$here/collector/test_script.sh" "$@"
}

run_golden() {
    docker run --rm --network none \
        -v "$repo":/repo:ro -v "$repo/tests/test_core/data":/golden -w /repo \
        -e PYTHONPATH=src -e PYTHONDONTWRITEBYTECODE=1 \
        "$python_image" sh -c 'python -m aridi.cli report --detail \
            tests/corpus/debian12/minimal/bundle.aridi > /golden/report-debian12-minimal.txt;
            test $? -le 1'
}

run_central() {
    echo "central: no tests yet (TODO.md, phase 5)"
}

run_legacy() {
    if [ -d "$repo/legacy" ]; then
        "$here/legacy/baseline.sh" compare
    else
        echo "legacy: legacy/ no longer exists, skipped"
    fi
}

suite=${1:-all}
case $suite in
    unit|collector|central|legacy|golden)
        shift
        "run_$suite" "$@"
        exit $?
        ;;
    all)
        failed=""
        for part in unit collector central legacy; do
            echo "==> $part"
            if ! "run_$part"; then
                failed="$failed $part"
            fi
        done
        echo
        if [ -n "$failed" ]; then
            echo "FAILED:$failed"
            exit 1
        fi
        echo "ALL PASSED: unit collector central legacy"
        ;;
    *)
        echo "usage: $0 [unit|collector|central|legacy|all|golden]" >&2
        exit 2
        ;;
esac
