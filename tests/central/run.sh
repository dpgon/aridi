#!/bin/sh
# Tests of the central component (TODO.md, phase 5). Run by "tests/run.sh central".
#
#   1. Builds aridi-central-test (tests/central/Dockerfile): python:3.12-slim with
#      requirements/central.txt installed with --require-hashes. Only this build uses
#      the network.
#   2. In that image, without network and with the repository read-only:
#      "manage.py check --deploy" with production settings and "manage.py test".
#   3. Integration (TODO.md 5.4): a disposable SSH target on an internal Docker network
#      (tests/central/ssh-target.sh) and the SSH tests against it.
#   4. Smoke test of the deployment (TODO.md 5.8): tests/central/smoke.sh.
# Steps 3 and 4 only run without TEST_LABEL.
#
# Usage: tests/central/run.sh [TEST_LABEL...]     (default: every test of aridi_central)

set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
image=aridi-central-test

docker build -q -t "$image" -f "$here/Dockerfile" "$repo/requirements" >/dev/null ||
    { echo "central: building $image failed"; exit 1; }

secret=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
status=0

docker run --rm --network none -v "$repo":/repo:ro -w /repo \
    -e PYTHONDONTWRITEBYTECODE=1 -e ARIDI_SECRET_KEY="$secret" \
    -e ARIDI_ALLOWED_HOSTS=aridi.example -e ARIDI_DB_PATH=/tmp/aridi.db \
    "$image" python src/aridi_central/manage.py check --deploy --fail-level WARNING ||
    status=1

[ $# -gt 0 ] || set -- aridi_central
docker run --rm --network none -v "$repo":/repo:ro -w /repo \
    -e PYTHONDONTWRITEBYTECODE=1 -e ARIDI_SECRET_KEY="$secret" \
    -e ARIDI_DB_PATH=/tmp/aridi.db -e ARIDI_TEST_DB_PATH=/tmp/aridi-test.db \
    "$image" python src/aridi_central/manage.py test --noinput "$@" || status=1

# Integration: only when no label was given (a full run).
if [ "$*" = aridi_central ]; then
    network=aridi-central-ssh
    target=aridi-ssh-target
    keys=$(mktemp -d)
    trap '"$here/ssh-target.sh" down "$target"; rm -rf "$keys"' EXIT INT TERM
    if "$here/ssh-target.sh" up "$target" "$network" "$keys"; then
        docker run --rm --network "$network" -v "$repo":/repo:ro -v "$keys":/k:ro -w /repo \
            -e PYTHONDONTWRITEBYTECODE=1 -e ARIDI_SECRET_KEY="$secret" \
            -e ARIDI_DB_PATH=/tmp/aridi.db -e ARIDI_TEST_DB_PATH=/tmp/aridi-test.db \
            -e ARIDI_TEST_SSH_HOST="$target" \
            "$image" python src/aridi_central/manage.py test --noinput \
            aridi_central.collection.tests.test_integration || status=1
    else
        echo "central: the SSH target could not be started"
        status=1
    fi
    "$here/ssh-target.sh" down "$target"
    # Deployment (TODO.md 5.8): docker compose up, web, worker, backup, down.
    "$here/smoke.sh" || status=1
fi

exit $status
