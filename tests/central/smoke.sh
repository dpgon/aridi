#!/bin/sh
# Smoke test of the deployment (TODO.md 5.8), run by tests/central/run.sh:
#   docker compose up (compose.yaml + tests/central/compose.smoke.yaml), a superuser, login,
#   a machine added through the web and collected over SSH by the worker (through an
#   ssh-agent, as in production), a backup with sqlite3 ".backup" and its restoration
#   checked, docker compose down.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
network=aridi-central-ssh
target=aridi-ssh-target
keys=$(mktemp -d)

random() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
fail() { echo "smoke: FAIL $*"; exit 1; }

export ARIDI_SECRET_KEY="$(random)"
export ARIDI_ALLOWED_HOSTS=aridi.example
export ARIDI_CSRF_TRUSTED_ORIGINS=https://aridi.example
export ARIDI_KNOWN_HOSTS_FILE="$keys/known_hosts"
# The agent comes from the sidecar of compose.smoke.yaml; this file only fills the
# variable that compose.yaml requires.
export ARIDI_SSH_AUTH_SOCK="$keys/unused.sock"
export SMOKE_KEYS="$keys"
compose="docker compose -p aridi-smoke -f $repo/compose.yaml -f $here/compose.smoke.yaml"

cleanup() {
    [ "${SMOKE_KEEP:-}" = 1 ] && return
    $compose down -v --remove-orphans >/dev/null 2>&1 || true
    "$here/ssh-target.sh" down "$target"
    rm -rf "$keys"
}
trap cleanup EXIT INT TERM

"$here/ssh-target.sh" up "$target" "$network" "$keys" || fail "SSH target"
: > "$keys/unused.sock"

$compose up -d --build --wait --quiet-pull >/dev/null 2>&1 || {
    $compose logs --tail 30; fail "docker compose up"; }
echo "smoke: ok docker compose up (web and worker healthy)"

password=$(random)
$compose exec -T -e DJANGO_SUPERUSER_PASSWORD="$password" web \
    python -m aridi_central.manage createsuperuser --noinput --username admin \
    --email admin@example.invalid >/dev/null || fail "createsuperuser"
$compose exec -T web python - "aridi@$target" "$password" < "$here/smoke_client.py" || {
    $compose logs --tail 30 worker; fail "web client"; }

$compose exec -T web sqlite3 /data/aridi.db ".backup /data/backup.db" || fail "backup"
check=$($compose exec -T web sqlite3 /data/backup.db "PRAGMA integrity_check")
[ "$check" = ok ] || { echo "smoke: FAIL backup integrity: $check"; exit 1; }
# Restore as README.md says: stop, replace the file and drop the old WAL, start.
$compose exec -T web python -m aridi_central.manage shell -v0 -c \
    "from aridi_central.inventory.models import Machine
Machine.objects.create(name='after-the-backup')" || fail "change after the backup"
$compose stop >/dev/null 2>&1
$compose run --rm --no-deps -T web sh -c \
    'cp /data/backup.db /data/aridi.db && rm -f /data/aridi.db-wal /data/aridi.db-shm' ||
    fail "restore"
$compose up -d --wait >/dev/null 2>&1 || fail "docker compose up after the restore"
restored=$($compose exec -T web python -m aridi_central.manage shell -v0 -c \
    "from aridi_central.inventory.models import Machine, Snapshot
print(Snapshot.objects.exclude(result='failed').count(),
      Machine.objects.filter(name='after-the-backup').count())")
[ "$restored" = "1 0" ] || fail "restored database: snapshots and later machine = $restored"
echo "smoke: ok backup with sqlite3 .backup and restore" \
    "(the snapshot is back, the later change is gone)"

$compose down -v >/dev/null 2>&1
echo "smoke: ok docker compose down"
