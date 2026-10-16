#!/bin/sh
# Acceptance of phases 5 and 6 (TODO.md): the central component in docker compose collects
# a real Lima VM (debian12-arm64) over SSH.
#
#   1. Creates a disposable VM without host mounts (as tests/lima/capture-vm.sh) and
#      prepares it like a real machine (README.md, "Preparing a machine"): account
#      "aridi" with a test key, the collector installed at
#      /usr/local/libexec/aridi-collect.sh and the sudo rule limited to it.
#   2. Makes a local collection in the VM (sh aridi-collect.sh), to be imported later.
#   3. docker compose up (compose.yaml + tests/lima/compose.acceptance.yaml), an
#      administrator and a read-only user.
#   4. inventory (phase 5): tests/lima/acceptance_client.py, through the web: adds the VM,
#      collects it on demand and by schedule, sees its page and gaps, imports the local
#      bundle, searches packages, ports and users; the read-only user gets 403 on every
#      change.
#      alerts (phase 6): tests/lima/alerts_client.py in stages, changing the VM between
#      them: a user with a shell and a port raise two alerts, in the web and in the test
#      webhook; silencing both rules for the VM avoids them; with the VM stopped, three
#      failed collections raise "does not respond".
#   5. docker compose down and VM deleted.
#
# Usage: tests/lima/central-acceptance.sh [inventory|alerts]     (default: inventory)

set -eu

mode=${1:-inventory}
case $mode in inventory|alerts) ;; *) echo "usage: $0 [inventory|alerts]" >&2; exit 2 ;; esac
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
vm=debian12-arm64
instance="aridi-central-$vm"
script=/usr/local/libexec/aridi-collect.sh
work=$(mktemp -d)

random() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
fail() { echo "acceptance: FAIL $*"; exit 1; }

export ARIDI_SECRET_KEY="$(random)"
export ARIDI_ALLOWED_HOSTS=aridi.example
export ARIDI_CSRF_TRUSTED_ORIGINS=https://aridi.example
export ARIDI_KNOWN_HOSTS_FILE="$work/known_hosts"
export ARIDI_SSH_AUTH_SOCK="$work/unused.sock"
export ACCEPTANCE_KEYS="$work"
export ACCEPTANCE_TESTS="$here"
# Alerts: a stopped VM fails at once; one attempt per collection is enough.
[ "$mode" = alerts ] && export ACCEPTANCE_JOB_ATTEMPTS=1
compose="docker compose -p aridi-acceptance -f $repo/compose.yaml -f $here/compose.acceptance.yaml"

cleanup() {
    [ "${ACCEPTANCE_KEEP:-}" = 1 ] && return
    $compose down -v --remove-orphans >/dev/null 2>&1 || true
    limactl delete --force "$instance" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

# 1. The VM
limactl delete --force "$instance" >/dev/null 2>&1 || true
limactl start --tty=false --mount-none --name "$instance" "$here/$vm.yaml" \
    > "$work/lima.log" 2>&1 || { cat "$work/lima.log"; fail "limactl start"; }
vmsh() { limactl shell --workdir / "$instance" "$@"; }
if vmsh sh -c "grep -qE ' - (virtiofs|9p|fuse\.sshfs) ' /proc/self/mountinfo"; then
    fail "the VM sees host directories"
fi
echo "acceptance: ok VM $instance without host mounts"

docker run --rm --network none -v "$work":/k aridi-central-test \
    ssh-keygen -q -t ed25519 -N "" -C aridi-acceptance -f /k/id
vmsh sh -c "id aridi >/dev/null 2>&1" || vmsh sudo useradd -m -s /bin/sh aridi
vmsh sudo install -d -o aridi -g aridi -m 0700 /home/aridi/.ssh
vmsh sudo sh -c 'cat > /home/aridi/.ssh/authorized_keys' < "$work/id.pub"
vmsh sudo chown aridi:aridi /home/aridi/.ssh/authorized_keys
vmsh sudo chmod 0600 /home/aridi/.ssh/authorized_keys
vmsh sudo sh -c "cat > /tmp/aridi-collect.sh" < "$repo/collector/aridi-collect.sh"
vmsh sudo install -D -o root -g root -m 0755 /tmp/aridi-collect.sh "$script"
vmsh sudo rm /tmp/aridi-collect.sh
vmsh sudo sh -c "echo 'aridi ALL=(root) NOPASSWD: $script \"\"' > /etc/sudoers.d/aridi \
    && chmod 0440 /etc/sudoers.d/aridi && visudo -cq"
port=$(limactl list --format '{{.SSHLocalPort}}' "$instance")
hostkey=$(vmsh sudo cat /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f1-2)
echo "[host.docker.internal]:$port $hostkey" > "$work/known_hosts"
: > "$work/unused.sock"
echo "acceptance: ok VM prepared (account, key, installed script, sudo rule)"

# 2. A local collection, made in the VM
vmsh sudo sh -s < "$repo/collector/aridi-collect.sh" > "$work/local.aridi"
echo "acceptance: ok local collection in the VM ($(wc -c < "$work/local.aridi" | tr -d ' ') bytes)"

# 3. The central
$compose up -d --build --wait --quiet-pull >/dev/null 2>&1 || {
    $compose logs --tail 30; fail "docker compose up"; }
admin=$(random)
reader=$(random)
$compose exec -T -e DJANGO_SUPERUSER_PASSWORD="$admin" web \
    python -m aridi_central.manage createsuperuser --noinput --username admin \
    --email admin@example.invalid >/dev/null || fail "createsuperuser"
$compose exec -T web python -m aridi_central.manage shell -v0 -c "
from django.contrib.auth.models import Group, User
user = User.objects.create_user('reader', password='$reader')
user.groups.add(Group.objects.get(name='read-only'))" || fail "read-only user"
$compose cp "$work/local.aridi" web:/tmp/local.aridi >/dev/null
echo "acceptance: ok docker compose up, administrator and read-only users"

# 4. Through the web
if [ "$mode" = inventory ]; then
    $compose exec -T web python - "aridi@host.docker.internal" "$port" "$admin" "$reader" \
        /tmp/local.aridi < "$here/acceptance_client.py" || {
        $compose logs --tail 40 worker; fail "web client"; }
    echo "acceptance: ok phase 5 acceptance"
    exit 0
fi

stage() {
    $compose exec -T web python - "$1" "aridi@host.docker.internal" "$port" "$admin" \
        < "$here/alerts_client.py" || {
        $compose logs --tail 40 worker; $compose logs --tail 20 hook; fail "stage $1"; }
}
listen() {
    # A listening socket that stays: a transient systemd service.
    vmsh sudo systemd-run --quiet --unit "aridi-listen-$1" python3 -m http.server "$1" \
        >/dev/null
}
stage baseline
vmsh sudo useradd -m -s /bin/bash mallory
listen 4444
echo "acceptance: ok in the VM: user mallory with /bin/bash, port 4444 listening"
stage changes
vmsh sudo useradd -m -s /bin/bash trudy
listen 4445
echo "acceptance: ok in the VM: user trudy with /bin/bash, port 4445 listening"
stage silenced
limactl stop "$instance" > "$work/lima-stop.log" 2>&1 || {
    cat "$work/lima-stop.log"; fail "limactl stop"; }
echo "acceptance: ok VM stopped"
stage stopped
echo "acceptance: ok phase 6 acceptance"
