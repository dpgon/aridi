#!/bin/sh
# Disposable SSH target for the tests of the central component (TODO.md 5.4 and 5.8).
#
#   ssh-target.sh up NAME NETWORK DIR   start container NAME on the internal Docker network
#                                       NETWORK, prepared as docs describe for a real
#                                       machine (decision of TODO.md 5.0):
#                                         - accounts "aridi" (with the sudo rule) and
#                                           "nosudo" (without it), same test key;
#                                         - the collector installed at
#                                           /usr/local/libexec/aridi-collect.sh, root, 0755;
#                                         - /etc/sudoers.d/aridi:
#                                           aridi ALL=(root) NOPASSWD: <that path> ""
#                                       and leave in DIR: id, id.pub (test key, made in a
#                                       container), known_hosts and ssh_config.
#   ssh-target.sh down NAME             remove the container
#
# Nothing of the host goes into the target: files are copied with "docker cp".

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
image=aridi-ssh-target
tools=aridi-central-test
script=/usr/local/libexec/aridi-collect.sh

up() {
    name=$1 network=$2 dir=$3
    docker build -q -t "$image" "$here/sshd" >/dev/null
    docker network inspect "$network" >/dev/null 2>&1 ||
        docker network create --internal "$network" >/dev/null
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --hostname "$name" --network "$network" "$image" >/dev/null

    rm -f "$dir/id" "$dir/id.pub"
    docker run --rm --network none -v "$dir":/k "$tools" \
        ssh-keygen -q -t ed25519 -N "" -C aridi-test -f /k/id
    for user in aridi nosudo; do
        docker exec "$name" install -d -o "$user" -g "$user" -m 0700 "/home/$user/.ssh"
        docker cp "$dir/id.pub" "$name:/home/$user/.ssh/authorized_keys"
        docker exec "$name" chown "$user:$user" "/home/$user/.ssh/authorized_keys"
        docker exec "$name" chmod 0600 "/home/$user/.ssh/authorized_keys"
    done

    docker cp "$repo/collector/aridi-collect.sh" "$name:/tmp/aridi-collect.sh"
    docker exec "$name" install -D -o root -g root -m 0755 /tmp/aridi-collect.sh "$script"
    docker exec "$name" rm /tmp/aridi-collect.sh
    docker exec "$name" sh -c "echo 'aridi ALL=(root) NOPASSWD: $script \"\"' \
        > /etc/sudoers.d/aridi && chmod 0440 /etc/sudoers.d/aridi && visudo -cq"

    tries=0
    until key=$(docker exec "$name" cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null); do
        tries=$((tries + 1))
        [ $tries -lt 30 ] || { echo "ssh-target: no host key in $name" >&2; return 1; }
        sleep 1
    done
    echo "$name $key" | cut -d' ' -f1-3 > "$dir/known_hosts"
    printf 'Host *\n    IdentityFile /k/id\n    IdentitiesOnly yes\n' > "$dir/ssh_config"
}

case ${1:-} in
    up) [ $# -eq 4 ] || { echo "usage: $0 up NAME NETWORK DIR" >&2; exit 2; }
        up "$2" "$3" "$4" ;;
    down) docker rm -f "$2" >/dev/null 2>&1 || true ;;
    *) echo "usage: $0 up NAME NETWORK DIR | down NAME" >&2; exit 2 ;;
esac
