"""Synthetic snapshot pairs for the tests of the changes app: a corpus snapshot and copies
of it with one thing changed."""

import copy
import functools

from aridi import bundle as core_bundle
from aridi.interpret import interpret

from aridi_central.testing import corpus_bundle


@functools.cache
def _base(name, variant):
    return interpret(core_bundle.parse(corpus_bundle(name, variant))).to_dict()


def snapshot(name="vm-debian12-arm64", variant="vm"):
    """A fresh deep copy of the snapshot dict of a corpus sample."""
    return copy.deepcopy(_base(name, variant))


def data(snap, area):
    return snap["sections"][area]["data"]


def set_status(snap, area, status, reason="test"):
    snap["sections"][area].update(status=status, reason=reason, data=None)
    return snap


USER = {"name": "mallory", "uid": 1500, "gid": 1500, "gecos": "", "home": "/home/mallory",
        "shell": "/bin/bash", "groups": ["mallory"], "password": "set",
        "algorithm": "yescrypt", "aging": None}


def add_user(snap, **fields):
    data(snap, "users")["users"].append(dict(USER, **fields))
    return snap


def add_listening(snap, proto="tcp", address="0.0.0.0", port=4444, name="nc"):
    data(snap, "network")["listening"].append(
        {"proto": proto, "address": address, "port": port, "uid": 0, "inode": 1,
         "processes": [{"pid": 999, "name": name}]})
    return snap
