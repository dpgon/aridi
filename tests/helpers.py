"""Shared helpers of the unit tests: synthetic bundles and the corpus samples."""

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "tests" / "corpus"
BOUNDARY = "0123456789abcdef0123456789abcdef"

# VM samples: Lima (tests/lima/) and plain QEMU for CentOS (tests/qemu/).
VMS = ("vm-debian12-arm64", "vm-rocky9-arm64", "vm-debian12-amd64", "vm-ubuntu2404-arm64",
       "vm-alma10-arm64", "vm-centos7-amd64", "vm-centos6-amd64")
SYSTEMD_VMS = tuple(name for name in VMS if name != "vm-centos6-amd64")
NFT_VMS = tuple(name for name in VMS if not name.startswith("vm-centos"))
IPTABLES_VMS = ("vm-centos7-amd64", "vm-centos6-amd64")
# The host as each VM sees it (where its SSH sessions come from): the gateway of Lima's
# user network, or of QEMU's.
VM_HOST = {name: "10.0.2.2" if name in IPTABLES_VMS else "192.168.5.2" for name in VMS}


def make_bundle(sections, version=1, boundary=BOUNDARY, close=None, collector="2.0.0.test"):
    """Bytes of a bundle laid out like collector/aridi-collect.sh does.

    sections: list of (name, content_bytes, status, rc, note) or (name, content_bytes);
    close: the number in the close line (default: the real count), or False for none.
    """
    out = [f"ARIDI-BUNDLE {version} {collector}\nboundary {boundary}\n".encode()]
    marker = f"--{boundary} "
    for item in sections:
        name, content, status, rc, note = (tuple(item) + ("ok", 0, ""))[:5]
        out.append(f"{marker}begin {name} kind=cmd tool=test limit=1000\n".encode())
        out.append(content + b"\n")
        out.append(f"{marker}end {name} status={status} rc={rc}\n".encode())
        if note:
            out.append(f"{marker}note {name} {note}\n".encode())
    if close is not False:
        count = len(sections) if close is None else close
        out.append(f"{marker}close sections={count}\n".encode())
    return b"".join(out)


def corpus_bundles():
    """Paths of every raw bundle of the corpus (tests/corpus/*/*/bundle.aridi)."""
    return sorted(CORPUS.glob("*/*/bundle.aridi"))


def facts(sample_dir):
    """Blocks of a sample's facts.txt (tests/corpus/facts.sh) as {name: text}."""
    blocks = {}
    name = None
    for line in (sample_dir / "facts.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("### "):
            name = line[4:].strip()
            blocks[name] = []
        elif name is not None:
            blocks[name].append(line)
    return {key: "\n".join(lines) for key, lines in blocks.items()}


def samples():
    """Directories of every corpus sample that has a bundle and facts."""
    return [path.parent for path in corpus_bundles() if (path.parent / "facts.txt").exists()]


def sample_name(sample_dir):
    """"debian12/minimal" for tests/corpus/debian12/minimal."""
    return f"{sample_dir.parent.name}/{sample_dir.name}"


def legacy_report(distro, variant="plain"):
    """Full report of the 2019 aridi for DISTRO (tests/parity/, phase 4.1)."""
    path = REPO / "tests" / "parity" / f"{distro}-{variant}" / "report.txt"
    return path.read_text(encoding="utf-8")


def legacy_bundle(distro, variant="plain"):
    """Path of the bundle collected right after the 2019 report (tests/parity/)."""
    return REPO / "tests" / "parity" / f"{distro}-{variant}" / "bundle.aridi"
