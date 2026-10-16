"""Helpers for the tests of the central component: the corpus of the repository."""

from pathlib import Path

from django.conf import settings

REPO = Path(settings.BASE_DIR).parent.parent
CORPUS = REPO / "tests" / "corpus"


def corpus_bundle(name, variant):
    """Bytes of tests/corpus/NAME/VARIANT/bundle.aridi."""
    return (CORPUS / name / variant / "bundle.aridi").read_bytes()
