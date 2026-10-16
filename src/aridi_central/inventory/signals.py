"""Signals of the inventory, so that other apps react without the inventory knowing them.

The changes app (phase 6) evaluates its alert rules on them.
"""

from django.dispatch import Signal

# A new snapshot with data was stored (keyword argument: snapshot).
snapshot_stored = Signal()
# A collection failed and was stored as a failed snapshot (keyword argument: snapshot).
collection_failed = Signal()
