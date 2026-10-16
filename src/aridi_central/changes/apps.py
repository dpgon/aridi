from django.apps import AppConfig


class ChangesConfig(AppConfig):
    """Changes between snapshots and alerts (TODO.md, phase 6)."""

    name = "aridi_central.changes"
    label = "changes"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from aridi_central.changes import evaluate
        from aridi_central.inventory.signals import collection_failed, snapshot_stored
        snapshot_stored.connect(evaluate.on_snapshot_stored, dispatch_uid="aridi_alerts")
        collection_failed.connect(evaluate.on_collection_failed,
                                  dispatch_uid="aridi_alerts_failure")
