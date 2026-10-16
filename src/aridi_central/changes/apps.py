from django.apps import AppConfig


class ChangesConfig(AppConfig):
    """Changes between snapshots and alerts (TODO.md, phase 6)."""

    name = "aridi_central.changes"
    label = "changes"
    default_auto_field = "django.db.models.BigAutoField"
