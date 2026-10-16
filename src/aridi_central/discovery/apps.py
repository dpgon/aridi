from django.apps import AppConfig


class DiscoveryConfig(AppConfig):
    """Network discovery from the central component (TODO.md, phase 7)."""

    name = "aridi_central.discovery"
    label = "discovery"
    default_auto_field = "django.db.models.BigAutoField"
