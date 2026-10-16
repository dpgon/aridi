from django.apps import AppConfig
from django.db.backends.signals import connection_created


def sqlite_pragmas(sender, connection, **kwargs):
    """WAL, a busy timeout and foreign keys on every SQLite connection (TODO.md 5.1)."""
    if connection.vendor != "sqlite":
        return
    with connection.cursor() as cursor:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=20000")
        cursor.execute("PRAGMA foreign_keys=ON")


class InventoryConfig(AppConfig):
    name = "aridi_central.inventory"
    label = "inventory"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        connection_created.connect(sqlite_pragmas, dispatch_uid="aridi_sqlite_pragmas")
