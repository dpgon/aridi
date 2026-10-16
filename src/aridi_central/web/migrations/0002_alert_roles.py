"""Data migration: the permissions of the alerts (phase 6) for the two roles."""

from django.db import migrations

from aridi_central.web.migrations import _roles

VIEW = ["changes.view_alert", "changes.view_ruleoverride", "changes.view_channel",
        "changes.view_delivery"]
ADMIN_ONLY = [
    "changes.change_alert",
    "changes.add_ruleoverride", "changes.change_ruleoverride", "changes.delete_ruleoverride",
    "changes.add_channel", "changes.change_channel", "changes.delete_channel",
]
ROLES = {"administration": VIEW + ADMIN_ONLY, "read-only": VIEW}


def create_roles(apps, schema_editor):
    _roles.grant(apps, ROLES)


def remove_roles(apps, schema_editor):
    _roles.revoke(apps, ROLES)


class Migration(migrations.Migration):
    dependencies = [("web", "0001_roles"), ("changes", "0001_initial")]
    operations = [migrations.RunPython(create_roles, remove_roles)]
