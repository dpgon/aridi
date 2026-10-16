"""Data migration: the permissions of network discovery (phase 7) for the two roles."""

from django.db import migrations

from aridi_central.web.migrations import _roles

VIEW = ["discovery.view_authorizednetwork", "discovery.view_scanresult"]
ADMIN_ONLY = ["discovery.add_authorizednetwork", "discovery.change_authorizednetwork",
              "discovery.delete_authorizednetwork"]
ROLES = {"administration": VIEW + ADMIN_ONLY, "read-only": VIEW}


def create_roles(apps, schema_editor):
    _roles.grant(apps, ROLES)


def remove_roles(apps, schema_editor):
    _roles.revoke(apps, ROLES)


class Migration(migrations.Migration):
    dependencies = [("web", "0002_alert_roles"), ("discovery", "0001_initial")]
    operations = [migrations.RunPython(create_roles, remove_roles)]
