"""Data migration: the "administration" and "read-only" groups with their permissions."""

from django.db import migrations

from aridi_central.web.migrations import _roles

# Frozen: the roles as phase 5 defined them. Later permissions come in later migrations.
VIEW = [
    "inventory.view_machine", "inventory.view_group", "inventory.view_snapshot",
    "collection.view_job", "collection.view_schedule",
]
ADMIN_ONLY = [
    "inventory.add_machine", "inventory.change_machine", "inventory.delete_machine",
    "inventory.add_group", "inventory.change_group", "inventory.delete_group",
    "inventory.add_snapshot",
    "collection.add_job",
    "collection.add_schedule", "collection.change_schedule", "collection.delete_schedule",
]
ROLES = {"administration": VIEW + ADMIN_ONLY, "read-only": VIEW}


def create_roles(apps, schema_editor):
    _roles.grant(apps, ROLES)


def remove_roles(apps, schema_editor):
    apps.get_model("auth", "Group").objects.filter(name__in=list(ROLES)).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("contenttypes", "0002_remove_content_type_name"),
        ("inventory", "0001_initial"),
        ("collection", "0001_initial"),
    ]
    operations = [migrations.RunPython(create_roles, remove_roles)]
