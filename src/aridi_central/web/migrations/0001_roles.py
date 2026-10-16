"""Data migration: the "administration" and "read-only" groups with their permissions."""

from django.contrib.auth.management import create_permissions
from django.db import migrations

from aridi_central.web.roles import ROLES


def create_roles(apps, schema_editor):
    # Permissions are normally created after all migrations; they are needed now.
    for app_config in apps.get_app_configs():
        app_config.models_module = True
        create_permissions(app_config, apps=apps, verbosity=0)
        app_config.models_module = None
    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    for name, codes in ROLES.items():
        group, _ = Group.objects.get_or_create(name=name)
        for code in codes:
            app_label, codename = code.split(".")
            group.permissions.add(Permission.objects.get(content_type__app_label=app_label,
                                                         codename=codename))


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
