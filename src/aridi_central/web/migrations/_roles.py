"""Helpers of the role migrations (the migration loader skips modules starting with "_")."""

from django.contrib.auth.management import create_permissions


def grant(apps, roles):
    """Give the groups of ROLES ({name: [app.codename]}) those permissions."""
    # Permissions are normally created after all migrations; they are needed now.
    for app_config in apps.get_app_configs():
        app_config.models_module = True
        create_permissions(app_config, apps=apps, verbosity=0)
        app_config.models_module = None
    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    for name, codes in roles.items():
        group, _ = Group.objects.get_or_create(name=name)
        for code in codes:
            app_label, codename = code.split(".")
            group.permissions.add(Permission.objects.get(content_type__app_label=app_label,
                                                         codename=codename))


def revoke(apps, roles):
    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    for name, codes in roles.items():
        group = Group.objects.filter(name=name).first()
        if group is None:
            continue
        for code in codes:
            app_label, codename = code.split(".")
            group.permissions.remove(*Permission.objects.filter(
                content_type__app_label=app_label, codename=codename))
