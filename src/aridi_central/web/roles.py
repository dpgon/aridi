"""The two roles of the central (docs/CAMBIO.md): administration and read-only.

They are Django groups created by the data migrations of web/ (0001 for phase 5, 0002 for
the alerts of phase 6). Permissions are the model permissions of Django: read-only gets
"view" ones only. A new permission here needs a new data migration that grants it.
"""

ADMIN = "administration"
READ_ONLY = "read-only"

VIEW = [
    "inventory.view_machine", "inventory.view_group", "inventory.view_snapshot",
    "collection.view_job", "collection.view_schedule",
    "changes.view_alert", "changes.view_ruleoverride", "changes.view_channel",
    "changes.view_delivery",
]
ADMIN_ONLY = [
    "inventory.add_machine", "inventory.change_machine", "inventory.delete_machine",
    "inventory.add_group", "inventory.change_group", "inventory.delete_group",
    "inventory.add_snapshot",          # import a raw bundle
    "collection.add_job",              # collect on demand
    "collection.add_schedule", "collection.change_schedule", "collection.delete_schedule",
    "changes.change_alert",            # mark an alert seen or resolved
    "changes.add_ruleoverride", "changes.change_ruleoverride", "changes.delete_ruleoverride",
    "changes.add_channel", "changes.change_channel", "changes.delete_channel",
]
ROLES = {ADMIN: VIEW + ADMIN_ONLY, READ_ONLY: VIEW}
