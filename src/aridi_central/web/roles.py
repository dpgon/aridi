"""The two roles of the central (docs/CAMBIO.md): administration and read-only.

They are Django groups created by the data migration web/0001. Permissions are the
model permissions of Django: read-only gets "view" ones only.
"""

ADMIN = "administration"
READ_ONLY = "read-only"

VIEW = [
    "inventory.view_machine", "inventory.view_group", "inventory.view_snapshot",
    "collection.view_job", "collection.view_schedule",
]
ADMIN_ONLY = [
    "inventory.add_machine", "inventory.change_machine", "inventory.delete_machine",
    "inventory.add_group", "inventory.change_group", "inventory.delete_group",
    "inventory.add_snapshot",          # import a raw bundle
    "collection.add_job",              # collect on demand
    "collection.add_schedule", "collection.change_schedule", "collection.delete_schedule",
]
ROLES = {ADMIN: VIEW + ADMIN_ONLY, READ_ONLY: VIEW}
