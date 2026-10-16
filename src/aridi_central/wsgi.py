"""WSGI entry point (gunicorn aridi_central.wsgi)."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aridi_central.settings")
application = get_wsgi_application()
