"""URLs of the central component: everything is in the web application."""

from django.urls import include, path

urlpatterns = [path("", include("aridi_central.web.urls"))]
