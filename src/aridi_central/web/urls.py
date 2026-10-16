from django.contrib.auth import views as auth_views
from django.urls import path

from aridi_central.web import views

urlpatterns = [
    path("healthz", views.healthz, name="healthz"),
    path("login/", auth_views.LoginView.as_view(template_name="web/login.html"),
         name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", views.machine_list, name="machine-list"),
    path("machines/new/", views.machine_create, name="machine-create"),
    path("machines/<int:pk>/", views.machine_detail, name="machine-detail"),
    path("machines/<int:pk>/edit/", views.machine_edit, name="machine-edit"),
    path("machines/<int:pk>/history/", views.machine_history, name="machine-history"),
    path("machines/<int:pk>/gaps/", views.machine_gaps, name="machine-gaps"),
    path("snapshots/<int:pk>/", views.snapshot_detail, name="snapshot-detail"),
    path("groups/", views.group_list, name="group-list"),
    path("groups/new/", views.group_create, name="group-create"),
    path("groups/<int:pk>/edit/", views.group_edit, name="group-edit"),
    path("schedules/new/", views.schedule_create, name="schedule-create"),
    path("schedules/<int:pk>/edit/", views.schedule_edit, name="schedule-edit"),
    path("schedules/<int:pk>/delete/", views.schedule_delete, name="schedule-delete"),
    path("collect/", views.collect, name="collect"),
    path("jobs/", views.job_list, name="job-list"),
    path("import/", views.import_view, name="import"),
    path("search/", views.search, name="search"),
]
