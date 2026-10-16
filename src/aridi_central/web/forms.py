"""Forms of the web interface."""

from django import forms

from aridi_central.changes.models import Alert, Channel, RuleOverride
from aridi_central.changes.rules import CHOICES, Severity
from aridi_central.collection.models import Schedule
from aridi_central.discovery.models import AuthorizedNetwork
from aridi_central.inventory.models import Group, Machine


class MachineForm(forms.ModelForm):
    class Meta:
        model = Machine
        fields = ["name", "ssh_target", "ssh_port", "proxy_jump", "privilege", "groups",
                  "active"]
        widgets = {"groups": forms.CheckboxSelectMultiple}


class GroupForm(forms.ModelForm):
    class Meta:
        model = Group
        fields = ["name", "description"]


class ScheduleForm(forms.ModelForm):
    class Meta:
        model = Schedule
        fields = ["machine", "group", "network", "kind", "every_hours", "daily_at", "active"]
        widgets = {"daily_at": forms.TimeInput(attrs={"type": "time"})}

    def save(self, commit=True):
        schedule = super().save(commit=False)
        # A changed schedule starts a new period (worker.due_schedules).
        schedule.next_run_at = None
        if commit:
            schedule.save()
        return schedule


class ImportForm(forms.Form):
    bundle = forms.FileField(help_text="Raw bundle made with aridi-collect.sh")
    machine = forms.ModelChoiceField(Machine.objects.all(), required=False,
                                     help_text="Leave empty to match by machine id")
    create = forms.BooleanField(required=False,
                                label="Create a machine named after the hostname if none "
                                      "matches")


class SearchForm(forms.Form):
    KINDS = [("package", "Package"), ("port", "Listening port"), ("user", "User"),
             ("service", "Service"), ("ip", "Related IP address")]
    kind = forms.ChoiceField(choices=KINDS)
    query = forms.CharField(max_length=255, help_text=(
        "package: name or name=version; port: number or tcp/22, udp/53; user, service: "
        "name; ip: address"))


# Alerts (phase 6)

class RuleOverrideForm(forms.ModelForm):
    class Meta:
        model = RuleOverride
        fields = ["rule", "machine", "group", "silenced", "severity", "threshold"]


class ChannelForm(forms.ModelForm):
    class Meta:
        model = Channel
        fields = ["name", "kind", "target", "min_severity", "groups", "active"]
        widgets = {"groups": forms.CheckboxSelectMultiple}


class AlertFilterForm(forms.Form):
    STATES = [("open", "open (new or seen)"), ("", "any")] + list(Alert.State.choices)
    state = forms.ChoiceField(choices=STATES, required=False, initial="open")
    severity = forms.ChoiceField(choices=[("", "any")] + list(Severity.choices),
                                 required=False)
    rule = forms.ChoiceField(choices=[("", "any")] + CHOICES, required=False)
    machine = forms.ModelChoiceField(Machine.objects.all(), required=False)


class AlertStateForm(forms.Form):
    state = forms.ChoiceField(choices=Alert.State.choices)
    note = forms.CharField(required=False, max_length=2000)


# Network discovery (phase 7)

class AuthorizedNetworkForm(forms.ModelForm):
    confirm = forms.BooleanField(
        label="I am allowed to scan this network: it belongs to us or its owner agreed")

    class Meta:
        model = AuthorizedNetwork
        fields = ["cidr", "description", "ports", "active"]
