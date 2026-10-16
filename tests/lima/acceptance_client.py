"""Web client of the phase 5 acceptance (tests/lima/central-acceptance.sh), run in "web".

Arguments: SSH_TARGET SSH_PORT ADMIN_PASSWORD READER_PASSWORD LOCAL_BUNDLE_PATH
Browser and check are also used by alerts_client.py (phase 6). Standard library only;
plain HTTP to gunicorn with X-Forwarded-Proto: https, as the TLS proxy would send.
"""

import http.client
import os
import re
import subprocess
import sys
import time
import urllib.parse
import uuid

HOST = os.environ["ARIDI_ALLOWED_HOSTS"].split(",")[0]


class Browser:
    def __init__(self):
        self.cookies = {}

    def request(self, method, path, form=None, files=None):
        conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=60)
        headers = {"Host": HOST, "X-Forwarded-Proto": "https",
                   "Referer": f"https://{HOST}/",
                   "Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())}
        body = None
        if form is not None or files is not None:
            form = dict(form or {}, csrfmiddlewaretoken=self.cookies.get("csrftoken", ""))
            if files:
                boundary = uuid.uuid4().hex
                parts = []
                for name, value in form.items():
                    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; '
                                 f'name="{name}"\r\n\r\n{value}\r\n'.encode())
                for name, (filename, data) in files.items():
                    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; '
                                 f'name="{name}"; filename="{filename}"\r\nContent-Type: '
                                 f'application/octet-stream\r\n\r\n'.encode() + data + b"\r\n")
                parts.append(f"--{boundary}--\r\n".encode())
                body = b"".join(parts)
                headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            else:
                body = urllib.parse.urlencode(form, doseq=True)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                key, _, rest = value.partition("=")
                self.cookies[key] = rest.split(";", 1)[0]
        return response.status, response.getheader("Location"), response.read().decode()

    def login(self, user, password):
        self.request("GET", "/login/")
        status, location, _ = self.request("POST", "/login/",
                                           {"username": user, "password": password})
        check(status == 302 and location == "/", f"{user} logs in")


def check(condition, message):
    if not condition:
        sys.exit(f"acceptance: FAIL {message}")
    print(f"acceptance: ok {message}")


def wait_for(browser, path, needle, what, seconds=300):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        _, _, body = browser.request("GET", path)
        if re.search(needle, body):
            return body
        time.sleep(3)
    sys.exit(f"acceptance: FAIL {what} (no {needle!r} in {path} after {seconds} s)")


def main():
    target, port, admin_password, reader_password, local_bundle = sys.argv[1:6]
    admin = Browser()
    admin.login("admin", admin_password)
    status, _, _ = admin.request("POST", "/machines/new/", {
        "name": "debian12-arm64", "ssh_target": target, "ssh_port": port, "privilege": "sudo",
        "active": "on"})
    check(status == 302, "the administrator adds the Lima VM")
    _, _, body = admin.request("GET", "/")
    machine = re.search(r'href="/machines/(\d+)/">debian12-arm64<', body).group(1)

    admin.request("POST", "/collect/", {"machine": machine})
    body = wait_for(admin, f"/machines/{machine}/", r"Snapshot of", "on-demand collection")
    check("on-demand SSH collection" in body, "on-demand collection over SSH")
    check("collector_outdated" not in body and "differs from the central" not in body,
          "the installed script is the central's version")
    check("Users and groups" in body and "Infrastructure" in body,
          "the machine page shows the areas")
    _, _, gaps = admin.request("GET", f"/machines/{machine}/gaps/")
    check("what could not be seen" in gaps, "the gaps page with their date")

    status, _, _ = admin.request("POST", "/schedules/new/", {
        "machine": machine, "kind": "interval", "every_hours": "1", "active": "on"})
    check(status == 302, "a schedule for the VM")
    # The hour passing: once the worker has set the first run time, move it into the past.
    subprocess.run([sys.executable, "-m", "aridi_central.manage", "shell", "-v0", "-c",
                    "import time\n"
                    "from datetime import timedelta\n"
                    "from django.utils import timezone\n"
                    "from aridi_central.collection.models import Schedule\n"
                    "for _ in range(60):\n"
                    "    if Schedule.objects.filter(next_run_at__isnull=False).exists(): break\n"
                    "    time.sleep(2)\n"
                    "Schedule.objects.update(next_run_at=timezone.now() - timedelta(minutes=1))\n"],
                   check=True)
    body = wait_for(admin, f"/machines/{machine}/history/", r"scheduled SSH collection",
                    "scheduled collection", seconds=420)
    check(True, "scheduled collection over SSH")

    with open(local_bundle, "rb") as handle:
        data = handle.read()
    status, location, body = admin.request("POST", "/import/", {"machine": machine},
                                           files={"bundle": ("local.aridi", data)})
    check(status == 302 and "/snapshots/" in (location or ""), "import of a local collection")
    _, _, history = admin.request("GET", f"/machines/{machine}/history/")
    check("imported bundle" in history, "the imported snapshot is in the history")

    for kind, query, what in (("package", "openssh-server", "package"), ("port", "tcp/22", "port"),
                              ("user", "aridi", "user")):
        _, _, body = admin.request("GET", "/search/?" + urllib.parse.urlencode(
            {"kind": kind, "query": query}))
        check("debian12-arm64" in body.split("<h1>Search the fleet</h1>")[1],
              f"search finds the VM by {what} ({query})")

    reader = Browser()
    reader.login("reader", reader_password)
    status, _, _ = reader.request("GET", f"/machines/{machine}/")
    check(status == 200, "read-only sees the machine")
    for method, path, form in (("POST", "/collect/", {"machine": machine}),
                               ("GET", "/machines/new/", None),
                               ("POST", f"/machines/{machine}/edit/", {"name": "x"}),
                               ("GET", "/import/", None),
                               ("POST", "/schedules/new/", {"machine": machine})):
        status, _, _ = reader.request(method, path, form if method == "POST" else None)
        check(status == 403, f"read-only cannot {method} {path}")


if __name__ == "__main__":
    main()
