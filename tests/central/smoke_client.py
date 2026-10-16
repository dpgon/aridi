"""Browser-like client of the smoke test (tests/central/smoke.sh), run inside "web".

Logs in, adds the SSH target as a machine, asks for a collection and waits until the
machine page shows a snapshot. Standard library only. Talks plain HTTP to gunicorn with
X-Forwarded-Proto: https, as the TLS proxy would.
"""

import http.client
import os
import re
import sys
import time
import urllib.parse

HOST = os.environ["ARIDI_ALLOWED_HOSTS"].split(",")[0]
TARGET = sys.argv[1]
PASSWORD = sys.argv[2]
cookies = {}


def request(method, path, form=None):
    conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=30)
    headers = {"Host": HOST, "X-Forwarded-Proto": "https", "Referer": f"https://{HOST}/",
               "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())}
    body = None
    if form is not None:
        form = dict(form, csrfmiddlewaretoken=cookies.get("csrftoken", ""))
        body = urllib.parse.urlencode(form, doseq=True)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    for name, value in response.getheaders():
        if name.lower() == "set-cookie":
            key, _, rest = value.partition("=")
            cookies[key] = rest.split(";", 1)[0]
    return response.status, response.getheader("Location"), response.read().decode()


def check(condition, message):
    if not condition:
        sys.exit(f"smoke: FAIL {message}")
    print(f"smoke: ok {message}")


status, location, _ = request("GET", "/")
check(status == 302 and "/login/" in location, "anonymous is sent to the login page")
request("GET", "/login/")
status, location, _ = request("POST", "/login/", {"username": "admin", "password": PASSWORD})
check(status == 302 and location == "/", "login")
status, location, body = request("POST", "/machines/new/", {
    "name": "ssh-target", "ssh_target": TARGET, "ssh_port": "22", "privilege": "sudo",
    "active": "on"})
check(status == 302, f"machine created ({status})")
_, _, body = request("GET", "/")
machine = re.search(r'href="/machines/(\d+)/">ssh-target<', body).group(1)
status, _, _ = request("POST", "/collect/", {"machine": machine})
check(status == 302, "collection queued")
deadline = time.monotonic() + 180
while time.monotonic() < deadline:
    _, _, body = request("GET", f"/machines/{machine}/")
    if "Snapshot of" in body:
        break
    if "Last collection failed" in body:
        sys.exit("smoke: FAIL " + re.search(r"Last collection failed[^<]*", body).group())
    time.sleep(3)
check("Snapshot of" in body, "the worker collected the machine over SSH")
check("Packages" in body and "with gaps" in body or "complete" in body,
      "the machine page shows the snapshot")
