# Image of the aridi central component (TODO.md 5.8): web (gunicorn) and worker.
#
# Pinned base image; third-party Python code only from requirements/central.txt, checked
# by hash. The project itself is copied, not pip-installed: building it would make pip
# download setuptools without a hash (README.md, "Installation").
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sqlite3 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 aridi \
 && useradd --system --uid 10001 --gid aridi --home-dir /home/aridi --create-home aridi \
 && install -d -o aridi -g aridi -m 0750 /data

COPY requirements/central.txt /tmp/central.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/central.txt && rm /tmp/central.txt

COPY src/aridi /app/src/aridi
COPY src/aridi_central /app/src/aridi_central
# The script that the worker sends (user mode) and whose SHA-256 it compares with the
# installed copies (sudo mode).
COPY collector/aridi-collect.sh /opt/aridi/aridi-collect.sh

ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=aridi_central.settings \
    ARIDI_DB_PATH=/data/aridi.db \
    ARIDI_COLLECTOR_SCRIPT=/opt/aridi/aridi-collect.sh

USER aridi
WORKDIR /home/aridi
VOLUME ["/data"]
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--access-logfile", "-", \
     "aridi_central.wsgi"]
