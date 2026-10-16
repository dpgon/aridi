# Test image of the central component (tests/run.sh central): python:3.12-slim with the
# pinned dependencies of requirements/central.txt and the OpenSSH client. The repository
# is mounted at run time, never copied. Build context: requirements/.
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sqlite3 \
 && rm -rf /var/lib/apt/lists/*
COPY central.txt /tmp/central.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/central.txt
