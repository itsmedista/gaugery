# Pinned by digest, so every build starts from the same bytes. To update: docker pull python:3.12-slim,
# then paste the digest from: docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

RUN apt-get update \
 && apt-get install -y --no-install-recommends smartmontools iputils-ping \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin monitorr \
 && mkdir -p /data && chown 10001:10001 /data

WORKDIR /app
COPY requirements.txt .
# every package, dependencies included, must match the hash recorded in requirements.txt
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY app.py hub.py agent.py common.py collectors.py alerts.py auth.py remote.py checks.py \
     dockerops.py security.py tlsutil.py netguard.py ./
COPY static ./static

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8088
EXPOSE 8088
# Unprivileged by default. Only the agent (docker-compose.yml) runs as root, for host access.
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 \
  CMD ["python", "app.py", "--healthcheck"]
CMD ["python", "app.py"]
