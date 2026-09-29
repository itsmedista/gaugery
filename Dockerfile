FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends smartmontools iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py collectors.py alerts.py auth.py remote.py checks.py dockerops.py security.py ./
COPY static ./static

ENV HOST_ROOT=/host \
    DB_PATH=/data/metrics.db \
    HOST=0.0.0.0 \
    PORT=8088 \
    PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 \
  CMD ["python", "app.py", "--healthcheck"]
CMD ["python", "app.py"]
