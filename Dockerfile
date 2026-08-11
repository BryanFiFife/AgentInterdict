FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MEMORYGUARD_DB=/data/memoryguard.db \
    MEMORYGUARD_BACKUP_DIR=/data/backups \
    MEMORYGUARD_PORT=43847

WORKDIR /app
COPY requirements.txt requirements-tested.txt ./
RUN pip install --no-cache-dir -r requirements-tested.txt \
    && groupadd --system memoryguard \
    && useradd --system --gid memoryguard --home /app memoryguard \
    && mkdir -p /data/backups \
    && chown -R memoryguard:memoryguard /app /data
COPY --chown=memoryguard:memoryguard memoryguard ./memoryguard
COPY --chown=memoryguard:memoryguard scripts ./scripts

USER memoryguard
VOLUME ["/data"]
EXPOSE 43847
CMD ["sh","-c","python scripts/doctor.py && exec uvicorn memoryguard.app:app --host ${MEMORYGUARD_HOST:-0.0.0.0} --port ${MEMORYGUARD_PORT:-43847}"]
