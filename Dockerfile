FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTINTERDICT_DB=/data/agentinterdict.db \
    AGENTINTERDICT_BACKUP_DIR=/data/backups \
    AGENTINTERDICT_PORT=43847 \
    AGENTINTERDICT_HOST=0.0.0.0

WORKDIR /app
COPY requirements.txt requirements-tested.txt ./
RUN pip install --no-cache-dir -r requirements-tested.txt \
    && groupadd --system agentinterdict \
    && useradd --system --gid agentinterdict --home /app agentinterdict \
    && mkdir -p /data/backups \
    && chown -R agentinterdict:agentinterdict /app /data
COPY --chown=agentinterdict:agentinterdict agentinterdict ./agentinterdict
COPY --chown=agentinterdict:agentinterdict scripts ./scripts

USER agentinterdict
VOLUME ["/data"]
EXPOSE 43847
CMD ["sh","-c","python scripts/doctor.py && exec uvicorn agentinterdict.app:app --host ${AGENTINTERDICT_HOST:-0.0.0.0} --port ${AGENTINTERDICT_PORT:-43847}"]
