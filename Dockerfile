# FlowSentry Desk. The image needs no model key and no network: it serves the committed
# data bundle, the recorded runs and the deterministic policy. Set ANTHROPIC_API_KEY and
# DESK_LIVE_AGENT=1 to add live Claude runs.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    PORT=7860 DESK_DB_PATH=/tmp/desk.sqlite3

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY desk ./desk
COPY web ./web
COPY data ./data
COPY runs ./runs
COPY reports ./reports

# Hugging Face Spaces runs containers as uid 1000; the app only writes /tmp.
RUN useradd --uid 1000 --create-home app && chown -R app /app
USER app

EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT', '7860'))"

CMD ["sh", "-c", "exec uvicorn desk.app:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
