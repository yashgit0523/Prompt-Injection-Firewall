# PromptGuard - AI Prompt Injection Firewall
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PROMPTGUARD_DB_PATH=/app/data/promptguard.db

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY datasets ./datasets
COPY scripts ./scripts
COPY tests ./tests
COPY pytest.ini .

# Run as an unprivileged user; only the data directory is writable.
RUN useradd --create-home --uid 10001 promptguard \
    && mkdir -p /app/data \
    && chown -R promptguard:promptguard /app/data
USER promptguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
