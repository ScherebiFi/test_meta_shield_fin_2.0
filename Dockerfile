FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/app/data/meta_shieldfin.db

WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt \
    && groupadd --system --gid 10001 shieldfin \
    && useradd --system --uid 10001 --gid shieldfin --home-dir /app shieldfin \
    && mkdir -p /app/data \
    && chown -R shieldfin:shieldfin /app
COPY backend ./backend
COPY frontend ./frontend
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health', timeout=3)"
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]