FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps (psycopg needs libpq at runtime via the binary wheel; build tools kept minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Collect static at build time (whitenoise serves them). Safe to no-op if none.
RUN python manage.py collectstatic --noinput || true

EXPOSE 8000

# Dokku/Procfile drives the real command; this is a sensible default for `docker run`.
CMD ["./entrypoint.sh"]
