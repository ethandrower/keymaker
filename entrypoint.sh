#!/usr/bin/env bash
set -e

# Wait for the database, then migrate and serve.
echo "Running migrations..."
python manage.py migrate --noinput

# Seed demo environments on local/dev if requested.
if [ "${SEED_DEMO:-0}" = "1" ]; then
    echo "Seeding demo data..."
    python manage.py seed_demo || true
fi

PORT="${PORT:-8000}"

if [ "${DJANGO_DEBUG:-0}" = "1" ]; then
    echo "Starting Django dev server on :${PORT}"
    exec python manage.py runserver "0.0.0.0:${PORT}"
else
    echo "Starting gunicorn on :${PORT}"
    exec gunicorn keymaker.wsgi:application --bind "0.0.0.0:${PORT}" --workers 3
fi
