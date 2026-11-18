#!/bin/bash

# Wait for Postgres
echo "Waiting for postgres..."
while ! nc -z ${POSTGRES_HOST:-db} ${POSTGRES_PORT:-5432}; do
  sleep 1
done
echo "PostgreSQL started"

python3 manage.py migrate
python3 manage.py runserver 0.0.0.0:8000

exec "$@"
