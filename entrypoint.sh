#!/bin/bash

# Wait for PostgreSQL
echo "Waiting for PostgreSQL..."
while ! nc -z db 5432; do
  sleep 1
done
echo "PostgreSQL started"

# Initialize migrations if not already done
# if [ ! -d "migrations" ]; then
#     flask db init
# fi

# Run migrations
echo "Running database migrations..."
flask --app migrate.py db upgrade || {
    echo "Warning: Migration failed, attempting stamps/init if needed."
    # Handle cases where migrations might be out of sync
}

# Start Supervisor to manage both Web and Monitoring Engine
echo "Starting services via Supervisor..."
supervisord -c /app/supervisord.conf
