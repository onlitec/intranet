#!/bin/bash
# Script to initialize PostgreSQL schema from existing migrations

export FLASK_APP=wsgi.py

echo "Initializing database schema..."
flask db upgrade

if [ $? -eq 0 ]; then
    echo "✅ Schema initialized successfully."
else
    echo "❌ Failed to initialize schema. Check if database is accessible."
    exit 1
fi
