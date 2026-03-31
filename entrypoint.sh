#!/bin/bash
# Exit immediately if a command exits with a non-zero status
set -e 

DB_PATH="instance/switches.db"

# Get file size using stat (returns 0 if the file doesn't exist)
DB_SIZE=$(stat -c%s "$DB_PATH" 2>/dev/null || echo 0)

# An initialized SQLite database with a schema will be greater than 0 bytes
if [ "$DB_SIZE" -gt 0 ]; then
    echo "Existing database found (Size: $DB_SIZE bytes). Skipping initialization."
else
    echo "Database missing or empty. Initializing..."
    python3 -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"
    echo "Database successfully initialized."
fi

echo "Starting Gunicorn..."
exec gunicorn --bind 0.0.0.0:5000 --workers 4 --threads 2 run:app
