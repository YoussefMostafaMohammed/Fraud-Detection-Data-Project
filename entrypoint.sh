#!/bin/bash
set -e

# Initialize DB if requested
if [ "$_AIRFLOW_DB_UPGRADE" = "true" ]; then
    echo "Upgrading DB..."
    airflow db upgrade
fi

# Create WWW user if requested
if [ "$_AIRFLOW_WWW_USER_CREATE" = "true" ]; then
    echo "Creating WWW user..."
    airflow users create \
        --username "${_AIRFLOW_WWW_USER_USERNAME:-admin}" \
        --firstname Admin \
        --lastname User \
        --role Admin \
        --email admin@example.com \
        --password "${_AIRFLOW_WWW_USER_PASSWORD:-admin}" \
        || true
fi

exec airflow "$@"
