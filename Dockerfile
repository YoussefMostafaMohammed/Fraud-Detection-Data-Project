FROM python:3.10-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AIRFLOW_VERSION=2.7.3 \
    AIRFLOW_HOME=/opt/airflow \
    VIRTUAL_ENV=/opt/venv

# Add virtual env to PATH
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create airflow user
RUN useradd -ms /bin/bash -d ${AIRFLOW_HOME} airflow

# Create virtual environment and install Airflow
RUN python -m venv $VIRTUAL_ENV \
    && pip install --upgrade pip \
    && pip install "apache-airflow==${AIRFLOW_VERSION}" --constraint "https://raw.githubusercontent.com/apache/airflow/constraints-${AIRFLOW_VERSION}/constraints-3.10.txt" \
    && chown -R airflow:airflow $VIRTUAL_ENV

# Copy requirements if needed (you can add a requirements.txt file to the project)
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt || true

# Set user and working directory
USER airflow
WORKDIR ${AIRFLOW_HOME}

# Initialization script
COPY --chown=airflow:airflow entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
