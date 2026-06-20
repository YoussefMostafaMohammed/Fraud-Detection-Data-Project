from datetime import datetime, timedelta
from pathlib import Path

from airflow import DAG
from airflow.operators.bash import BashOperator

DAG_DIR = Path(__file__).parent

default_args = {
    "owner": "airflow",
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}

with DAG(
    dag_id="report_hourly_dag",
    default_args=default_args,
    start_date=datetime(2026, 6, 10),
    schedule="* 1 * * *",  # Run every hour
    catchup=False,
) as dag:

    run_report = BashOperator(
        task_id="run_report_script",
        bash_command=f"python3 {DAG_DIR}/report.py",
    )

    run_report

    