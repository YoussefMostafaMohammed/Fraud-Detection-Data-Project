from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator, BranchPythonOperator
from airflow.operators.empty import EmptyOperator
from airflow.providers.amazon.aws.hooks.s3 import S3Hook
import requests
import json
import os
import logging
from time import sleep

# ============================
# CONFIG
# ============================
S3_BUCKET = "cyber-threat-intel-data-lake"
ASSET_LOCAL_PATH = "/opt/airflow/data/raw/large_asset_inventory.csv"
MAX_RETRIES = 3
RETRY_DELAY = 10

# Only need last_run file locally (for incremental timing)
NVD_LAST_RUN_FILE = "/opt/airflow/data/nvd_last_run.txt"

def upload_to_s3(local_file, s3_key):
    s3 = S3Hook(aws_conn_id='aws_default')
    s3.load_file(filename=local_file, key=s3_key, bucket_name=S3_BUCKET, replace=True)
    logging.info(f"Uploaded to s3://{S3_BUCKET}/{s3_key}")

def read_file(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return f.read().strip()
    return None

def write_file(filename, content):
    with open(filename, "w") as f:
        f.write(content)

# ============================
# NVD: INITIAL FULL LOAD
# ============================

def fetch_nvd_initial(**kwargs):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page = 2000
    start_index = 0
    all_results = []
    
    logging.info("=== NVD INITIAL LOAD: Fetching ALL CVEs ===")

    while True:
        params = {"resultsPerPage": results_per_page, "startIndex": start_index}
        
        # FIX: Retry loop instead of continue
        for attempt in range(1, 6):
            try:
                response = requests.get(url, params=params, timeout=30)
                response.raise_for_status()
                break
            except Exception as e:
                logging.error(f"Attempt {attempt}/5 failed: {e}")
                sleep(6)
                if attempt == 5:
                    raise
        
        # FIX: Rate limit
        sleep(6)

        data = response.json()
        total_results = data.get("totalResults", 0)
        cves = data.get("vulnerabilities", [])
        all_results.extend(cves)
        
        logging.info(f"Progress: {len(all_results)}/{total_results}")
        
        start_index += results_per_page
        if start_index >= total_results:
            break

    filename = f"/tmp/nvd_cves_initial_{datetime.utcnow().strftime('%Y%m%d')}.json"
    with open(filename, "w") as f:
        json.dump(all_results, f)
    
    logging.info(f"Saved {len(all_results)} CVEs")
    upload_to_s3(filename, "bronze/nvd/initial/nvd_cves_full.json")
    
    # FIX: Add timezone suffix
    write_file(NVD_LAST_RUN_FILE, datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"))    
    logging.info("=== NVD INITIAL LOAD COMPLETE ===")

# ============================
# NVD: INCREMENTAL DAILY
# ============================

def fetch_nvd_incremental(**kwargs):
    s3 = S3Hook(aws_conn_id='aws_default')
    if not s3.check_for_key("bronze/nvd/initial/nvd_cves_full.json", S3_BUCKET):
        raise Exception("Initial NVD file not found in S3! Run nvd_initial_load first.")
    
    today = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    last_run = read_file(NVD_LAST_RUN_FILE)
    if not last_run:
        last_run = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page = 2000
    all_results = []

    logging.info(f"=== NVD INCREMENTAL: {last_run} to {today} ===")

    # FIX: Chunk into 120-day windows (NVD API limit)
    last_run_dt = datetime.strptime(last_run.replace("Z", ""), "%Y-%m-%dT%H:%M:%S.%f")
    today_dt = datetime.utcnow()
    
    chunk_start = last_run_dt
    while chunk_start < today_dt:
        chunk_end = min(chunk_start + timedelta(days=120), today_dt)
        pub_start = chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        pub_end = chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        start_index = 0
        
        while True:
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                "pubStartDate": pub_start,
                "pubEndDate": pub_end
            }
            
            # FIX: Retry loop per page
            for attempt in range(1, 6):
                try:
                    response = requests.get(url, params=params, timeout=30)
                    response.raise_for_status()
                    break
                except Exception as e:
                    logging.error(f"Attempt {attempt}/5: {e}")
                    sleep(6)
                    if attempt == 5:
                        raise
            
            # FIX: Rate limit
            sleep(6)

            data = response.json()
            total_results = data.get("totalResults", 0)
            cves = data.get("vulnerabilities", [])
            all_results.extend(cves)
            
            logging.info(f"Chunk {chunk_start.date()}→{chunk_end.date()}: {len(cves)} CVEs, total: {len(all_results)}/{total_results}")
            
            start_index += results_per_page
            if start_index >= total_results:
                break
        
        chunk_start = chunk_end

    today_str = datetime.utcnow().strftime('%Y-%m-%d')
    filename = f"/tmp/nvd_cves_{today_str}.json"
    
    with open(filename, "w") as f:
        json.dump(all_results, f)
    
    upload_to_s3(filename, f"bronze/nvd/{today_str}/nvd_cves.json")
    logging.info(f"Uploaded {len(all_results)} new CVEs")

    write_file(NVD_LAST_RUN_FILE, today)
    logging.info("=== NVD INCREMENTAL COMPLETE ===")

# ============================
# BRANCHING: Check S3
# ============================
def choose_nvd_path(**kwargs):
    s3 = S3Hook(aws_conn_id='aws_default')
    
    if s3.check_for_key("bronze/nvd/initial/nvd_cves_full.json", S3_BUCKET):
        logging.info("Initial NVD found in S3. Running incremental.")
        kwargs['ti'].xcom_push(key='run_type', value='incremental')
        return 'nvd_incremental'
    
    logging.info("No initial NVD in S3. Running initial load.")
    kwargs['ti'].xcom_push(key='run_type', value='initial')  # ← Save note
    return 'nvd_initial_load'

# ============================
# CISA KEV
# ============================
def fetch_cisa_kev(**kwargs):
    today_str = datetime.utcnow().strftime('%Y-%m-%d')
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    
    filename = f"/tmp/cisa_kev_{today_str}.json"
    with open(filename, "w") as f:
        f.write(response.text)
    
    upload_to_s3(filename, f"bronze/cisa_kev/{today_str}/cisa_kev.json")
    logging.info("CISA KEV uploaded")

# ============================
# EPSS
# ============================
def fetch_epss_scores(**kwargs):
    today_str = datetime.utcnow().strftime('%Y-%m-%d')
    url = "https://api.first.org/data/v1/epss"
    
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    
    filename = f"/tmp/epss_scores_{today_str}.json"
    with open(filename, "w") as f:
        f.write(response.text)
    
    upload_to_s3(filename, f"bronze/epss/{today_str}/epss_scores.json")
    logging.info("EPSS uploaded")

# ============================
# ASSETS
# ============================
def load_asset_inventory(**kwargs):
    today_str = datetime.utcnow().strftime('%Y-%m-%d')
    
    if not os.path.exists(ASSET_LOCAL_PATH):
        raise FileNotFoundError(f"Asset file not found: {ASSET_LOCAL_PATH}")
    
    upload_to_s3(ASSET_LOCAL_PATH, f"bronze/assets/{today_str}/asset_inventory.csv")
    logging.info("Assets uploaded")

# ============================
# VALIDATION
# ============================
def validate_bronze(**kwargs):
    today_str = datetime.utcnow().strftime('%Y-%m-%d')
    s3 = S3Hook(aws_conn_id='aws_default')
    
    run_type = kwargs['ti'].xcom_pull(task_ids='choose_nvd_path', key='run_type')
    
    if run_type == 'initial':
        keys = [
            "bronze/nvd/initial/nvd_cves_full.json",
            f"bronze/cisa_kev/{today_str}/cisa_kev.json",
            f"bronze/epss/{today_str}/epss_scores.json",
            f"bronze/assets/{today_str}/asset_inventory.csv"
        ]
    else:
        keys = [
            f"bronze/nvd/{today_str}/nvd_cves.json",
            f"bronze/cisa_kev/{today_str}/cisa_kev.json",
            f"bronze/epss/{today_str}/epss_scores.json",
            f"bronze/assets/{today_str}/asset_inventory.csv"
        ]
    
    for key in keys:
        if not s3.check_for_key(key, S3_BUCKET):
            raise Exception(f"MISSING: {key}")
        logging.info(f"FOUND: {key}")
    
    logging.info("All bronze files validated")

# ============================
# DAG
# ============================
default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'start_date': datetime(2026, 6, 1),
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
    'execution_timeout': timedelta(hours=3)
}

dag = DAG(
    'daily_vulnerability_ingestion',
    default_args=default_args,
    description='Bronze layer: S3-aware initial vs incremental',
    schedule=timedelta(days=1),
    catchup=False
)

# Tasks
start = PythonOperator(task_id='start', python_callable=lambda: logging.info("=== START ==="), dag=dag)

task_choose_nvd = BranchPythonOperator(
    task_id='choose_nvd_path',
    python_callable=choose_nvd_path,
    dag=dag
)
task_nvd_join = EmptyOperator(
    task_id='nvd_join',
    trigger_rule='none_failed',
    dag=dag
)

task_nvd_initial = PythonOperator(task_id='nvd_initial_load', python_callable=fetch_nvd_initial, dag=dag)
task_nvd_daily = PythonOperator(task_id='nvd_incremental', python_callable=fetch_nvd_incremental, dag=dag)

task_cisa = PythonOperator(task_id='fetch_cisa_kev', python_callable=fetch_cisa_kev,trigger_rule="none_failed", dag=dag)
task_epss = PythonOperator(task_id='fetch_epss_scores', python_callable=fetch_epss_scores,trigger_rule="none_failed", dag=dag)
task_assets = PythonOperator(task_id='load_assets', python_callable=load_asset_inventory,trigger_rule="none_failed", dag=dag)

task_validate = PythonOperator(task_id='validate_bronze', python_callable=validate_bronze,trigger_rule="none_failed", dag=dag)
task_end = PythonOperator(task_id='end', python_callable=lambda: logging.info("=== END ==="),trigger_rule="none_failed", dag=dag)

# Dependencies
start >> task_choose_nvd

# NVD branch - only one will run
task_choose_nvd >> [task_nvd_initial, task_nvd_daily]

# Join NVD branches
task_nvd_initial >> task_nvd_join
task_nvd_daily >> task_nvd_join

# Sources run AFTER NVD completes
task_nvd_join >> [task_cisa, task_epss, task_assets]

# Validation waits for all sources
[task_cisa, task_epss, task_assets] >> task_validate >> task_end