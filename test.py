#!/usr/bin/env python3
"""
NVD CVE Downloader - Local Test Script
Downloads NVD CVE data (initial full load or incremental)
"""

import requests
import json
import os
from datetime import datetime, timedelta
from time import sleep


def download_nvd_cves(mode="initial", last_run=None, output_dir="./nvd_data"):
    """
    Download NVD CVEs
    
    mode: "initial" for full history, "incremental" for delta since last_run
    last_run: datetime string in format "YYYY-MM-DDTHH:MM:SS.000 UTC-00:00"
    output_dir: where to save the JSON file
    """
    
    os.makedirs(output_dir, exist_ok=True)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page = 2000
    start_index = 0
    all_results = []
    
    if mode == "initial":
        print("=== Downloading ALL NVD CVEs (Initial Load) ===")
        params_base = {}
        # No date filters = get everything
    else:
        if not last_run:
            last_run = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000 UTC-00:00")
        
        today = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000 UTC-00:00")
        print(f"=== Downloading Incremental NVD CVEs ===")
        print(f"From: {last_run}")
        print(f"To:   {today}")
        
        params_base = {
            "pubStartDate": last_run,
            "pubEndDate": today
        }
        
        # Chunk into 120-day windows for incremental
        last_run_dt = datetime.strptime(last_run.replace(" UTC-00:00", ""), "%Y-%m-%dT%H:%M:%S.%f")
        today_dt = datetime.utcnow()
        
        if (today_dt - last_run_dt).days > 120:
            print(f"WARNING: Date range > 120 days. NVD API may reject. Range: {(today_dt - last_run_dt).days} days")
            print("Consider using mode='initial' or splitting into smaller chunks.")

    while True:
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
            **params_base
        }
        
        # Retry loop
        for attempt in range(1, 6):
            try:
                print(f"  Fetching start_index={start_index} (attempt {attempt}/5)...", end=" ")
                response = requests.get(url, params=params, timeout=30)
                response.raise_for_status()
                print("OK")
                break
            except Exception as e:
                print(f"FAILED: {e}")
                sleep(6)
                if attempt == 5:
                    print("Max retries reached. Aborting.")
                    raise
        
        # Rate limit: 5 requests per 30 seconds
        sleep(6)

        data = response.json()
        total_results = data.get("totalResults", 0)
        cves = data.get("vulnerabilities", [])
        all_results.extend(cves)
        
        print(f"  Progress: {len(all_results):,} / {total_results:,} CVEs")
        
        start_index += results_per_page
        if start_index >= total_results:
            break

    # Save to file
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if mode == "initial":
        filename = f"{output_dir}/nvd_cves_initial_{timestamp}.json"
    else:
        filename = f"{output_dir}/nvd_cves_incremental_{timestamp}.json"
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump({
            "fetch_time": datetime.utcnow().isoformat(),
            "mode": mode,
            "total_cves": len(all_results),
            "cves": all_results
        }, f, indent=2)
    
    print(f"\n=== DONE ===")
    print(f"Saved {len(all_results):,} CVEs to: {filename}")
    print(f"File size: {os.path.getsize(filename) / (1024*1024):.2f} MB")
    
    return filename


def download_sample(output_dir="./nvd_data"):
    """Quick test: download just 10 CVEs"""
    os.makedirs(output_dir, exist_ok=True)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    print("=== Downloading Sample (10 CVEs) ===")
    response = requests.get(url, params={"resultsPerPage": 10, "startIndex": 0}, timeout=30)
    response.raise_for_status()
    
    data = response.json()
    cves = data.get("vulnerabilities", [])
    
    filename = f"{output_dir}/nvd_sample_10.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    print(f"Saved {len(cves)} CVEs to: {filename}")
    print(f"Total CVEs in NVD database: {data.get('totalResults', 'N/A'):,}")
    
    # Print first CVE ID as example
    if cves:
        cve_id = cves[0].get("cve", {}).get("id", "N/A")
        print(f"First CVE: {cve_id}")
    
    return filename


# ============================
# MAIN
# ============================
if __name__ == "__main__":
    import sys
    
    print("NVD CVE Downloader")
    print("=" * 50)
    print("1. Download SAMPLE (10 CVEs) - Quick test")
    print("2. Download FULL (all CVEs) - ~355K records, takes ~1 hour")
    print("3. Download INCREMENTAL (last 24 hours) - Quick")
    print("=" * 50)
    
    choice = input("Enter choice (1/2/3): ").strip()
    
    if choice == "1":
        download_sample()
    
    elif choice == "2":
        confirm = input("This will download ~355K CVEs and take ~1 hour. Continue? (y/n): ").strip().lower()
        if confirm == "y":
            download_nvd_cves(mode="initial")
        else:
            print("Cancelled.")
    
    elif choice == "3":
        download_nvd_cves(mode="incremental")
    
    else:
        print("Invalid choice. Exiting.")