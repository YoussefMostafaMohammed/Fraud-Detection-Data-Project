#!/usr/bin/env python3
"""
Unified CVE Reporter
Fetches CISA KEV + NVD data, analyzes, reports, and emails.
"""

import os
import csv
import time
import sys
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from collections import Counter
from pathlib import Path
import requests


# ─── Configuration ─────────────────────────────────────────────────────────────

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CSV = "cisa_kev.csv"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CSV = "nvd.csv"
NVD_RESULTS_PER_PAGE = 2000
NVD_SLEEP_BETWEEN_REQUESTS = 6
NVD_LOOKBACK_MINUTES = 60

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "abdelbarym130@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "rite pcbv ljpk yrrg")
EMAIL_RECIPIENTS = [
   "opponentok1@gmail.com",
    "mostafanayef74@gmail.com",
    "ayagama662@gmail.com",
    "ahmedwaheedgad@gmail.com",
    "yousefmostafamohammed@gmail.com",
    ]

REPORT_FILE = "nvd_report.txt"
TOP_CWE_COUNT = 10


# ─── CISA KEV ─────────────────────────────────────────────────────────────────

def fetch_cisa_kev(output_path: str = CISA_KEV_CSV) -> None:
    response = requests.get(CISA_KEV_URL, timeout=120)
    response.raise_for_status()

    vulnerabilities = response.json().get("vulnerabilities", [])

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "CVE ID",
            "Vendor",
            "Product",
            "Vulnerability Name",
            "Date Added",
            "Due Date",
            "Required Action",
            "Notes",
        ])
        for vuln in vulnerabilities:
            writer.writerow([
                vuln.get("cveID", ""),
                vuln.get("vendorProject", ""),
                vuln.get("product", ""),
                vuln.get("vulnerabilityName", ""),
                vuln.get("dateAdded", ""),
                vuln.get("dueDate", ""),
                vuln.get("requiredAction", ""),
                vuln.get("notes", ""),
            ])


# ─── NVD ──────────────────────────────────────────────────────────────────────

def fetch_nvd(output_path: str = NVD_CSV) -> None:
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=NVD_LOOKBACK_MINUTES)

    pub_start = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pub_end = end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    all_cves = []
    start_index = 0
    max_pages = 50  # Safety limit to prevent infinite loops

    for _ in range(max_pages):
        params = {
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
            "startIndex": start_index,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
        }

        try:
            response = requests.get(NVD_API_URL, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()

            cves = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            if not cves:
                break

            all_cves.extend(cves)

            if start_index + len(cves) >= total_results:
                break

            start_index += NVD_RESULTS_PER_PAGE
            time.sleep(NVD_SLEEP_BETWEEN_REQUESTS)

        except requests.exceptions.RequestException:
            time.sleep(10)
            continue

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CVE ID", "Base Score (v3.1)", "Severity (v3.1)", "CWE"])

        for entry in all_cves:
            cve = entry.get("cve", {})
            cve_id = cve.get("id", "")

            metrics = cve.get("metrics", {})
            cvss_v31_list = metrics.get("cvssMetricV31", [])
            if cvss_v31_list:
                cvss_data = cvss_v31_list[0].get("cvssData", {})
                base_score = cvss_data.get("baseScore", "")
                severity = cvss_data.get("baseSeverity", "")
            else:
                base_score = ""
                severity = ""

            weaknesses = cve.get("weaknesses", [])
            cwe_values = [
                desc.get("value", "")
                for w in weaknesses
                for desc in w.get("description", [])
                if desc.get("lang") == "en"
            ]
            cwe = " | ".join(cwe_values) if cwe_values else ""

            writer.writerow([cve_id, base_score, severity, cwe])


# ─── Analyzer ─────────────────────────────────────────────────────────────────

def read_cve_data(filepath):
    """Read the CSV and return a list of dictionaries with cleaned values."""
    rows = []
    with open(filepath, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            clean = {k.strip(): v.strip() for k, v in row.items()}
            rows.append(clean)
    return rows


def safe_float(value):
    """Convert to float, returning None if not possible."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_cwe(raw_cwe):
    """Normalize a CWE string. Returns the cleaned CWE ID or empty string."""
    if not raw_cwe:
        return ''
    raw_cwe = raw_cwe.strip()
    if raw_cwe.upper().startswith('CWE-'):
        return raw_cwe
    if raw_cwe.isdigit():
        return f'CWE-{raw_cwe}'
    return raw_cwe


def analyze(rows):
    """Compute all statistics and return a dictionary of results."""
    total = len(rows)

    severity_counter = Counter()
    valid_base_scores = []
    cwe_counter = Counter()

    for row in rows:
        sev = row.get('Severity (v3.1)', '').strip().title()
        sev_mapping = {
            'None': 'None',
            'Low': 'Low',
            'Medium': 'Medium',
            'High': 'High',
            'Critical': 'Critical',
        }
        sev = sev_mapping.get(sev, 'Unknown')
        severity_counter[sev] += 1

        score = safe_float(row.get('Base Score (v3.1)', ''))
        if score is not None:
            valid_base_scores.append(score)

        cwe = normalize_cwe(row.get('CWE', ''))
        if cwe:
            cwe_counter[cwe] += 1

    if valid_base_scores:
        avg_score = sum(valid_base_scores) / len(valid_base_scores)
        min_score = min(valid_base_scores)
        max_score = max(valid_base_scores)
    else:
        avg_score = min_score = max_score = None

    top_cwes = cwe_counter.most_common(TOP_CWE_COUNT)
    non_empty_cwe_total = sum(cwe_counter.values())

    severity_percent = {}
    for level in ['Critical', 'High', 'Medium', 'Low', 'None', 'Unknown']:
        cnt = severity_counter.get(level, 0)
        pct = (cnt / total * 100) if total > 0 else 0.0
        severity_percent[level] = (cnt, pct)

    return {
        'total': total,
        'severity_counts': severity_counter,
        'severity_percent': severity_percent,
        'valid_scores': len(valid_base_scores),
        'avg_score': avg_score,
        'min_score': min_score,
        'max_score': max_score,
        'top_cwes': top_cwes,
        'non_empty_cwe_total': non_empty_cwe_total,
    }


def generate_report(stats):
    """Create the formatted report string."""
    lines = []
    sep = "=" * 56
    lines.append(sep)
    lines.append("        NVD DATASET EXECUTIVE SUMMARY REPORT")
    lines.append(sep)
    lines.append("")

    lines.append(f"Total CVEs analysed: {stats['total']}")
    lines.append("")

    lines.append("-" * 56)
    lines.append("SEVERITY DISTRIBUTION")
    lines.append("-" * 56)
    lines.append(f"{'Level':<12} {'Count':>6} {'Percentage':>10}")
    lines.append("-" * 34)
    for level in ['Critical', 'High', 'Medium', 'Low', 'None']:
        cnt, pct = stats['severity_percent'][level]
        lines.append(f"{level:<12} {cnt:>6} {pct:>9.1f}%")
    if stats['severity_percent'].get('Unknown', (0, 0))[0] > 0:
        cnt_u, pct_u = stats['severity_percent']['Unknown']
        lines.append(f"{'Unknown':<12} {cnt_u:>6} {pct_u:>9.1f}%")
    lines.append("")

    lines.append("-" * 56)
    lines.append("CVSS v3.1 BASE SCORE STATISTICS")
    lines.append("-" * 56)
    if stats['valid_scores'] > 0:
        lines.append(f"  Valid scores   : {stats['valid_scores']} "
                     f"({stats['valid_scores']/max(stats['total'],1)*100:.1f}% of dataset)")
        lines.append(f"  Average score  : {stats['avg_score']:.2f}")
        lines.append(f"  Minimum score  : {stats['min_score']:.1f}")
        lines.append(f"  Maximum score  : {stats['max_score']:.1f}")
    else:
        lines.append("  No valid Base Score values found.")
    lines.append("")

    lines.append("-" * 56)
    lines.append(f"TOP {TOP_CWE_COUNT} RECURRING CWE CATEGORIES")
    lines.append("-" * 56)
    if stats['non_empty_cwe_total'] == 0:
        lines.append("  No CWE data available.")
    else:
        lines.append(f"  (Based on {stats['non_empty_cwe_total']} non‑empty CWE entries)")
        lines.append("")
        for rank, (cwe, count) in enumerate(stats['top_cwes'], 1):
            pct = count / stats['non_empty_cwe_total'] * 100
            lines.append(f"  {rank:2}. {cwe:<20} {count:>5}  ({pct:.1f}%)")
    lines.append("")

    lines.append("-" * 56)
    lines.append("KEY INSIGHTS")
    lines.append("-" * 56)

    crit_cnt = stats['severity_percent']['Critical'][0]
    high_cnt = stats['severity_percent']['High'][0]
    crit_high_pct = ((crit_cnt + high_cnt) / max(stats['total'], 1)) * 100
    lines.append(f"  • {crit_high_pct:.1f}% of CVEs are Critical or High severity "
                 f"({crit_cnt + high_cnt} out of {stats['total']}).")

    if stats['top_cwes']:
        top_cwe_name, top_cwe_count = stats['top_cwes'][0]
        top_pct = top_cwe_count / stats['non_empty_cwe_total'] * 100
        lines.append(f"  • The most common weakness is {top_cwe_name}, "
                     f"appearing {top_cwe_count} times ({top_pct:.1f}% of all CWEs).")

        lines.append(f"  • The top {min(3, len(stats['top_cwes']))} CWEs account for "
                     f"{sum(c for _, c in stats['top_cwes'][:3])} vulnerabilities – "
                     f"targeting these can significantly reduce risk.")

    if stats['valid_scores'] > 0:
        if stats['avg_score'] >= 7.0:
            lines.append(f"  • The average CVSS score is {stats['avg_score']:.1f} (High), "
                         "indicating an overall elevated risk posture.")
        elif stats['avg_score'] >= 4.0:
            lines.append(f"  • The average CVSS score is {stats['avg_score']:.1f} (Medium).")
        else:
            lines.append(f"  • The average CVSS score is {stats['avg_score']:.1f} (Low).")

    lines.append("")
    lines.append(sep)
    lines.append("Report generated by unified_cve_reporter.py")
    lines.append(sep)
    return "\n".join(lines)


# ─── Email ────────────────────────────────────────────────────────────────────

def send_email(
    cisa_path: str = CISA_KEV_CSV,
    nvd_path: str = NVD_CSV,
    report_path: str = REPORT_FILE,
) -> None:
    msg = EmailMessage()
    msg["Subject"] = "CISA KEV & NVD Reports"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = ", ".join(EMAIL_RECIPIENTS)
    msg.set_content("Please find the attached CISA KEV, NVD CSV files and the executive summary report.")

    attachments = [
        (cisa_path, "text", "csv", "cisa_kev.csv"),
        (nvd_path, "text", "csv", "nvd.csv"),
        (report_path, "text", "plain", "nvd_report.txt"),
    ]

    for path, maintype, subtype, filename in attachments:
        if not Path(path).exists():
            print(f"Warning: Attachment '{path}' not found, skipping.")
            continue
        with open(path, "rb") as f:
            msg.add_attachment(f.read(), maintype=maintype, subtype=subtype, filename=filename)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("Fetching CISA KEV data...")
    fetch_cisa_kev()

    print("Fetching NVD data...")
    fetch_nvd()

    print("Analyzing NVD data...")
    rows = read_cve_data(NVD_CSV)
    if not rows:
        print("No NVD data found. Creating empty report.")
        stats = {
            'total': 0,
            'severity_counts': Counter(),
            'severity_percent': {lvl: (0, 0.0) for lvl in ['Critical', 'High', 'Medium', 'Low', 'None', 'Unknown']},
            'valid_scores': 0,
            'avg_score': None,
            'min_score': None,
            'max_score': None,
            'top_cwes': [],
            'non_empty_cwe_total': 0,
        }
    else:
        stats = analyze(rows)

    report = generate_report(stats)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Report written to {REPORT_FILE}")

    print("Sending email...")
    send_email()
    print("Done.")


if __name__ == "__main__":
    main()