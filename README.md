# Vulnerability Intelligence Platform

A real-time security data pipeline that aggregates vulnerability feeds from NVD, CISA KEV, and EPSS to prioritize patching based on actual exploitation risk.

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   NVD CVE API   │     │  CISA KEV Feed  │     │   EPSS API      │
│   (Batch + Poll)│     │   (Batch + Poll)│     │   (Batch + Poll)│
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     Apache Airflow        │
                    │   Orchestration Layer     │
                    │  • Daily batch at 3 AM      │
                    │  • Smart polling every 5min │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │        AWS S3             │
                    │      Raw Data Lake        │
                    │  raw/nvd/YYYY/MM/DD/      │
                    │  raw/cisa/YYYY/MM/DD/     │
                    │  raw/epss/YYYY/MM/DD/     │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Transform Layer      │
                    │  • Clean CVE IDs          │
                    │  • Extract CVSS scores    │
                    │  • Normalize vendors        │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      PostgreSQL           │
                    │    Processed Warehouse    │
                    │  • cves_clean             │
                    │  • cisa_kev_clean         │
                    │  • epss_scores            │
                    │  • asset_inventory        │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Matching Engine        │
                    │  CVE vendor/product ↔     │
                    │  Asset inventory          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Risk Scoring Engine    │
                    │  CVSS × EPSS × CISA_KEV × │
                    │  Asset_Criticality        │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
    ┌─────────▼─────────┐  ┌─────▼─────┐  ┌───────▼────────┐
    │   Batch Output    │  │  Kafka    │  │  Streaming     │
    │   (Daily Reports) │  │  Topics   │  │  Alerts        │
    │                   │  │           │  │                │
    │  • risk_scores    │  │cve-stream │  │  • Slack       │
    │  • patch_priority │  │siem-alerts│  │  • PagerDuty   │
    │  • asset_matches  │  │net-logs   │  │  • Email       │
    └───────────────────┘  └───────────┘  └────────────────┘
```

## Data Sources

| Source | Type | Update Frequency | Data Provided |
|--------|------|-----------------|---------------|
| NVD CVE API | REST JSON | Daily batch + 5min poll | All CVEs with CVSS scores |
| CISA KEV Catalog | JSON/CSV | Daily batch + 5min poll | Actively exploited vulnerabilities |
| EPSS API | REST JSON | Daily batch + 5min poll | Exploitation probability scores |
| Asset Inventory | CSV/DB | Weekly | Internal device/software inventory |

## Batch Pipeline

Runs daily at 3:00 AM via Apache Airflow:

1. **Extract** — Pull full datasets from NVD, CISA, and EPSS APIs
2. **Store Raw** — Save original JSON/CSV to S3 with date partitioning
3. **Transform** — Clean, normalize, and deduplicate records
4. **Load** — Insert processed data into PostgreSQL warehouse
5. **Match** — Correlate CVEs against asset inventory
6. **Score** — Calculate composite risk scores

## Streaming Pipeline

Runs continuous smart polling every 5 minutes:

1. **Poll** — Query APIs for changes since last check using `lastModStartDate`
2. **Detect** — Compare responses against local cache to find new entries
3. **Stream** — Push changes to Kafka topics
4. **Process** — Flink/Spark enriches with asset data and calculates risk
5. **Alert** — Trigger PagerDuty/Slack for critical matches (>90 risk score)

## S3 Data Lake Structure

```
vulnerability-intelligence-raw/
├── raw/
│   ├── nvd/YYYY/MM/DD/cves_YYYY-MM-DD_HH-MM.json
│   ├── cisa_kev/YYYY/MM/DD/kev_YYYY-MM-DD_HH-MM.json
│   ├── epss/YYYY/MM/DD/epss_YYYY-MM-DD_HH-MM.json
│   └── assets/YYYY/MM/DD/assets_YYYY-MM-DD.csv
└── streaming/
    ├── cve-stream/YYYY/MM/DD/HH/MM/events.json
    ├── siem-alerts/YYYY/MM/DD/HH/MM/alert.json
    └── network-logs/YYYY/MM/DD/HH/MM/logs.parquet
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| S3 for raw storage | Cheap, durable, enables reprocessing and audit |
| PostgreSQL for processed data | Structured queries, joins, reporting |
| Smart polling vs. true streaming | NVD/CISA/EPSS are REST APIs without webhook support |
| Kafka as message broker | Decouples producers from consumers, handles backpressure |
| Risk scoring formula | Combines technical severity (CVSS), exploitation likelihood (EPSS), and business context (asset criticality) |

## Tech Stack

- **Orchestration**: Apache Airflow
- **Storage**: AWS S3 (raw), PostgreSQL (processed)
- **Streaming**: Apache Kafka + Flink
- **Alerting**: Slack, PagerDuty
- **Visualization**: Apache Superset / Power BI

## Why This Matters

Without this platform, security teams discover critical vulnerabilities 12+ hours after publication. With streaming detection and risk-based prioritization, critical patches begin within minutes of a CVE hitting the NVD database.