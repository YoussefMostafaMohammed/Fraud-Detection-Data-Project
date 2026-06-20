import json
import os
import time
from pathlib import Path

import psycopg2
import requests
from dotenv import load_dotenv
from kafka import KafkaConsumer, TopicPartition


load_dotenv(Path(__file__).with_name(".env"))

TOPIC = "vulnerability_events"
BOOTSTRAP_SERVERS = "127.0.0.1:9092"
KAFKA_PARTITION = 0

POSTGRES_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "cyber_threat_db",
    "user": "postgres",
    "password": "aya",
}

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
TELEGRAM_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
ALERT_MIN_RISK_SCORE = float(os.getenv("ALERT_MIN_RISK_SCORE", "85"))
ALERT_ON_KNOWN_EXPLOITED = os.getenv("ALERT_ON_KNOWN_EXPLOITED", "true").lower() == "true"


CREATE_TABLES_SQL = """
CREATE SCHEMA IF NOT EXISTS streaming;

CREATE TABLE IF NOT EXISTS streaming.realtime_risk_scores (
    event_id TEXT PRIMARY KEY,
    source TEXT,
    asset_id TEXT,
    hostname TEXT,
    vendor TEXT,
    product TEXT,
    version TEXT,
    criticality TEXT,
    internet_facing TEXT,
    cve_id TEXT,
    description TEXT,
    cvss_score DOUBLE PRECISION,
    severity TEXT,
    epss_score DOUBLE PRECISION,
    known_exploited BOOLEAN,
    risk_score DOUBLE PRECISION,
    patch_priority TEXT,
    detected_at TIMESTAMP,
    inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS streaming.realtime_alerts (
    event_id TEXT PRIMARY KEY,
    source TEXT,
    asset_id TEXT,
    hostname TEXT,
    vendor TEXT,
    product TEXT,
    cve_id TEXT,
    risk_score DOUBLE PRECISION,
    patch_priority TEXT,
    detected_at TIMESTAMP,
    alert_message TEXT,
    inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS streaming.notified_cves (
    cve_id TEXT PRIMARY KEY,
    first_event_id TEXT,
    first_asset_id TEXT,
    first_seen_at TIMESTAMP,
    risk_score DOUBLE PRECISION,
    patch_priority TEXT,
    notified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


INSERT_RISK_SQL = """
INSERT INTO streaming.realtime_risk_scores (
    event_id, source, asset_id, hostname, vendor, product, version,
    criticality, internet_facing, cve_id, description, cvss_score,
    severity, epss_score, known_exploited, risk_score, patch_priority,
    detected_at
)
VALUES (
    %(event_id)s, %(source)s, %(asset_id)s, %(hostname)s, %(vendor)s,
    %(product)s, %(version)s, %(criticality)s, %(internet_facing)s,
    %(cve_id)s, %(description)s, %(cvss_score)s, %(severity)s,
    %(epss_score)s, %(known_exploited)s, %(risk_score)s,
    %(patch_priority)s, %(detected_at)s::timestamp
)
ON CONFLICT (event_id) DO NOTHING;
"""


INSERT_ALERT_SQL = """
INSERT INTO streaming.realtime_alerts (
    event_id, source, asset_id, hostname, vendor, product, cve_id,
    risk_score, patch_priority, detected_at, alert_message
)
VALUES (
    %(event_id)s, %(source)s, %(asset_id)s, %(hostname)s, %(vendor)s,
    %(product)s, %(cve_id)s, %(risk_score)s, %(patch_priority)s,
    %(detected_at)s::timestamp, %(alert_message)s
)
ON CONFLICT (event_id) DO NOTHING;
"""


INSERT_NOTIFIED_CVE_SQL = """
INSERT INTO streaming.notified_cves (
    cve_id,
    first_event_id,
    first_asset_id,
    first_seen_at,
    risk_score,
    patch_priority
)
VALUES (
    %(cve_id)s,
    %(event_id)s,
    %(asset_id)s,
    %(detected_at)s::timestamp,
    %(risk_score)s,
    %(patch_priority)s
)
ON CONFLICT (cve_id) DO NOTHING
RETURNING cve_id;
"""


def get_postgres_connection():
    return psycopg2.connect(**POSTGRES_CONFIG)


def criticality_weight(criticality):
    return {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
    }.get(str(criticality).lower(), 0.3)


def calculate_risk_score(event):
    cvss_score = float(event.get("cvss_score") or 0)
    epss_score = float(event.get("epss_score") or 0)
    asset_weight = criticality_weight(event.get("criticality"))
    internet_bonus = 10 if str(event.get("internet_facing")).lower() == "yes" else 0
    exploited_bonus = 15 if event.get("known_exploited") else 0

    score = (
        (cvss_score * 6)
        + (epss_score * 20)
        + (asset_weight * 15)
        + internet_bonus
        + exploited_bonus
    )
    return round(min(score, 100), 2)


def patch_priority(risk_score):
    if risk_score >= 85:
        return "Urgent"
    if risk_score >= 70:
        return "High"
    if risk_score >= 50:
        return "Medium"
    return "Low"


def should_alert(event):
    if event["risk_score"] >= ALERT_MIN_RISK_SCORE:
        return True
    return ALERT_ON_KNOWN_EXPLOITED and event.get("known_exploited") is True


def mark_cve_as_notified(cursor, event):
    cursor.execute(INSERT_NOTIFIED_CVE_SQL, event)
    return cursor.fetchone() is not None


def send_telegram_alert(message):
    if not TELEGRAM_ENABLED:
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        print("Sent Telegram alert.", flush=True)
    except Exception as exc:
        print(f"FAILED to send Telegram alert: {type(exc).__name__}: {exc}", flush=True)


def build_alert_message(event):
    return (
        "<b>Streaming Cyber Threat Alert</b>\n"
        f"<b>Asset:</b> {event['asset_id']}\n"
        f"<b>Hostname:</b> {event.get('hostname') or 'N/A'}\n"
        f"<b>Vendor/Product:</b> {event.get('vendor') or 'N/A'} / {event.get('product') or 'N/A'}\n"
        f"<b>CVE:</b> {event['cve_id']}\n"
        f"<b>Severity:</b> {event.get('severity') or 'N/A'}\n"
        f"<b>Risk Score:</b> {event['risk_score']}\n"
        f"<b>Patch Priority:</b> {event['patch_priority']}"
    )


def normalize_event(event):
    required_fields = ["event_id", "asset_id", "cve_id", "detected_at"]
    missing = [field for field in required_fields if not event.get(field)]
    if missing:
        raise ValueError(f"Missing required fields: {missing}")

    event["risk_score"] = calculate_risk_score(event)
    event["patch_priority"] = patch_priority(event["risk_score"])
    event["alert_message"] = build_alert_message(event)
    return event


def main():
    print("Starting streaming-only Kafka -> PostgreSQL consumer...", flush=True)
    print(f"Kafka topic: {TOPIC}", flush=True)
    print(f"Kafka bootstrap: {BOOTSTRAP_SERVERS}", flush=True)
    print(f"Telegram enabled: {TELEGRAM_ENABLED}", flush=True)
    print(f"Alert min risk score: {ALERT_MIN_RISK_SCORE}", flush=True)
    print(f"Alert on known exploited: {ALERT_ON_KNOWN_EXPLOITED}", flush=True)

    conn = get_postgres_connection()
    conn.autocommit = True

    with conn.cursor() as cur:
        cur.execute(CREATE_TABLES_SQL)

    consumer = KafkaConsumer(
        bootstrap_servers=BOOTSTRAP_SERVERS,
        enable_auto_commit=False,
        consumer_timeout_ms=1000,
        value_deserializer=lambda value: json.loads(value.decode("utf-8")),
    )

    partition = TopicPartition(TOPIC, KAFKA_PARTITION)
    consumer.assign([partition])
    consumer.seek_to_end(partition)

    print(
        f"Listening for new streaming events from {TOPIC} partition {KAFKA_PARTITION}.",
        flush=True,
    )

    while True:
        records = consumer.poll(timeout_ms=1000)

        if not records:
            print("waiting for Kafka messages...", flush=True)
            time.sleep(2)
            continue

        for topic_partition, messages in records.items():
            for message in messages:
                try:
                    event = normalize_event(message.value)
                    print(
                        f"received offset={message.offset}: asset_id={event['asset_id']} "
                        f"cve_id={event['cve_id']} risk_score={event['risk_score']}",
                        flush=True,
                    )

                    with conn.cursor() as cur:
                        cur.execute(INSERT_RISK_SQL, event)

                        if should_alert(event):
                            if not mark_cve_as_notified(cur, event):
                                print(
                                    "CVE was already notified before. "
                                    "Skipping Telegram notification.",
                                    flush=True,
                                )
                                continue

                            cur.execute(INSERT_ALERT_SQL, event)
                            print("Inserted streaming realtime alert.", flush=True)
                            send_telegram_alert(event["alert_message"])
                        else:
                            print("Stored risk score only. Alert threshold not met.", flush=True)

                except Exception as exc:
                    print(f"FAILED to process event: {type(exc).__name__}: {exc}", flush=True)

                time.sleep(0.1)


if __name__ == "__main__":
    main()
