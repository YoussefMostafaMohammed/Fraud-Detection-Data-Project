## المرحلة 0: الفكرة العامة

عندك شركة عندها **أجهزة وبرامج** (Asset Inventory)، وعندك **ثغرات أمنية** (CVEs) بتطلع كل يوم. 

**الهدف:** نعرف **أي جهاز عندنا عليه ثغرة خطيرة ومحتاج يتصلح بسرعة**.

---

## المرحلة 1: جمع البيانات (Data Ingestion)

### المصادر:

| المصدر | بيجيب إيه | إزاي |
| --- | --- | --- |
| **NVD API** | كل الثغرات (CVEs) ودرجة خطورتها (CVSS) | REST API — JSON |
| **CISA KEV** | الثغرات اللي **بتتستغل فعلاً** دلوقتي | JSON Catalog |
| **EPSS API** | احتمالية استغلال كل ثغرة (0 لـ 1) | REST API |
| **Asset Inventory** | الأجهزة والبرامج اللي عندنا | CSV file |

### الكود (Airflow DAG):

```python
# daily_vulnerability_ingestion.py
from airflow import DAG
from airflow.operators.python import PythonOperator
import requests
import boto3
import json
from datetime import datetime

def fetch_nvd_to_s3():
    # 1. نجيب البيانات من NVD
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    response = requests.get(url)
    data = response.json()
    
    # 2. نجهز S3 client
    s3 = boto3.client('s3')
    bucket = 'cyber-threat-intel-data-lake'
    
    # 3. نعمل partition بالتاريخ
    today = datetime.now().strftime('%Y-%m-%d')
    
    # 4. نرفع على Bronze
    s3.put_object(
        Bucket=bucket,
        Key=f'bronze/nvd/{today}/nvd_cves.json',
        Body=json.dumps(data)
    )

def fetch_cisa_kev_to_s3():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    data = response.json()
    
    s3 = boto3.client('s3')
    today = datetime.now().strftime('%Y-%m-%d')
    
    s3.put_object(
        Bucket='cyber-threat-intel-data-lake',
        Key=f'bronze/cisa_kev/{today}/cisa_kev.json',
        Body=json.dumps(data)
    )

def fetch_epss_to_s3():
    # EPSS بيجيب scores لكل CVEs
    url = "https://api.first.org/data/v1/epss"
    response = requests.get(url)
    data = response.json()
    
    s3 = boto3.client('s3')
    today = datetime.now().strftime('%Y-%m-%d')
    
    s3.put_object(
        Bucket='cyber-threat-intel-data-lake',
        Key=f'bronze/epss/{today}/epss_scores.json',
        Body=json.dumps(data)
    )

# الـ DAG
with DAG(
    'daily_vulnerability_ingestion',
    schedule='0 3 * * *',  # كل يوم 3 الفجر
    start_date=datetime(2026, 1, 1),
    catchup=False
) as dag:
    
    task_nvd = PythonOperator(
        task_id='fetch_nvd',
        python_callable=fetch_nvd_to_s3
    )
    
    task_cisa = PythonOperator(
        task_id='fetch_cisa',
        python_callable=fetch_cisa_kev_to_s3
    )
    
    task_epss = PythonOperator(
        task_id='fetch_epss',
        python_callable=fetch_epss_to_s3
    )
    
    # التلات tasks دول ممكن يشتغلوا بالتوازي
    [task_nvd, task_cisa, task_epss]
```

**إيه اللي بيحصل بالظبط؟**

1. Airflow بيصحى الساعة 3 الفجر
2. بيشغل 3 Python functions بالتوازي
3. كل function بتعمل HTTP GET للـ API بتاعها
4. بترجع JSON
5. بترفعه على S3 في فولدر `bronze/`

---

## المرحلة 2: التخزين (S3 Data Lake)

### ليه S3؟

- **Cheap**: 0.023 per GB per month
- **Scalable**: مفيش limit
- **Durable**: 99.999999999% (11 nines)
- **Versioning**: لو غلطت، ترجع

### الـ Bucket Structure:

```
s3://cyber-threat-intel-data-lake/
│
├── bronze/                    ← البيانات الخام زي ما جت
│   ├── nvd/2026-11-09/nvd_cves.json
│   ├── cisa_kev/2026-11-09/cisa_kev.json
│   ├── epss/2026-11-09/epss_scores.json
│   └── assets/2026-11-09/asset_inventory.csv
│
├── silver/                    ← بيانات متنضفة ومنظمة
│   ├── cves_clean/
│   ├── cisa_kev_clean/
│   ├── epss_scores/
│   └── asset_inventory_clean/
│
└── gold/                      ← جداول جاهزة للتحليل
    ├── dim_asset/
    ├── dim_cve/
    ├── dim_date/
    ├── fact_asset_vulnerability/
    └── fact_epss_trend/
```

### ليه 3 Layers (Medallion Architecture)؟

| Layer | الهدف | مثال |
| --- | --- | --- |
| **Bronze** | نحتفظ بالبيانات الخام | JSON زي ما جاه من API |
| **Silver** | ننضف ونظبط | نشيل التكرار، نصلح الـ schema |
| **Gold** | جداول جاهزة للـ BI | Facts و Dimensions |

**الفايدة:** لو حصل error في Gold، نرجع لـ Silver. لو Silver فيه مشكلة، نرجع لـ Bronze.

---

## المرحلة 3: التحويل (AWS Glue)

### Glue إيه هو؟

**Serverless Spark** — AWS بتدير كل حاجة، انت بس بتديله الكود.

- مش محتاج تدير servers
- بيscale تلقائياً
- بيتكامل مع S3 مباشرة

### Glue Job 1: Silver Transform (Bronze → Silver)

```python
# silver_transform.py
import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from pyspark.sql.functions import col, explode, lit, to_date, when

# 1. نجهز الـ contexts
args = getResolvedOptions(sys.argv, ['JOB_NAME'])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

# 2. نقرأ من Bronze
bronze_path = "s3://cyber-threat-intel-data-lake/bronze/nvd/"
df = spark.read.json(bronze_path)

# 3. نفك الـ Nested JSON
# NVD بيرجع JSON معقد، محتاجين نفكها
df_flat = df.select(
    col("cve.id").alias("cve_id"),
    col("cve.published").alias("published_date"),
    col("cve.lastModified").alias("last_modified"),
    col("cve.descriptions")[0]["value"].alias("description"),
    col("cve.metrics.cvssMetricV31")[0]["cvssData"]["baseScore"].alias("cvss_v3_score"),
    col("cve.metrics.cvssMetricV31")[0]["cvssData"]["baseSeverity"].alias("cvss_v3_severity"),
    col("cve.metrics.cvssMetricV31")[0]["cvssData"]["vectorString"].alias("cvss_vector"),
    col("cve.configurations")[0]["nodes"][0]["cpeMatch"][0]["criteria"].alias("cpe")
)

# 4. نفلتر nulls
df_clean = df_flat.filter(
    col("cvss_v3_score").isNotNull() &
    col("cve_id").isNotNull()
)

# 5. نعمل deduplication
df_dedup = df_clean.dropDuplicates(["cve_id"])

# 6. نضيف تاريخ المعالجة
from pyspark.sql.functions import current_date
df_final = df_dedup.withColumn("processed_date", current_date())

# 7. نكتب على Silver بصيغة Parquet
df_final.write.mode("overwrite").parquet(
    "s3://cyber-threat-intel-data-lake/silver/cves_clean/"
)

job.commit()
```

**إيه اللي بيحصل هنا؟**

| الخطوة | الوصف |
| --- | --- |
| Read | بنقرأ كل ملفات JSON من Bronze |
| Flatten | بنفك الـ nested JSON (NVD بيرجع JSON معقد جداً) |
| Filter | بنشيل records اللي مفيش CVSS score |
| Deduplicate | بنشيل التكرار |
| Add Metadata | بنضيف تاريخ المعالجة |
| Write | بنكتب Parquet على Silver |

### ليه Parquet مش JSON/CSV؟

| الصيغة | المشكلة | Parquet |
| --- | --- | --- |
| JSON | Slow, no schema | **10x faster** |
| CSV | No types, big size | **10x smaller** |
| Parquet | Columnar, compressed, schema built-in | ✅ |

---

### Glue Job 2: Gold Transform (Silver → Gold)

هنا بنعمل **Galaxy Schema** — تصميم قاعدة بيانات للتحليل:

```python
# gold_transform.py
from pyspark.sql.functions import *
from pyspark.sql.types import *

# 1. نقرأ من Silver
cves_df = spark.read.parquet("s3://.../silver/cves_clean/")
assets_df = spark.read.parquet("s3://.../silver/asset_inventory_clean/")
epss_df = spark.read.parquet("s3://.../silver/epss_scores/")
cisa_df = spark.read.parquet("s3://.../silver/cisa_kev_clean/")

# 2. نعمل dim_cve
dim_cve = cves_df.select(
    monotonically_increasing_id().alias("cve_key"),
    col("cve_id"),
    col("description"),
    col("cvss_v3_score"),
    col("cvss_v3_severity"),
    col("cpe")
)

# 3. نعمل dim_asset
dim_asset = assets_df.select(
    monotonically_increasing_id().alias("asset_key"),
    col("asset_id"),
    col("hostname"),
    col("vendor"),
    col("product"),
    col("version"),
    col("criticality"),  # 1-4
    col("internet_facing")  # boolean
)

# 4. نعمل dim_date
dim_date = spark.sql("""
    SELECT 
        date_key,
        full_date,
        year,
        month,
        day,
        quarter,
        is_weekend
    FROM date_dimension_table
""")

# 5. نعمل fact_asset_vulnerability (الجدول الأهم)
# بنعمل join بين assets و cves بناءً على CPE
fact_table = assets_df.join(
    cves_df,
    assets_df.product == cves_df.cpe_product,
    "inner"
).join(
    epss_df,
    "cve_id",
    "left"
).join(
    cisa_df,
    "cve_id",
    "left"
).select(
    col("asset_key"),
    col("cve_key"),
    col("date_key"),
    # نحسب Risk Score
    (
        (col("cvss_v3_score") / 10 * 0.30) +
        (col("epss_score") * 100 * 0.30) +
        (when(col("cisa_kev").isNotNull(), 10).otherwise(0) * 0.20) +
        (col("criticality") / 4 * 10 * 0.15) +
        (when(col("internet_facing"), 10).otherwise(0) * 0.05)
    ).alias("risk_score"),
    col("epss_score"),
    col("cisa_kev").isNotNull().alias("is_cisa_exploited")
)

# 6. نكتب الجداول
dim_cve.write.mode("overwrite").parquet("s3://.../gold/dim_cve/")
dim_asset.write.mode("overwrite").parquet("s3://.../gold/dim_asset/")
dim_date.write.mode("overwrite").parquet("s3://.../gold/dim_date/")
fact_table.write.mode("overwrite").parquet("s3://.../gold/fact_asset_vulnerability/")
```

### Galaxy Schema Structure:

```
                    dim_date
                        │
                        │
dim_asset ──────► fact_asset_vulnerability ◄────── dim_cve
   (الأجهزة)         (الجدول الأساسي)            (الثغرات)
                        │
                        ▼
                fact_epss_trend
```

**إيه هو الـ Galaxy Schema؟**
- **Dimensions**: جداول الوصف (asset, cve, date)
- **Facts**: جداول الأرقام (risk scores)
- **ليه Galaxy مش Star؟** لأن عندنا Facts كتير (fact_asset_vulnerability + fact_epss_trend) بيتشاركوا نفس Dimensions

---

## المرحلة 4: التحميل لـ PostgreSQL

```python
# load_gold_to_postgres.py
import psycopg2
import pandas as pd
from sqlalchemy import create_engine

# 1. نقرأ من Gold
dim_cve = pd.read_parquet("s3://.../gold/dim_cve/")
dim_asset = pd.read_parquet("s3://.../gold/dim_asset/")
fact_table = pd.read_parquet("s3://.../gold/fact_asset_vulnerability/")

# 2. نعمل connection لـ PostgreSQL
engine = create_engine('postgresql://user:pass@host:5432/cti_db')

# 3. نكتب الجداول
dim_cve.to_sql('dim_cve', engine, if_exists='replace', index=False)
dim_asset.to_sql('dim_asset', engine, if_exists='replace', index=False)
fact_table.to_sql('fact_asset_vulnerability', engine, if_exists='replace', index=False)
```

**ليه PostgreSQL مش نقرأ من S3 على طول؟**
- Power BI بيتكلم SQL بشكل أفضل
- Query performance أحسن
- Concurrent users

---

## المرحلة 5: الـ Streaming Pipeline (Real-time)

ده خط منفصل تماماً — للتنبيهات الفورية.

### Kafka Producer (محاكي أحداث)

```python
# kafka_producer.py
from kafka import KafkaProducer
import json
import time
import random

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# بنحاكي events — في الحقيقة دي ممكن تجي من SIEM أو Scanner
while True:
    event = {
        "asset_id": f"ASSET-{random.randint(1, 1000)}",
        "cve_id": f"CVE-2026-{random.randint(1000, 9999)}",
        "cvss_score": round(random.uniform(0, 10), 1),
        "epss_score": round(random.uniform(0, 1), 3),
        "is_cisa_kev": random.choice([True, False]),
        "criticality": random.randint(1, 4),
        "internet_facing": random.choice([True, False]),
        "timestamp": time.time()
    }
    
    producer.send('vulnerability-events', event)
    time.sleep(1)  # event كل ثانية
```

### Kafka Consumer (Risk Scoring + Alerts)

```python
# kafka_consumer.py
from kafka import KafkaConsumer
import psycopg2
import requests
import json

# 1. نعمل connection لـ Kafka
consumer = KafkaConsumer(
    'vulnerability-events',
    bootstrap_servers=['localhost:9092'],
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

# 2. نعمل connection لـ PostgreSQL
conn = psycopg2.connect(
    host='localhost',
    database='cti_db',
    user='user',
    password='pass'
)
cursor = conn.cursor()

# 3. Telegram Bot للتنبيهات
TELEGRAM_TOKEN = 'your_bot_token'
CHAT_ID = 'your_chat_id'

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    requests.post(url, json=payload)

# 4. نسمع الـ events
for event in consumer:
    data = event.value
    
    # نحسب Risk Score
    risk_score = (
        (data['cvss_score'] / 10 * 0.30) +
        (data['epss_score'] * 100 * 0.30) +
        (10 * 0.20 if data['is_cisa_kev'] else 0) +
        (data['criticality'] / 4 * 10 * 0.15) +
        (10 * 0.05 if data['internet_facing'] else 0)
    )
    
    # نخزن في PostgreSQL
    cursor.execute("""
        INSERT INTO real_time_risk_scores 
        (asset_id, cve_id, risk_score, timestamp)
        VALUES (%s, %s, %s, %s)
    """, (data['asset_id'], data['cve_id'], risk_score, data['timestamp']))
    conn.commit()
    
    # لو خطورة عالية، نبعت تنبيه
    if risk_score >= 85:
        alert_msg = f"""
🚨 *URGENT: Critical Vulnerability Detected*

*Asset:* {data['asset_id']}
*CVE:* {data['cve_id']}
*Risk Score:* {risk_score:.1f}

*Immediate action required!*
        """
        send_telegram_alert(alert_msg)
    
    print(f"Processed: {data['cve_id']} - Score: {risk_score:.1f}")
```

### Streamlit Dashboard (Live Monitoring)

```python
# streamlit_dashboard.py
import streamlit as st
import psycopg2
import pandas as pd
import time

st.set_page_config(page_title="CTI Dashboard", layout="wide")

st.title("🔴 Real-Time Vulnerability Monitor")

# Auto-refresh كل 5 ثواني
st_autorefresh = st.experimental_rerun

# نقرأ من PostgreSQL
@st.cache_data(ttl=5)  # cache لـ 5 ثواني بس
def load_data():
    conn = psycopg2.connect(
        host='localhost',
        database='cti_db',
        user='user',
        password='pass'
    )
    
    # آخر 100 event
    df = pd.read_sql("""
        SELECT 
            asset_id,
            cve_id,
            risk_score,
            timestamp
        FROM real_time_risk_scores
        ORDER BY timestamp DESC
        LIMIT 100
    """, conn)
    
    conn.close()
    return df

# نعرض الداتا
df = load_data()

col1, col2, col3 = st.columns(3)
col1.metric("Total Events", len(df))
col2.metric("Critical (≥85)", len(df[df['risk_score'] >= 85]))
col3.metric("High (70-84)", len(df[(df['risk_score'] >= 70) & (df['risk_score'] < 85)]))

# جدول
st.dataframe(df)

# Chart
st.bar_chart(df['risk_score'])

# Auto-refresh
time.sleep(5)
st.experimental_rerun()
```

---

## المرحلة 6: Micro-Batch Pipeline (Hourly Reports)

ده للتقارير المتوسطة — مش urgent بس محتاجة attention.

```python
# report_hourly_dag.py (Airflow DAG)
from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime
import smtplib
from email.mime.text import MimeText

def send_hourly_digest():
    import psycopg2
    import pandas as pd
    
    # 1. نقرأ من PostgreSQL
    conn = psycopg2.connect(...)
    
    # آخر ساعة
    df = pd.read_sql("""
        SELECT 
            asset_id,
            cve_id,
            risk_score
        FROM real_time_risk_scores
        WHERE timestamp >= NOW() - INTERVAL '1 hour'
        AND risk_score BETWEEN 50 AND 84  -- Medium و High بس
        ORDER BY risk_score DESC
    """, conn)
    
    # 2. نعمل HTML report
    html = f"""
    <html>
    <body>
        <h2>Hourly Vulnerability Digest</h2>
        <p>Total vulnerabilities (medium/high): {len(df)}</p>
        <table border="1">
            <tr>
                <th>Asset</th>
                <th>CVE</th>
                <th>Risk Score</th>
            </tr>
            {df.to_html(index=False)}
        </table>
    </body>
    </html>
    """
    
    # 3. نبعت إيميل
    msg = MIMEText(html, 'html')
    msg['Subject'] = f'Hourly Vulnerability Report - {datetime.now()}'
    msg['From'] = 'cti@company.com'
    msg['To'] = 'security-team@company.com'
    
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login('cti@company.com', 'password')
        server.send_message(msg)

with DAG(
    'hourly_digest',
    schedule='0 * * * *',  # كل ساعة
    start_date=datetime(2026, 1, 1)
) as dag:
    
    send_report = PythonOperator(
        task_id='send_hourly_digest',
        python_callable=send_hourly_digest
    )
```

---

## المرحلة 7: Power BI (Executive Dashboard)

### إزاي Power BI بيقرأ البيانات؟

1. **Data Source**: PostgreSQL (Gold layer)
2. **Connection**: DirectQuery أو Import
3. **Model**: Star Schema (Facts + Dimensions)

### الـ Dashboards:

| Dashboard | بيعرض إيه |
| --- | --- |
| **Executive Summary** | Top 10 critical assets, risk trends |
| **Vulnerability Heatmap** | حسب المنتج/الجهاز |
| **Patching Priority** | إيه اللي لازم يتصلح الأول |
| **Trend Analysis** | EPSS scores مع الوقت |

---

## 🎯 الخلاصة — الأسئلة المتوقعة في الانترفيو

### س: اشرحلي الـ Architecture بتاع المشروع

> "عندنا hybrid batch + streaming pipeline. الـ batch بيشتغل يومياً الساعة 3 الفجر — Airflow بيجيب بيانات من NVD و CISA و EPSS APIs، يرفعها على S3 Bronze layer. بعدين AWS Glue بيحولها لـ Silver (cleansed Parquet)، وبعدين لـ Gold (Galaxy Schema). من Gold بنحمل على PostgreSQL، و Power BI بيقرأ منها للتقارير. الـ streaming pipeline منفصل — Kafka Producer بيحاكي events، Consumer بيحسب risk score real-time، ولو score ≥ 85 بيبعت Telegram alert. Streamlit Dashboard بيعرض live data. Micro-batch pipeline بيبعت hourly email digest للتقارير المتوسطة."

### س: ليه استخدمت S3؟

> "لأنه cheap, scalable, durable. وكمان عشان نعمل Medallion Architecture — Bronze للبيانات الخام، Silver للمنضف، Gold للجاهز للتحليل. ده بيدينا audit trail وإمكانية reprocessing."

### س: AWS Glue بيعمل إيه بالظبط؟

> "Glue هو serverless Spark. بنستخدمه للـ ETL — بيقرأ من S3 Bronze، يعمل flattening للـ nested JSON، filtering, deduplication، ويكتب Parquet على Silver. وبعدين job تاني بيحول Silver لـ Galaxy Schema في Gold."

### س: ليه Parquet؟

> "Columnar storage — أسرع 10 مرات من JSON في الـ analytics queries، وأصغر في المساحة بـ 10 مرات. وكمان schema built-in."

### س: إيه هو Galaxy Schema؟

> "تصميم قاعدة بيانات للـ OLAP — Facts في النص (fact_asset_vulnerability, fact_epss_trend) و Dimensions حواليها (dim_asset, dim_cve, dim_date). بيتشاركوا نفس dimensions — عشان كده اسمه Galaxy مش Star."

### س: الـ Risk Score بيتحسب إزاي؟

> "Weighted sum: CVSS (30%) + EPSS (30%) + CISA KEV (20%) + Asset Criticality (15%) + Internet Facing (5%). لو ≥ 85 بنبعت Telegram alert فوري."

### س: الفرق بين الـ 3 pipelines؟

> "Batch: daily analytics على كل البيانات. Streaming: real-time alerts للـ critical. Micro-batch: hourly digest للـ medium/high — عشان محدش يتضايق من alert fatigue."
