import streamlit as st
import psycopg2
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time

# ==================== THEME CONFIGURATION ====================

st.set_page_config(
    page_title="Cyber Threat Intelligence - Live Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for lavender/purple theme
st.markdown("""
<style>
    .stApp { background-color: #FAF8F5; }
    h1, h2, h3 { color: #6B4EE6 !important; font-family: 'Segoe UI', sans-serif; }
    div[data-testid="stMetricValue"] { color: #6B4EE6; font-size: 2rem; font-weight: bold; }
    div[data-testid="stMetricLabel"] { color: #9B8FD4; font-size: 0.9rem; }
    .stDataFrame { border: 2px solid #B8A9E0; border-radius: 12px; }
    .urgent-alert { background-color: #FFE5E5; border-left: 4px solid #FF6B6B; padding: 12px; border-radius: 8px; margin: 8px 0; }
    .high-alert { background-color: #FFF4E5; border-left: 4px solid #FFA500; padding: 12px; border-radius: 8px; margin: 8px 0; }
    .stButton>button { background-color: #B8A9E0; color: white; border-radius: 8px; border: none; }
    .stButton>button:hover { background-color: #9B8FD4; }
</style>
""", unsafe_allow_html=True)

# ==================== DATABASE CONNECTION ====================

@st.cache_resource
def get_connection():
    return psycopg2.connect(
        host="localhost",
        port=5432,
        dbname="cyber_threat_db",
        user="postgres",
        password="aya"
    )

def fetch_risk_data():
    try:
        conn = get_connection()
        query = """
        SELECT event_id, asset_id, hostname, vendor, product, cve_id,
               cvss_score, epss_score, known_exploited, risk_score,
               patch_priority, detected_at
        FROM streaming.realtime_risk_scores
        ORDER BY detected_at DESC
        LIMIT 100
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"❌ Database connection failed: {e}")
        return pd.DataFrame()

def fetch_alert_data():
    try:
        conn = get_connection()
        query = """
        SELECT event_id, asset_id, cve_id, risk_score, patch_priority,
               alert_message, detected_at
        FROM streaming.realtime_alerts
        ORDER BY detected_at DESC
        LIMIT 50
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def fetch_hourly_stats():
    try:
        conn = get_connection()
        query = """
        SELECT DATE_TRUNC('hour', detected_at) as hour,
               COUNT(*) as event_count,
               AVG(risk_score) as avg_risk,
               MAX(risk_score) as max_risk,
               COUNT(CASE WHEN risk_score >= 85 THEN 1 END) as urgent_count
        FROM streaming.realtime_risk_scores
        WHERE detected_at >= NOW() - INTERVAL '24 hours'
        GROUP BY 1
        ORDER BY 1
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

# ==================== DASHBOARD LAYOUT ====================

st.markdown("""
    <h1 style='text-align: center; color: #6B4EE6;'>🛡️ Cyber Threat Intelligence Platform</h1>
    <p style='text-align: center; color: #9B8FD4; font-size: 1.1rem;'>Real-Time Vulnerability Risk Monitor</p>
    <hr style='border: 2px solid #B8A9E0; margin: 20px 0;'>
""", unsafe_allow_html=True)

# Auto-refresh
col_auto, col_refresh = st.columns([1, 5])
with col_auto:
    auto_refresh = st.checkbox("🔄 Auto-refresh (5s)", value=True)
with col_refresh:
    if st.button("🔄 Refresh Now"):
        st.rerun()

# ==================== FETCH DATA ====================

df_risk = fetch_risk_data()
df_alerts = fetch_alert_data()
df_hourly = fetch_hourly_stats()

# If no data, show demo/welcome screen
if df_risk.empty:
    st.warning("⚠️ No data available. Make sure PostgreSQL is running and Kafka consumer is ingesting data.")
    
    st.info("""
    **To start the full pipeline:**
    
    1. **Start PostgreSQL:** `docker-compose up -d postgres`
    2. **Start Kafka:** `docker-compose up -d kafka zookeeper`
    3. **Run consumer:** `python streaming/kafka_consumer.py`
    4. **Run producer:** `python streaming/kafka_producer.py`
    5. **Refresh this page**
    """)
    
    # Show demo metrics with zeros
    total_events = 0
    urgent_count = 0
    high_count = 0
    avg_risk = 0.0
    assets_affected = 0
else:
    total_events = len(df_risk)
    urgent_count = len(df_risk[df_risk['risk_score'] >= 85])
    high_count = len(df_risk[(df_risk['risk_score'] >= 70) & (df_risk['risk_score'] < 85)])
    avg_risk = df_risk['risk_score'].mean()
    assets_affected = df_risk['asset_id'].nunique()

# ==================== METRICS ROW ====================

st.markdown("<h3 style='color: #6B4EE6;'>📊 Live Metrics</h3>", unsafe_allow_html=True)

m1, m2, m3, m4, m5 = st.columns(5)

with m1:
    st.metric("Total Events", f"{total_events}")
with m2:
    st.metric("🚨 Urgent (≥85)", f"{urgent_count}", delta="Critical" if urgent_count > 0 else "Safe", delta_color="inverse")
with m3:
    st.metric("⚠️ High (70-84)", f"{high_count}")
with m4:
    st.metric("Avg Risk Score", f"{avg_risk:.1f}")
with m5:
    st.metric("Assets Affected", f"{assets_affected}")

# ==================== CHARTS ROW ====================

if not df_risk.empty:
    st.markdown("<h3 style='color: #6B4EE6;'>📈 Risk Analytics</h3>", unsafe_allow_html=True)
    
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        df_risk['priority'] = df_risk['risk_score'].apply(
            lambda x: 'Urgent' if x >= 85 else 'High' if x >= 70 else 'Medium' if x >= 50 else 'Low'
        )
        fig_pie = px.pie(
            df_risk, names='priority', title='Risk Priority Distribution',
            color='priority',
            color_discrete_map={'Urgent': '#FF6B6B', 'High': '#FFA500', 'Medium': '#FFD700', 'Low': '#90EE90'}
        )
        fig_pie.update_layout(plot_bgcolor='#FAF8F5', paper_bgcolor='#FAF8F5', font_color='#6B4EE6')
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col_chart2:
        if not df_hourly.empty:
            fig_line = px.line(
                df_hourly, x='hour', y=['avg_risk', 'max_risk'],
                title='24-Hour Risk Score Trend',
                labels={'hour': 'Hour', 'value': 'Risk Score', 'variable': 'Metric'}
            )
            fig_line.update_layout(plot_bgcolor='#FAF8F5', paper_bgcolor='#FAF8F5', font_color='#6B4EE6')
            st.plotly_chart(fig_line, use_container_width=True)

# ==================== LIVE ALERT FEED ====================

st.markdown("<h3 style='color: #6B4EE6;'>🔴 Live Alert Feed</h3>", unsafe_allow_html=True)

if not df_alerts.empty:
    for _, alert in df_alerts.head(10).iterrows():
        risk = alert['risk_score']
        if risk >= 85:
            st.markdown(f"""
                <div class="urgent-alert">
                    <b>🚨 URGENT</b> | {alert['detected_at'].strftime('%H:%M:%S')}<<br>
                    <b>Asset:</b> {alert['asset_id']} | <b>CVE:</b> {alert['cve_id']}<<br>
                    <b>Risk Score:</b> {risk:.1f} | <b>Priority:</b> {alert['patch_priority']}
                </div>
            """, unsafe_allow_html=True)
        elif risk >= 70:
            st.markdown(f"""
                <div class="high-alert">
                    <b>⚠️ HIGH</b> | {alert['detected_at'].strftime('%H:%M:%S')}<<br>
                    <b>Asset:</b> {alert['asset_id']} | <b>CVE:</b> {alert['cve_id']}<<br>
                    <b>Risk Score:</b> {risk:.1f}
                </div>
            """, unsafe_allow_html=True)
else:
    st.info("No alerts triggered yet. Waiting for high-risk events...")

# ==================== DATA TABLE ====================

if not df_risk.empty:
    st.markdown("<h3 style='color: #6B4EE6;'>📋 Recent Risk Events</h3>", unsafe_allow_html=True)
    
    display_df = df_risk.copy()
    display_df['detected_at'] = display_df['detected_at'].dt.strftime('%H:%M:%S')
    display_df['risk_score'] = display_df['risk_score'].round(2)
    
    styled_df = display_df[['detected_at', 'asset_id', 'cve_id', 'risk_score', 'patch_priority', 'cvss_score', 'epss_score']].style.applymap(
        lambda x: 'background-color: #FFE5E5; color: #FF6B6B; font-weight: bold' if x >= 85 else 
                  'background-color: #FFF4E5; color: #FFA500' if x >= 70 else '',
        subset=['risk_score']
    )
    st.dataframe(styled_df, use_container_width=True, height=400)

# ==================== AUTO REFRESH ====================

if auto_refresh and not df_risk.empty:
    time.sleep(5)
    st.rerun()

# ==================== FOOTER ====================

st.markdown("""
    <hr style='border: 1px solid #B8A9E0;'>
    <p style='text-align: center; color: #9B8FD4; font-size: 0.8rem;'>
        Cyber Threat Intelligence Platform | Batch + Streaming + Micro-Batch<br>
        <span style='color: #B8A9E0;'>Built with Streamlit • PostgreSQL • Kafka • Python</span>
    </p>
""", unsafe_allow_html=True)