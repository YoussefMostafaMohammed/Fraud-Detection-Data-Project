import streamlit as st
import psycopg2
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
from sqlalchemy import create_engine

# ==================== THEME CONFIGURATION ====================

st.set_page_config(
    page_title="Cyber Threat Intelligence - Live Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS — FORCE light theme, visible text everywhere
st.markdown("""
<style>
    /* Force light background */
    .stApp { 
        background-color: #FAF8F5; 
    }
    
    /* Headings — dark purple with high contrast */
    h1 { color: #4C1D95 !important; font-family: 'Segoe UI', sans-serif; font-weight: 700; }
    h2 { color: #4C1D95 !important; font-family: 'Segoe UI', sans-serif; font-weight: 600; }
    h3 { color: #4C1D95 !important; font-family: 'Segoe UI', sans-serif; font-weight: 600; }
    
    /* Metric values — bold purple */
    div[data-testid="stMetricValue"] { 
        color: #5B3FD6; 
        font-size: 2.2rem; 
        font-weight: bold; 
    }
    
    /* FIXED: Metric labels — Streamlit uses p tags inside metric containers */
    div[data-testid="stMetricLabel"] > div { 
        color: #1F2937 !important; 
        font-size: 0.95rem !important; 
        font-weight: 600 !important;
    }
    
    /* Alternative selector for metric labels */
    .stMetric label, .stMetric p {
        color: #1F2937 !important;
        font-weight: 600 !important;
    }
    
    /* Metric delta */
    div[data-testid="stMetricDelta"] {
        color: #DC2626 !important;
        font-weight: 600;
    }
    
    /* Alert boxes */
    .urgent-alert { 
        background-color: #FEE2E2; 
        border-left: 4px solid #DC2626; 
        padding: 12px; 
        border-radius: 8px; 
        margin: 8px 0; 
        color: #7F1D1D !important;
        font-family: 'Segoe UI', sans-serif;
    }
    .urgent-alert b { color: #991B1B !important; }
    
    .high-alert { 
        background-color: #FEF3C7; 
        border-left: 4px solid #D97706; 
        padding: 12px; 
        border-radius: 8px; 
        margin: 8px 0; 
        color: #78350F !important;
        font-family: 'Segoe UI', sans-serif;
    }
    .high-alert b { color: #D97706 !important; }
    
    .medium-alert { 
        background-color: #DBEAFE; 
        border-left: 4px solid #2563EB; 
        padding: 12px; 
        border-radius: 8px; 
        margin: 8px 0; 
        color: #1E3A5F !important;
        font-family: 'Segoe UI', sans-serif;
    }
    .medium-alert b { color: #2563EB !important; }
    
    .stButton>button { 
        background-color: #B8A9E0; 
        color: white; 
        border-radius: 8px; 
        border: none; 
    }
    .stButton>button:hover { 
        background-color: #9B8FD4; 
    }
</style>
""", unsafe_allow_html=True)

# ==================== DATABASE CONNECTION ====================

POSTGRES_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "cyber_threat_db",
    "user": "postgres",
    "password": "aya",
}

@st.cache_resource
def get_engine():
    conn_str = f"postgresql+psycopg2://{POSTGRES_CONFIG['user']}:{POSTGRES_CONFIG['password']}@{POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}/{POSTGRES_CONFIG['dbname']}"
    return create_engine(conn_str)

def fetch_risk_data():
    try:
        engine = get_engine()
        query = """
        SELECT event_id, asset_id, hostname, vendor, product, cve_id,
               cvss_score, epss_score, known_exploited, risk_score,
               patch_priority, detected_at
        FROM streaming.realtime_risk_scores
        ORDER BY detected_at DESC
        LIMIT 100
        """
        return pd.read_sql(query, engine)
    except Exception as e:
        st.error(f"❌ Database error: {e}")
        return pd.DataFrame()

def fetch_alert_data():
    try:
        engine = get_engine()
        query = """
        SELECT event_id, asset_id, cve_id, risk_score, patch_priority,
               alert_message, detected_at
        FROM streaming.realtime_alerts
        ORDER BY detected_at DESC
        LIMIT 50
        """
        return pd.read_sql(query, engine)
    except:
        return pd.DataFrame()

def fetch_time_bucket_stats():
    """Fetch 5-minute bucket stats for the last hour"""
    try:
        engine = get_engine()
        query = """
        SELECT 
            DATE_TRUNC('minute', detected_at) - 
                (EXTRACT(MINUTE FROM detected_at)::int % 5) * INTERVAL '1 minute' as time_bucket,
            COUNT(*) as event_count,
            COUNT(CASE WHEN risk_score >= 85 THEN 1 END) as critical_count
        FROM streaming.realtime_risk_scores
        WHERE detected_at >= NOW() - INTERVAL '1 hour'
        GROUP BY 1
        ORDER BY 1
        """
        return pd.read_sql(query, engine)
    except:
        return pd.DataFrame()

def fetch_top_vulnerable_assets():
    """Fetch top 10 most vulnerable assets"""
    try:
        engine = get_engine()
        query = """
        SELECT asset_id, 
               COUNT(*) as total_events,
               AVG(risk_score) as avg_risk,
               MAX(risk_score) as max_risk,
               COUNT(CASE WHEN risk_score >= 85 THEN 1 END) as critical_count
        FROM streaming.realtime_risk_scores
        WHERE detected_at >= NOW() - INTERVAL '24 hours'
        GROUP BY asset_id
        ORDER BY critical_count DESC, avg_risk DESC
        LIMIT 10
        """
        return pd.read_sql(query, engine)
    except:
        return pd.DataFrame()

def fetch_vendor_risk_summary():
    """Fetch risk summary by vendor"""
    try:
        engine = get_engine()
        query = """
        SELECT 
            vendor,
            COUNT(*) as event_count,
            AVG(risk_score) as avg_risk,
            COUNT(CASE WHEN risk_score >= 85 THEN 1 END) as critical_count,
            COUNT(CASE WHEN known_exploited = true THEN 1 END) as exploited_count
        FROM streaming.realtime_risk_scores
        WHERE detected_at >= NOW() - INTERVAL '24 hours'
        GROUP BY vendor
        ORDER BY critical_count DESC, avg_risk DESC
        """
        return pd.read_sql(query, engine)
    except:
        return pd.DataFrame()

def fetch_risk_trend():
    """Fetch risk trend over time — per-event"""
    try:
        engine = get_engine()
        query = """
        SELECT 
            detected_at,
            risk_score,
            asset_id,
            cve_id,
            known_exploited
        FROM streaming.realtime_risk_scores
        WHERE detected_at >= NOW() - INTERVAL '1 hour'
        ORDER BY detected_at
        """
        return pd.read_sql(query, engine)
    except:
        return pd.DataFrame()

# ==================== DASHBOARD LAYOUT ====================

st.markdown("""
    <h1 style='text-align: center; color: #4C1D95;'>🛡️ Cyber Threat Intelligence Platform</h1>
    <p style='text-align: center; color: #7A6BC4; font-size: 1.1rem;'>Real-Time Vulnerability Risk Monitor</p>
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
df_time_buckets = fetch_time_bucket_stats()
df_assets = fetch_top_vulnerable_assets()
df_vendors = fetch_vendor_risk_summary()
df_trend = fetch_risk_trend()

# If no data, show setup instructions
if df_risk.empty:
    st.warning("⚠️ No data available. The streaming pipeline is not running or database is empty.")
    
    st.info("""
    **To start the full pipeline:**
    
    1. **Start Docker:** `docker-compose up -d`
    2. **Start Consumer:** `python streaming/kafka_consumer.py`
    3. **Start Producer:** `python streaming/kafka_producer.py`
    4. **Refresh this page**
    """)
    
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

st.markdown("### 📊 Live Metrics")

m1, m2, m3, m4, m5 = st.columns(5)

with m1:
    st.metric("Total Events", f"{total_events}")
with m2:
    st.metric("🚨 Critical (≥85)", f"{urgent_count}", delta="Critical" if urgent_count > 0 else "Safe", delta_color="inverse")
with m3:
    st.metric("⚠️ High Risk (70-84)", f"{high_count}")
with m4:
    st.metric("Avg Risk Score", f"{avg_risk:.1f}")
with m5:
    st.metric("Assets Affected", f"{assets_affected}")

# ==================== CHARTS ROW 1 ====================

if not df_risk.empty:
    st.markdown("### 📈 Risk Analytics")
    
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        # Pie chart — Risk Priority Distribution
        df_risk = df_risk.copy()
        df_risk['priority'] = df_risk['risk_score'].apply(
            lambda x: 'Critical' if x >= 85 else 'High' if x >= 70 else 'Medium' if x >= 50 else 'Low'
        )
        fig_pie = px.pie(
            df_risk, names='priority', title='Risk Priority Distribution',
            color='priority',
            color_discrete_map={
                'Critical': '#DC2626', 
                'High': '#D97706', 
                'Medium': '#2563EB', 
                'Low': '#059669'
            }
        )
        fig_pie.update_layout(
            paper_bgcolor='#FAF8F5',
            plot_bgcolor='#FAF8F5',
            font=dict(color='#1F2937'),
            title_font_color='#4C1D95',
            legend=dict(
                font=dict(color='#1F2937', size=12),
                bgcolor='rgba(255,255,255,0.95)',
                bordercolor='#B8A9E0',
                borderwidth=1
            )
        )
        fig_pie.update_traces(
            textfont=dict(color='white', size=13),
            insidetextorientation='radial'
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col_chart2:
        # Top 10 Most Vulnerable Assets
        if not df_assets.empty:
            fig_bar = px.bar(
                df_assets,
                y='asset_id',
                x='critical_count',
                orientation='h',
                title='🔥 Top 10 Most Vulnerable Assets (Critical Events)',
                labels={'asset_id': 'Asset ID', 'critical_count': 'Critical Event Count'},
                text='critical_count'
            )
            fig_bar.update_traces(
                marker_color='#DC2626',
                textposition='outside',
                textfont=dict(color='#1F2937', size=12)
            )
            fig_bar.update_layout(
                paper_bgcolor='#FAF8F5',
                plot_bgcolor='#FAF8F5',
                font=dict(color='#1F2937'),
                title_font_color='#4C1D95',
                yaxis=dict(
                    tickfont=dict(color='#1F2937', size=11),
                    title_font=dict(color='#1F2937'),
                    gridcolor='#E5E7EB'
                ),
                xaxis=dict(
                    tickfont=dict(color='#1F2937'),
                    title_font=dict(color='#1F2937'),
                    gridcolor='#E5E7EB'
                ),
                margin=dict(l=10, r=10, t=50, b=30)
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No asset data available.")

# ==================== CHARTS ROW 2 ====================

if not df_risk.empty:
    col_chart3, col_chart4 = st.columns(2)
    
    with col_chart3:
        # Risk Trend Timeline
        if not df_trend.empty and len(df_trend) > 1:
            fig_trend = go.Figure()
            
            fig_trend.add_trace(go.Scatter(
                x=df_trend['detected_at'],
                y=df_trend['risk_score'],
                mode='markers',
                name='Risk Events',
                marker=dict(
                    size=10,
                    color=df_trend['risk_score'],
                    colorscale=[[0, '#059669'], [0.5, '#2563EB'], [0.7, '#D97706'], [1, '#DC2626']],
                    showscale=True,
                    colorbar=dict(title='Risk Score'),
                    line=dict(width=1, color='#1F2937')
                ),
                text=df_trend['cve_id'],
                hovertemplate='<b>%{text}</b><br>Risk: %{y:.1f}<br>Time: %{x}<extra></extra>'
            ))
            
            fig_trend.add_hline(y=85, line_dash="dash", line_color="#DC2626", 
                               annotation_text="Critical", annotation_position="right",
                               annotation_font_color='#DC2626')
            
            fig_trend.update_layout(
                title='⏱️ Risk Score Timeline (Last Hour)',
                xaxis_title='Detection Time',
                yaxis_title='Risk Score',
                paper_bgcolor='#FAF8F5',
                plot_bgcolor='#FAF8F5',
                font=dict(color='#1F2937'),
                title_font_color='#4C1D95',
                xaxis=dict(
                    tickfont=dict(color='#1F2937'),
                    gridcolor='#E5E7EB'
                ),
                yaxis=dict(
                    tickfont=dict(color='#1F2937'),
                    gridcolor='#E5E7EB',
                    range=[0, 105]
                ),
                showlegend=False,
                margin=dict(l=10, r=10, t=50, b=30)
            )
            st.plotly_chart(fig_trend, use_container_width=True)
        else:
            st.info("Not enough timeline data. Need 2+ events in the last hour.")
    
    with col_chart4:
        # Vendor Risk Summary
        if not df_vendors.empty:
            fig_vendor = px.bar(
                df_vendors,
                x='vendor',
                y='critical_count',
                color='avg_risk',
                title='🏢 Vendor Risk Summary (Critical Events)',
                labels={
                    'vendor': 'Vendor',
                    'critical_count': 'Critical Events',
                    'avg_risk': 'Avg Risk'
                },
                text='exploited_count',
                color_continuous_scale='RdYlBu_r'
            )
            fig_vendor.update_traces(
                texttemplate='%{text} exploited',
                textposition='outside',
                textfont=dict(color='#1F2937', size=11)
            )
            fig_vendor.update_layout(
                paper_bgcolor='#FAF8F5',
                plot_bgcolor='#FAF8F5',
                font=dict(color='#1F2937'),
                title_font_color='#4C1D95',
                xaxis=dict(
                    tickfont=dict(color='#1F2937', size=11),
                    title_font=dict(color='#1F2937'),
                    gridcolor='#E5E7EB'
                ),
                yaxis=dict(
                    tickfont=dict(color='#1F2937'),
                    title_font=dict(color='#1F2937'),
                    gridcolor='#E5E7EB'
                ),
                margin=dict(l=10, r=10, t=50, b=30)
            )
            st.plotly_chart(fig_vendor, use_container_width=True)
        else:
            st.info("No vendor data available.")

# ==================== LIVE ALERT FEED ====================

st.markdown("### 🔴 Live Alert Feed")

if not df_alerts.empty:
    for _, alert in df_alerts.head(10).iterrows():
        risk = alert['risk_score']
        detected = alert['detected_at'].strftime('%H:%M:%S') if pd.notna(alert['detected_at']) else 'N/A'
        
        if risk >= 85:
            st.markdown(f"""
                <div class="urgent-alert">
                    <b>🚨 CRITICAL ALERT</b> | {detected}<br>
                    <b>Asset:</b> {alert['asset_id']} | <b>CVE:</b> {alert['cve_id']}<br>
                    <b>Risk Score:</b> {risk:.1f} | <b>Priority:</b> {alert['patch_priority']}
                </div>
            """, unsafe_allow_html=True)
        elif risk >= 70:
            st.markdown(f"""
                <div class="high-alert">
                    <b>⚠️ HIGH RISK</b> | {detected}<br>
                    <b>Asset:</b> {alert['asset_id']} | <b>CVE:</b> {alert['cve_id']}<br>
                    <b>Risk Score:</b> {risk:.1f}
                </div>
            """, unsafe_allow_html=True)
        elif risk >= 50:
            st.markdown(f"""
                <div class="medium-alert">
                    <b>ℹ️ MEDIUM RISK</b> | {detected}<br>
                    <b>Asset:</b> {alert['asset_id']} | <b>CVE:</b> {alert['cve_id']}<br>
                    <b>Risk Score:</b> {risk:.1f}
                </div>
            """, unsafe_allow_html=True)
else:
    st.info("No alerts triggered yet. Waiting for high-risk events...")

# ==================== DATA TABLE — FIXED LIGHT MODE ====================
if not df_risk.empty:
    st.markdown("### 📋 Recent Risk Events")
    
    # Prepare display dataframe
    display_df = df_risk.copy()
    display_df['detected_at'] = display_df['detected_at'].dt.strftime('%H:%M:%S')
    display_df['risk_score_fmt'] = display_df['risk_score'].round(2)
    display_df['cvss_score_fmt'] = display_df['cvss_score'].round(2)
    display_df['epss_score_fmt'] = display_df['epss_score'].round(4)
    
    table_df = display_df[['detected_at', 'asset_id', 'cve_id', 'risk_score_fmt', 
                           'patch_priority', 'cvss_score_fmt', 'epss_score_fmt']].copy()
    table_df.columns = ['Time', 'Asset', 'CVE', 'Risk Score', 'Priority', 'CVSS', 'EPSS']
    
    def color_risk(val):
        val = float(val)
        if val >= 85:
            return 'background-color: #FEE2E2; color: #DC2626; font-weight: bold'
        elif val >= 70:
            return 'background-color: #FEF3C7; color: #D97706; font-weight: bold'
        elif val >= 50:
            return 'background-color: #DBEAFE; color: #2563EB'
        return 'background-color: #D1FAE5; color: #059669'
    
    # FIX: Set explicit dark text + transparent bg on ALL cells first.
    # This prevents Streamlit's theme from injecting white text on unstyled cells.
    styled_df = (table_df
        .style
        .set_properties(**{'color': '#1f2937', 'background-color': 'transparent'})
        .map(color_risk, subset=['Risk Score'])
    )
    
    st.dataframe(styled_df, use_container_width=True, hide_index=True)
# ==================== AUTO REFRESH ====================

if auto_refresh and not df_risk.empty:
    time.sleep(5)
    st.rerun()

# ==================== FOOTER ====================

st.markdown("""
    <hr style='border: 1px solid #B8A9E0;'>
    <p style='text-align: center; color: #7A6BC4; font-size: 0.8rem;'>
        Cyber Threat Intelligence Platform | Batch + Streaming + Micro-Batch<br>
        <span style='color: #B8A9E0;'>Built with Streamlit • PostgreSQL • Kafka • Python</span>
    </p>
""", unsafe_allow_html=True)