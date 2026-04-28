import streamlit as st
import sqlite3
import pandas as pd
import sys
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go
import numpy as np

# Add project root to path to import config
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from src.utils.config import DB_PATH

# 1. Page Config
st.set_page_config(page_title="Sentrix SOC Command Center", layout="wide", page_icon="🛡️")

# 2. Custom CSS
st.markdown("""
    <style>
    .stApp {
        background-color: #050811;
        color: #e2e8f0;
    }
    div[data-testid="stMetricValue"] {
        font-size: 2.5rem;
        color: #00e5ff;
        text-shadow: 0 0 10px rgba(0,229,255,0.3);
    }
    div[data-testid="stMetricLabel"] {
        font-size: 1.1rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    div[data-testid="metric-container"] {
        background: rgba(20, 25, 40, 0.6);
        border: 1px solid rgba(0, 229, 255, 0.2);
        padding: 20px;
        border-radius: 12px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    }
    h1, h2, h3 { color: #fff; }
    </style>
    """, unsafe_allow_html=True)

def load_data():
    if not DB_PATH.exists():
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT * FROM requests ORDER BY timestamp DESC"
    df = pd.read_sql(query, conn)
    conn.close()
    
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Mock Geo IP generator for demonstration purposes
        np.random.seed(42)
        unique_ips = df['client_ip'].unique()
        ip_map = {ip: (np.random.uniform(20, 50), np.random.uniform(-120, -70)) for ip in unique_ips} # US bounds
        df['lat'] = df['client_ip'].map(lambda x: ip_map[x][0])
        df['lon'] = df['client_ip'].map(lambda x: ip_map[x][1])
    return df

st.title("🛡️ Sentrix SOC Dashboard")
st.markdown("Industry-standard monitoring: Real-time Reverse Proxy Traffic & Advanced Threat Hunting.")

colA, colB = st.columns([0.8, 0.2])
with colB:
    if st.button("↻ Refresh Live Stream", use_container_width=True):
        st.rerun()

df = load_data()

with st.expander("📘 How to Use & Test the Proxy WAF"):
    st.markdown("""
    ### Testing the Web Application Firewall
    The Sentrix FastAPI is now acting as a direct Reverse Proxy on Port 8000. It intercepts all traffic.
    
    1. **Target the WAF:** Make requests directly to `http://localhost:8000` (e.g., `http://localhost:8000/login`).
    2. **Trigger an Attack:** Send payloads: `admin' OR 1=1 --` for SQLi, etc. The proxy will cut the connection before it reaches the backend.
    """)

if df.empty:
    st.info("No logs found. Send some traffic through the Reverse Proxy API (Port 8000).")
else:
    # Top Metrics
    total_reqs = len(df)
    blocked = len(df[df['action'] == 'block'])
    flagged = len(df[df['action'] == 'flag'])
    allowed = len(df[df['action'] == 'allow'])
    
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.metric("Total Requests Ingested", total_reqs)
    with col2: st.metric("Traffic Allowed (Throughput)", allowed)
    with col3: st.metric("Threat Warnings Tagged", flagged)
    with col4: st.metric("Threats Blocked (Prevented)", blocked, delta_color="inverse")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🌐 Threat Origins (Geo-IP)", "📉 Attack Analytics", "📄 Raw Access Logs"])
    
    with tab1:
        st.subheader("Global Threat Origins (Simulated for Demo)")
        if not df[df['action'] == 'block'].empty:
            threats = df[df['action'] != 'allow']
            fig = px.scatter_geo(threats, lat='lat', lon='lon', color='final_label',
                                 hover_name='client_ip', size_max=15, 
                                 title="Blocked & Flagged Traffic by Geo-Location",
                                 template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("No active threats mapping available.")

    with tab2:
        col_c1, col_c2 = st.columns(2)
        
        with col_c1:
            st.subheader("Threat Volumes Over Time")
            # Resample by hour/minute
            time_df = df.copy()
            time_df.set_index('timestamp', inplace=True)
            counts = time_df.resample('1T')['action'].count().reset_index()
            fig2 = px.line(counts, x='timestamp', y='action', title='Requests Per Minute (RPM)',
                           labels={'action': 'Request Count'}, template="plotly_dark")
            fig2.update_traces(line_color="#00e5ff", line_width=3)
            st.plotly_chart(fig2, use_container_width=True)
            
        with col_c2:
            st.subheader("Attack Signatures Composition")
            threats_only = df[df['action'] != 'allow']
            if not threats_only.empty:
                fig3 = px.pie(threats_only, names='final_label', title="Distribution of Detected Attack Classes",
                              color_discrete_sequence=px.colors.sequential.RdBu, template="plotly_dark")
                fig3.update_traces(hole=.4)
                st.plotly_chart(fig3, use_container_width=True)
            else:
                st.info("No payload signatures blocked yet.")

    with tab3:
        st.subheader("Actionable Raw Data")
        display_df = df[['timestamp', 'client_ip', 'method', 'path', 'action', 'final_label', 'decision_reason']]
        def highlight_action(s):
            if s['action'] == 'block': return ['background-color: rgba(255, 51, 102, 0.2)'] * len(s)
            elif s['action'] == 'flag': return ['background-color: rgba(255, 193, 7, 0.2)'] * len(s)
            else: return [''] * len(s)
        styled_df = display_df.style.apply(highlight_action, axis=1)
        st.dataframe(styled_df, use_container_width=True, height=400)
