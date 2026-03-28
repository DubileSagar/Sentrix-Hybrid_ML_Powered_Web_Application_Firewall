import streamlit as st
import sqlite3
import pandas as pd
import sys
from pathlib import Path

# Add project root to path to import config
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from src.utils.config import DB_PATH

st.set_page_config(page_title="Sentrix WAF Dashboard", layout="wide", page_icon="🛡️")

def load_data():
    if not DB_PATH.exists():
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT * FROM requests ORDER BY timestamp DESC"
    df = pd.read_sql(query, conn)
    conn.close()
    return df

st.title("🛡️ Sentrix WAF Monitoring Dashboard")
st.markdown("Monitor real-time HTTP traffic and ML-powered threat detection.")

if st.button("Refresh Data"):
    st.rerun()

df = load_data()

if df.empty:
    st.info("No logs found. Send some traffic through the WAF API to see data here.")
else:
    # 1. Metrics
    total_reqs = len(df)
    blocked = len(df[df['action'] == 'block'])
    flagged = len(df[df['action'] == 'flag'])
    allowed = len(df[df['action'] == 'allow'])
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", total_reqs)
    col2.metric("Allowed Traffic", allowed)
    col3.metric("Flagged Warnings", flagged)
    col4.metric("Blocked Threats", blocked)
    
    st.markdown("---")
    
    # 2. Charts
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        st.subheader("Action Distribution")
        action_counts = df['action'].value_counts()
        st.bar_chart(action_counts)

    with chart_col2:
        st.subheader("Attack Classifications (Blocks & Flags)")
        threats_df = df[df['action'] != 'allow']
        if not threats_df.empty:
            label_counts = threats_df['final_label'].value_counts()
            st.bar_chart(label_counts)
        else:
            st.info("No threats detected yet!")
            
    st.markdown("---")
    
    # 3. Data Table
    st.subheader("Recent Requests Log")
    display_df = df[['timestamp', 'client_ip', 'method', 'path', 'action', 'final_label', 'ml_confidence', 'decision_reason']]
    st.dataframe(display_df, use_container_width=True)
