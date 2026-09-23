import streamlit as st
import pandas as pd
import plotly.express as px
from data_loader import load_and_prep_data
from agent import NetworkIntrusionAgent

# 1. Update the browser tab title
st.set_page_config(page_title="M-NIDS Dashboard", layout="wide")

@st.cache_resource
def init_agent():
    df_train, _ = load_and_prep_data()
    agent = NetworkIntrusionAgent()
    agent.train(df_train)
    return agent

# 2. Update the main dashboard header
st.title("🛡️ Machine-Learning Network Intrusion Detection System")

agent = init_agent()

uploaded_file = st.file_uploader("Upload Network Traffic CSV (NSL-KDD format)", type="csv")

if uploaded_file is not None:
    df_input = pd.read_csv(uploaded_file)
else:
    st.info("No file uploaded. Using default test sample.")
    try:
        df_input = pd.read_csv("sample_dashboard_data.csv")
    except FileNotFoundError:
        st.warning("Please run `python evaluate.py` first to generate the sample data.")
        st.stop()

with st.spinner("Analyzing traffic..."):
    # Drop previous analysis columns if re-uploading
    clean_df = df_input[[c for c in df_input.columns if c not in ['suspicious_prob', 'anomaly_score', 'risk_score', 'risk_level', 'predicted_attack', 'alert']]]
    results = agent.predict(clean_df)

# Stats Row
total_traffic = len(results)
suspicious_count = len(results[results['risk_level'].isin(['High', 'Medium'])])
high_risk = len(results[results['risk_level'] == 'High'])

col1, col2, col3 = st.columns(3)
col1.metric("Total Connections Analyzed", total_traffic)
col2.metric("Suspicious Connections", suspicious_count, f"{(suspicious_count/total_traffic)*100:.1f}%")
col3.metric("High Risk Alerts", high_risk)

# Charts Row
col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    st.subheader("Traffic Risk Distribution")
    fig1 = px.pie(results, names='risk_level', color='risk_level', 
                  color_discrete_map={'Low':'green', 'Medium':'orange', 'High':'red'})
    st.plotly_chart(fig1, use_container_width=True)

with col_chart2:
    st.subheader("Detected Attack Types")
    attack_counts = results[results['predicted_attack'] != 'normal']['predicted_attack'].value_counts().reset_index()
    attack_counts.columns = ['Attack Type', 'Count']
    fig2 = px.bar(attack_counts, x='Attack Type', y='Count', color='Attack Type')
    st.plotly_chart(fig2, use_container_width=True)

# Live Alerts Feed
st.subheader("🚨 Active Threat Alerts")
alerts = results.dropna(subset=['alert'])['alert'].tolist()
if alerts:
    for alert in alerts[:20]: # Show top 20
        st.error(alert)
else:
    st.success("No active threats detected.")

# Traffic Table
st.subheader("Detailed Traffic Log")
st.dataframe(
    results[['duration', 'protocol_type', 'service', 'src_bytes', 'dst_bytes', 
             'risk_score', 'risk_level', 'predicted_attack']].style.apply(
        lambda x: ['background-color: #ffcccc' if x['risk_level'] == 'High' 
                   else 'background-color: #ffe5cc' if x['risk_level'] == 'Medium' 
                   else '' for _ in x], axis=1
    ),
    use_container_width=True
)