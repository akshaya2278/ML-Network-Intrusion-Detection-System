🛡️ Machine-Learning Network Intrusion Detection System (M-NIDS)
M-NIDS is an intelligent, end-to-end cybersecurity agent designed to analyze network traffic, detect malicious activity, and flag potential zero-day threats. It leverages the NSL-KDD dataset and uses an ensemble of machine learning models to provide real-time risk scoring, attack classification, and automated alerts via an interactive monitoring dashboard.

✨ Key Features
Multi-Stage Detection Engine:

Binary Classification (Random Forest): Accurately filters normal traffic from suspicious activity.

Multi-Class Classification (XGBoost): Categorizes known malicious traffic into specific attack families (DoS, Probe, R2L, U2R).

Zero-Day Anomaly Detection (Isolation Forest): An unsupervised model trained only on normal traffic to catch novel, unseen attack patterns.

Intelligent Risk Scoring: Combines binary confidence and anomaly scores into a unified 0-1 risk metric, generating contextual alerts for High and Medium risk connections.

Interactive Dashboard: A locally hosted Streamlit application for monitoring traffic stats, viewing risk distributions, and reviewing live security alerts.

Automated Data Pipeline: Programmatically downloads, cleans, scales, and encodes the NSL-KDD dataset with a built-in synthetic fallback if the network is offline.
