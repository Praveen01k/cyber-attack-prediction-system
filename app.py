"""
Cyber Attack Prediction System
Interactive Security Operations Center (SOC) Web Application
Built with Streamlit, Scikit-Learn, and Plotly.
"""

import sys
import os
import io
import json
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# Add src to sys.path
SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from predictor import CyberThreatPredictor
from preprocessing import ALL_FEATURE_ORDER, PROTOCOL_MAP, SERVICE_MAP, FLAG_MAP

# ----------------- PAGE CONFIG -----------------
st.set_page_config(
    page_title="Cyber Attack Prediction System | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------- CUSTOM CSS -----------------
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0px;
    }
    .sub-header {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
    }
    .alert-box {
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 15px;
        font-weight: 600;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 18px;
        border-radius: 6px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- INITIALIZE PREDICTOR -----------------
@st.cache_resource
def get_predictor():
    return CyberThreatPredictor()

predictor = get_predictor()

# ----------------- PRESET ATTACK SCENARIOS -----------------
PRESETS = {
    "Custom / Manual Input": None,
    "Normal Web Browsing (Safe HTTP)": {
        'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
        'duration': 2, 'src_bytes': 350, 'dst_bytes': 2800,
        'wrong_fragment': 0, 'urgent': 0, 'num_failed_logins': 0,
        'logged_in': 1, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'count': 8, 'srv_count': 7,
        'serror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
        'dst_host_count': 120, 'dst_host_srv_count': 180,
        'dst_host_same_srv_rate': 0.95, 'dst_host_diff_srv_rate': 0.03,
        'dst_host_serror_rate': 0.0
    },
    "SYN Flood DoS Attack (High Packet Velocity)": {
        'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
        'duration': 0, 'src_bytes': 0, 'dst_bytes': 0,
        'wrong_fragment': 0, 'urgent': 0, 'num_failed_logins': 0,
        'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'count': 450, 'srv_count': 380,
        'serror_rate': 1.0, 'same_srv_rate': 0.98, 'diff_srv_rate': 0.02,
        'dst_host_count': 255, 'dst_host_srv_count': 12,
        'dst_host_same_srv_rate': 0.05, 'dst_host_diff_srv_rate': 0.85,
        'dst_host_serror_rate': 0.98
    },
    "Port Scanning Probe (Nmap Reconnaissance)": {
        'protocol_type': 'tcp', 'service': 'other', 'flag': 'REJ',
        'duration': 1, 'src_bytes': 40, 'dst_bytes': 0,
        'wrong_fragment': 0, 'urgent': 0, 'num_failed_logins': 0,
        'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'count': 220, 'srv_count': 4,
        'serror_rate': 0.35, 'same_srv_rate': 0.12, 'diff_srv_rate': 0.88,
        'dst_host_count': 255, 'dst_host_srv_count': 6,
        'dst_host_same_srv_rate': 0.04, 'dst_host_diff_srv_rate': 0.92,
        'dst_host_serror_rate': 0.45
    },
    "SSH Brute Force Attack (R2L Unauthorized Access)": {
        'protocol_type': 'tcp', 'service': 'ssh', 'flag': 'SF',
        'duration': 18, 'src_bytes': 650, 'dst_bytes': 1400,
        'wrong_fragment': 0, 'urgent': 0, 'num_failed_logins': 4,
        'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'count': 12, 'srv_count': 9,
        'serror_rate': 0.0, 'same_srv_rate': 0.85, 'diff_srv_rate': 0.05,
        'dst_host_count': 45, 'dst_host_srv_count': 40,
        'dst_host_same_srv_rate': 0.80, 'dst_host_diff_srv_rate': 0.10,
        'dst_host_serror_rate': 0.0
    },
    "Buffer Overflow Exploit (U2R Root Compromise)": {
        'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF',
        'duration': 55, 'src_bytes': 1850, 'dst_bytes': 4200,
        'wrong_fragment': 0, 'urgent': 1, 'num_failed_logins': 0,
        'logged_in': 1, 'num_compromised': 3, 'root_shell': 1,
        'su_attempted': 1, 'num_root': 4, 'count': 2, 'srv_count': 2,
        'serror_rate': 0.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
        'dst_host_count': 15, 'dst_host_srv_count': 15,
        'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
        'dst_host_serror_rate': 0.0
    }
}

# ----------------- SIDEBAR CONTROLS -----------------
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("SOC Configuration")
    
    model_choice = st.selectbox(
        "🧠 Active Prediction Model",
        options=["Random Forest (Default)", "Support Vector Machine (SVM)"],
        index=0,
        help="Select between the two approved ML classification models."
    )
    model_type_key = 'svm' if "SVM" in model_choice else 'random_forest'
    
    st.divider()
    st.subheader("⚡ Threat Simulation Presets")
    selected_preset = st.selectbox(
        "Load Pre-Configured Attack Vector:",
        options=list(PRESETS.keys()),
        index=0
    )
    
    st.divider()
    st.markdown("""
    **Project Performa Info**
    - **Course Code:** 8CD7-50
    - **Group No:** 5
    - **Authors:** Ajay Saini & Praveen Sharma
    - **Guide:** Suman Kanta
    - **Branch:** CSE (Data Science), BKBIET
    """)

# ----------------- MAIN HEADER -----------------
st.markdown('<div class="main-header">🛡️ Cyber Attack Prediction System</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">AI-Powered Intrusion Detection, Anomaly Detection & Early Warning Response Engine | NSL-KDD & CICIDS2017 Architecture</div>',
    unsafe_allow_html=True
)

# ----------------- TABS -----------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🎯 Live Threat Predictor",
    "📂 Batch Network Log Scanner",
    "📊 Model Benchmark & Comparison",
    "📋 Incident Response Playbook",
    "🎓 Academic Documentation"
])

# ================= TAB 1: LIVE PREDICTOR =================
with tab1:
    st.subheader("Real-Time Network Packet Inspection")
    st.caption("Inspect live network connection parameters to classify benign vs. malicious traffic and trigger automated containment.")

    preset_values = PRESETS.get(selected_preset)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("#### 1. Protocol & Service Attributes")
        proto = st.selectbox(
            "Protocol Type",
            options=list(PROTOCOL_MAP.keys()),
            index=list(PROTOCOL_MAP.keys()).index(preset_values['protocol_type']) if preset_values else 0
        )
        service = st.selectbox(
            "Target Network Service",
            options=list(SERVICE_MAP.keys()),
            index=list(SERVICE_MAP.keys()).index(preset_values['service']) if preset_values else 0
        )
        flag = st.selectbox(
            "Connection Status Flag",
            options=list(FLAG_MAP.keys()),
            index=list(FLAG_MAP.keys()).index(preset_values['flag']) if preset_values else 0,
            help="SF: Normal connection, S0: SYN flood error, REJ: Connection rejected"
        )
        duration = st.number_input(
            "Connection Duration (seconds)",
            min_value=0, max_value=3600,
            value=preset_values['duration'] if preset_values else 2
        )
        src_bytes = st.number_input(
            "Source Bytes (Payload Out)",
            min_value=0, max_value=100000,
            value=preset_values['src_bytes'] if preset_values else 350
        )
        dst_bytes = st.number_input(
            "Destination Bytes (Payload In)",
            min_value=0, max_value=100000,
            value=preset_values['dst_bytes'] if preset_values else 2500
        )

    with col2:
        st.markdown("#### 2. Host Traffic Statistics")
        count = st.slider(
            "Connections to same host (Past 2s)",
            min_value=1, max_value=512,
            value=preset_values['count'] if preset_values else 10
        )
        srv_count = st.slider(
            "Connections to same service (Past 2s)",
            min_value=1, max_value=512,
            value=preset_values['srv_count'] if preset_values else 8
        )
        serror_rate = st.slider(
            "SYN Error Rate (% connections with errors)",
            min_value=0.0, max_value=1.0, step=0.01,
            value=float(preset_values['serror_rate']) if preset_values else 0.0
        )
        same_srv_rate = st.slider(
            "Same Service Rate",
            min_value=0.0, max_value=1.0, step=0.01,
            value=float(preset_values['same_srv_rate']) if preset_values else 0.95
        )
        diff_srv_rate = st.slider(
            "Different Service Rate (Scan indicator)",
            min_value=0.0, max_value=1.0, step=0.01,
            value=float(preset_values['diff_srv_rate']) if preset_values else 0.05
        )

    with col3:
        st.markdown("#### 3. Behavioral & Anomaly Indicators")
        num_failed_logins = st.number_input(
            "Failed Login Attempts",
            min_value=0, max_value=20,
            value=preset_values['num_failed_logins'] if preset_values else 0
        )
        logged_in = st.selectbox(
            "Authentication Successful (Logged In)",
            options=[1, 0],
            index=0 if (preset_values and preset_values['logged_in'] == 1) else (1 if preset_values else 0)
        )
        root_shell = st.selectbox(
            "Root Shell Obtained",
            options=[0, 1],
            index=1 if (preset_values and preset_values['root_shell'] == 1) else 0
        )
        su_attempted = st.selectbox(
            "su Root Attempted",
            options=[0, 1],
            index=1 if (preset_values and preset_values['su_attempted'] == 1) else 0
        )
        num_compromised = st.number_input(
            "Compromised Conditions Count",
            min_value=0, max_value=50,
            value=preset_values['num_compromised'] if preset_values else 0
        )
        num_root = st.number_input(
            "Root File Operations Count",
            min_value=0, max_value=50,
            value=preset_values['num_root'] if preset_values else 0
        )

    # Package input dictionary
    packet_input = {
        'protocol_type': proto,
        'service': service,
        'flag': flag,
        'duration': duration,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'wrong_fragment': preset_values['wrong_fragment'] if preset_values else 0,
        'urgent': preset_values['urgent'] if preset_values else 0,
        'num_failed_logins': num_failed_logins,
        'logged_in': logged_in,
        'num_compromised': num_compromised,
        'root_shell': root_shell,
        'su_attempted': su_attempted,
        'num_root': num_root,
        'count': count,
        'srv_count': srv_count,
        'serror_rate': serror_rate,
        'same_srv_rate': same_srv_rate,
        'diff_srv_rate': diff_srv_rate,
        'dst_host_count': preset_values['dst_host_count'] if preset_values else 150,
        'dst_host_srv_count': preset_values['dst_host_srv_count'] if preset_values else 140,
        'dst_host_same_srv_rate': preset_values['dst_host_same_srv_rate'] if preset_values else 0.90,
        'dst_host_diff_srv_rate': preset_values['dst_host_diff_srv_rate'] if preset_values else 0.05,
        'dst_host_serror_rate': preset_values['dst_host_serror_rate'] if preset_values else 0.0
    }

    st.markdown("<br>", unsafe_allow_html=True)
    predict_btn = st.button("🚀 Analyze Packet & Predict Threat", type="primary", use_container_width=True)

    if predict_btn or selected_preset != "Custom / Manual Input":
        result = predictor.predict_single(packet_input, model_type=model_type_key)
        mit = result['mitigation']
        
        st.markdown("---")
        st.markdown("### 🔍 Threat Detection Results")

        # Early warning alert banner
        banner_bg = "#064e3b" if mit['severity'] == "LOW" else ("#78350f" if mit['severity'] == "MEDIUM" else "#7f1d1d")
        banner_border = mit['color']
        st.markdown(f"""
        <div style="background-color: {banner_bg}; border-left: 6px solid {banner_border}; border-radius: 8px; padding: 14px 18px; margin-bottom: 20px;">
            <div style="font-size: 1.15rem; font-weight: 700; color: #fff;">{mit['early_warning']}</div>
            <div style="color: #e2e8f0; font-size: 0.9rem; margin-top: 4px;">{mit['description']}</div>
        </div>
        """, unsafe_allow_html=True)

        # KPI Metrics
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Predicted Traffic Class", result['predicted_class'])
        with m2:
            st.metric("Threat Severity", mit['severity'])
        with m3:
            st.metric("Confidence Score", f"{result['confidence'] * 100:.1f}%")
        with m4:
            st.metric("Risk Score", f"{mit['risk_score']} / 100")

        # Visualizations & Mitigation side-by-side
        vcol1, vcol2 = st.columns([1.2, 1])
        
        with vcol1:
            st.markdown("#### Threat Probability Distribution")
            probs_df = pd.DataFrame(list(result['probability_breakdown'].items()), columns=['Class', 'Probability'])
            fig_prob = px.bar(
                probs_df, x='Probability', y='Class', orientation='h',
                color='Probability', color_continuous_scale='Reds',
                range_x=[0, 1.0], text_auto='.1%'
            )
            fig_prob.update_layout(height=280, margin=dict(l=0, r=0, t=20, b=20), template="plotly_dark")
            st.plotly_chart(fig_prob, use_container_width=True)

        with vcol2:
            st.markdown("#### Automated SOC Incident Mitigation")
            st.info(f"**Recommended Immediate Action:**\n\n{mit['immediate_action']}")
            st.markdown("**Suggested Firewall Defense Script:**")
            st.code(mit['firewall_rule'], language="bash")

# ================= TAB 2: BATCH SCANNER =================
with tab2:
    st.subheader("Batch Network Traffic Analyzer")
    st.caption("Upload network capture logs or CSV datasets to detect anomalies across thousands of connection records simultaneously.")

    bcol1, bcol2 = st.columns([2, 1])
    with bcol1:
        uploaded_file = st.file_uploader("Upload Network CSV Log File", type=["csv"])
    with bcol2:
        st.markdown("<br>", unsafe_allow_html=True)
        load_sample = st.button("📥 Load Benchmark Sample Log (100 packets)", use_container_width=True)

    sample_batch_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sample_network_traffic.csv')

    target_df = None
    if uploaded_file is not None:
        target_df = pd.read_csv(uploaded_file)
    elif load_sample and os.path.exists(sample_batch_path):
        target_df = pd.read_csv(sample_batch_path)

    if target_df is not None:
        st.success(f"Loaded {len(target_df)} connection logs. Executing predictive analysis with {model_choice}...")
        
        with st.spinner("Classifying packets and calculating threat indices..."):
            analyzed_df = predictor.predict_batch(target_df, model_type=model_type_key)

        # Batch Metrics
        total_records = len(analyzed_df)
        normal_count = (analyzed_df['predicted_attack'] == 'Normal').sum()
        malicious_count = total_records - normal_count
        malicious_pct = (malicious_count / total_records) * 100

        bm1, bm2, bm3, bm4 = st.columns(4)
        with bm1:
            st.metric("Total Connections Analyzed", f"{total_records:,}")
        with bm2:
            st.metric("Benign / Normal Traffic", f"{normal_count:,}")
        with bm3:
            st.metric("Threats Flagged", f"{malicious_count:,}", delta=f"{malicious_pct:.1f}% Threat Ratio", delta_color="inverse")
        with bm4:
            critical_count = (analyzed_df['severity'] == 'CRITICAL').sum()
            st.metric("Critical Compromises", f"{critical_count:,}", delta="Urgent Containment" if critical_count > 0 else "Clear", delta_color="inverse")

        st.markdown("---")
        chart_col1, chart_col2 = st.columns([1, 1.3])
        
        with chart_col1:
            st.markdown("#### Attack Class Breakdown")
            class_counts = analyzed_df['predicted_attack'].value_counts().reset_index()
            class_counts.columns = ['Attack Type', 'Count']
            fig_donut = px.pie(
                class_counts, values='Count', names='Attack Type',
                hole=0.45,
                color_discrete_sequence=px.colors.sequential.RdBu_r
            )
            fig_donut.update_layout(height=320, margin=dict(l=0, r=0, t=20, b=20), template="plotly_dark")
            st.plotly_chart(fig_donut, use_container_width=True)

        with chart_col2:
            st.markdown("#### Threat Severity Distribution")
            sev_counts = analyzed_df['severity'].value_counts().reset_index()
            sev_counts.columns = ['Severity', 'Count']
            color_map = {'LOW': '#10b981', 'MEDIUM': '#f59e0b', 'HIGH': '#ef4444', 'CRITICAL': '#7f1d1d'}
            fig_bar = px.bar(
                sev_counts, x='Severity', y='Count',
                color='Severity', color_discrete_map=color_map,
                text='Count'
            )
            fig_bar.update_layout(height=320, margin=dict(l=0, r=0, t=20, b=20), template="plotly_dark")
            st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("#### 🚨 Flagged Suspicious & Malicious Connections")
        flagged_df = analyzed_df[analyzed_df['predicted_attack'] != 'Normal']
        if len(flagged_df) > 0:
            st.dataframe(
                flagged_df[['predicted_attack', 'severity', 'risk_score', 'confidence', 'protocol_type', 'service', 'flag', 'serror_rate', 'num_failed_logins']].head(50),
                use_container_width=True
            )
        else:
            st.success("No malicious packets detected in this dataset. All connections are classified as Normal.")

        # Download Report
        csv_buffer = io.StringIO()
        analyzed_df.to_csv(csv_buffer, index=False)
        st.download_button(
            label="📥 Download Analyzed SOC Security Report (.csv)",
            data=csv_buffer.getvalue(),
            file_name="cyber_security_soc_report.csv",
            mime="text/csv"
        )
    else:
        st.info("Upload a CSV file or click 'Load Benchmark Sample Log' to initiate batch analysis.")

# ================= TAB 3: MODEL BENCHMARK =================
with tab3:
    st.subheader("Model Benchmark: Random Forest vs. Support Vector Machine")
    st.caption("Empirical performance evaluation on the NSL-KDD / CICIDS2017 benchmark dataset.")

    metrics = predictor.metrics
    if metrics:
        rf_meta = metrics.get('random_forest', {})
        svm_meta = metrics.get('svm', {})

        col_rf, col_svm = st.columns(2)
        
        with col_rf:
            st.markdown("### 🌲 Random Forest Classifier")
            rm1, rm2, rm3, rm4 = st.columns(4)
            rm1.metric("Accuracy", f"{rf_meta.get('accuracy', 0)*100:.1f}%")
            rm2.metric("Precision", f"{rf_meta.get('precision', 0)*100:.1f}%")
            rm3.metric("Recall", f"{rf_meta.get('recall', 0)*100:.1f}%")
            rm4.metric("F1-Score", f"{rf_meta.get('f1_score', 0)*100:.1f}%")

            # RF Confusion Matrix
            rf_cm = np.array(rf_meta.get('confusion_matrix', []))
            if rf_cm.size > 0:
                fig_rf_cm = px.imshow(
                    rf_cm,
                    labels=dict(x="Predicted Class", y="Actual Class", color="Count"),
                    x=metrics['classes'], y=metrics['classes'],
                    text_auto=True, color_continuous_scale="Viridis",
                    title="Random Forest Confusion Matrix"
                )
                fig_rf_cm.update_layout(height=340, template="plotly_dark", margin=dict(l=0, r=0, t=40, b=20))
                st.plotly_chart(fig_rf_cm, use_container_width=True)

        with col_svm:
            st.markdown("### ⚡ Support Vector Machine (SVM)")
            sm1, sm2, sm3, sm4 = st.columns(4)
            sm1.metric("Accuracy", f"{svm_meta.get('accuracy', 0)*100:.1f}%")
            sm2.metric("Precision", f"{svm_meta.get('precision', 0)*100:.1f}%")
            sm3.metric("Recall", f"{svm_meta.get('recall', 0)*100:.1f}%")
            sm4.metric("F1-Score", f"{svm_meta.get('f1_score', 0)*100:.1f}%")

            # SVM Confusion Matrix
            svm_cm = np.array(svm_meta.get('confusion_matrix', []))
            if svm_cm.size > 0:
                fig_svm_cm = px.imshow(
                    svm_cm,
                    labels=dict(x="Predicted Class", y="Actual Class", color="Count"),
                    x=metrics['classes'], y=metrics['classes'],
                    text_auto=True, color_continuous_scale="Plasma",
                    title="SVM Confusion Matrix"
                )
                fig_svm_cm.update_layout(height=340, template="plotly_dark", margin=dict(l=0, r=0, t=40, b=20))
                st.plotly_chart(fig_svm_cm, use_container_width=True)

        st.markdown("---")
        st.markdown("### 🏆 Top Network Feature Importances (Gini Impurity)")
        feat_df = pd.DataFrame(metrics.get('feature_importances', [])[:12])
        if not feat_df.empty:
            fig_feat = px.bar(
                feat_df, x='importance', y='feature', orientation='h',
                color='importance', color_continuous_scale='Blues',
                title="Top Predictive Features for Cyber Attack Classification"
            )
            fig_feat.update_layout(height=380, template="plotly_dark", yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_feat, use_container_width=True)
    else:
        st.warning("Model metrics file not found. Please run `src/train.py` first.")

# ================= TAB 4: INCIDENT PLAYBOOK =================
with tab4:
    st.subheader("SOC Incident Response & Defense Playbook")
    st.markdown("""
    When an intrusion or anomalous pattern is predicted by the machine learning engine, 
    SOC analysts follow standard operational containment procedures based on the MITRE ATT&CK framework:
    """)

    p1, p2 = st.columns(2)
    with p1:
        with st.expander("🔥 1. Denial of Service (DoS) Containment", expanded=True):
            st.markdown("""
            - **Detection Signature:** High connection count (`count` > 300), high SYN error rate (`serror_rate` > 0.8), zero or minimal return payload.
            - **Attack Types:** SYN Flood, Smurf, Neptune, Ping of Death.
            - **Immediate Mitigation:**
              1. Enable kernel SYN Cookies (`sysctl -w net.ipv4.tcp_syncookies=1`).
              2. Apply rate-limiting on incoming SYN handshakes.
              3. Route affected ingress traffic through Cloudflare / AWS Shield DDoS mitigation scrubbers.
            """)
        
        with st.expander("🔎 2. Probe / Port Scanning Neutralization", expanded=True):
            st.markdown("""
            - **Detection Signature:** Elevated different service rate (`diff_srv_rate` > 0.7), rejected connections (`flag` = REJ), scanning multiple ports in milliseconds.
            - **Attack Types:** Nmap Stealth SYN scan, PortSweep, Satan.
            - **Immediate Mitigation:**
              1. Drop ICMP ping responses from external untrusted subnets.
              2. Add aggressive scanning source IPs to dynamic iptables blacklists.
              3. Configure honey-ports to trap reconnaissance bots.
            """)

    with p2:
        with st.expander("🔑 3. Remote-to-Local (R2L) Brute Force Defense", expanded=True):
            st.markdown("""
            - **Detection Signature:** Multiple consecutive failed logins (`num_failed_logins` >= 3), persistent connections to SSH (port 22) or FTP (port 21).
            - **Attack Types:** Password guessing, Hydra dictionary attacks, SSH credential stuffing.
            - **Immediate Mitigation:**
              1. Instantly trigger account temporary lockout (30-minute freeze).
              2. Mandate Hardware MFA (FIDO2 / TOTP).
              3. Enable Fail2Ban to ban offending IPs after 3 failed password trials.
            """)

        with st.expander("💀 4. User-to-Root (U2R) Privilege Escalation Containment", expanded=True):
            st.markdown("""
            - **Detection Signature:** Unauthorized root shell invocation (`root_shell` = 1), unexpected `su` operations, abnormal payload bytes indicative of shellcode / buffer overflow.
            - **Attack Types:** Buffer overflows, dirty COW, kernel exploits.
            - **Immediate Mitigation:**
              1. **Host Isolation:** Sever network interfaces to stop lateral movement.
              2. Revoke sudo access and kill active bash/sh root process trees.
              3. Capture volatile memory dump for forensic analysis.
            """)

# ================= TAB 5: ACADEMIC METADATA =================
with tab5:
    st.subheader("B.Tech Capstone Project Specifications")
    st.markdown("""
    This project is submitted in partial fulfillment of the requirements for the degree of **Bachelor of Technology in Computer Science and Engineering (Specialization: Data Science)**.
    """)

    mcol1, mcol2 = st.columns(2)
    with mcol1:
        st.markdown("""
        #### 📋 Project Performa
        - **Project Title:** Cyber Attack Prediction System
        - **Course Code:** 8CD7-50
        - **Group No:** 5
        - **Institution:** BK Birla Institute of Engineering & Technology, Pilani
        - **University:** Bikaner Technical University (BTU)
        - **Project Guide:** Suman Kanta
        - **Approval Date:** 13-03-2026
        """)

    with mcol2:
        st.markdown("""
        #### 👥 Project Authors
        1. **Ajay Saini** (BTU Roll No: `22EBKDS003`)
           - Branch: CSE (Data Science)
           - Email: ajayysaiini@gmail.com
        2. **Praveen Sharma** (BTU Roll No: `22EBKDS043`)
           - Branch: CSE (Data Science)
           - Email: Praveensharma01k@gmail.com
        """)

    st.markdown("---")
    st.markdown("#### 📚 Formal Academic References (Cited in Proposal)")
    st.markdown("""
    1. **Sommer, R., & Paxson, V.** (2010). *Machine Learning for Network Intrusion Detection: Challenges and Future Directions*. IEEE Symposium on Security and Privacy.
    2. **Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A.** (2009). *A Detailed Analysis of the KDD CUP 99 Data Set*. IEEE Symposium on Computational Intelligence for Security and Defense Applications.
    3. **Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A.** (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP.
    4. **Goodfellow, I., Bengio, Y., & Courville, A.** (2016). *Deep Learning*. MIT Press.
    """)
