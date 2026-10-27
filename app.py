"""
app.py - PhishGuard Enterprise URL Threat Intelligence
A clean, modern, and production-grade cybersecurity web application powered by
Multi-Vector Network & Infrastructure Telemetry, Structural Heuristics, and Google Gemini AI.
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, Optional

import streamlit as st
from threat_engine import execute_threat_intelligence_pipeline


st.set_page_config(
    page_title="PhishGuard | URL Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


CLEAN_CSS = """
<style>
html, body, [class*="css"] {
    font-family: Arial, Roboto, sans-serif;
    color: #202124;
}

.stApp, [data-testid="stAppViewContainer"] {
    background: #fff;
    color: #202124;
}

[data-testid="stHeader"] {
    background: #fff;
}

.stDeployButton,
.stAppDeployButton,
[data-testid="stDeployButton"],
[data-testid="stAppDeployButton"],
button[aria-label="Deploy"] {
    display: none !important;
}

[data-testid="stSidebar"] {
    background: #f8f9fa;
    border-right: 1px solid #dadce0;
}

[data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
[data-testid="stSidebar"] label {
    color: #3c4043;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1050px;
}

.clean-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 16px;
    margin-bottom: 22px;
    border-bottom: 1px solid #dadce0;
}

.brand-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 1.3rem;
    font-weight: 600;
    color: #202124;
    letter-spacing: -0.2px;
}

.brand-badge {
    font-size: 0.7rem;
    font-weight: 600;
    padding: 4px 9px;
    border-radius: 999px;
    background: #e8f0fe;
    color: #1967d2;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 0.74rem;
    font-weight: 500;
    padding: 3px 10px;
    border-radius: 9999px;
}
.status-ai {
    background: #e6f4ea;
    color: #188038;
    border: 1px solid #ceead6;
}
.status-telemetry {
    background: #e8f0fe;
    color: #1967d2;
    border: 1px solid #d2e3fc;
}

.verdict-card {
    background: #fff;
    border: 1px solid #dadce0;
    border-radius: 12px;
    padding: 18px 22px;
    margin: 18px 0 20px 0;
    position: relative;
    overflow: hidden;
    box-shadow: 0 1px 2px rgba(60, 64, 67, 0.12);
}

.verdict-card-safe {
    border-left: 4px solid #188038;
}

.verdict-card-suspicious {
    border-left: 4px solid #f9ab00;
}

.verdict-card-danger {
    border-left: 4px solid #d93025;
}

.verdict-headline {
    font-size: 1.15rem;
    font-weight: 700;
    color: #202124;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.verdict-desc {
    color: #5f6368;
    font-size: 0.92rem;
    line-height: 1.55;
}

.tag-badge {
    font-size: 0.75rem;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 999px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    display: inline-block;
}
.tag-safe { background: #e6f4ea; color: #188038; }
.tag-suspicious { background: #fef7e0; color: #b06000; }
.tag-danger { background: #fce8e6; color: #d93025; }

.telemetry-strip {
    background: #f8f9fa;
    border: 1px solid #dadce0;
    border-radius: 8px;
    padding: 10px 14px;
    display: flex;
    flex-wrap: wrap;
    gap: 14px;
    font-size: 0.82rem;
    margin: 14px 0 20px 0;
}
.telemetry-item {
    display: inline-flex;
    align-items: center;
    gap: 6px;
}
.telemetry-key {
    color: #5f6368;
    font-weight: 600;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}
.telemetry-val {
    color: #3c4043;
    font-family: Consolas, monospace;
}

.metric-box {
    background: #fff;
    border: 1px solid #dadce0;
    border-radius: 10px;
    padding: 14px 18px;
    height: 100%;
    box-shadow: 0 1px 2px rgba(60, 64, 67, 0.12);
}
.metric-title {
    font-size: 0.72rem;
    font-weight: 600;
    color: #5f6368;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
}
.metric-number {
    font-size: 1.45rem;
    font-weight: 700;
    line-height: 1.2;
}

.clean-flag-item {
    background: #fce8e6;
    border-left: 2px solid #d93025;
    padding: 8px 12px;
    margin-bottom: 6px;
    font-size: 0.88rem;
    color: #3c4043;
    border-radius: 0 6px 6px 0;
}

.clean-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    border-bottom: 1px solid #dadce0;
    font-size: 0.85rem;
}
.clean-row:last-child {
    border-bottom: none;
}
.row-label {
    color: #3c4043;
}
.row-pass {
    color: #188038;
    font-size: 0.75rem;
    font-weight: 600;
}
.row-flag {
    color: #d93025;
    font-size: 0.75rem;
    font-weight: 600;
}

[data-testid="stTextInput"] input {
    border: 1px solid #dadce0;
    border-radius: 24px;
    min-height: 48px;
    padding-left: 18px;
    box-shadow: 0 1px 3px rgba(60, 64, 67, 0.2);
}

[data-testid="stTextInput"] input:focus {
    border-color: #1a73e8;
    box-shadow: 0 1px 6px rgba(60, 64, 67, 0.28);
}

[data-testid="stButton"] button,
[data-testid="stFormSubmitButton"] button {
    border-radius: 20px;
    border-color: #dadce0;
    color: #3c4043;
    background: #fff;
    font-weight: 500;
    transition: background 120ms ease, box-shadow 120ms ease;
}

[data-testid="stButton"] button:hover,
[data-testid="stFormSubmitButton"] button:hover {
    border-color: #dadce0;
    background: #f8f9fa;
    color: #202124;
}

[data-testid="stFormSubmitButton"] button[kind="primary"],
[data-testid="stButton"] button[kind="primary"] {
    background: #1a73e8;
    border-color: #1a73e8;
    color: #fff;
}

[data-testid="stFormSubmitButton"] button[kind="primary"]:hover,
[data-testid="stButton"] button[kind="primary"]:hover {
    background: #1765cc;
    border-color: #1765cc;
    color: #fff;
}

code, pre {
    color: #3c4043;
}
</style>
"""
st.markdown(CLEAN_CSS, unsafe_allow_html=True)


if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "current_result" not in st.session_state:
    st.session_state.current_result = None
if "url_search_input" not in st.session_state:
    st.session_state.url_search_input = ""


def select_url(url: str) -> None:
    st.session_state.url_search_input = url


def clear_history() -> None:
    st.session_state.scan_history = []
    st.session_state.current_result = None
    st.session_state.url_search_input = ""

env_api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")
try:
    secret_key = st.secrets.get("GEMINI_API_KEY", "") if hasattr(st, "secrets") else ""
except Exception:
    secret_key = ""

if "api_key" not in st.session_state:
    st.session_state.api_key = env_api_key or secret_key
if "selected_model" not in st.session_state:
    st.session_state.selected_model = "gemini-2.5-flash"


with st.sidebar:
    st.markdown("#### 🕒 Scan History")
    
    if not st.session_state.scan_history:
        st.markdown(
            """
            <div style="color: #5f6368; font-size: 0.84rem; padding: 8px 0; line-height: 1.4;">
                No scans recorded yet.<br>
                Analyzed URLs will appear here for fast recall.
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.caption(f"{len(st.session_state.scan_history)} recent scan(s)")
        
        for idx, item in enumerate(reversed(st.session_state.scan_history[-15:])):
            r_level = item.get("risk_level", "Suspicious")
            r_score = item.get("risk_score", 0)
            u_clean = item.get("display_url", item.get("url", ""))[:26]
            u_full = item.get("url", "")
            t_stamp = item.get("timestamp", "")

            indicator = "🟢" if r_level == "Safe" else "🟡" if r_level == "Suspicious" else "🔴"
            btn_label = f"{indicator} {u_clean}"
            
            st.button(
                btn_label,
                key=f"hist_{idx}_{t_stamp}",
                use_container_width=True,
                help=f"Threat Index: {r_score}/100 • Time: {t_stamp}\nURL: {u_full}",
                on_click=select_url,
                args=(u_full,),
            )

        st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
        st.button("Clear History", use_container_width=True, on_click=clear_history)


header_left, header_right = st.columns([3.3, 1.7], vertical_alignment="center")

with header_left:
    st.markdown(
        """
        <div class="brand-title">
            <span>🛡️ PhishGuard</span>
            <span class="brand-badge">Multi-Vector Threat Intelligence</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

with header_right:
    col_stat, col_set = st.columns([1.6, 1], vertical_alignment="center")
    has_api = bool(st.session_state.api_key and st.session_state.api_key.strip())
    
    with col_stat:
        if has_api:
            st.markdown('<span class="status-pill status-ai">● Telemetry + Gemini AI</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="status-pill status-telemetry">● Threat Analysis</span>', unsafe_allow_html=True)
            
    with col_set:
        with st.popover("Settings", use_container_width=True):
            st.markdown("##### Threat Engine Settings")
            new_key = st.text_input(
                "Gemini API Key:",
                value=st.session_state.api_key,
                type="password",
                placeholder="AIzaSy...",
                help="Add Google Gemini API Key for deep LLM forensic correlation and reasoning.",
            )
            if new_key != st.session_state.api_key:
                st.session_state.api_key = new_key
                st.rerun()

            st.session_state.selected_model = st.selectbox(
                "Gemini Model:",
                options=["gemini-2.5-flash", "gemini-1.5-flash"],
                index=0 if st.session_state.selected_model == "gemini-2.5-flash" else 1,
            )
            st.caption("[Get a free key from Google AI Studio](https://aistudio.google.com/app/apikey)")
            st.caption("Active Engines: Lexical Heuristics • Gemini AI")


with st.form("url_scan_form"):
    search_col1, search_col2 = st.columns([4.2, 1], vertical_alignment="bottom")
    with search_col1:
        url_input_val = st.text_input(
            "Target URL:",
            placeholder="Search or enter a website URL",
            label_visibility="collapsed",
            key="url_search_input",
        )
    with search_col2:
        scan_clicked = st.form_submit_button("Scan URL", type="primary", use_container_width=True)

# Quick Samples
st.markdown("<p style='font-size: 0.78rem; color: #5f6368; margin: 4px 0 2px 0;'>Quick test URLs</p>", unsafe_allow_html=True)
p_cols = st.columns(5)
with p_cols[0]:
    st.button("Google (Safe)", use_container_width=True, on_click=select_url, args=("https://www.google.com/search?q=cybersecurity",))
with p_cols[1]:
    st.button("GitHub (Safe)", use_container_width=True, on_click=select_url, args=("https://github.com/microsoft/vscode",))
with p_cols[2]:
    st.button("PayPa1 (Typosquat)", use_container_width=True, on_click=select_url, args=("http://paypa1-security-verification.com/login.php",))
with p_cols[3]:
    st.button("Apple (Subdomain)", use_container_width=True, on_click=select_url, args=("http://appleid.apple.com.manage-account-security.net/auth/verify",))
with p_cols[4]:
    st.button("Chase (IP Host)", use_container_width=True, on_click=select_url, args=("http://192.168.1.105/chase/online/login.html",))

st.markdown("<div style='margin-bottom: 18px;'></div>", unsafe_allow_html=True)

if scan_clicked:
    target_url = url_input_val.strip()

    if not target_url:
        st.warning("Please enter a valid URL to analyze.", icon="⚠️")
    else:
        with st.spinner("Probing live DNS, validating TLS certificates, and inspecting URL telemetry..."):
            pipeline_result = execute_threat_intelligence_pipeline(
                url=target_url,
                api_key=st.session_state.api_key,
                model_name=st.session_state.selected_model,
            )

        if not pipeline_result.get("valid", True):
            st.error(f"Invalid URL: {pipeline_result.get('error', 'Malformed URL string')}")
            st.session_state.current_result = None
        else:
            st.session_state.current_result = pipeline_result

            # Update history list
            ass = pipeline_result["assessment"]
            clean_display = target_url.replace("https://", "").replace("http://", "")[:30]
            if not st.session_state.scan_history or st.session_state.scan_history[-1].get("url") != target_url:
                st.session_state.scan_history.append({
                    "url": target_url,
                    "display_url": clean_display,
                    "risk_level": ass.get("risk_level", "Suspicious"),
                    "risk_score": ass.get("risk_score", 0),
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                })
            


if st.session_state.current_result:
    res = st.session_state.current_result
    ass = res["assessment"]
    heuristic_res = res["heuristic_res"]
    infra_res = res["infra_res"]
    det = heuristic_res.get("details", {})
    dns_info = infra_res.get("dns", {})
    ssl_info = infra_res.get("ssl", {})
    http_info = infra_res.get("http", {})

    final_level = ass.get("risk_level", "Suspicious")
    final_score = ass.get("risk_score", 0)
    v_title = ass.get("verdict_headline", "Analysis Complete")
    v_summary = ass.get("summary", "")
    v_rec = ass.get("recommendation", "")
    red_flags = ass.get("red_flags", [])
    brand_info = ass.get("brand_impersonation", {})
    social_tactics = ass.get("social_engineering_tactics", [])
    target_url = res["target_url"]

    # 1. Clean Verdict Card
    card_class = (
        "verdict-card-safe" if final_level == "Safe"
        else "verdict-card-suspicious" if final_level == "Suspicious"
        else "verdict-card-danger"
    )
    badge_class = (
        "tag-safe" if final_level == "Safe"
        else "tag-suspicious" if final_level == "Suspicious"
        else "tag-danger"
    )
    icon = "🛡️" if final_level == "Safe" else "⚠️" if final_level == "Suspicious" else "🚨"

    st.markdown(
        f"""
        <div class="verdict-card {card_class}">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 8px;">
                <div class="verdict-headline">
                    <span>{icon}</span>
                    <span>{v_title}</span>
                </div>
                <span class="tag-badge {badge_class}">{final_level}</span>
            </div>
            <div class="verdict-desc">{v_summary}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Live Infrastructure Telemetry Strip
    dns_status_text = (
        f"{dns_info.get('primary_ip', 'Resolved')}"
        if dns_info.get("resolved")
        else dns_info.get("dns_status", "Unresolved")
    )
    ssl_text = (
        f"{ssl_info.get('issuer_org') or ssl_info.get('issuer_cn') or 'TLS Valid'}"
        if ssl_info.get("has_ssl")
        else ssl_info.get("ssl_status", "No SSL")
    )
    http_text = (
        f"{http_info.get('status_code')} ({http_info.get('latency_ms')}ms)"
        if http_info.get("is_alive")
        else "Unresponsive"
    )
    redirect_notice = (
        f" • ➔ {http_info.get('final_url')[:35]}"
        if http_info.get("redirect_count", 0) > 0
        else ""
    )

    st.markdown(
        f"""
        <div class="telemetry-strip">
            <span class="telemetry-item"><span class="telemetry-key">DNS:</span><span class="telemetry-val">{dns_status_text}</span></span>
            <span class="telemetry-item"><span class="telemetry-key">SSL / Issuer:</span><span class="telemetry-val">{ssl_text}</span></span>
            <span class="telemetry-item"><span class="telemetry-key">HTTP Probe:</span><span class="telemetry-val">{http_text}{redirect_notice}</span></span>
            <span class="telemetry-item"><span class="telemetry-key">Engine:</span><span class="telemetry-val">{'Gemini AI + Telemetry' if res.get('engine_used') == 'gemini_multimodal' else 'Multi-Vector Telemetry'}</span></span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. Clean 4-Column Metrics
    m1, m2, m3, m4 = st.columns(4)

    with m1:
        score_color = "#188038" if final_score < 30 else "#b06000" if final_score < 70 else "#d93025"
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-title">Threat Index</div>
                <div class="metric-number" style="color: {score_color};">
                    {final_score} <span style="font-size: 0.85rem; color: #5f6368; font-weight: 500;">/ 100</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with m2:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-title">Threat Assessment</div>
                <div class="metric-number" style="font-size: 1.25rem;">
                    <span class="tag-badge {badge_class}">{final_level}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with m3:
        if ssl_info.get("has_ssl"):
            infra_status_str = "Active (TLS)"
            infra_color = "#188038"
        elif not dns_info.get("resolved"):
            infra_status_str = "NXDOMAIN"
            infra_color = "#d93025"
        elif infra_res.get("http_fallback_used"):
            infra_status_str = "HTTP Fallback (TLS Unverified)"
            infra_color = "#b06000"
        elif det.get("scheme") == "https":
            infra_status_str = "TLS Unverified"
            infra_color = "#b06000"
        else:
            infra_status_str = "Insecure HTTP"
            infra_color = "#d93025"
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-title">Infrastructure Status</div>
                <div class="metric-number" style="font-size: 1.15rem; color: {infra_color};">
                    {infra_status_str}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with m4:
        is_spoof = brand_info.get("is_impersonating", False)
        spoof_name = brand_info.get("targeted_brand") or "None"
        s_color = "#d93025" if is_spoof else "#188038"
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-title">Brand Impersonation</div>
                <div class="metric-number" style="font-size: 1.15rem; color: {s_color};">
                    {spoof_name}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    tab_assessment = st.tabs(["Threat Assessment"])

    with tab_assessment[0]:
        c1, c2 = st.columns([1.6, 1.2])

        with c1:
            st.markdown("##### 🚨 Threat Indicators & Forensic Evidence:")
            if red_flags:
                for f in red_flags:
                    st.markdown(f'<div class="clean-flag-item">⚠️ {f}</div>', unsafe_allow_html=True)
            else:
                st.success("No malicious, deceptive, or structural anomalies detected.")

        with c2:
            st.markdown("##### 💡 Actionable Guidance:")
            if final_level == "Safe":
                st.success(f"{v_rec}")
            elif final_level == "Suspicious":
                st.warning(f"{v_rec}")
            else:
                st.error(f"{v_rec}")

            if brand_info.get("is_impersonating"):
                st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
                st.markdown("##### 🎯 Brand Protection Alert:")
                st.error(
                    f"**Impersonated Target:** {brand_info.get('targeted_brand')}\n\n"
                    f"**Deception Mechanism:** {brand_info.get('spoofing_technique', 'Lookalike domain mimicry')}\n\n"
                    f"**Verification:** The SSL certificate does not validate ownership by {brand_info.get('targeted_brand')}."
                )

            if social_tactics:
                st.markdown("<div style='margin-top: 12px;'></div>", unsafe_allow_html=True)
                st.markdown("##### 🎭 Social Engineering Tactics:")
                for t in social_tactics:
                    st.markdown(f"- {t}")


st.markdown("<div style='margin-top: 36px;'></div>", unsafe_allow_html=True)
st.markdown(
    """
    <div style="text-align: center; color: #5f6368; font-size: 0.78rem; padding: 12px 0; border-top: 1px solid #dadce0;">
        PhishGuard URL Inspector • Multi-Vector Telemetry, Live DNS/TLS Validation & Google Gemini AI
    </div>
    """,
    unsafe_allow_html=True,
)
