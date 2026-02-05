import streamlit as st
import pandas as pd

from core.data_loader import load_local_reports, get_ttp_and_country_columns
from core.geo_utils import get_nordic_baltic_countries
from core.risk_scoring import calculate_iso_risk_score, calculate_nist_risk_score
from core.ml_models import (
    ml_generate_executive_summary,
    ml_threat_actor_profiling,
    ml_automated_threat_prioritization,
    ml_nordic_geographic_risk_forecast,
)
from core.nlp_intel import extract_nlp_intelligence
from core.recommendations import recommend_courses

st.set_page_config(page_title="ML Intelligence", page_icon="🤖", layout="wide")

# Load data
items = load_local_reports()
ttp_columns, country_columns = get_ttp_and_country_columns(items)

st.markdown('<h2 class="glow-text">ADVANCED ML INTELLIGENCE CENTER</h2>', unsafe_allow_html=True)

# -------------------------------
# DATA SELECTION
# -------------------------------
report_dates = sorted(items['report_date'].dt.date.unique(), reverse=True)
selected_date = st.selectbox("Select Intelligence Report Period", report_dates, index=0)
selected_report = items[items['report_date'].dt.date == selected_date]

# Country filter
all_countries = []
if country_columns:
    all_countries = pd.Series(pd.concat([items[col] for col in country_columns], ignore_index=True))
    all_countries = sorted(all_countries.dropna().unique().tolist())

nordic_baltic = get_nordic_baltic_countries()
default_countries = [c for c in nordic_baltic if c in all_countries]

selected_countries = st.multiselect("Geographic Filter", options=all_countries, default=default_countries)

# -------------------------------
# BASELINE METRICS
# -------------------------------
if ttp_columns:
    all_ttps = pd.Series(pd.concat([selected_report[col] for col in ttp_columns], ignore_index=True))
    all_ttps_flat = []
    unique_techniques = set()
    for val in all_ttps:
        if isinstance(val, (list, tuple, set)):
            vals = [str(x) for x in val if x not in [None, "None"]]
            all_ttps_flat.extend(vals)
            unique_techniques.update(vals)
        elif pd.notna(val) and str(val) != "None":
            all_ttps_flat.append(str(val))
            unique_techniques.add(str(val))
    unique_ttps_count = len(unique_techniques)
    total_ttp_count = len(all_ttps_flat)
else:
    unique_ttps_count = 0
    total_ttp_count = 0
    unique_techniques = set()

country_count = len([c for c in all_countries if c in selected_countries]) if selected_countries else len(all_countries)
sources_count = selected_report['source'].nunique() if 'source' in selected_report.columns else 0
regional_focus = bool(selected_countries and any(c in nordic_baltic for c in selected_countries))

iso_score = calculate_iso_risk_score(total_ttp_count, country_count, sources_count, regional_focus)
nist_score = calculate_nist_risk_score(total_ttp_count, country_count, unique_techniques, regional_focus)

# -------------------------------
# EXECUTIVE SUMMARY
# -------------------------------
st.markdown("""
<div style="margin-top: 20px; margin-bottom: 30px; padding: 20px; 
background: linear-gradient(145deg, #1a1a1a, #2a2a2a); 
border: 2px solid #00aaff; border-radius: 15px;">
    <h3 class="glow-text">ML-POWERED SUMMARY</h3>
</div>
""", unsafe_allow_html=True)

with st.spinner("Running machine learning analysis..."):
    summary, threat_color = ml_generate_executive_summary(
        selected_report, ttp_columns, country_columns, iso_score, nist_score
    )

st.markdown(f"""
<div style="padding: 25px; background: linear-gradient(145deg, #2a2a2a, #1a1a1a); 
border-left: 4px solid {threat_color}; border-radius: 10px; margin-top: 20px;">
    <h4 style="color: {threat_color}; margin-top: 0;">
        THREAT LEVEL: {summary['threat_level']}
        <span style="font-size: 12px; color: #00aaff; margin-left: 10px;">
            ML Confidence: {summary['ml_confidence']*100:.0f}%
        </span>
    </h4>
</div>
""", unsafe_allow_html=True)

# Display insights
if summary['key_insights']:
    st.subheader("Key Intelligence Insights")
    for insight in summary['key_insights']:
        st.write(f"• {insight}")

if summary['attack_patterns']:
    st.subheader("ML-Detected Attack Patterns")
    for pattern in summary['attack_patterns']:
        st.write(f"• {pattern}")

if summary['recommendations']:
    st.subheader("Strategic Recommendations")
    for rec in summary['recommendations']:
        st.write(f"• {rec}")

# -------------------------------
# ML MODULE TABS
# -------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Threat Actor Profiling",
    "Automated Threat Prioritization",
    "Geographic Risk Forecast",
    "NLP Intelligence Extraction",
    "Resource Allocation Optimizer"
])

# -------------------------------
# TAB 1 — THREAT ACTOR PROFILING
# -------------------------------
with tab1:
    st.markdown("<h3 class='glow-text'>Threat Actor Profiling</h3>", unsafe_allow_html=True)
    with st.spinner("Analyzing threat actor patterns..."):
        actor_profiles = ml_threat_actor_profiling(selected_report, ttp_columns)

    if actor_profiles:
        cols = st.columns(len(actor_profiles))
        for col, (actor_name, profile) in zip(cols, actor_profiles.items()):
            soph_color = (
                "#ff4444" if profile['sophistication'] == "High"
                else "#ffaa00" if "Medium" in profile['sophistication']
                else "#44ff44"
            )
            col.markdown(f"""
            <div style="background:#1a1a1a; padding:15px; border-radius:10px; 
            border:2px solid {soph_color}; height:260px;">
                <h4 style="color:{soph_color}; margin:0;">{actor_name}</h4>
                <p style="color:#ffff00; font-size:16px; margin:5px 0;">{profile['type']}</p>
                <p style="font-size:11px; color:#cccccc;">
                    <strong>Sophistication:</strong> {profile['sophistication']}<br>
                    <strong>Incidents:</strong> {profile['incident_count']} ({profile['percentage']:.1f}%)
                </p>
                <p style="font-size:10px; color:#888888;"><strong>Signature TTPs:</strong></p>
                <ul style="font-size:9px; color:#aaaaaa;">
                    {''.join([f"<li>{ttp}</li>" for ttp in profile['signature_ttps']])}
                </ul>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Insufficient data for threat actor profiling.")

# -------------------------------
# TAB 2 — AUTOMATED THREAT PRIORITIZATION
# -------------------------------
with tab2:
    st.markdown("<h3 class='glow-text'>Automated Threat Prioritization</h3>", unsafe_allow_html=True)
    with st.spinner("Calculating threat priority scores..."):
        prioritized = ml_automated_threat_prioritization(
            selected_report, ttp_columns, country_columns, iso_score, nist_score
        )

    if prioritized:
        for threat in prioritized[:5]:
            st.markdown(f"""
            <div style="background:#1a1a1a; padding:12px; border-radius:8px; 
            border-left:4px solid {threat['color']}; margin-bottom:10px;">
                <p style="color:{threat['color']}; font-weight:bold; margin:0;">
                    {threat['priority']} — Score {threat['score']:.0f}
                </p>
                <p style="color:#ffff00; font-size:12px; margin:5px 0;">
                    {threat['ttp']}
                </p>
                <p style="font-size:10px; color:#888888;">
                    Freq: {threat['frequency']} | Geo: {threat['countries']} | 
                    {"Nordic Impact" if threat['nordic_impact'] else "Global Only"}
                </p>
            </div>
            """, unsafe_allow_html=True)

        with st.expander("View Full Prioritized List"):
            for idx, threat in enumerate(prioritized, 1):
                st.write(f"**#{idx} — {threat['priority']} ({threat['score']:.1f})** — {threat['ttp']}")
    else:
        st.info("Unable to calculate threat priorities.")

# -------------------------------
# TAB 3 — GEOGRAPHIC RISK FORECAST
# -------------------------------
with tab3:
    st.markdown("<h3 class='glow-text'>Geographic Risk Forecast</h3>", unsafe_allow_html=True)
    with st.spinner("Forecasting regional threat risks..."):
        geo_forecasts = ml_nordic_geographic_risk_forecast(items, country_columns, periods=4)

    if geo_forecasts:
        for country, forecast in geo_forecasts.items():
            color = {
                'CRITICAL': '#ff4444',
                'ELEVATED': '#ffaa00',
                'MODERATE': '#ffff00',
                'LOW': '#44ff44'
            }.get(forecast['risk_level'], '#888888')

            st.markdown(f"""
            <div style="background:#1a1a1a; padding:10px; border-radius:8px; 
            border-left:4px solid {color}; margin-bottom:10px;">
                <strong style="color:{color};">{country}</strong><br>
                <span style="font-size:11px; color:#cccccc;">
                    Risk: {forecast['risk_level']} ({forecast['confidence']} confidence)<br>
                    Trend: {forecast['trend']}<br>
                    Forecast: {forecast['forecast_avg']:.1f} avg attacks/week
                </span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Insufficient historical data for forecasting.")

# -------------------------------
# TAB 4 — NLP INTELLIGENCE EXTRACTION
# -------------------------------
with tab4:
    st.markdown("<h3 class='glow-text'>NLP Intelligence Extraction</h3>", unsafe_allow_html=True)
    with st.spinner("Extracting intelligence..."):
        intel = extract_nlp_intelligence(selected_report, ttp_columns)

    if intel:
        col1, col2, col3 = st.columns(3)

        with col1:
            st.subheader("Attack Vectors")
            for kw, score in intel['attack_vectors']:
                st.write(f"• **{kw}** ({score:.3f})")

        with col2:
            st.subheader("Techniques")
            for kw, score in intel['techniques']:
                st.write(f"• **{kw}** ({score:.3f})")

        with col3:
            st.subheader("Emerging Patterns")
            for pattern in intel['emerging_patterns']:
                st.write(f"• {pattern}")

    else:
        st.info("Not enough data for NLP extraction.")

# -------------------------------
# TAB 5 — RESOURCE ALLOCATION OPTIMIZER
# -------------------------------
with tab5:
    st.markdown("<h3 class='glow-text'>Resource Allocation Optimizer</h3>", unsafe_allow_html=True)

    with st.spinner("Optimizing resource allocation..."):
        prioritized = ml_automated_threat_prioritization(
            selected_report, ttp_columns, country_columns, iso_score, nist_score
        )
        allocation = ml_resource_allocation_optimizer(prioritized, iso_score, nist_score)

    if allocation:
        st.subheader("Recommended Budget Distribution")
        for category, pct in allocation['allocations']:
            st.write(f"• **{category}** — {pct:.1f}%")

        st.subheader("Top Investment Areas")
        for area in allocation['top_investment_areas']:
            st.write(f"• {area}")

        st.subheader("Overall Recommendation")
        st.write(f"**{allocation['urgency']}** — {allocation['budget_recommendation']}")
    else:
        st.info("Not enough data for resource optimization.")
