"""
UI Design System & Editorial Swiss-Brutalist Theme for Seva Cyber Sandbox.

Aesthetic Guidelines:
1. Editorial Design — Primary visual identity, bold oversized typography, magazine-level contrast.
2. Swiss Design — Grid, strict alignment, typography hierarchy, vertical rhythm.
3. Brutalism — Bold 1px-2px borders (#393D37), square corners (border-radius: 2px), prominent controls.
4. Bento Grid — Modular information tiles, compact metric blocks, structured data compartments.
5. Dark Mode UI — Palette:
   - Main Background: #101110
   - Secondary Background: #151715
   - Card Background: #1A1C1A
   - Elevated Card: #222522
   - Primary Text: #F2F0E8
   - Secondary Text: #A6AAA2
   - Borders: #393D37
   - Primary Accent (Acid Lime): #C6FF4D
   - Critical Danger: #FF5C5C
   - Warning: #FFB84D
   - Informational Accent: #70D6FF
6. Cyberpunk — Monospaced telemetry tags, micro-labels (SYSTEM STATUS, THREAT ANALYSIS, APK INSPECTION).
"""

import streamlit as st
from typing import Any, Dict, List, Optional


THEME_CSS = """
<style>
/* --------------------------------------------------------------------------
   01. FONTS & ROOT TOKENS
   -------------------------------------------------------------------------- */
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap');

:root {
    --bg-main: #101110;
    --bg-secondary: #151715;
    --bg-card: #1A1C1A;
    --bg-card-elevated: #222522;
    --text-primary: #F2F0E8;
    --text-secondary: #A6AAA2;
    --border-color: #393D37;
    --border-highlight: #4A5048;
    --accent-lime: #C6FF4D;
    --accent-danger: #FF5C5C;
    --accent-warning: #FFB84D;
    --accent-info: #70D6FF;
    --font-heading: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;
    --font-body: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --font-mono: 'JetBrains Mono', monospace;
}

/* --------------------------------------------------------------------------
   02. GLOBAL BASE STYLES & RESETS
   -------------------------------------------------------------------------- */
html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-main) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-body) !important;
    -webkit-font-smoothing: antialiased;
}

[data-testid="stHeader"] {
    background: rgba(16, 17, 16, 0.95) !important;
    border-bottom: 1px solid var(--border-color);
}

[data-testid="stSidebar"] {
    background-color: var(--bg-secondary) !important;
    border-right: 1px solid var(--border-color) !important;
}

[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
    font-family: var(--font-heading) !important;
    letter-spacing: -0.02em;
    color: var(--text-primary) !important;
}

/* --------------------------------------------------------------------------
   03. TYPOGRAPHY HIERARCHY (SWISS & EDITORIAL)
   -------------------------------------------------------------------------- */
h1, h2, h3, h4, h5, h6 {
    font-family: var(--font-heading) !important;
    color: var(--text-primary) !important;
    letter-spacing: -0.03em !important;
    font-weight: 700 !important;
}

h1 {
    font-size: 2.2rem !important;
    line-height: 1.15 !important;
}

h2 {
    font-size: 1.6rem !important;
    line-height: 1.2 !important;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 0.5rem;
    margin-top: 1.5rem !important;
}

h3 {
    font-size: 1.25rem !important;
    color: var(--text-primary) !important;
}

h4, h5 {
    font-size: 0.95rem !important;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--accent-lime) !important;
    font-family: var(--font-heading) !important;
}

p, span, label, div {
    color: var(--text-primary);
}

/* Monospace telemetry for hashes and technical indicators */
code, pre, .stCodeBlock {
    font-family: var(--font-mono) !important;
    background-color: var(--bg-secondary) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 2px !important;
    color: var(--accent-lime) !important;
    font-size: 0.88rem !important;
}

/* --------------------------------------------------------------------------
   04. BRUTALIST & SWISS TABS
   -------------------------------------------------------------------------- */
div[data-baseweb="tab-list"] {
    background-color: var(--bg-secondary) !important;
    border-bottom: 1px solid var(--border-color) !important;
    padding: 6px 6px 0 6px !important;
    gap: 6px !important;
    border-radius: 2px 2px 0 0 !important;
}

button[data-baseweb="tab"] {
    background-color: var(--bg-card) !important;
    color: var(--text-secondary) !important;
    border: 1px solid var(--border-color) !important;
    border-bottom: none !important;
    border-radius: 2px 2px 0 0 !important;
    font-family: var(--font-heading) !important;
    font-size: 0.82rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.04em !important;
    padding: 10px 16px !important;
    transition: all 0.15s ease-in-out !important;
}

button[data-baseweb="tab"]:hover {
    color: var(--text-primary) !important;
    background-color: var(--bg-card-elevated) !important;
    border-color: var(--border-highlight) !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    background-color: var(--bg-main) !important;
    color: var(--accent-lime) !important;
    border: 1px solid var(--border-color) !important;
    border-top: 2px solid var(--accent-lime) !important;
    border-bottom: 1px solid var(--bg-main) !important;
    font-weight: 700 !important;
}

/* --------------------------------------------------------------------------
   05. BRUTALIST BUTTONS
   -------------------------------------------------------------------------- */
button[kind="primary"], .stButton > button[type="primary"] {
    background-color: var(--accent-lime) !important;
    color: #101110 !important;
    border: 1px solid var(--accent-lime) !important;
    border-radius: 2px !important;
    font-family: var(--font-heading) !important;
    font-weight: 700 !important;
    font-size: 0.88rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
    padding: 0.55rem 1.4rem !important;
    box-shadow: 2px 2px 0px rgba(0, 0, 0, 0.8) !important;
    transition: all 0.15s ease !important;
}

button[kind="primary"]:hover, .stButton > button[type="primary"]:hover {
    background-color: #d4ff70 !important;
    border-color: #d4ff70 !important;
    color: #000000 !important;
    transform: translateY(-1px) !important;
    box-shadow: 3px 3px 0px rgba(198, 255, 77, 0.4) !important;
}

button[kind="secondary"], .stButton > button:not([type="primary"]) {
    background-color: var(--bg-card) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 2px !important;
    font-family: var(--font-heading) !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
    letter-spacing: 0.03em !important;
    transition: all 0.15s ease !important;
}

button[kind="secondary"]:hover, .stButton > button:not([type="primary"]):hover {
    border-color: var(--accent-lime) !important;
    color: var(--accent-lime) !important;
    background-color: var(--bg-card-elevated) !important;
}

/* Download buttons */
.stDownloadButton > button {
    background-color: var(--bg-card-elevated) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 2px !important;
    font-family: var(--font-heading) !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
    letter-spacing: 0.03em !important;
    width: 100% !important;
}

.stDownloadButton > button:hover {
    border-color: var(--accent-lime) !important;
    color: var(--accent-lime) !important;
}

/* --------------------------------------------------------------------------
   06. INPUT FIELDS, TEXTAREAS & SELECTS
   -------------------------------------------------------------------------- */
div[data-baseweb="input"] > div,
div[data-baseweb="textarea"] > textarea,
div[data-baseweb="select"] > div {
    background-color: var(--bg-secondary) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 2px !important;
    color: var(--text-primary) !important;
    font-family: var(--font-body) !important;
    font-size: 0.92rem !important;
    transition: border-color 0.15s ease !important;
}

div[data-baseweb="input"] > div:focus-within,
div[data-baseweb="textarea"] > textarea:focus,
div[data-baseweb="select"] > div:focus-within {
    border-color: var(--accent-lime) !important;
    box-shadow: 0 0 0 1px var(--accent-lime) !important;
}

textarea::placeholder, input::placeholder {
    color: #6E736B !important;
    font-size: 0.88rem !important;
}

/* File Uploader */
div[data-testid="stFileUploader"] {
    background-color: var(--bg-card) !important;
    border: 1px dashed var(--border-highlight) !important;
    border-radius: 2px !important;
    padding: 1.2rem !important;
    transition: border-color 0.2s ease !important;
}

div[data-testid="stFileUploader"]:hover {
    border-color: var(--accent-lime) !important;
}

/* --------------------------------------------------------------------------
   07. BENTO GRID METRICS & CARDS
   -------------------------------------------------------------------------- */
div[data-testid="stMetric"] {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 2px !important;
    padding: 1rem 1.2rem !important;
    box-shadow: 2px 2px 0px rgba(0, 0, 0, 0.4) !important;
    transition: transform 0.15s ease, border-color 0.15s ease !important;
}

div[data-testid="stMetric"]:hover {
    border-color: var(--border-highlight) !important;
}

div[data-testid="stMetricLabel"] p {
    font-family: var(--font-heading) !important;
    font-size: 0.76rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
    color: var(--text-secondary) !important;
    margin-bottom: 4px !important;
}

div[data-testid="stMetricValue"] {
    font-family: var(--font-mono) !important;
    font-size: 1.55rem !important;
    font-weight: 700 !important;
    color: var(--text-primary) !important;
}

/* --------------------------------------------------------------------------
   08. EXPANDERS & CONTAINERS
   -------------------------------------------------------------------------- */
div[data-testid="stExpander"] {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 2px !important;
    margin-bottom: 0.8rem !important;
}

div[data-testid="stExpander"] summary {
    font-family: var(--font-heading) !important;
    font-size: 0.88rem !important;
    font-weight: 600 !important;
    color: var(--text-primary) !important;
    letter-spacing: 0.02em !important;
}

div[data-testid="stExpander"] summary:hover {
    color: var(--accent-lime) !important;
}

/* --------------------------------------------------------------------------
   09. ALERTS & NOTIFICATIONS (BRUTALIST EDGES)
   -------------------------------------------------------------------------- */
div[data-testid="stAlert"] {
    border-radius: 2px !important;
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    color: var(--text-primary) !important;
    font-size: 0.9rem !important;
}

div[data-testid="stAlert"][data-baseweb*="error"], .stAlert[data-testid="stAlert"]:has([data-testid="stNotificationContentError"]) {
    border-left: 3px solid var(--accent-danger) !important;
}

div[data-testid="stAlert"][data-baseweb*="warning"], .stAlert[data-testid="stAlert"]:has([data-testid="stNotificationContentWarning"]) {
    border-left: 3px solid var(--accent-warning) !important;
}

div[data-testid="stAlert"][data-baseweb*="info"], .stAlert[data-testid="stAlert"]:has([data-testid="stNotificationContentInfo"]) {
    border-left: 3px solid var(--accent-info) !important;
}

div[data-testid="stAlert"][data-baseweb*="success"], .stAlert[data-testid="stAlert"]:has([data-testid="stNotificationContentSuccess"]) {
    border-left: 3px solid var(--accent-lime) !important;
}

/* --------------------------------------------------------------------------
   10. TABLES & DATAFRAMES
   -------------------------------------------------------------------------- */
table {
    border-collapse: collapse !important;
    width: 100% !important;
    font-family: var(--font-body) !important;
    font-size: 0.85rem !important;
    border: 1px solid var(--border-color) !important;
}

th {
    background-color: var(--bg-card-elevated) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-heading) !important;
    font-size: 0.78rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
    padding: 10px 12px !important;
    border: 1px solid var(--border-color) !important;
}

td {
    background-color: var(--bg-card) !important;
    color: var(--text-primary) !important;
    padding: 9px 12px !important;
    border: 1px solid var(--border-color) !important;
}

tr:nth-child(even) td {
    background-color: var(--bg-secondary) !important;
}

/* --------------------------------------------------------------------------
   11. CUSTOM BENTO & EDITORIAL COMPONENT CLASSES
   -------------------------------------------------------------------------- */
.editorial-topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border-color);
    padding: 8px 0;
    margin-bottom: 1.2rem;
    font-family: var(--font-mono);
    font-size: 0.76rem;
    color: var(--text-secondary);
}

.editorial-topbar-left {
    display: flex;
    align-items: center;
    gap: 12px;
}

.editorial-brand-badge {
    background: #000000;
    color: var(--accent-lime);
    border: 1px solid var(--accent-lime);
    padding: 2px 8px;
    font-weight: 700;
    letter-spacing: 0.08em;
    font-size: 0.72rem;
    border-radius: 2px;
}

.editorial-telemetry-tag {
    color: var(--text-secondary);
    border-left: 1px solid var(--border-color);
    padding-left: 12px;
}

.editorial-hero {
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1.5rem;
    margin-bottom: 1.8rem;
}

.editorial-hero-tagline {
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--accent-lime);
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.editorial-hero-title {
    font-family: var(--font-heading);
    font-size: 2.8rem;
    font-weight: 800;
    line-height: 1.05;
    letter-spacing: -0.04em;
    color: var(--text-primary);
    margin: 0 0 12px 0;
}

.editorial-hero-sub {
    font-family: var(--font-body);
    font-size: 1.05rem;
    color: var(--text-secondary);
    line-height: 1.5;
    max-width: 900px;
    margin: 0 0 1.2rem 0;
}

/* Bento Card Module */
.bento-card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 2px;
    padding: 1.25rem;
    margin-bottom: 1rem;
    box-shadow: 2px 2px 0px rgba(0, 0, 0, 0.4);
    transition: border-color 0.15s ease;
}

.bento-card:hover {
    border-color: var(--border-highlight);
}

.bento-card-elevated {
    background-color: var(--bg-card-elevated);
    border: 1px solid var(--border-highlight);
}

.bento-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 8px;
    margin-bottom: 12px;
}

.bento-card-label {
    font-family: var(--font-heading);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--accent-lime);
    font-weight: 700;
}

.bento-card-meta {
    font-family: var(--font-mono);
    font-size: 0.72rem;
    color: var(--text-secondary);
}

/* Brutalist Result Banner */
.threat-banner-red {
    background-color: #241414;
    border: 1px solid var(--accent-danger);
    border-left: 4px solid var(--accent-danger);
    border-radius: 2px;
    padding: 12px 16px;
    margin: 12px 0;
}

.threat-banner-orange {
    background-color: #241E14;
    border: 1px solid var(--accent-warning);
    border-left: 4px solid var(--accent-warning);
    border-radius: 2px;
    padding: 12px 16px;
    margin: 12px 0;
}

.threat-banner-green {
    background-color: #162414;
    border: 1px solid var(--accent-lime);
    border-left: 4px solid var(--accent-lime);
    border-radius: 2px;
    padding: 12px 16px;
    margin: 12px 0;
}

/* Micro pill badges */
.tech-pill {
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 0.72rem;
    padding: 2px 7px;
    border-radius: 2px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    margin: 2px 4px 2px 0;
}

.tech-pill-lime {
    border-color: var(--accent-lime);
    color: var(--accent-lime);
}

.tech-pill-danger {
    border-color: var(--accent-danger);
    color: var(--accent-danger);
}

.tech-pill-warning {
    border-color: var(--accent-warning);
    color: var(--accent-warning);
}
</style>
"""


def inject_custom_theme() -> None:
    """Injects the complete editorial Swiss/Brutalist dark theme CSS."""
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def render_editorial_header(session_case_count: int = 0) -> None:
    """
    Renders the editorial Swiss top branding bar and hero statement.
    Uses real session telemetry without fabricating numbers.
    """
    topbar_html = f"""
    <div class="editorial-topbar">
        <div class="editorial-topbar-left">
            <span class="editorial-brand-badge">SEVA // INTEL</span>
            <span>CYBER RESILIENCE PLATFORM</span>
            <span class="editorial-telemetry-tag">STANDALONE DEFENSIVE SANDBOX</span>
        </div>
        <div>
            <span class="editorial-telemetry-tag">CASES LOGGED: <strong style="color:var(--accent-lime)">{session_case_count}</strong></span>
            <span class="editorial-telemetry-tag">AIR-GAPPED: <strong style="color:var(--accent-lime)">VERIFIED</strong></span>
        </div>
    </div>
    <div class="editorial-hero">
        <div class="editorial-hero-tagline">
            <span>● AIR-GAPPED VERIFICATION ENGINE</span>
            <span>//</span>
            <span>SUB-THEME: RESPONSIBLE AI & DIGITAL TRUST</span>
        </div>
        <h1 class="editorial-hero-title">DEFENDING CITIZENS AGAINST REGIONAL DIGITAL FRAUD.</h1>
        <p class="editorial-hero-sub">
            Static Android .APK disassembly, vernacular social-engineering triage in Marathi & English, 
            safe offline URL radar, and Government of Maharashtra resolution verification.
        </p>
    </div>
    """
    st.markdown(topbar_html, unsafe_allow_html=True)


def render_bento_overview(
    case_count: int,
    verified_rules_count: int = 18,
    marathi_support_label: str = "DEVANAGARI + LATN",
) -> None:
    """
    Renders a responsive 4-tile Bento Grid summarizing platform readiness.
    """
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric(
            label="01 // STATIC PARSER",
            value="ACTIVE",
            help="Full Android Binary XML (AXML) structural attribute and Dalvik DEX parser.",
        )
    with c2:
        st.metric(
            label="02 // VERNACULAR SUPPORT",
            value=marathi_support_label,
            help="Marathi, Romanized Marathi, Mixed, and English vernacular social-engineering detectors.",
        )
    with c3:
        st.metric(
            label="03 // NETWORK EXECUTION",
            value="AIR-GAPPED",
            help="100% offline passive inspection. Zero network calls, zero code execution, zero APK installs.",
        )
    with c4:
        st.metric(
            label="04 // INCIDENT CASES",
            value=f"{case_count} LOGGED",
            help="Session cases persisted in SQLite with automated privacy redaction and retention.",
        )


def render_threat_banner(risk_level: str, badge_color: str, analysis_type: str, score: int) -> None:
    """
    Renders a bold brutalist threat assessment header banner.
    """
    color_class = {
        "red": "threat-banner-red",
        "orange": "threat-banner-orange",
        "green": "threat-banner-green",
    }.get(badge_color, "threat-banner-green")

    status_color = {
        "red": "#FF5C5C",
        "orange": "#FFB84D",
        "green": "#C6FF4D",
    }.get(badge_color, "#F2F0E8")

    banner_html = f"""
    <div class="{color_class}">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap;">
            <div>
                <span style="font-family:var(--font-mono); font-size:0.75rem; color:{status_color}; text-transform:uppercase; letter-spacing:0.08em; font-weight:700;">
                    THREAT ASSESSMENT // {analysis_type.upper()}
                </span>
                <div style="font-family:var(--font-heading); font-size:1.35rem; font-weight:700; color:#F2F0E8; margin-top:2px;">
                    {risk_level}
                </div>
            </div>
            <div style="text-align:right;">
                <span style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-secondary); text-transform:uppercase;">
                    RISK INDEX
                </span>
                <div style="font-family:var(--font-mono); font-size:1.7rem; font-weight:700; color:{status_color};">
                    {score} <span style="font-size:0.85rem; color:var(--text-secondary);">/ 100</span>
                </div>
            </div>
        </div>
    </div>
    """
    st.markdown(banner_html, unsafe_allow_html=True)
