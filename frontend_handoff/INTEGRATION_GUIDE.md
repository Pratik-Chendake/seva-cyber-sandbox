# SEVA CYBER SANDBOX — FRONTEND INTEGRATION & 3D DEVELOPMENT GUIDE

This document provides complete technical specifications for frontend engineers and AI assistants (such as Claude) tasked with redesigning the user interface and building interactive 3D cybersecurity visualizations for the **Seva Cyber Sandbox**.

---

## 1. Architectural Overview & Design Philosophy

The Seva Cyber Sandbox interface adheres to an **Editorial Swiss-Brutalist Dark** aesthetic system:
1. **Editorial Design:** Bold oversized typography, editorial section numbers (`01 // STATIC PARSER`), magazine-level contrast (`#101110` background vs `#F2F0E8` text).
2. **Swiss Design:** Strict modular grid alignment, vertical rhythm, clean hierarchy, baseline alignment.
3. **Brutalism:** Bold 1px-2px solid borders (`#393D37`), square corners (`border-radius: 2px`), prominent utilitarian controls, zero rounded bubbly pill shapes.
4. **Bento Grid:** Compartmentalized information cards, modular metric tiles, structured evidence compartments.
5. **Dark Mode UI:** Core palette:
   - Main Background: `#101110`
   - Secondary / Sidebar: `#151715`
   - Card Background: `#1A1C1A`
   - Elevated Card: `#222522`
   - Primary Text: `#F2F0E8`
   - Secondary Text: `#A6AAA2`
   - Borders: `#393D37` / Highlight: `#4A5048`
   - Primary Accent (Acid Lime): `#C6FF4D`
   - Critical Danger: `#FF5C5C`
   - Warning: `#FFB84D`
   - Info Accent: `#70D6FF`
6. **Cyberpunk:** Monospaced telemetry tags, micro-labels (`THREAT ASSESSMENT // MESSAGE INTEL`), spatial coordinate radar.

---

## 2. Integration Pathways with Python Streamlit

You have three distinct options for integrating this frontend into Streamlit.

### Option A: Embedded 3D Canvas with Native Streamlit (Recommended)
Embed the 3D threat radar or specialized visualizer directly into `app.py` using `st.components.v1.html()`, while retaining Streamlit's native backend event loop for case persistence and evaluation.

```python
import streamlit.components.v1 as components

# Read the standalone HTML or component bundle
with open("frontend_handoff/index.html", "r", encoding="utf-8") as f:
    html_content = f.read()

# Render directly inside any tab or container
components.html(html_content, height=800, scrolling=True)
```

### Option B: Full Bi-Directional Custom Streamlit Component
For deep bi-directional synchronization (e.g. clicking a 3D node in Three.js updates Streamlit's `st.session_state`), package `frontend_handoff/` as a Streamlit Custom Component using `streamlit-component-lib`.

#### Component Protocol:
1. **Receiving Data from Streamlit:**
```javascript
import { Streamlit } from "streamlit-component-lib";

function onRender(event) {
    const { cases, theme, activeTab } = event.detail.args;
    // Update Three.js scene or HTML tables with real backend data
    updateRadarScene(cases);
    Streamlit.setFrameHeight();
}

Streamlit.events.addEventListener(Streamlit.RENDER_EVENT, onRender);
Streamlit.setComponentReady();
```

2. **Sending Events back to Streamlit:**
```javascript
// When an operator clicks a threat blip or submits an adjudication:
Streamlit.setComponentValue({
    action: "SELECT_CASE",
    case_id: "CASE-20261030-APK-4B1C",
    timestamp: Date.now()
});
```

3. **Consuming in Python (`app.py`):**
```python
import streamlit as st
import streamlit.components.v1 as components

_component_func = components.declare_component(
    "threat_radar_3d",
    path="./frontend_handoff"
)

# Call component and receive user clicks:
event_data = _component_func(
    cases=st.session_state.case_store.list_cases(),
    default={"action": "NONE"}
)

if event_data.get("action") == "SELECT_CASE":
    st.session_state["active_review_case"] = event_data["case_id"]
```

---

## 3. Interactive 3D Threat Radar Development (Three.js / WebGL)

The file `frontend_handoff/index.html` designates a dedicated container for 3D graphics:
```html
<section class="canvas-3d-wrapper">
    <div class="canvas-3d-header">
        <span>RADAR VIEWPORT // PASSIVE THREAT SPATIAL MAP</span>
        <span>INTERACTIVE 3D COMPATIBLE // THREE.JS / WEBGL DROP-IN ANCHOR</span>
    </div>
    <div class="canvas-3d-viewport" id="radar-viewport-container">
        <canvas id="threejs-threat-canvas"></canvas>
    </div>
</section>
```

### Recommended 3D Visualization Architecture:
1. **Coordinate System:**
   - Polar coordinates centered at `(0, 0, 0)`.
   - **Radius ($r$):** Maps inversely to Threat Score. Critical threats ($Score \ge 80$) sit on the outer danger perimeter; benign records ($Score < 20$) cluster near the central green core.
   - **Azimuth ($\theta$):** Partitioned into 4 quadrants representing analysis vectors:
     - Quadrant 1 ($0^\circ - 90^\circ$): Vernacular WhatsApp Phishing (`MSG`)
     - Quadrant 2 ($90^\circ - 180^\circ$): Static APK Disassembly (`APK`)
     - Quadrant 3 ($180^\circ - 270^\circ$): Suspicious URL & Domain Radar (`URL`)
     - Quadrant 4 ($270^\circ - 360^\circ$): State Scheme Announcements (`SCHEME`)
2. **Visual Nodes (Threat Blips):**
   - Instanced meshes with emissive glows (`#FF5C5C` for Critical, `#FFB84D` for Warning, `#C6FF4D` for Cleared).
   - Raycasting for mouse cursor hover: reveals a brutalist HUD tooltip with Case ID, Target Identifier, and Risk Index.
3. **Cyberpunk Post-Processing (Subtle):**
   - Bloom pass with low threshold ($0.85$) to produce subtle phosphor luminescence on critical threat nodes.
   - Concentric wireframe grid rings with slow rotation animation ($0.005\text{ rad/s}$).

---

## 4. Air-Gapped & Offline Security Requirements

The Seva Cyber Sandbox is designed for strict defensive and air-gapped deployments:
1. **Zero External Requests:** Never load scripts, CSS, or fonts from third-party CDNs (e.g., Google Fonts, cdnjs, unpkg) at runtime.
2. **Local Font Fallbacks:** The stylesheet defines standard system font fallbacks (`-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, monospace`) if external web fonts are unreachable.
3. **Local Three.js Bundling:** Place `three.min.js` directly in `frontend_handoff/assets/` if compiling offline Three.js builds.
4. **Zero Code Execution Boundary:** The UI represents static analysis results. Never attempt to execute uploaded Android bytecode or make active HTTP requests to parsed URLs.
5. **Mandatory Disclaimers:** All exported reports must preserve the disclaimer:
   > *"Cybersecurity Analysis Summary — Not an Official Forensic Certification under Section 65B of the Indian Evidence Act."*

---

## 5. Mock Data Schemas for Offline Development

All mock data files in `frontend_handoff/mock_data/` are 100% fictional and follow the production Python schemas:
- `phishing_mock.json`: Real-world regional scam lures (MSEDCL disconnection, bank KYC, protective advisories).
- `apk_mock.json`: Static structural observations (AXML `0x80003`, Dalvik `dex\n035`, permission weights).
- `url_mock.json`: 9 observable characteristics (scheme, port, allowlisted `.gov.in`, lookalike, shorteners).
- `scheme_mock.json`: Government of Maharashtra Resolution (GR) comparison and discrepancy breakdowns.
- `cases_mock.json`: SQLite case store rows and review audit logs.
- `evaluation_mock.json`: Benchmark metrics across 39 records (Rule vs ML vs Concordance).
- `models_mock.json`: Neural model version registry with SHA-256 weights hashes.
- `patterns_mock.json`: Candidate fraud pattern discovery hypotheses with Wilson lower bound and lift.

---

## 6. Verification & Acceptance Checklist

Before finalizing any frontend changes:
- [ ] Open `frontend_handoff/index.html` directly in a browser via `file:///` without a web server.
- [ ] Verify that all 7 main tabs switch seamlessly.
- [ ] Verify that Tab 07 switches smoothly between all 3 subtabs.
- [ ] Click "🔍 Analyze WhatsApp Message" and verify that threat banners, indicators, and hybrid diagnostics render.
- [ ] Click "🔬 Inspect APK Package Statically" and verify metadata cards, AXML observations, and permissions table render.
- [ ] Click "🔬 Analyze URL Statically" and verify the 9-tile observable characteristics grid renders.
- [ ] Click "🏛️ Analyze Claim with Official Sources" and verify the GR comparison breakdown renders.
- [ ] Confirm Web Audio alert chimes play without console errors.
- [ ] Run `pytest tests` in the Python workspace to confirm 100% passing tests (zero breakage of existing backend logic).
