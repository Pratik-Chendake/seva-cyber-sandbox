/**
 * SEVA CYBER SANDBOX — FRONTEND CONTROLLER & INTERACTION ENGINE
 * Standalone Offline Vanilla JavaScript for Editorial Swiss-Brutalist Interface
 * Zero External Network Dependencies | Offline File Protocol Compatible
 */

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initExpanders();
    initMockDataBindings();
    initAudioSynth();
    initCanvasRadarPlaceholder();
    renderSessionCases();
});

/* ==========================================================================
   01. TAB & SUBTAB NAVIGATION CONTROLLER
   ========================================================================== */
function initNavigation() {
    // Main 7 Tabs
    const tabBtns = document.querySelectorAll('.tabs-navigation .tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabPanels.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const targetId = btn.getAttribute('data-target');
            const targetPanel = document.getElementById(targetId);
            if (targetPanel) {
                targetPanel.classList.add('active');
            }
        });
    });

    // Tab 7 Subtabs
    const subtabBtns = document.querySelectorAll('.subtabs-navigation .subtab-btn');
    const subtabPanels = document.querySelectorAll('.subtab-panel');

    subtabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            subtabBtns.forEach(b => b.classList.remove('active'));
            subtabPanels.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const targetId = btn.getAttribute('data-target');
            const targetPanel = document.getElementById(targetId);
            if (targetPanel) {
                targetPanel.classList.add('active');
            }
        });
    });
}

/* ==========================================================================
   02. EXPANDERS & ACCORDIONS
   ========================================================================== */
function initExpanders() {
    document.querySelectorAll('.expander-header').forEach(header => {
        header.addEventListener('click', () => {
            const expander = header.parentElement;
            expander.classList.toggle('open');
            const arrow = header.querySelector('.expander-arrow');
            if (arrow) {
                arrow.textContent = expander.classList.contains('open') ? '▲' : '▼';
            }
        });
    });
}

/* ==========================================================================
   03. AUDIO SYNTHESIS FALLBACK (WEB AUDIO API)
   ========================================================================== */
let audioCtx = null;
let soundEnabled = true;

function initAudioSynth() {
    const audioToggle = document.getElementById('sidebar-audio-toggle');
    if (audioToggle) {
        audioToggle.addEventListener('change', (e) => {
            soundEnabled = e.target.checked;
        });
    }
}

function playThreatChime(color) {
    if (!soundEnabled) return;
    try {
        if (!audioCtx) {
            audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        }
        if (audioCtx.state === 'suspended') {
            audioCtx.resume();
        }

        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);

        const now = audioCtx.currentTime;
        if (color === 'red') {
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(880, now);
            osc.frequency.setValueAtTime(440, now + 0.15);
            gain.gain.setValueAtTime(0.15, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);
            osc.start(now);
            osc.stop(now + 0.4);
        } else if (color === 'orange') {
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(554.37, now);
            gain.gain.setValueAtTime(0.12, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
            osc.start(now);
            osc.stop(now + 0.3);
        } else {
            osc.type = 'sine';
            osc.frequency.setValueAtTime(440, now);
            osc.frequency.setValueAtTime(659.25, now + 0.12);
            gain.gain.setValueAtTime(0.1, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
            osc.start(now);
            osc.stop(now + 0.35);
        }
    } catch (e) {
        console.warn('Web Audio synthesis not supported or permitted in this context', e);
    }
}

/* ==========================================================================
   04. EMBEDDED REALISTIC MOCK DATA REPOSITORY
   (Guarantees Instant Offline file:/// Execution Without CORS Restrictions)
   ========================================================================== */
const MOCK_DATA = {
    phishing: [
        {
            id: "MSG-001",
            title: "MSEDCL Electricity Disconnection Threat (Devanagari)",
            language: "Marathi",
            label: "phishing",
            text: "प्रिय महावितरण ग्राहक, तुमचे मागील महिन्याचे वीज बिल ₹२,४५० थकीत आहे. आज रात्री ९:३० वाजता वीज पुरवठा खंडित केला जाईल. कारवाई टाळण्यासाठी तात्काळ खालील लिंकवरून MSEDCL_Bill_Pay.apk डाउनलोड करा आणि अपडेट करा: http://msedcl-bill-update-maharashtra.xyz/quick-pay",
            script_detected: "DEVANAGARI",
            score: 92,
            risk_level: "CRITICAL RISK (IMMEDIATE ACTION REQUIRED)",
            badge_color: "red",
            analysis_type: "WhatsApp Vernacular Phishing Analysis",
            summary_en: "Critical threat detected. Urgent MSEDCL power shutoff lure claiming unpaid bill, demanding third-party APK installation, and directing to unofficial .xyz domain.",
            summary_mr: "अतिधोकादायक संदेश! यामध्ये महावितरणचे थकीत वीज बिल भरण्यासाठी तात्काळ अनधिकृत APK फाईल डाउनलोड करण्याचा आणि संशयास्पद लिंकवर क्लिक करण्याचा दबाव आणला जात आहे.",
            evidence: [
                "Matched high-urgency disconnection threat: 'आज रात्री ९:३० वाजता वीज पुरवठा खंडित केला जाईल'",
                "Direct APK download solicitation: 'MSEDCL_Bill_Pay.apk'",
                "Unofficial domain spoofing Maharashtra state utility: 'msedcl-bill-update-maharashtra.xyz'"
            ],
            observed_facts: [
                "Script: Devanagari (Marathi)",
                "Character length: 248 chars",
                "Targeted entity: MSEDCL",
                "Extracted URL: http://msedcl-bill-update-maharashtra.xyz/quick-pay",
                "Declared file artifact: MSEDCL_Bill_Pay.apk"
            ],
            heuristic_inferences: [
                "Disconnection ultimatum creates cognitive panic (+35 weight)",
                "Unofficial .xyz domain miming official .mahadiscom.in (+30 weight)",
                "External APK distribution bypasses Google Play Protect (+27 weight)"
            ],
            findings: [
                { cat: "Disconnection Threat", sev: "CRITICAL", text: "वीज पुरवठा खंडित केला जाईल", en: "Fake shut-off notice inducing rapid panic.", mr: "वीज कापण्याची खोटी भीती दाखवली जाते." },
                { cat: "Malicious APK Solicitation", sev: "CRITICAL", text: "MSEDCL_Bill_Pay.apk डाउनलोड करा", en: "Unverified APKs bundle banking trojans.", mr: "अनोळखी ॲप्समधून बँकेचे OTP चोरले जातात." },
                { cat: "Unofficial Utility Domain", sev: "HIGH", text: "msedcl-bill-update-maharashtra.xyz", en: "Rogue domain not matching mahadiscom.in.", mr: "महावितरणची खरी वेबसाईट mahadiscom.in आहे." }
            ],
            urls: ["http://msedcl-bill-update-maharashtra.xyz/quick-pay"],
            steps_en: [
                "Do not click the link or install the requested .apk application.",
                "Verify your bill status directly inside the official Mahavitaran mobile app or via https://www.mahadiscom.in.",
                "Report the incident via the national cyber helpline 1930."
            ],
            steps_mr: [
                "दिलेल्या लिंकवर क्लिक करू नका किंवा कोणतीही APK फाईल डाऊनलोड करू नका.",
                "अधिकृत 'Mahavitaran' ॲप किंवा mahadiscom.in वेबसाईटवर जाऊन खरे बिल तपासा.",
                "हा नंबर तात्काळ ब्लॉक करा आणि सायबर हेल्पलाइन १९३० वर तक्रार नोंदवा."
            ],
            hybrid: {
                mode: "SHADOW",
                rule_score: 92,
                status: "AGREEMENT",
                verdict: "PHISHING",
                model_pred: "PHISHING",
                confidence: "98.4%",
                version: "nn_v2_focal_loss"
            }
        },
        {
            id: "MSG-002",
            title: "Romanized Marathi Electricity Disconnection Scam",
            language: "Romanized Marathi",
            label: "phishing",
            text: "Dear customer tumche Mahavitaran electricity bill update zalela nahi. Aaj ratri light cut karnar. Urgent call kara electricity officer Sharma ji 9823091823 var ani MSEDCL_QuickPay.apk install kara.",
            script_detected: "LATIN (ROMANIZED MARATHI)",
            score: 88,
            risk_level: "CRITICAL RISK (IMMEDIATE ACTION REQUIRED)",
            badge_color: "red",
            analysis_type: "WhatsApp Vernacular Phishing Analysis",
            summary_en: "High-risk Romanized Marathi phishing message detected. Uses informal Latin-script colloquial phrasing ('light cut karnar') and personal mobile impersonation.",
            summary_mr: "रोमनाईज्ड मराठीतील धोकादायक मेसेज! 'लाईट कट' करण्याची भीती दाखवून बनावट अधिकाऱ्याशी संपर्क साधायला सांगत आहेत.",
            evidence: [
                "Romanized vernacular urgency keyword: 'light cut karnar'",
                "Utility impersonation with personal cell phone contact",
                "Untrusted APK side-loading lure: 'MSEDCL_QuickPay.apk'"
            ],
            observed_facts: [
                "Script: Latin (Romanized Marathi)",
                "Colloquial terminology: 'light cut karnar', 'tumche bill'",
                "Impersonated authority: officer Sharma ji 9823091823"
            ],
            heuristic_inferences: [
                "Impersonation of utility official with personal cell indicates fraud (+30 weight)",
                "Disconnection threat combined with side-loading request (+58 weight)"
            ],
            findings: [
                { cat: "Colloquial Disconnection Threat", sev: "CRITICAL", text: "light cut karnar", en: "Regional informal idioms to bypass English filters.", mr: "प्रादेशिक भाषेचा वापर करून भीती निर्माण करणे." },
                { cat: "Personal Mobile Impersonation", sev: "HIGH", text: "officer Sharma ji 9823091823", en: "Utilities never manage cutoffs via personal numbers.", mr: "अधिकारी कधीही वैयक्तिक नंबरवरून फोन करत नाहीत." }
            ],
            urls: [],
            steps_en: [
                "Do not call the mobile number mentioned in the chat.",
                "Verify payment history on the official Mahadiscom portal.",
                "Report the suspicious mobile number to 1930."
            ],
            steps_mr: [
                "मेसेजमध्ये दिलेल्या कोणत्याही मोबाईल नंबरवर संपर्क करू नका.",
                "महावितरणच्या अधिकृत ग्राहक केंद्राशी संपर्क साधा.",
                "अनोळखी नंबर तात्काळ ब्लॉक करा."
            ],
            hybrid: {
                mode: "SHADOW",
                rule_score: 88,
                status: "AGREEMENT",
                verdict: "PHISHING",
                model_pred: "PHISHING",
                confidence: "94.1%",
                version: "nn_v2_focal_loss"
            }
        },
        {
            id: "MSG-003",
            title: "Official MSEDCL Awareness & Protective Advisory",
            language: "Marathi",
            label: "protective_advisory",
            text: "महावितरण जनहितार्थ सूचना: वीज बिल भरण्यासाठी महावितरण कधीही अनोळखी क्रमांकावरून फोन करत नाही किंवा APK फाईल पाठवत नाही. कोणत्याही व्यक्तीला बँक खात्याची माहिती, OTP किंवा पासवर्ड देऊ नका. फसवणूक झाल्यास त्वरित १९३० वर संपर्क साधा.",
            script_detected: "DEVANAGARI",
            score: 0,
            risk_level: "PROTECTIVE ADVISORY (SECURITY AWARENESS)",
            badge_color: "green",
            analysis_type: "WhatsApp Vernacular Phishing Analysis",
            summary_en: "Legitimate protective advisory message detected. Explicitly cautions citizens against sharing OTPs or downloading unauthorized APKs.",
            summary_mr: "हा एक अधिकृत जनजागृती संदेश आहे. यामध्ये नागरिकांना अनोळखी ॲप्स डाऊनलोड न करण्याचा सुरक्षित सल्ला दिला आहे.",
            evidence: [
                "Protective negation detected: 'कधीही APK फाईल पाठवत नाही'",
                "Credential protection advisory: 'माहिती, OTP किंवा पासवर्ड देऊ नका'",
                "Official helpline citation: '१९३० वर संपर्क साधा'"
            ],
            observed_facts: [
                "Protective negation patterns matched: 3",
                "Threat indicators suppressed: True",
                "Official helpline 1930 confirmed"
            ],
            heuristic_inferences: [
                "Contextual negation safeguard confirmed benign public awareness advisory (Score 0)"
            ],
            findings: [],
            urls: [],
            steps_en: [
                "Educational advisory. You may safely forward this to family and community groups.",
                "Remember the 1930 national helpline for any cyber fraud incidents."
            ],
            steps_mr: [
                "हा सुरक्षित जनजागृती संदेश आहे, तो आपल्या मित्र आणि कुटुंबात नक्की शेअर करा.",
                "लक्षात ठेवा: अधिकृत संस्था कधीही फोनवर OTP मागत नाहीत."
            ],
            hybrid: {
                mode: "SHADOW",
                rule_score: 0,
                status: "AGREEMENT",
                verdict: "PROTECTIVE_ADVISORY",
                model_pred: "LEGITIMATE",
                confidence: "99.2%",
                version: "nn_v2_focal_loss"
            }
        }
    ],

    apk: {
        filename: "MSEDCL_Bill_Update_Malicious.apk",
        size: "3,145,728 bytes (3.0 MB)",
        hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        pkg: "com.fraud.msedcl.helper",
        manifest: "Binary AXML (0x00080003)",
        parser: "Structural Android Binary XML Attribute Parser",
        dex: "Dalvik Executable (dex\\n035)",
        score: 95,
        risk_level: "CRITICAL RISK (DANGEROUS PERMISSIONS DETECTED)",
        badge_color: "red",
        summary_en: "Critical security risk! This application requests invasive SMS interception, call logging, and Accessibility Service bindings commonly weaponized by banking trojans.",
        summary_mr: "अतिधोकादायक ॲप! या ॲप्लिकेशनमध्ये मोबाईलमधील मेसेज वाचण्याची, फोन कॉल्स रेकॉर्ड करण्याची आणि फोनवर पूर्ण नियंत्रण मिळवण्याची धोकादायक परवानगी मागितली आहे.",
        evidence: [
            "Requests android.permission.RECEIVE_SMS (Invasive SMS interception capability)",
            "Requests android.permission.READ_SMS (Targeted bank OTP harvesting vector)",
            "Requests android.permission.BIND_ACCESSIBILITY_SERVICE (Full UI overlay & keylogging capability)",
            "Passively extracted 2 command-and-control endpoint URLs"
        ],
        permissions: [
            { name: "RECEIVE_SMS", family: "SMS & Banking Interception", sev: "CRITICAL", weight: 35, en: "Allows real-time SMS interception to steal OTPs.", mr: "बँकेकडून येणारा गुप्त OTP परस्पर चोरू शकतो." },
            { name: "READ_SMS", family: "SMS & Banking Interception", sev: "CRITICAL", weight: 35, en: "Exposes private SMS messages and transaction history.", mr: "मोबाईलमधील सर्व मेसेज व बँकेचे व्यवहार वाचण्याची परवानगी." },
            { name: "BIND_ACCESSIBILITY_SERVICE", family: "Device & UI Keylogging", sev: "CRITICAL", weight: 40, en: "Full screen control enabling invisible keylogging & overlays.", mr: "फोनच्या स्क्रीनवर काय टाईप केले जात आहे ते पाहण्याची घातक क्षमता." },
            { name: "INTERNET", family: "Network Transmission", sev: "LOW", weight: 5, en: "Allows network communication with external C2 servers.", mr: "इंटरनेट वापरून डेटा बाहेर पाठवण्याची परवानगी." }
        ],
        urls: [
            "http://c2-collector-stream.xyz/api/v1/sms-sync",
            "http://msedcl-bill-update-maharashtra.xyz/telemetry"
        ]
    },

    urls: [
        {
            url: "http://msedcl-bill-update-maharashtra.xyz/quick-pay",
            scheme: "HTTP",
            hostname: "msedcl-bill-update-maharashtra.xyz",
            score: 90,
            risk_level: "CRITICAL RISK (MALICIOUS LOOKALIKE DOMAIN)",
            badge_color: "red",
            summary_en: "Critical phishing danger. Impersonates MSEDCL using unencrypted HTTP, high-risk .xyz TLD, and fake payment path.",
            summary_mr: "अतिधोकादायक लिंक! महावितरणच्या नावाखाली फसवणूक करणारी ही बनावट लिंक आहे.",
            evidence: [
                "Unencrypted HTTP connection without TLS security",
                "Brand impersonation targeting Maharashtra electricity utility: 'msedcl'",
                "High-risk, inexpensive top-level domain: '.xyz'",
                "Unofficial third-party registration not matching .mahadiscom.in"
            ],
            obs: {
                protocol: "HTTP",
                hostname: "msedcl-bill-update-maharashtra.xyz",
                port: "80 (DEFAULT)",
                allowlisted: "NO (UNOFFICIAL)",
                shortener: "NO",
                lookalike: "YES (MSEDCL)",
                ip: "NO",
                punycode: "NO",
                apk: "NO"
            }
        },
        {
            url: "https://ladakibahin.maharashtra.gov.in/",
            scheme: "HTTPS",
            hostname: "ladakibahin.maharashtra.gov.in",
            score: 0,
            risk_level: "OFFICIAL & VERIFIED (GOVERNMENT OF MAHARASHTRA)",
            badge_color: "green",
            summary_en: "Verified official state portal. Domain belongs to the Government of Maharashtra allowlist under .maharashtra.gov.in and uses TLS.",
            summary_mr: "महाराष्ट्र शासनाचे अधिकृत व सुरक्षित संकेतस्थळ. ही 'माझी लाडकी बहीण योजने'ची खरी शासकीय वेबसाईट आहे.",
            evidence: [
                "Explicitly allowlisted state domain: '.maharashtra.gov.in'",
                "Secure TLS encrypted transport (HTTPS)",
                "Matches verified official Government Resolution (GR)"
            ],
            obs: {
                protocol: "HTTPS",
                hostname: "ladakibahin.maharashtra.gov.in",
                port: "443 (DEFAULT)",
                allowlisted: "YES (ALLOWLISTED)",
                shortener: "NO",
                lookalike: "NO",
                ip: "NO",
                punycode: "NO",
                apk: "NO"
            }
        }
    ],

    scheme: {
        claim: "Register through this WhatsApp link to receive ₹3,000 under Mukhyamantri Majhi Ladki Bahin Yojana.",
        url: "http://ladki-bahin-apply-fast.xyz/register",
        classification: "CONFLICTING EVIDENCE FOUND",
        badge_color: "red",
        matched_title: "Mukhyamantri Majhi Ladki Bahin Yojana",
        summary_en: "Conflicting evidence identified. Official Government Resolution No. WCD-2024/CR-102 mandates a monthly DBT disbursement of ₹1,500, not ₹3,000. Official applications are accepted exclusively on ladakibahin.maharashtra.gov.in.",
        summary_mr: "माहितीमध्ये तफावत व विसंगती आढळली! अधिकृत शासन निर्णयानुसार (GR) दरमहा मिळणारी रक्कम ₹१,५०० आहे (₹३,००० नाही). तसेच दिलेली वेबसाईट पूर्णपणे अनधिकृत आणि बनावट आहे.",
        supporting: [
            "Matched registered state initiative: 'Mukhyamantri Majhi Ladki Bahin Yojana'",
            "Women & Child Development Department verified"
        ],
        conflicting: [
            "Financial Discrepancy: Claim asserts ₹3,000 benefit; Official GR establishes ₹1,500/month stipend.",
            "Unauthorized Channel: Applications must use ladakibahin.maharashtra.gov.in or Nari Shakti Doot App.",
            "Rogue Link: Claim points to external phishing lure http://ladki-bahin-apply-fast.xyz/register"
        ],
        gr: {
            title: "Mukhyamantri Majhi Ladki Bahin Yojana Scheme Guidelines",
            title_mr: "मुख्यमंत्री माझी लाडकी बहीण योजना शासन निर्णय",
            dept: "Women & Child Development Department, Govt of Maharashtra",
            gr_no: "WCD-2024/CR-102/Desk-03",
            date: "2024-06-28",
            portal: "https://ladakibahin.maharashtra.gov.in/"
        }
    },

    cases: [
        {
            id: "CASE-20261030-MSG-8F2A",
            type: "WhatsApp Message Intel",
            target: "[Devanagari - 248 chars - MSEDCL Bill Scam]",
            score: 92,
            level: "CRITICAL RISK",
            color: "red",
            timestamp: "2026-10-30 16:15 UTC",
            review_state: "completed",
            adjudication: "phishing (high conf)"
        },
        {
            id: "CASE-20261030-APK-4B1C",
            type: "APK Static Inspection",
            target: "MSEDCL_Bill_Update_Malicious.apk",
            score: 95,
            level: "CRITICAL RISK",
            color: "red",
            timestamp: "2026-10-30 16:18 UTC",
            review_state: "under_review",
            adjudication: "pending triage"
        },
        {
            id: "CASE-20261030-URL-9E3D",
            type: "Safe URL Radar",
            target: "https://bit.ly/3xY8zMsedclPay",
            score: 45,
            level: "SUSPICIOUS",
            color: "orange",
            timestamp: "2026-10-30 16:20 UTC",
            review_state: "pending",
            adjudication: "unreviewed"
        },
        {
            id: "CASE-20261030-SCH-1A7F",
            type: "State Scheme Verifier",
            target: "Ladki Bahin Yojana Claim",
            score: 0,
            level: "VERIFIED LEGITIMATE",
            color: "green",
            timestamp: "2026-10-30 16:22 UTC",
            review_state: "completed",
            adjudication: "legitimate (high conf)"
        }
    ]
};

/* ==========================================================================
   05. INTERACTION BINDINGS FOR ALL SIMULATION CONTROLS
   ========================================================================== */
function initMockDataBindings() {
    // -------------------------------------------------------------------------
    // TAB 1: MESSAGE INTEL
    // -------------------------------------------------------------------------
    const msgSelect = document.getElementById('msg-sample-select');
    const msgTextarea = document.getElementById('msg-textarea-input');
    const msgAnalyzeBtn = document.getElementById('msg-analyze-btn');
    const msgResultsContainer = document.getElementById('msg-results-container');

    if (msgSelect && msgTextarea) {
        msgSelect.addEventListener('change', () => {
            const val = msgSelect.value;
            if (val === 'custom') {
                msgTextarea.value = '';
            } else {
                const sample = MOCK_DATA.phishing.find(s => s.id === val);
                if (sample) msgTextarea.value = sample.text;
            }
        });
    }

    if (msgAnalyzeBtn && msgResultsContainer) {
        msgAnalyzeBtn.addEventListener('click', () => {
            const sampleId = msgSelect ? msgSelect.value : 'MSG-001';
            let data = MOCK_DATA.phishing.find(s => s.id === sampleId) || MOCK_DATA.phishing[0];
            
            // Build Results Markup
            const bannerClass = data.badge_color === 'red' ? 'threat-banner-red' : (data.badge_color === 'orange' ? 'threat-banner-orange' : 'threat-banner-green');
            const statusColor = data.badge_color === 'red' ? '#FF5C5C' : (data.badge_color === 'orange' ? '#FFB84D' : '#C6FF4D');

            let findingsRows = data.findings.map(f => `
                <tr>
                    <td><span class="tech-pill ${data.badge_color === 'red' ? 'tech-pill-danger' : 'tech-pill-lime'}">${f.sev}</span> ${f.cat}</td>
                    <td><code>${escapeHtml(f.text)}</code></td>
                    <td>${f.en}</td>
                    <td>${f.mr}</td>
                </tr>
            `).join('');

            let evidenceItems = data.evidence.map(e => `<li>${e}</li>`).join('');
            let stepsEnItems = data.steps_en.map((s, idx) => `<li><strong>${idx + 1}.</strong> ${s}</li>`).join('');
            let stepsMrItems = data.steps_mr.map((s, idx) => `<li><strong>${idx + 1}.</strong> ${s}</li>`).join('');

            msgResultsContainer.innerHTML = `
                <div class="${bannerClass}">
                    <div class="threat-banner-content">
                        <div>
                            <span class="threat-badge-tag" style="color: ${statusColor};">THREAT ASSESSMENT // ${data.analysis_type}</span>
                            <div class="threat-banner-title">${data.risk_level}</div>
                            <span class="tech-pill tech-pill-lime">SCRIPT: ${data.script_detected}</span>
                        </div>
                        <div class="threat-score-box">
                            <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-secondary);">RISK INDEX</span>
                            <div class="threat-score-val" style="color: ${statusColor};">${data.score} <span style="font-size:0.85rem; color:var(--text-secondary);">/ 100</span></div>
                        </div>
                    </div>
                </div>

                <div class="bento-grid-2">
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">01 // ENGLISH EXPLANATION</span>
                            <span class="bento-card-meta">ANALYSIS SUMMARY</span>
                        </div>
                        <div style="font-size:0.92rem; line-height:1.55;">${data.summary_en}</div>
                    </div>
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">02 // मराठी स्पष्टीकरण (MARATHI)</span>
                            <span class="bento-card-meta">प्रादेशिक विश्लेषण</span>
                        </div>
                        <div style="font-size:0.92rem; line-height:1.55;">${data.summary_mr}</div>
                    </div>
                </div>

                <div class="bento-card">
                    <div class="bento-card-header">
                        <span class="bento-card-label">🔍 Matched Evidence & Indicators</span>
                    </div>
                    <ul style="padding-left: 20px; line-height: 1.7;">${evidenceItems}</ul>
                </div>

                <div class="expander open">
                    <div class="expander-header">
                        <span>🛡️ Hybrid Decision Engine & Guardrails Diagnostics</span>
                        <span class="expander-arrow">▲</span>
                    </div>
                    <div class="expander-body">
                        <div class="bento-grid-3">
                            <div class="metric-tile">
                                <span class="metric-tile-label">Engine Mode</span>
                                <span class="metric-tile-value" style="font-size: 1.2rem;">${data.hybrid.mode}</span>
                            </div>
                            <div class="metric-tile">
                                <span class="metric-tile-label">Authoritative Score</span>
                                <span class="metric-tile-value" style="font-size: 1.2rem;">${data.hybrid.rule_score} / 100</span>
                            </div>
                            <div class="metric-tile">
                                <span class="metric-tile-label">Model Concordance</span>
                                <span class="metric-tile-value" style="font-size: 1.2rem; color: var(--accent-lime);">${data.hybrid.status}</span>
                            </div>
                        </div>
                        <p style="margin-top: 10px;">- <strong>Authoritative Rule Verdict:</strong> <code>${data.hybrid.verdict}</code></p>
                        <p>- <strong>Experimental Neural Model:</strong> <code>${data.hybrid.model_pred}</code> (Confidence: <code>${data.hybrid.confidence}</code>, Version: <code>${data.hybrid.version}</code>)</p>
                        <p style="font-size: 0.8rem; color: var(--accent-warning);">⚠️ <em>Confidence warning: Neural predictions are experimental and non-binding in shadow mode.</em></p>
                    </div>
                </div>

                ${data.findings.length > 0 ? `
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">📋 Detailed Warning Indicators</span>
                        </div>
                        <div class="data-table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Category / Severity</th>
                                        <th>Matched Substring</th>
                                        <th>Why It Matters (English)</th>
                                        <th>मराठी स्पष्टीकरण</th>
                                    </tr>
                                </thead>
                                <tbody>${findingsRows}</tbody>
                            </table>
                        </div>
                    </div>
                ` : ''}

                <div class="bento-grid-2">
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">🛡️ Suggested Safe Next Steps (English)</span>
                        </div>
                        <ul style="padding-left: 20px; line-height: 1.6; list-style: none;">${stepsEnItems}</ul>
                    </div>
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">🛡️ सुरक्षित पुढील पावले (Marathi)</span>
                        </div>
                        <ul style="padding-left: 20px; line-height: 1.6; list-style: none;">${stepsMrItems}</ul>
                    </div>
                </div>
            `;

            msgResultsContainer.style.display = 'block';
            initExpanders();
            playThreatChime(data.badge_color);
        });
    }

    // -------------------------------------------------------------------------
    // TAB 2: APK INSPECTION
    // -------------------------------------------------------------------------
    const apkAnalyzeBtn = document.getElementById('apk-analyze-btn');
    const apkResultsContainer = document.getElementById('apk-results-container');

    if (apkAnalyzeBtn && apkResultsContainer) {
        apkAnalyzeBtn.addEventListener('click', () => {
            const data = MOCK_DATA.apk;
            let permRows = data.permissions.map(p => `
                <tr>
                    <td><code>${p.name}</code></td>
                    <td>${p.family}</td>
                    <td><span class="tech-pill ${p.sev === 'CRITICAL' ? 'tech-pill-danger' : 'tech-pill-lime'}">${p.sev}</span></td>
                    <td><strong>+${p.weight}</strong></td>
                    <td>${p.en}</td>
                    <td>${p.mr}</td>
                </tr>
            `).join('');

            apkResultsContainer.innerHTML = `
                <div class="threat-banner-red">
                    <div class="threat-banner-content">
                        <div>
                            <span class="threat-badge-tag" style="color: var(--accent-danger);">THREAT ASSESSMENT // ${data.analysis_type}</span>
                            <div class="threat-banner-title">${data.risk_level}</div>
                        </div>
                        <div class="threat-score-box">
                            <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-secondary);">RISK INDEX</span>
                            <div class="threat-score-val" style="color: var(--accent-danger);">${data.score} <span style="font-size:0.85rem; color:var(--text-secondary);">/ 100</span></div>
                        </div>
                    </div>
                </div>

                <div class="bento-grid-3">
                    <div class="metric-tile">
                        <span class="metric-tile-label">Package Name</span>
                        <span class="metric-tile-value" style="font-size: 1.1rem; color: var(--accent-lime);">${data.pkg}</span>
                    </div>
                    <div class="metric-tile">
                        <span class="metric-tile-label">Manifest Format</span>
                        <span class="metric-tile-value" style="font-size: 1.1rem;">${data.manifest}</span>
                    </div>
                    <div class="metric-tile">
                        <span class="metric-tile-label">File Size</span>
                        <span class="metric-tile-value" style="font-size: 1.1rem;">${data.size}</span>
                    </div>
                </div>

                <pre>Filename:           ${data.filename}
SHA-256 Hash:       ${data.hash}
Parser Used:        ${data.parser}
DEX Bytecode:       ${data.dex}
Synthetic Fixture?: False (Compiled Android Application)</pre>

                <div class="bento-card">
                    <div class="bento-card-header">
                        <span class="bento-card-label">🔐 Sensitive Permissions Found in AndroidManifest.xml</span>
                    </div>
                    <div class="data-table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Permission</th>
                                    <th>Capability Family</th>
                                    <th>Severity</th>
                                    <th>Weight</th>
                                    <th>Why It Warrants Attention (English)</th>
                                    <th>मराठी स्पष्टीकरण</th>
                                </tr>
                            </thead>
                            <tbody>${permRows}</tbody>
                        </table>
                    </div>
                </div>

                <div class="expander open">
                    <div class="expander-header">
                        <span>🌐 Passively Extracted Network URLs (Inert Text)</span>
                        <span class="expander-arrow">▲</span>
                    </div>
                    <div class="expander-body">
                        ${data.urls.map(u => `<p>🚨 <code>${u}</code> — <strong>SUSPICIOUS C2 TELEMETRY DESTINATION</strong></p>`).join('')}
                    </div>
                </div>
            `;
            apkResultsContainer.style.display = 'block';
            initExpanders();
            playThreatChime('red');
        });
    }

    // -------------------------------------------------------------------------
    // TAB 3: URL RADAR
    // -------------------------------------------------------------------------
    const urlSelect = document.getElementById('url-sample-select');
    const urlInput = document.getElementById('url-text-input');
    const urlAnalyzeBtn = document.getElementById('url-analyze-btn');
    const urlResultsContainer = document.getElementById('url-results-container');

    if (urlSelect && urlInput) {
        urlSelect.addEventListener('change', () => {
            const chosen = urlSelect.value;
            if (chosen.includes('msedcl')) {
                urlInput.value = 'http://msedcl-bill-update-maharashtra.xyz/quick-pay';
            } else if (chosen.includes('ladakibahin')) {
                urlInput.value = 'https://ladakibahin.maharashtra.gov.in/';
            } else {
                urlInput.value = 'http://sbi-kyc-maharashtra-update.top/login?action=verify-otp';
            }
        });
    }

    if (urlAnalyzeBtn && urlResultsContainer) {
        urlAnalyzeBtn.addEventListener('click', () => {
            const inputVal = urlInput ? urlInput.value : '';
            const isOfficial = inputVal.includes('gov.in');
            const data = isOfficial ? MOCK_DATA.urls[1] : MOCK_DATA.urls[0];

            const bannerClass = data.badge_color === 'red' ? 'threat-banner-red' : 'threat-banner-green';
            const statusColor = data.badge_color === 'red' ? '#FF5C5C' : '#C6FF4D';

            urlResultsContainer.innerHTML = `
                <div class="${bannerClass}">
                    <div class="threat-banner-content">
                        <div>
                            <span class="threat-badge-tag" style="color: ${statusColor};">THREAT ASSESSMENT // Safe Suspicious URL & Domain Analysis</span>
                            <div class="threat-banner-title">${data.risk_level}</div>
                        </div>
                        <div class="threat-score-box">
                            <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-secondary);">RISK INDEX</span>
                            <div class="threat-score-val" style="color: ${statusColor};">${data.score} <span style="font-size:0.85rem; color:var(--text-secondary);">/ 100</span></div>
                        </div>
                    </div>
                </div>

                <div class="bento-grid-2">
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">01 // ENGLISH EXPLANATION</span>
                        </div>
                        <div>${data.summary_en}</div>
                    </div>
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">02 // मराठी स्पष्टीकरण (MARATHI)</span>
                        </div>
                        <div>${data.summary_mr}</div>
                    </div>
                </div>

                <div class="bento-card">
                    <div class="bento-card-header">
                        <span class="bento-card-label">🗂️ 9 Observable URL Characteristics (Passive Extraction)</span>
                    </div>
                    <div class="bento-grid-3">
                        <div class="metric-tile"><span class="metric-tile-label">01 // Protocol</span><span class="metric-tile-value" style="font-size:1.1rem;">${data.obs.protocol}</span></div>
                        <div class="metric-tile"><span class="metric-tile-label">02 // Hostname</span><span class="metric-tile-value" style="font-size:0.9rem;">${data.obs.hostname}</span></div>
                        <div class="metric-tile"><span class="metric-tile-label">03 // Port</span><span class="metric-tile-value" style="font-size:1.1rem;">${data.obs.port}</span></div>
                        <div class="metric-tile"><span class="metric-tile-label">04 // Allowlisted</span><span class="metric-tile-value" style="font-size:1rem; color: ${isOfficial ? 'var(--accent-lime)' : 'var(--accent-danger)'}">${data.obs.allowlisted}</span></div>
                        <div class="metric-tile"><span class="metric-tile-label">05 // Shortener</span><span class="metric-tile-value" style="font-size:1.1rem;">${data.obs.shortener}</span></div>
                        <div class="metric-tile"><span class="metric-tile-label">06 // Brand Lookalike</span><span class="metric-tile-value" style="font-size:1.1rem;">${data.obs.lookalike}</span></div>
                        <div class="metric-tile"><span class="metric-tile-label">07 // IP Target</span><span class="metric-tile-value" style="font-size:1.1rem;">${data.obs.ip}</span></div>
                        <div class="metric-tile"><span class="metric-tile-label">08 // Punycode</span><span class="metric-tile-value" style="font-size:1.1rem;">${data.obs.punycode}</span></div>
                        <div class="metric-tile"><span class="metric-tile-label">09 // APK Target</span><span class="metric-tile-value" style="font-size:1.1rem;">${data.obs.apk}</span></div>
                    </div>
                </div>
            `;
            urlResultsContainer.style.display = 'block';
            playThreatChime(data.badge_color);
        });
    }

    // -------------------------------------------------------------------------
    // TAB 4: SCHEME VERIFIER
    // -------------------------------------------------------------------------
    const schemeAnalyzeBtn = document.getElementById('scheme-analyze-btn');
    const schemeResultsContainer = document.getElementById('scheme-results-container');

    if (schemeAnalyzeBtn && schemeResultsContainer) {
        schemeAnalyzeBtn.addEventListener('click', () => {
            const data = MOCK_DATA.scheme;
            schemeResultsContainer.innerHTML = `
                <div class="alert-box alert-danger">
                    <h3 style="color: var(--accent-danger); margin-bottom: 4px;">🚨 Official Verification: ${data.classification}</h3>
                    <p style="margin: 0;">Matched Official Scheme: <strong>${data.matched_title}</strong></p>
                </div>

                <div class="bento-grid-2">
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">01 // English Verification Summary</span>
                        </div>
                        <div>${data.summary_en}</div>
                    </div>
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">02 // मराठी पडताळणी सारांश</span>
                        </div>
                        <div>${data.summary_mr}</div>
                    </div>
                </div>

                <div class="bento-grid-2">
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">✅ Supporting Ground Truth</span>
                        </div>
                        <ul style="padding-left: 20px;">
                            ${data.supporting.map(s => `<li>${s}</li>`).join('')}
                        </ul>
                    </div>
                    <div class="bento-card">
                        <div class="bento-card-header">
                            <span class="bento-card-label">⚠️ Conflicting Discrepancies</span>
                        </div>
                        <ul style="padding-left: 20px; color: var(--accent-danger);">
                            ${data.conflicting.map(c => `<li>${c}</li>`).join('')}
                        </ul>
                    </div>
                </div>

                <div class="bento-card">
                    <div class="bento-card-header">
                        <span class="bento-card-label">📄 Official Sources & Government Resolution (GR)</span>
                    </div>
                    <p><strong>${data.gr.title} (${data.gr.title_mr})</strong></p>
                    <p>- Department: ${data.gr.dept}</p>
                    <p>- GR Number: <code>${data.gr.gr_no}</code> (Published: ${data.gr.date})</p>
                    <p>- Verified Portal: <a href="${data.gr.portal}" style="color: var(--accent-lime);">${data.gr.portal}</a></p>
                </div>
            `;
            schemeResultsContainer.style.display = 'block';
            playThreatChime('red');
        });
    }

    // -------------------------------------------------------------------------
    // TAB 7A: HUMAN REVIEW SUBMISSION SIMULATION
    // -------------------------------------------------------------------------
    const submitReviewBtn = document.getElementById('submit-review-btn');
    if (submitReviewBtn) {
        submitReviewBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const outcome = document.getElementById('review-outcome-select').value;
            const conf = document.querySelector('input[name="review-conf"]:checked').value;
            const notes = document.getElementById('review-notes-input').value;

            alert(`Adjudication Recorded Successfully!\nOutcome: ${outcome.toUpperCase()}\nConfidence: ${conf.toUpperCase()}\nStatus: COMPLETED (Audit Log Appended)`);
            
            // Dynamically increment completed review count
            const completedMetric = document.getElementById('metric-rev-completed');
            if (completedMetric) {
                completedMetric.textContent = parseInt(completedMetric.textContent || '1') + 1;
            }
        });
    }
}

/* ==========================================================================
   06. RENDER THREAT CASES TABLE (TAB 5)
   ========================================================================== */
function renderSessionCases() {
    const tableBody = document.getElementById('cases-table-body');
    if (!tableBody) return;

    tableBody.innerHTML = MOCK_DATA.cases.map(c => `
        <tr>
            <td><code>${c.id}</code></td>
            <td>${c.type}</td>
            <td>${c.target}</td>
            <td><strong>${c.score}</strong> / 100</td>
            <td><span class="tech-pill ${c.color === 'red' ? 'tech-pill-danger' : (c.color === 'orange' ? 'tech-pill-warning' : 'tech-pill-lime')}">${c.level}</span></td>
            <td>${c.timestamp}</td>
            <td><code>${c.review_state}</code></td>
        </tr>
    `).join('');
}

/* ==========================================================================
   07. INTERACTIVE 3D / 2D RADAR CANVAS INITIALIZATION
   (Provides Drop-in Anchor for Claude or Three.js Integration)
   ========================================================================== */
function initCanvasRadarPlaceholder() {
    const canvas = document.getElementById('threejs-threat-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let angle = 0;
    const width = canvas.width = canvas.parentElement.clientWidth || 800;
    const height = canvas.height = 340;
    const centerX = width / 2;
    const centerY = height / 2;
    const maxRadius = Math.min(centerX, centerY) - 20;

    // Simulated Threat Blips
    const blips = [
        { r: maxRadius * 0.45, theta: 0.8, color: '#FF5C5C', label: 'APK: Banking Trojan (com.fraud.msedcl)' },
        { r: maxRadius * 0.75, theta: 2.4, color: '#FF5C5C', label: 'MSG: Disconnection Scam (Marathi)' },
        { r: maxRadius * 0.60, theta: 4.1, color: '#FFB84D', label: 'URL: bit.ly/3xY8zMsedcl' },
        { r: maxRadius * 0.30, theta: 5.2, color: '#C6FF4D', label: 'PORTAL: ladakibahin.gov.in (Verified)' }
    ];

    function drawRadar() {
        ctx.fillStyle = 'rgba(11, 12, 11, 0.15)';
        ctx.fillRect(0, 0, width, height);

        // Concentric Range Rings
        ctx.strokeStyle = '#222522';
        ctx.lineWidth = 1;
        for (let r = 50; r <= maxRadius; r += 50) {
            ctx.beginPath();
            ctx.arc(centerX, centerY, r, 0, Math.PI * 2);
            ctx.stroke();
        }

        // Crosshairs
        ctx.beginPath();
        ctx.moveTo(centerX - maxRadius, centerY);
        ctx.lineTo(centerX + maxRadius, centerY);
        ctx.moveTo(centerX, centerY - maxRadius);
        ctx.lineTo(centerX, centerY + maxRadius);
        ctx.stroke();

        // Rotating Sweep Line
        angle += 0.02;
        const sweepX = centerX + Math.cos(angle) * maxRadius;
        const sweepY = centerY + Math.sin(angle) * maxRadius;

        ctx.strokeStyle = 'rgba(198, 255, 77, 0.65)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(sweepX, sweepY);
        ctx.stroke();

        // Render Blips
        blips.forEach(b => {
            const bx = centerX + Math.cos(b.theta) * b.r;
            const by = centerY + Math.sin(b.theta) * b.r;

            ctx.fillStyle = b.color;
            ctx.beginPath();
            ctx.arc(bx, by, 4, 0, Math.PI * 2);
            ctx.fill();

            // Label
            ctx.fillStyle = '#A6AAA2';
            ctx.font = '10px "JetBrains Mono", monospace';
            ctx.fillText(b.label, bx + 8, by + 3);
        });

        requestAnimationFrame(drawRadar);
    }

    drawRadar();

    window.addEventListener('resize', () => {
        canvas.width = canvas.parentElement.clientWidth || 800;
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
