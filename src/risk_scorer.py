"""
Heuristic Risk Scoring Engine for Seva Cyber Sandbox.

METHODOLOGY & DEDUPLICATION RULES:
1. Separate scoring logic and terminology for APK Static Permission-Risk vs. Text Phishing Indicators.
2. Capability Family Caps prevent double-counting overlapping permissions:
   - SMS_ACCESS family (READ_SMS, RECEIVE_SMS, SEND_SMS) is capped at 40 points max.
   - CALL_CONTACTS family (READ_CONTACTS, READ_CALL_LOG) is capped at 18 points max.
   - DEVICE_SENSORS family (CAMERA, RECORD_AUDIO) is capped at 20 points max.
3. Scores are heuristic severity indices (0-100), NOT mathematical probabilities of maliciousness.
"""

from typing import Any, Dict, List

FAMILY_CAPS: Dict[str, int] = {
    "SCREEN_CONTROL": 35,
    "SMS_ACCESS": 40,
    "PACKAGE_INSTALL": 24,
    "SCREEN_OVERLAY": 16,
    "CALL_CONTACTS": 18,
    "DEVICE_SENSORS": 20,
    "LOCATION": 8,
}


def score_apk_analysis(apk_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes a deduplicated 0-100 heuristic permission-risk score for an APK analysis dictionary.
    """
    if not apk_result.get("is_valid_apk"):
        err = apk_result.get("error_message") or "File could not be parsed as a valid APK archive."
        return {
            "analysis_type": "APK Static Permission-Risk Assessment",
            "risk_level": "Invalid or Unreadable File (Cannot Verify)",
            "score": 0,
            "badge_color": "red",
            "summary_en": err,
            "summary_mr": "ही फाईल वैध अँड्रॉइड (.apk) फाईल नाही किंवा ती खराब (corrupt) झालेली आहे.",
            "evidence": [err],
            "safe_next_steps_en": [
                "Do not attempt to open or install this file.",
                "Delete the file from your Downloads or WhatsApp media folder.",
            ],
            "safe_next_steps_mr": [
                "ही फाईल उघडण्याचा किंवा इन्स्टॉल करण्याचा प्रयत्न करू नका.",
                "तुमच्या फोनमधून ही फाईल तात्काळ डिलीट करा.",
            ],
            "observed_facts": ["Archive could not be validated or decompressed."],
            "heuristic_inferences": [f"Risk assessment aborted: {err}"],
            "limitations": (
                "Static inspection cannot analyze corrupted, encrypted, oversized, or non-APK files."
            ),
        }

    family_totals: Dict[str, int] = {}
    evidence_list: List[str] = []

    for perm in apk_result.get("permissions_found", []):
        fam = perm.get("family", "OTHER")
        weight = int(perm.get("weight", 10))
        cap = FAMILY_CAPS.get(fam, 30)
        previous = family_totals.get(fam, 0)
        family_totals[fam] = min(cap, previous + weight)
        evidence_list.append(
            f"Declared Permission [{perm['short_name']}] ({perm['severity']} sensitivity, family '{fam}'): {perm['reason_en']}"
        )

    raw_score = sum(family_totals.values())

    # Synergy bonus only when two distinct high-risk capability families co-occur
    active_families = set(family_totals.keys())
    if "SMS_ACCESS" in active_families and (
        "SCREEN_CONTROL" in active_families or "PACKAGE_INSTALL" in active_families
    ):
        raw_score += 12
        evidence_list.append(
            "Multi-Family Risk Combination: Requests both SMS access and screen/package installation control."
        )

    if apk_result.get("heuristic_warnings"):
        raw_score += 10
        for hw in apk_result["heuristic_warnings"]:
            evidence_list.append(hw)

    if apk_result.get("passive_urls"):
        raw_score += 8
        evidence_list.append(
            f"Passively extracted {len(apk_result['passive_urls'])} embedded external URL string(s) inside package."
        )

    final_score = min(100, raw_score)

    if final_score >= 55:
        risk_level = "High-Risk Permission Indicators Detected"
        badge_color = "red"
        summary_en = (
            "This package requests high-sensitivity capabilities (such as SMS interception, accessibility "
            "screen control, or secondary package installation) frequently abused in WhatsApp APK scams."
        )
        summary_mr = (
            "सावधान! हे ॲप तुमचे एसएमएस (SMS/OTP) वाचण्याची किंवा स्क्रीन नियंत्रित करण्याची संवेदनशील परवानगी मागते. "
            "व्हॉट्सॲपवर आलेली अशी फाईल इन्स्टॉल करू नका."
        )
    elif final_score >= 20:
        risk_level = "Potentially Suspicious Permission Profile (Review Context)"
        badge_color = "orange"
        summary_en = (
            "This package requests access to personal device data (such as contacts, call logs, microphone, or location). "
            "Verify the publisher independently before installing outside the Google Play Store."
        )
        summary_mr = (
            "हे ॲप कॉन्टॅक्ट्स, कॉल हिस्ट्री किंवा लोकेशन सारख्या परवानग्या मागते. अधिकृत Google Play Store शिवाय असे ॲप इन्स्टॉल करणे टाळावे."
        )
    else:
        risk_level = "No Strong Permission-Risk Indicators Detected"
        badge_color = "green"
        summary_en = (
            "No high-risk SMS or accessibility permissions were found in the manifest. "
            "However, static permission inspection cannot guarantee that an unverified APK is safe."
        )
        summary_mr = (
            "या फाईलमध्ये एसएमएस किंवा स्क्रीन नियंत्रणाच्या धोक्याच्या परवानग्या आढळल्या नाहीत. तरीही अनोळखी स्रोतावरून घेतलेले ॲप सावधगिरीने वापरावे."
        )

    return {
        "analysis_type": "APK Static Permission-Risk Assessment",
        "risk_level": risk_level,
        "score": final_score,
        "badge_color": badge_color,
        "summary_en": summary_en,
        "summary_mr": summary_mr,
        "evidence": evidence_list if evidence_list else ["No sensitive permissions from the watch catalog were declared."],
        "safe_next_steps_en": [
            "Never install .apk files received over WhatsApp claiming to be from MSEDCL, banks, RTO, or welfare schemes.",
            "Download utility and banking apps strictly from the official Google Play Store.",
            "If an untrusted APK was already installed, enable Airplane Mode, uninstall it via Settings -> Apps, and call 1930 if banking details were exposed.",
        ],
        "safe_next_steps_mr": [
            "व्हॉट्सॲपवर महावितरण, बँक किंवा सरकारी योजनेच्या नावाने आलेली कोणतीही .apk फाईल इन्स्टॉल करू नका.",
            "अधिकृत ॲप्स नेहमी Google Play Store वरूनच डाउनलोड करा.",
            "चुकून अशी फाईल इन्स्टॉल झाली असल्यास तात्काळ इंटरनेट बंद करा, सेटिंग्जमधून ॲप अनइन्स्टॉल करा आणि १९३० (1930) सायबर हेल्पलाईनवर संपर्क साधा.",
        ],
        "observed_facts": apk_result.get("observed_facts", []),
        "heuristic_inferences": apk_result.get("heuristic_inferences", [])
        + [f"Calculated heuristic risk index: {final_score}/100 ({risk_level})"],
        "limitations": (
            "Heuristic Score Limitation: This 0-100 index is a weighted checklist of declared permissions and structural traits, "
            "NOT a probability of maliciousness. Legitimate apps may also request sensitive permissions, and static analysis does not inspect runtime code execution."
        ),
    }


def score_message_analysis(msg_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes a deduplicated 0-100 heuristic phishing indicator score for a message analysis dictionary.
    """
    if msg_result.get("is_empty"):
        return {
            "analysis_type": "Text-Based Vernacular Phishing Assessment",
            "risk_level": "No Input Provided",
            "score": 0,
            "badge_color": "gray",
            "summary_en": msg_result.get("advice_en", "Please enter a message to analyze."),
            "summary_mr": msg_result.get("advice_mr", "कृपया तपासणीसाठी मेसेज टाका."),
            "evidence": [],
            "safe_next_steps_en": [],
            "safe_next_steps_mr": [],
            "observed_facts": msg_result.get("observed_facts", ["Empty input"]),
            "heuristic_inferences": msg_result.get("heuristic_inferences", ["No risk assessment performed"]),
            "limitations": msg_result.get("uncertainty_note", ""),
        }

    findings = msg_result.get("findings", [])
    seen_ids = set()
    raw_score = 0
    evidence_list: List[str] = []

    for item in findings:
        rid = item["id"]
        if rid not in seen_ids:
            seen_ids.add(rid)
            raw_score += int(item["weight"])
            evidence_list.append(
                f"[{item['category']}] Matched '{item['matched_text']}' — {item['why_it_matters_en']}"
            )

    if len(seen_ids) >= 3:
        raw_score += 10

    final_score = min(100, raw_score)

    if final_score >= 50:
        risk_level = "High-Risk Phishing Indicators Detected"
        badge_color = "red"
        summary_en = (
            "This message combines high-risk social engineering warning signs (such as OTP/PIN requests, "
            ".apk installation lures, urgent disconnection threats, or unverified web links)."
        )
        summary_mr = (
            "धोकादायक संकेत! या मेसेजमध्ये भीती दाखवून तात्काळ कृती करण्याची मागणी, संशयास्पद लिंक, .apk फाईल किंवा OTP/PIN ची मागणी आढळली आहे."
        )
    elif final_score >= 20:
        risk_level = "Potentially Suspicious Message (Verify Independently)"
        badge_color = "orange"
        summary_en = (
            "This message contains warning signs often seen in phishing or task scams. "
            "Verify the claim independently before clicking links or replying."
        )
        summary_mr = (
            "संशयास्पद मेसेज: यातील माहितीची अधिकृत कार्यालयात किंवा अधिकृत वेबसाइटवर खात्री केल्याशिवाय कोणत्याही लिंकवर क्लिक करू नका."
        )
    else:
        risk_level = "No Strong Phishing Indicators Detected"
        badge_color = "green"
        summary_en = (
            "No strong phishing patterns were matched in this text. However, automated rules cannot "
            "catch every scam—always verify unexpected payment or personal data requests."
        )
        summary_mr = (
            "या मेसेजमध्ये फसवणुकीचे ठळक संकेत आढळले नाहीत. तरीही अनोळखी व्यक्तीकडून आलेल्या पैशांच्या किंवा वैयक्तिक माहितीच्या मागणीबाबत नेहमी सावध राहा."
        )

    return {
        "analysis_type": "Text-Based Vernacular Phishing Assessment",
        "risk_level": risk_level,
        "score": final_score,
        "badge_color": badge_color,
        "summary_en": summary_en,
        "summary_mr": summary_mr,
        "evidence": evidence_list if evidence_list else ["No phishing indicator rules were triggered."],
        "safe_next_steps_en": [
            "Do not click links or call private mobile numbers inside unexpected urgent messages.",
            "Check your electricity bill, challan, or KYC status by visiting the official website or local office directly.",
            "Never share your OTP, UPI PIN, or password—even if someone claims to be from MSEDCL, a bank, or police.",
            "Report suspected cyber fraud immediately to 1930 or https://cybercrime.gov.in.",
        ],
        "safe_next_steps_mr": [
            "मेसेजमध्ये दिलेल्या अनोळखी लिंकवर क्लिक करू नका किंवा त्यातील खाजगी मोबाईल नंबरवर कॉल करू नका.",
            "तुमचे वीज बिल किंवा केवायसी (KYC) स्थिती फक्त अधिकृत वेबसाइट किंवा कार्यालयात जाऊनच तपासा.",
            "बँक, महावितरण किंवा पोलीस अधिकारी असल्याचा दावा करणाऱ्या कोणालाही तुमचा OTP किंवा UPI PIN सांगू नका.",
            "सायबर फसवणुकीची तक्रार १९३० (1930) या हेल्पलाईनवर किंवा cybercrime.gov.in वर नोंदवा.",
        ],
        "observed_facts": msg_result.get("observed_facts", []),
        "heuristic_inferences": msg_result.get("heuristic_inferences", [])
        + [f"Calculated heuristic risk index: {final_score}/100 ({risk_level})"],
        "limitations": msg_result.get(
            "uncertainty_note",
            "Heuristic text scoring evaluates known patterns and is not a guarantee of safety.",
        ),
    }


def apply_threat_intelligence_to_score(
    scored_res: Dict[str, Any],
    threat_intel: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Additive helper that integrates threat intelligence matches into risk assessment.

    DECISION BOUNDARY:
    - Only 'reviewed' threat indicators can increase the risk index (up to 20 pts, capped at 100).
    - 'unreviewed' leads are treated as informational and do NOT increase the risk score.
    - A threat intelligence match is NOT sole proof of fraud; it is added as corroborating evidence.
    """
    if not threat_intel or not threat_intel.get("has_matches"):
        return scored_res

    updated = dict(scored_res)
    updated["observed_facts"] = list(scored_res.get("observed_facts", []))
    updated["heuristic_inferences"] = list(scored_res.get("heuristic_inferences", []))
    updated["evidence"] = list(scored_res.get("evidence", []))

    trusted_count = threat_intel.get("trusted_matches_count", 0)
    unreviewed_count = threat_intel.get("unreviewed_leads_count", 0)

    if trusted_count > 0:
        base_score = int(scored_res.get("score", 0))
        bonus = min(20, trusted_count * 10)
        new_score = min(100, base_score + bonus)
        updated["score"] = new_score

        if new_score >= 50 and updated.get("badge_color") != "red":
            updated["badge_color"] = "red"
            updated["risk_level"] = "High-Risk Threat Indicators Detected (Intelligence Match)"

        evidence_str = (
            f"[Threat Intelligence] Matched {trusted_count} verified indicator(s) in local repository "
            f"(Severity: {threat_intel.get('highest_severity') or 'high'}, Confidence: {threat_intel.get('highest_confidence')}%)."
        )
        updated["evidence"].insert(0, evidence_str)
        updated["heuristic_inferences"].append(
            f"Threat Intelligence Adjustment: Added {bonus} risk points for verified indicator match."
        )

    if unreviewed_count > 0:
        updated["observed_facts"].append(
            f"Knowledge Base Lead: {unreviewed_count} unreviewed indicator(s) matched in local repository (requires analyst verification)."
        )

    return updated
