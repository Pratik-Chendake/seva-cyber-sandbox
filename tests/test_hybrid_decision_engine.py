"""
Comprehensive Unit Test Suite for Hybrid Decision Engine and Safety Guardrails.
Part of Seva Cyber Sandbox (Phase 4).

Covers all 16 required verification scenarios:
1. Default mode (shadow) cannot let model predictions change production risk scores.
2. rules_only mode completely disables experimental model inference.
3. Shadow mode records model/rule concordance without altering existing outcomes.
4. Strong rule-based evidence is never suppressed by a benign model prediction.
5. A model-only phishing prediction cannot establish confirmed fraud.
6. Unreviewed threat intelligence does not increase trusted risk score.
7. Malformed, missing, or corrupt checkpoints cause safe rule-based fallback.
8. NaN, infinity, or invalid probability outputs are rejected safely.
9. Invalid configuration does not enable a more permissive or model-controlled mode.
10. Marathi (Devanagari), Romanized Marathi, English, and mixed-language inputs are handled.
11. Protective advisories do not automatically become phishing due to isolated keywords.
12. Legitimate messages containing URLs are not classified as fraud solely because a URL exists.
13. Existing risk score bounds (0-100) and schema remain strictly compatible.
14. No raw message text or personal information is written to diagnostics/telemetry.
15. Zero network calls occur during model loading or inference.
16. Locked evaluation dataset digest is verified and unchanged.
"""

import hashlib
import json
import os
import socket
import tempfile
from typing import Any, Dict, List
import numpy as np
import pytest

from src.hybrid_decision_engine import (
    ENGINE_VERSION,
    HybridDecisionEngine,
    HybridOperatingMode,
    SafeModelHolder,
    evaluate_message_hybrid,
    parse_operating_mode,
)
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_message_analysis
from src.dataset_validator import compute_locked_test_hash, verify_locked_test_integrity

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CHECKPOINT_DIR = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1")
LOCKED_MANIFEST_PATH = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
EVAL_DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")


# ---------------------------------------------------------------------------
# Test 1: Default Mode (Shadow) Cannot Alter Production Risk Scores
# ---------------------------------------------------------------------------

def test_01_default_mode_cannot_alter_production_risk_scores():
    """In shadow mode, production risk score must be strictly invariant to model predictions."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)
    assert engine.operating_mode == HybridOperatingMode.SHADOW

    test_messages = [
        "प्रिय ग्राहक, महावितरण बिल भरा http://scam.in",
        "Your electricity bill is paid successfully. Thank you for using MSEDCL.",
        "सायबर पोलीस सावधानता: कोणालाही OTP किंवा UPI PIN सांगू नका.",
        "Emergency loan approved! Send Aadhaar details immediately to 9822000000.",
    ]

    for msg in test_messages:
        rule_res = analyze_message_text(msg)
        expected_rule_score = score_message_analysis(rule_res)["score"]

        hybrid_res = engine.evaluate_message(msg)
        final_score = hybrid_res["final_decision"]["final_risk_score"]
        diff = hybrid_res["final_decision"]["production_score_difference"]

        assert final_score == expected_rule_score, f"Score mismatch on '{msg}': {final_score} != {expected_rule_score}"
        assert diff == 0, f"Production score difference must be 0 in shadow mode, got {diff}"
        assert hybrid_res["operating_mode"] == "shadow"


# ---------------------------------------------------------------------------
# Test 2: rules_only Mode Disables Model Inference Completely
# ---------------------------------------------------------------------------

def test_02_rules_only_mode_disables_model_inference():
    """In rules_only mode, model inference must be completely bypassed."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.RULES_ONLY, checkpoint_dir=CHECKPOINT_DIR)
    assert engine.operating_mode == HybridOperatingMode.RULES_ONLY

    res = engine.evaluate_message("प्रिय ग्राहक, महावितरण बिल भरा http://scam.in")
    model_sec = res["experimental_model"]

    assert model_sec["is_enabled"] is False
    assert model_sec["is_available"] is False
    assert model_sec["predicted_label"] is None
    assert model_sec["confidence_scores"] is None
    assert "Disabled" in model_sec["fallback_reason"]
    assert res["concordance"]["status"] == "NOT_APPLICABLE"


# ---------------------------------------------------------------------------
# Test 3: Shadow Mode Records Concordance Without Changing Results
# ---------------------------------------------------------------------------

def test_03_shadow_mode_records_concordance_without_changing_results():
    """Shadow mode must correctly compute agreement/disagreement without affecting decisions."""
    engine_shadow = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)
    engine_rules = HybridDecisionEngine(operating_mode=HybridOperatingMode.RULES_ONLY, checkpoint_dir=CHECKPOINT_DIR)

    msg = "प्रिय ग्राहक, महावितरण बिल भरा http://scam.in"
    res_shadow = engine_shadow.evaluate_message(msg)
    res_rules = engine_rules.evaluate_message(msg)

    # Concordance must be recorded
    assert res_shadow["concordance"]["status"] in ("AGREEMENT", "DISAGREEMENT")
    assert res_shadow["experimental_model"]["is_available"] is True
    assert res_shadow["experimental_model"]["predicted_label"] is not None

    # Final decision scores and verdict must match rules_only exactly
    assert res_shadow["final_decision"]["final_risk_score"] == res_rules["final_decision"]["final_risk_score"]
    assert res_shadow["final_decision"]["risk_level"] == res_rules["final_decision"]["risk_level"]
    assert res_shadow["final_decision"]["badge_color"] == res_rules["final_decision"]["badge_color"]
    assert res_shadow["final_decision"]["action_verdict"] == res_rules["final_decision"]["action_verdict"]


# ---------------------------------------------------------------------------
# Test 4: Strong Rule-Based Evidence Never Suppressed by Benign Model
# ---------------------------------------------------------------------------

def test_04_strong_rule_evidence_never_suppressed_by_benign_model():
    """High-risk rule findings cannot be suppressed even if the model predicts legitimate."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)

    # Mock model to simulate a false negative (predicting legitimate on obvious scam)
    engine.model_holder.predict_safe = lambda text: {
        "is_enabled": True,
        "is_available": True,
        "predicted_label": "legitimate",
        "predicted_index": 1,
        "confidence": 0.99,
        "confidence_scores": {"phishing": 0.01, "legitimate": 0.99, "protective_advisory": 0.0},
        "is_calibrated": False,
        "model_version": "mock-test",
        "checkpoint_dir": CHECKPOINT_DIR,
        "fallback_reason": None,
        "confidence_warning": "Mock warning",
    }

    # Severe scam with OTP request + urgency + link
    severe_scam = "तातडीची सूचना: तुमचे वीज बिल थकीत आहे. आज रात्री वीज खंडित होईल. त्वरित OTP सांगा http://fake-msedcl.in"
    res = engine.evaluate_message(severe_scam)

    assert res["final_decision"]["final_risk_score"] >= 50
    assert res["final_decision"]["action_verdict"] == "HIGH_RISK_BLOCK"
    assert res["final_decision"]["badge_color"] == "red"
    assert any("GR-02" in g for g in res["final_decision"]["guardrails_applied"])


# ---------------------------------------------------------------------------
# Test 5: Model-Only Phishing Prediction Cannot Establish Confirmed Fraud
# ---------------------------------------------------------------------------

def test_05_model_only_phishing_prediction_cannot_confirm_fraud():
    """A model prediction of phishing without rule evidence cannot mark a benign message as fraud."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)

    # Mock model to simulate a false positive (predicting phishing on harmless message)
    engine.model_holder.predict_safe = lambda text: {
        "is_enabled": True,
        "is_available": True,
        "predicted_label": "phishing",
        "predicted_index": 0,
        "confidence": 0.95,
        "confidence_scores": {"phishing": 0.95, "legitimate": 0.03, "protective_advisory": 0.02},
        "is_calibrated": False,
        "model_version": "mock-test",
        "checkpoint_dir": CHECKPOINT_DIR,
        "fallback_reason": None,
        "confidence_warning": "Mock warning",
    }

    harmless_text = "Good morning! Your OPD appointment is scheduled for tomorrow at 10 AM at Civil Hospital."
    res = engine.evaluate_message(harmless_text)

    # Must NOT become high-risk fraud block
    assert res["final_decision"]["final_risk_score"] < 20
    assert res["final_decision"]["action_verdict"] == "INFORMATIONAL_SAFE"
    assert res["final_decision"]["badge_color"] == "green"
    assert any("GR-03" in g for g in res["final_decision"]["guardrails_applied"])


# ---------------------------------------------------------------------------
# Test 6: Unreviewed Threat Intelligence Does Not Increase Trusted Risk
# ---------------------------------------------------------------------------

def test_06_unreviewed_threat_intelligence_does_not_increase_trusted_risk():
    """Unreviewed intelligence leads must be logged but cannot increase trusted risk scores."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)

    msg = "Your bill receipt is available for download."
    unreviewed_intel = {
        "has_matches": True,
        "trusted_matches_count": 0,
        "unreviewed_leads_count": 3,
        "highest_severity": "high",
        "highest_confidence": 75,
        "trusted_matches": [],
        "unreviewed_leads": [
            {"indicator_id": "IND-UNREV-1", "indicator_type": "url", "severity": "high", "confidence_score": 75},
            {"indicator_id": "IND-UNREV-2", "indicator_type": "domain", "severity": "medium", "confidence_score": 60},
        ],
    }

    res = engine.evaluate_message(msg, threat_intel=unreviewed_intel)

    # Base rule score for this message is 0
    assert res["final_decision"]["final_risk_score"] == 0
    assert res["threat_intelligence"]["unreviewed_leads_count"] == 3
    assert res["threat_intelligence"]["trusted_matches_count"] == 0
    assert any("GR-04" in g for g in res["final_decision"]["guardrails_applied"])


# ---------------------------------------------------------------------------
# Test 7: Malformed, Missing, or Corrupt Checkpoints Cause Safe Fallback
# ---------------------------------------------------------------------------

def test_07_safe_fallback_on_missing_or_corrupt_checkpoint():
    """Missing or corrupted checkpoints must safely fall back to rule-based analysis."""
    # 1. Nonexistent directory
    missing_dir = os.path.join(tempfile.gettempdir(), "_missing_ckpt_test_dir_123")
    engine_missing = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=missing_dir)

    res_missing = engine_missing.evaluate_message("महावितरण बिल भरा")
    assert res_missing["experimental_model"]["is_available"] is False
    assert "not found" in res_missing["experimental_model"]["fallback_reason"].lower()
    assert res_missing["final_decision"]["final_risk_score"] >= 0

    # 2. Corrupt directory with invalid weights
    with tempfile.TemporaryDirectory() as corrupt_dir:
        meta_path = os.path.join(corrupt_dir, "model_metadata.json")
        weights_path = os.path.join(corrupt_dir, "model_weights.npz")

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"model_version": "corrupt", "input_dim": 1024, "hidden_dim1": 64, "hidden_dim2": 32, "num_classes": 3}, f)

        # Write corrupt file
        with open(weights_path, "wb") as f:
            f.write(b"CORRUPTED_NON_NPZ_DATA_HEADER")

        engine_corrupt = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=corrupt_dir)
        res_corrupt = engine_corrupt.evaluate_message("महावितरण बिल भरा")

        assert res_corrupt["experimental_model"]["is_available"] is False
        assert res_corrupt["final_decision"]["final_risk_score"] >= 0
        assert any("GR-07" in g for g in res_corrupt["final_decision"]["guardrails_applied"])


# ---------------------------------------------------------------------------
# Test 8: NaN, Infinity, or Invalid Probability Outputs are Rejected
# ---------------------------------------------------------------------------

def test_08_rejection_of_nan_infinity_or_invalid_probabilities():
    """Non-finite or out-of-bounds probability outputs must be rejected safely."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)

    # Simulate model producing NaN in prediction
    class BrokenModel:
        model_version = "broken-v1"
        def predict_one(self, text, hasher=None):
            return {
                "predicted_label": "phishing",
                "predicted_index": 0,
                "confidence": float("nan"),
                "probabilities": {
                    "phishing": float("nan"),
                    "legitimate": 0.5,
                    "protective_advisory": 0.5,
                },
                "model_version": "broken-v1",
            }

    holder = SafeModelHolder(CHECKPOINT_DIR)
    holder._model = BrokenModel()
    holder._load_attempted = True
    holder._load_error = None

    safe_pred = holder.predict_safe("Test input")
    assert safe_pred["is_available"] is False
    assert "Non-finite" in safe_pred["fallback_reason"]


# ---------------------------------------------------------------------------
# Test 9: Invalid Configuration Does Not Enable Permissive Mode
# ---------------------------------------------------------------------------

def test_09_invalid_configuration_fails_safe_to_shadow():
    """Malformed or invalid operating mode strings must fall back to SHADOW."""
    for bad_mode in ["autonomous", "production_ai", "", "123", "NULL", "model_overrides_rules"]:
        mode = parse_operating_mode(bad_mode)
        assert mode == HybridOperatingMode.SHADOW, f"Failed for mode: {bad_mode}"

    engine = HybridDecisionEngine(operating_mode="unrecognized_mode_xyz")
    assert engine.operating_mode == HybridOperatingMode.SHADOW


# ---------------------------------------------------------------------------
# Test 10: Multilingual Vernacular Inputs Handled
# ---------------------------------------------------------------------------

def test_10_multilingual_vernacular_inputs_handled():
    """Engine must handle pure Marathi, Romanized Marathi, English, and Mixed texts."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)

    samples = [
        ("mr", "महावितरण वीज बिल भरण्यासाठी येथे क्लिक करा."),
        ("mr-Latn", "Tumche light bill pending aahe. Aata ch bhara."),
        ("mr-en", "MSEDCL bill alert: payment update karun ghya."),
        ("en", "Urgent security notice: update your KYC immediately."),
    ]

    for lang, text in samples:
        res = engine.evaluate_message(text)
        assert "engine_version" in res
        assert "rule_based_evidence" in res
        assert "concordance" in res
        assert "final_decision" in res
        assert 0 <= res["final_decision"]["final_risk_score"] <= 100


# ---------------------------------------------------------------------------
# Test 11: Protective Advisories Not Phishing From Isolated Keywords
# ---------------------------------------------------------------------------

def test_11_protective_advisories_not_phishing_from_isolated_keywords():
    """Security advisories containing words like OTP or PIN must not be flagged as phishing."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)

    advisories = [
        "सायबर पोलीस सावधानता: महावितरण किंवा बँक अधिकारी कधीही OTP किंवा PIN मागत नाहीत. कोणालाही सांगू नका.",
        "Security Alert: Never share your OTP or UPI PIN with anyone claiming to be from customer care.",
        "MahaVitaran Safety Note: Do not click unknown links or share netbanking password with callers.",
    ]

    for adv in advisories:
        res = engine.evaluate_message(adv)
        assert res["final_decision"]["final_risk_score"] < 20, f"Advisory falsely escalated: {adv} -> {res['final_decision']['final_risk_score']}"
        assert res["final_decision"]["action_verdict"] == "INFORMATIONAL_SAFE"


# ---------------------------------------------------------------------------
# Test 12: Legitimate Messages With URLs Not Classified as Fraud
# ---------------------------------------------------------------------------

def test_12_legitimate_messages_with_urls_not_fraud_solely_from_url():
    """Legitimate messages containing official or informative URLs must not become fraud solely due to the URL."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)

    legit_with_url = (
        "महावितरण अधिकृत सूचना: आपल्या वीज मीटरचे मासिक वाचन नोंदवण्यासाठी https://www.mahadiscom.in वर भेट द्या."
    )
    res = engine.evaluate_message(legit_with_url)

    # Must not be high-risk fraud block
    assert res["final_decision"]["final_risk_score"] < 50
    assert res["final_decision"]["badge_color"] != "red"


# ---------------------------------------------------------------------------
# Test 13: Existing Risk Score Bounds and Schema Remain Compatible
# ---------------------------------------------------------------------------

def test_13_existing_risk_score_bounds_and_schema_compatibility():
    """Scores must stay in [0, 100] and structured schema must contain all expected contract keys."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)

    test_cases = [
        "",
        "   ",
        "Simple text",
        "MSEDCL urgent disconnection tonight! Pay now: http://pay.in",
        "A" * 500,
    ]

    expected_keys = {
        "engine_version",
        "operating_mode",
        "rule_based_evidence",
        "threat_intelligence",
        "experimental_model",
        "concordance",
        "final_decision",
        "advisory_notes",
        "audit_metadata",
    }

    for tc in test_cases:
        res = engine.evaluate_message(tc)
        assert expected_keys.issubset(set(res.keys()))
        score = res["final_decision"]["final_risk_score"]
        assert isinstance(score, int)
        assert 0 <= score <= 100


# ---------------------------------------------------------------------------
# Test 14: Zero Raw Message Text or PII Written to Diagnostics
# ---------------------------------------------------------------------------

def test_14_zero_raw_message_text_or_pii_in_diagnostics():
    """Audit metadata must never record raw text or sensitive PII like Aadhaar or phone numbers."""
    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)

    sensitive_text = (
        "Secret Aadhaar: 9876 5432 1098 and Phone: 9822123456 with OTP: 789123. Update KYC immediately."
    )
    res = engine.evaluate_message(sensitive_text)
    audit = res["audit_metadata"]

    audit_str = json.dumps(audit)
    assert "9876 5432 1098" not in audit_str
    assert "9822123456" not in audit_str
    assert "789123" not in audit_str
    assert sensitive_text not in audit_str
    assert "diagnostic_event_id" in audit
    assert "length_bucket" in audit
    assert "input_sha256" not in audit
    assert "input_sha256" not in audit_str


# ---------------------------------------------------------------------------
# Test 15: Zero Network Calls Guarantee
# ---------------------------------------------------------------------------

def test_15_zero_network_calls_guarantee(monkeypatch):
    """Evaluating the hybrid engine must execute 100% offline with zero network socket operations."""
    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("Forbidden network socket creation detected in zero-budget offline sandbox!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    engine = HybridDecisionEngine(operating_mode=HybridOperatingMode.SHADOW, checkpoint_dir=CHECKPOINT_DIR)
    res = engine.evaluate_message("महावितरण बिल थकीत आहे http://fake-msedcl.in")

    assert res["final_decision"]["final_risk_score"] >= 0
    assert res["experimental_model"]["is_available"] is True


# ---------------------------------------------------------------------------
# Test 16: Locked Evaluation Dataset Digest and Pre-Existing Tests Preserved
# ---------------------------------------------------------------------------

def test_16_locked_evaluation_digest_and_pre_existing_tests_preserved():
    """Locked evaluation manifest checksum must strictly remain unchanged."""
    assert os.path.exists(LOCKED_MANIFEST_PATH)
    assert os.path.exists(EVAL_DATASET_PATH)

    with open(LOCKED_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    with open(EVAL_DATASET_PATH, "r", encoding="utf-8") as f:
        records = json.load(f)

    expected_digest = manifest["sha256_checksum"]
    actual_digest = compute_locked_test_hash(records)

    assert actual_digest == expected_digest, f"Digest mismatch: {actual_digest} != {expected_digest}"
    assert actual_digest == "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"
