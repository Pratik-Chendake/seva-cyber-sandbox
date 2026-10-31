"""
Phase 6.9.5 — Shadow Model Operational Monitoring Test Suite.

Verifies:
1. Inference telemetry and latency profiling (mean, p95, max).
2. Disagreement classification and taxonomy tracking.
3. Fail-open / fail-safe resilience: model error triggers fallback without altering score delta (0.00).
4. Persistence and markdown operational report generation.
"""

import json
import os
import tempfile
import pytest

from src.shadow_monitoring import ShadowModelMonitor


@pytest.fixture
def monitor():
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    metrics_path = os.path.join(temp_dir.name, "shadow_metrics.json")
    mon = ShadowModelMonitor(metrics_path=metrics_path)
    yield mon
    try:
        temp_dir.cleanup()
    except Exception:
        pass


def test_record_inference_and_latency_tracking(monitor):
    """Verifies that inference telemetry records events and calculates latency percentiles."""
    latencies = [12.5, 15.0, 10.0, 25.0, 18.0]
    for i, lat in enumerate(latencies):
        res = monitor.record_inference(
            case_id=f"CASE-SHADOW-{i}",
            rule_verdict="phishing",
            neural_prediction="phishing",
            confidence=0.92,
            latency_ms=lat,
        )
        assert res["production_score_delta"] == 0.00
        assert res["is_production_authoritative"] is False
        assert res["is_disagreement"] is False

    summary = monitor.get_summary()
    assert summary["total_evaluations"] == 5
    assert summary["agreements"] == 5
    assert summary["disagreements"] == 0
    assert summary["agreement_rate"] == 1.0

    lat_m = summary["latency"]
    assert lat_m["sample_count"] == 5
    assert lat_m["mean_ms"] == round(sum(latencies) / len(latencies), 2)
    assert lat_m["max_ms"] == 25.0
    assert lat_m["p95_ms"] >= 18.0


def test_disagreement_detection_and_taxonomy(monitor):
    """Verifies disagreement classification across different rule/model combinations."""
    # 1. Rule Phishing vs Model Legitimate
    r1 = monitor.record_inference(
        case_id="CASE-DIS-01",
        rule_verdict="phishing",
        neural_prediction="legitimate",
        confidence=0.88,
        latency_ms=14.0,
    )
    assert r1["is_disagreement"] is True
    assert r1["event_type"] == "rule_phish_model_legit"
    assert r1["production_score_delta"] == 0.00

    # 2. Rule Legitimate vs Model Phishing
    r2 = monitor.record_inference(
        case_id="CASE-DIS-02",
        rule_verdict="legitimate",
        neural_prediction="phishing",
        confidence=0.74,
        latency_ms=16.0,
    )
    assert r2["is_disagreement"] is True
    assert r2["event_type"] == "rule_legit_model_phish"

    # 3. Agreement
    r3 = monitor.record_inference(
        case_id="CASE-AGR-01",
        rule_verdict="legitimate",
        neural_prediction="legitimate",
        confidence=0.99,
        latency_ms=11.0,
    )
    assert r3["is_disagreement"] is False
    assert r3["event_type"] == "agreement"

    summary = monitor.get_summary()
    assert summary["total_evaluations"] == 3
    assert summary["agreements"] == 1
    assert summary["disagreements"] == 2
    assert summary["disagreement_rate"] == round(2 / 3, 4)

    bd = summary["disagreement_breakdown"]
    assert bd["rule_phish_model_legit"] == 1
    assert bd["rule_legit_model_phish"] == 1


def test_fail_open_resilience_on_model_error(monitor):
    """
    Verifies that when neural inference encounters an error or returns None,
    the system fails open safely: records fallback, zero score delta, and zero crash.
    """
    res = monitor.record_inference(
        case_id="CASE-ERR-01",
        rule_verdict="phishing",
        neural_prediction=None,
        confidence=0.0,
        latency_ms=0.0,
        model_error="Neural inference timed out on CPU worker",
    )

    assert res["is_fallback"] is True
    assert res["event_type"] == "model_fallback"
    assert res["model_error"] == "Neural inference timed out on CPU worker"
    assert res["production_score_delta"] == 0.00

    summary = monitor.get_summary()
    assert summary["total_evaluations"] == 1
    assert summary["model_fallback_evaluations"] == 1
    assert summary["fallback_rate"] == 1.0


def test_save_metrics_and_markdown_report(monitor):
    """Verifies that shadow metrics are saved to disk and rendered to markdown."""
    monitor.record_inference("CASE-REP-01", "phishing", "phishing", 0.95, 12.0)
    monitor.record_inference("CASE-REP-02", "phishing", "legitimate", 0.70, 15.0)

    saved_path = monitor.save_metrics()
    assert os.path.exists(saved_path)

    with open(saved_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["aggregate_counts"]["total_evaluations"] == 2

    report = monitor.generate_monitoring_report_markdown()
    assert "Shadow Model Operational Monitoring Report" in report
    assert "Score Delta vs Production:" in report
    assert "Disagreement Taxonomy" in report
    assert "Latency Profile" in report
