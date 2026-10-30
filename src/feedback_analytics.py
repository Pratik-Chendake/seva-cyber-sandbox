"""
Feedback Analytics and Disagreement Metrics Module.
Part of Seva Cyber Sandbox (Phase 6.6).

PURPOSE:
Generates aggregate operational intelligence from local human reviews and model-rule disagreements.
Quantifies where deterministic rules and neural models agree, where they diverge, and how human
operators adjudicate discrepancies.

GOVERNANCE & ATTRIBUTION RULES:
1. Explicit Unauthenticated Attribution:
   - All review outcomes are strictly labeled as 'local_operator_feedback_statistics'.
   - Statistics must NOT be claimed as certified Bayesian ground truth or objective model accuracy.
2. Production Scoring Invariance:
   - Analytical metrics are informational and diagnostic only.
   - Metrics NEVER automatically retrain, reweight, or promote models, nor alter deterministic production rules.
3. Privacy Preservation:
   - Aggregates coarse numerical counts only; zero raw message text or PII is processed or exported.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional

from src.case_repository import (
    CaseRepository,
    get_default_case_repository,
    get_utc_now_iso,
)

logger = logging.getLogger(__name__)


class FeedbackAnalytics:
    """
    Computes aggregate metrics and diagnostic reports from human-in-the-loop review
    records and model-rule disagreement telemetry.
    """

    def __init__(
        self,
        repository: Optional[CaseRepository] = None,
        shadow_controller: Optional[Any] = None,
    ):
        self.repository = repository or get_default_case_repository()
        self.shadow_controller = shadow_controller

    def compute_analytics(self) -> Dict[str, Any]:
        """
        Compiles comprehensive feedback analytics across all local disagreement events,
        human review adjudications, and consent-gated training feature records.
        """
        now_utc = get_utc_now_iso()

        with self.repository.get_connection() as conn:
            # 1. Total event counts
            total_events = conn.execute("SELECT COUNT(*) AS c FROM model_disagreement_events;").fetchone()["c"]
            agreements = conn.execute("SELECT COUNT(*) AS c FROM model_disagreement_events WHERE event_type = 'agreement';").fetchone()["c"]
            non_comparable = conn.execute("SELECT COUNT(*) AS c FROM model_disagreement_events WHERE event_type = 'non_comparable';").fetchone()["c"]
            disagreements = max(0, total_events - agreements - non_comparable)

            comparable_total = agreements + disagreements
            agreement_rate = round(agreements / comparable_total, 4) if comparable_total > 0 else 0.0
            disagreement_rate = round(disagreements / comparable_total, 4) if comparable_total > 0 else 0.0

            # 2. Event type breakdown
            type_rows = conn.execute(
                "SELECT event_type, COUNT(*) AS c FROM model_disagreement_events GROUP BY event_type ORDER BY c DESC;"
            ).fetchall()
            events_by_type = {r["event_type"]: r["c"] for r in type_rows}

            # 3. Review state distribution
            state_rows = conn.execute(
                "SELECT review_state, COUNT(*) AS c FROM model_disagreement_events GROUP BY review_state;"
            ).fetchall()
            review_states = {r["review_state"]: r["c"] for r in state_rows}
            pending_count = review_states.get("pending", 0)
            completed_count = review_states.get("completed", 0)
            insufficient_count = review_states.get("insufficient_evidence", 0)
            superseded_count = review_states.get("superseded", 0)
            rejected_count = review_states.get("rejected", 0)

            # 4. Review assessments from non-superseded reviews
            assess_rows = conn.execute(
                """
                SELECT reviewer_assessment, COUNT(*) AS c
                FROM disagreement_reviews
                WHERE is_superseded = 0
                GROUP BY reviewer_assessment;
                """
            ).fetchall()
            assessments = {r["reviewer_assessment"]: r["c"] for r in assess_rows}

            rules_correct = assessments.get("rules_correct", 0)
            model_correct = assessments.get("model_correct", 0)
            both_investigate = assessments.get("both_investigate", 0)
            neither_sufficient = assessments.get("neither_sufficient", 0)

            adjudicated_total = rules_correct + model_correct + both_investigate + neither_sufficient
            rules_correct_pct = round((rules_correct / adjudicated_total) * 100, 2) if adjudicated_total > 0 else 0.0
            model_correct_pct = round((model_correct / adjudicated_total) * 100, 2) if adjudicated_total > 0 else 0.0

            # 5. Human adjudicated outcome distribution
            outcome_rows = conn.execute(
                """
                SELECT outcome_label, COUNT(*) AS c
                FROM disagreement_reviews
                WHERE is_superseded = 0
                GROUP BY outcome_label;
                """
            ).fetchall()
            outcomes_dist = {r["outcome_label"]: r["c"] for r in outcome_rows}

            # 6. Model version distribution
            ver_rows = conn.execute(
                """
                SELECT COALESCE(model_version, 'unknown') AS ver,
                       COUNT(*) AS total,
                       SUM(CASE WHEN event_type = 'agreement' THEN 1 ELSE 0 END) AS agrees,
                       SUM(CASE WHEN event_type NOT IN ('agreement', 'non_comparable') THEN 1 ELSE 0 END) AS dis
                FROM model_disagreement_events
                GROUP BY model_version;
                """
            ).fetchall()
            model_ver_comparison = {}
            for r in ver_rows:
                v = r["ver"]
                comp = (r["agrees"] or 0) + (r["dis"] or 0)
                agr_pct = round(((r["agrees"] or 0) / comp) * 100, 2) if comp > 0 else 0.0
                model_ver_comparison[v] = {
                    "total_evaluations": r["total"],
                    "agreements": r["agrees"] or 0,
                    "disagreements": r["dis"] or 0,
                    "agreement_rate_pct": agr_pct,
                }

            # 7. Language and script distribution
            lang_rows = conn.execute(
                "SELECT language_category, COUNT(*) AS c FROM model_disagreement_events GROUP BY language_category;"
            ).fetchall()
            lang_dist = {r["language_category"]: r["c"] for r in lang_rows}

            script_rows = conn.execute(
                "SELECT script_category, COUNT(*) AS c FROM model_disagreement_events GROUP BY script_category;"
            ).fetchall()
            script_dist = {r["script_category"]: r["c"] for r in script_rows}

            # 8. Consent and training curation summary
            consented_events = conn.execute("SELECT COUNT(*) AS c FROM model_disagreement_events WHERE consent_given = 1;").fetchone()["c"]
            features_stored = conn.execute("SELECT COUNT(*) AS c FROM training_feature_records;").fetchone()["c"]
            features_revoked = conn.execute("SELECT COUNT(*) AS c FROM training_feature_records WHERE eligibility_state = 'consent_revoked';").fetchone()["c"]

        # Run feature curation check if secret is configured
        curation_summary = {
            "consented_events_count": consented_events,
            "feature_records_stored": features_stored,
            "consent_revoked_count": features_revoked,
            "eligible_for_training_count": 0,
            "curation_status": "HMAC_KEY_REQUIRED",
        }
        try:
            curation_res = self.repository.curate_training_features()
            curation_summary["eligible_for_training_count"] = curation_res.get("eligible_count", 0)
            curation_summary["curation_status"] = curation_res.get("report", {}).get("data_quality_status", "VALID")
        except Exception as e:
            curation_summary["curation_status"] = f"Unavailable ({type(e).__name__})"

        return {
            "report_title": "local_operator_feedback_statistics",
            "schema_version": "1.0.0",
            "generated_at_utc": now_utc,
            "provenance_disclaimer": (
                "LOCAL OPERATOR FEEDBACK STATISTICS: All metrics are derived from local unauthenticated "
                "operator reviews. Reviewer decisions represent local hypothesis evaluations, not verified "
                "independent ground truth. These metrics are strictly diagnostic and do NOT alter production "
                "detection rules or risk scores."
            ),
            "disagreement_metrics": {
                "total_events": total_events,
                "agreements": agreements,
                "disagreements": disagreements,
                "non_comparable": non_comparable,
                "agreement_rate": agreement_rate,
                "disagreement_rate": disagreement_rate,
            },
            "disagreement_types_breakdown": events_by_type,
            "review_queue_status": {
                "pending": pending_count,
                "completed": completed_count,
                "insufficient_evidence": insufficient_count,
                "superseded": superseded_count,
                "rejected": rejected_count,
            },
            "operator_accuracy_assessments": {
                "adjudicated_reviews_total": adjudicated_total,
                "rules_judged_correct_count": rules_correct,
                "rules_judged_correct_percentage": rules_correct_pct,
                "model_judged_correct_count": model_correct,
                "model_judged_correct_percentage": model_correct_pct,
                "both_require_investigation_count": both_investigate,
                "neither_sufficient_evidence_count": neither_sufficient,
            },
            "human_outcomes_distribution": outcomes_dist,
            "model_version_comparison": model_ver_comparison,
            "language_and_script_distribution": {
                "by_language": lang_dist,
                "by_script": script_dist,
            },
            "training_curation_summary": curation_summary,
        }

    def generate_markdown_report(self) -> str:
        """Formats the feedback analytics as a clean Markdown report."""
        stats = self.compute_analytics()
        dm = stats["disagreement_metrics"]
        oa = stats["operator_accuracy_assessments"]
        rq = stats["review_queue_status"]

        lines = [
            "# Seva Cyber Sandbox — Local Operator Feedback Analytics",
            f"**Generated:** {stats['generated_at_utc']}",
            f"**Report Type:** `{stats['report_title']}`",
            "",
            "> [!NOTE]",
            f"> {stats['provenance_disclaimer']}",
            "",
            "## 1. Disagreement & Concordance Summary",
            f"- **Total Events Recorded:** {dm['total_events']}",
            f"- **Rules & Model Agreements:** {dm['agreements']} ({dm['agreement_rate'] * 100:.1f}%)",
            f"- **Model-Rule Disagreements:** {dm['disagreements']} ({dm['disagreement_rate'] * 100:.1f}%)",
            f"- **Non-Comparable Evaluations:** {dm['non_comparable']}",
            "",
            "## 2. Review Queue Adjudication Status",
            f"- **Pending Operator Reviews:** {rq['pending']}",
            f"- **Completed Reviews:** {rq['completed']}",
            f"- **Insufficient Evidence Records:** {rq['insufficient_evidence']}",
            f"- **Superseded Prior Reviews:** {rq['superseded']}",
            "",
            "## 3. Comparative Accuracy Assessments (Operator Adjudication)",
            f"- **Deterministic Rules Judged Correct:** {oa['rules_judged_correct_count']} ({oa['rules_judged_correct_percentage']}%)",
            f"- **Neural Model Judged Correct:** {oa['model_judged_correct_count']} ({oa['model_judged_correct_percentage']}%)",
            f"- **Both Require Further Investigation:** {oa['both_require_investigation_count']}",
            f"- **Neither Sufficient Evidence:** {oa['neither_sufficient_evidence_count']}",
            "",
            "## 4. Disagreement Breakdown by Pairwise Type",
        ]

        for ev_type, count in stats["disagreement_types_breakdown"].items():
            lines.append(f"- `{ev_type}`: **{count}**")

        lines.extend([
            "",
            "## 5. Model Version Comparison",
        ])
        for ver, vstats in stats["model_version_comparison"].items():
            lines.append(
                f"- **{ver}**: {vstats['total_evaluations']} evals | {vstats['agreements']} agrees ({vstats['agreement_rate_pct']}%) | {vstats['disagreements']} disagrees"
            )

        lines.extend([
            "",
            "## 6. Training Curation Integration",
            f"- **Consented Events:** {stats['training_curation_summary']['consented_events_count']}",
            f"- **Feature Vectors Stored:** {stats['training_curation_summary']['feature_records_stored']}",
            f"- **Eligible Training Examples:** {stats['training_curation_summary']['eligible_for_training_count']}",
            f"- **Revoked Consents:** {stats['training_curation_summary']['consent_revoked_count']}",
            f"- **Curation Pipeline Status:** `{stats['training_curation_summary']['curation_status']}`",
        ])

        return "\n".join(lines)
