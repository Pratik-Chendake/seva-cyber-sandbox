"""
Phase 6.8.6 — Real-World Evidence Quality and Dataset Readiness Analyzer.

Inspects operational and experimental SQLite repositories to compute comprehensive
evidence metrics, validation state distributions, campaign clustering, and training gate status.
Strictly adheres to zero-fabrication rules: if genuine corroborated real-world evidence
is below the statistical safety thresholds, issues:
'BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE'.
"""

import json
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

VALID_LANGUAGES = {"mr", "mr-Latn", "mr-en", "en"}
DEFAULT_THRESHOLDS = {
    "min_total_corroborated": 30,
    "min_per_class": 10,
    "min_independent_campaigns": 5,
    "min_distinct_languages": 2,
    "max_campaign_conflicts": 0,
    "min_eligible_ratio": 0.80,
}


def detect_language_from_text(text: str) -> str:
    """Heuristic language detection between Devanagari Marathi, Romanized Marathi, Mixed, and English."""
    if not text or not isinstance(text, str):
        return "unknown"

    has_devanagari = bool(re.search(r"[\u0900-\u097F]", text))
    has_latin = bool(re.search(r"[a-zA-Z]", text))

    if has_devanagari and has_latin:
        return "mr-en"
    elif has_devanagari:
        return "mr"
    elif has_latin:
        # Check for common Marathi Romanized keywords
        lower = text.lower()
        mr_markers = ["tumcha", "kard", "yojana", "khate", "taptap", "anudan", "hafta", "shasan", "labh"]
        if any(w in lower for w in mr_markers):
            return "mr-Latn"
        return "en"
    return "unknown"


class DatasetReadinessAnalyzer:
    """Analyzes real-world evidence stored in SQLite for training readiness and data quality."""

    def __init__(
        self,
        db_path: str = "instance/seva_cases.sqlite3",
        thresholds: Optional[Dict[str, Any]] = None,
    ):
        self.db_path = db_path
        self.thresholds = dict(DEFAULT_THRESHOLDS)
        if thresholds:
            self.thresholds.update(thresholds)

    def _get_connection(self) -> sqlite3.Connection:
        if not os.path.exists(self.db_path):
            # Return connection to in-memory or empty if not yet created on disk
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def analyze_readiness(self) -> Dict[str, Any]:
        """Performs comprehensive read-only analysis of real-world evidence quality and training readiness."""
        if not os.path.exists(self.db_path):
            return self._empty_readiness_result(reason="Database file does not exist.")

        with self._get_connection() as conn:
            # Check if evidence tables exist
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='evidence_provenance';")
            if not cur.fetchone():
                return self._empty_readiness_result(reason="evidence_provenance table does not exist.")

            # Total evidence records
            cur = conn.execute("SELECT COUNT(*) as cnt FROM evidence_provenance;")
            total_evidence = cur.fetchone()["cnt"]

            if total_evidence == 0:
                return self._empty_readiness_result(reason="Zero evidence records registered in database.")

            # Status distribution
            status_counts: Dict[str, int] = {}
            cur = conn.execute("SELECT lifecycle_status, COUNT(*) as cnt FROM evidence_provenance GROUP BY lifecycle_status;")
            for r in cur.fetchall():
                status_counts[r["lifecycle_status"]] = r["cnt"]

            # Origin distribution
            origin_counts: Dict[str, int] = {}
            cur = conn.execute("SELECT evidence_origin, COUNT(*) as cnt FROM evidence_provenance GROUP BY evidence_origin;")
            for r in cur.fetchall():
                origin_counts[r["evidence_origin"]] = r["cnt"]

            # Type distribution
            type_counts: Dict[str, int] = {}
            cur = conn.execute("SELECT evidence_type, COUNT(*) as cnt FROM evidence_provenance GROUP BY evidence_type;")
            for r in cur.fetchall():
                type_counts[r["evidence_type"]] = r["cnt"]

            # Ground truth classification distribution (corroborated conclusion takes precedence)
            class_counts: Dict[str, int] = {"phishing": 0, "legitimate": 0, "protective_advisory": 0, "unknown": 0}
            cur = conn.execute(
                """
                SELECT
                    COALESCE(corroborated_conclusion, reviewer_classification, user_classification, 'unknown') as effective_label,
                    COUNT(*) as cnt
                FROM evidence_provenance
                GROUP BY effective_label;
                """
            )
            for r in cur.fetchall():
                lbl = r["effective_label"]
                if lbl in class_counts:
                    class_counts[lbl] = r["cnt"]
                else:
                    class_counts[lbl] = r["cnt"]

            # Verification level distribution
            vlevel_counts: Dict[str, int] = {
                "unverified": 0,
                "single_reviewed": 0,
                "self_reviewed": 0,
                "independently_corroborated": 0,
            }
            cur_cols = conn.execute("PRAGMA table_info(evidence_provenance);")
            cols = [col["name"] for col in cur_cols.fetchall()]

            if "verification_level" in cols:
                cur = conn.execute(
                    "SELECT verification_level, COUNT(*) as cnt FROM evidence_provenance GROUP BY verification_level;"
                )
                for r in cur.fetchall():
                    lvl = r["verification_level"] or "unverified"
                    vlevel_counts[lvl] = r["cnt"]

            # Eligibility tier distribution
            tier_counts: Dict[str, int] = {
                "not_eligible": 0,
                "eligible_exploratory_review": 0,
                "eligible_supervised_candidate_training": 0,
                "independently_corroborated_evaluation_candidate": 0,
            }
            if "eligibility_tier" in cols:
                cur = conn.execute(
                    "SELECT eligibility_tier, COUNT(*) as cnt FROM evidence_provenance GROUP BY eligibility_tier;"
                )
                for r in cur.fetchall():
                    tier = r["eligibility_tier"] or "not_eligible"
                    tier_counts[tier] = r["cnt"]

            # Campaign clusters and conflicts
            cur_camp_tbl = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='campaign_clusters';")
            independent_campaigns = 0
            campaign_conflicts = 0
            if cur_camp_tbl.fetchone():
                cur = conn.execute("SELECT COUNT(*) as cnt FROM campaign_clusters;")
                independent_campaigns = cur.fetchone()["cnt"]

                # Detect campaign label conflicts
                cur = conn.execute(
                    """
                    SELECT e.campaign_id, COUNT(DISTINCT COALESCE(e.corroborated_conclusion, e.reviewer_classification)) as label_variants
                    FROM evidence_provenance e
                    WHERE e.campaign_id IS NOT NULL AND e.campaign_id != ''
                    GROUP BY e.campaign_id
                    HAVING label_variants > 1;
                    """
                )
                campaign_conflicts = len(cur.fetchall())

            # Language breakdown
            lang_counts: Dict[str, int] = {"mr": 0, "mr-Latn": 0, "mr-en": 0, "en": 0, "unknown": 0}
            cur = conn.execute("SELECT metadata_json, evidence_type FROM evidence_provenance;")
            for r in cur.fetchall():
                meta = {}
                try:
                    meta = json.loads(r["metadata_json"] or "{}")
                except Exception:
                    pass

                lang = meta.get("language")
                if not lang or lang not in VALID_LANGUAGES:
                    # Try text heuristic
                    sample_text = meta.get("message_text") or meta.get("text") or meta.get("user_description") or ""
                    lang = detect_language_from_text(sample_text)
                lang_counts[lang] = lang_counts.get(lang, 0) + 1

            corroborated_count = status_counts.get("corroborated", 0)
            indep_corroborated_count = vlevel_counts.get("independently_corroborated", 0)

            # Evaluate training readiness gate
            blocking_reasons: List[str] = []
            deficits: Dict[str, Any] = {}

            # Check 1: Minimum corroborated items
            min_corroborated = self.thresholds["min_total_corroborated"]
            if corroborated_count < min_corroborated:
                deficit = min_corroborated - corroborated_count
                deficits["corroborated_samples_needed"] = deficit
                blocking_reasons.append(
                    f"Insufficient corroborated real-world evidence: {corroborated_count}/{min_corroborated} (deficit: {deficit})."
                )

            # Check 2: Class balance (phishing and legitimate)
            min_per_class = self.thresholds["min_per_class"]
            for cls_name in ["phishing", "legitimate"]:
                cnt = class_counts.get(cls_name, 0)
                if cnt < min_per_class:
                    deficit = min_per_class - cnt
                    deficits[f"{cls_name}_samples_needed"] = deficit
                    blocking_reasons.append(
                        f"Insufficient {cls_name} samples: {cnt}/{min_per_class} (deficit: {deficit})."
                    )

            # Check 3: Independent campaign count
            min_camps = self.thresholds["min_independent_campaigns"]
            if independent_campaigns < min_camps:
                deficit = min_camps - independent_campaigns
                deficits["independent_campaigns_needed"] = deficit
                blocking_reasons.append(
                    f"Insufficient independent campaign clusters: {independent_campaigns}/{min_camps} (deficit: {deficit})."
                )

            # Check 4: Campaign conflicts
            max_conflicts = self.thresholds["max_campaign_conflicts"]
            if campaign_conflicts > max_conflicts:
                blocking_reasons.append(
                    f"Unresolved conflicting campaign labels detected: {campaign_conflicts} conflicting clusters."
                )

            # Check 5: Language representation
            active_langs = sum(1 for k, v in lang_counts.items() if k in VALID_LANGUAGES and v > 0)
            min_langs = self.thresholds["min_distinct_languages"]
            if active_langs < min_langs:
                blocking_reasons.append(
                    f"Insufficient language representation: {active_langs}/{min_langs} distinct languages present."
                )

            is_ready = len(blocking_reasons) == 0
            gate_verdict = (
                "READY_FOR_DATASET_CONSTRUCTION"
                if is_ready
                else "BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE"
            )

            return {
                "db_path": self.db_path,
                "total_evidence_count": total_evidence,
                "corroborated_count": corroborated_count,
                "independently_corroborated_count": indep_corroborated_count,
                "status_distribution": status_counts,
                "origin_distribution": origin_counts,
                "type_distribution": type_counts,
                "classification_distribution": class_counts,
                "verification_level_distribution": vlevel_counts,
                "eligibility_tier_distribution": tier_counts,
                "language_distribution": lang_counts,
                "independent_campaign_count": independent_campaigns,
                "campaign_conflict_count": campaign_conflicts,
                "gate_verdict": gate_verdict,
                "is_ready_for_training": is_ready,
                "blocking_reasons": blocking_reasons,
                "deficits": deficits,
                "thresholds": self.thresholds,
            }

    def _empty_readiness_result(self, reason: str) -> Dict[str, Any]:
        """Generates an honest blocked verdict when database has no valid evidence."""
        return {
            "db_path": self.db_path,
            "total_evidence_count": 0,
            "corroborated_count": 0,
            "independently_corroborated_count": 0,
            "status_distribution": {},
            "origin_distribution": {},
            "type_distribution": {},
            "classification_distribution": {"phishing": 0, "legitimate": 0, "protective_advisory": 0, "unknown": 0},
            "verification_level_distribution": {
                "unverified": 0,
                "single_reviewed": 0,
                "self_reviewed": 0,
                "independently_corroborated": 0,
            },
            "eligibility_tier_distribution": {
                "not_eligible": 0,
                "eligible_exploratory_review": 0,
                "eligible_supervised_candidate_training": 0,
                "independently_corroborated_evaluation_candidate": 0,
            },
            "language_distribution": {"mr": 0, "mr-Latn": 0, "mr-en": 0, "en": 0, "unknown": 0},
            "independent_campaign_count": 0,
            "campaign_conflict_count": 0,
            "gate_verdict": "BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE",
            "is_ready_for_training": False,
            "blocking_reasons": [
                f"No real-world evidence records available ({reason}).",
                f"Corroborated samples deficit: {self.thresholds['min_total_corroborated']}.",
                f"Phishing samples deficit: {self.thresholds['min_per_class']}.",
                f"Legitimate samples deficit: {self.thresholds['min_per_class']}.",
                f"Independent campaigns deficit: {self.thresholds['min_independent_campaigns']}.",
            ],
            "deficits": {
                "corroborated_samples_needed": self.thresholds["min_total_corroborated"],
                "phishing_samples_needed": self.thresholds["min_per_class"],
                "legitimate_samples_needed": self.thresholds["min_per_class"],
                "independent_campaigns_needed": self.thresholds["min_independent_campaigns"],
            },
            "thresholds": self.thresholds,
        }

    def generate_markdown_report(self) -> str:
        """Renders the readiness analysis into clean GitHub-flavored markdown."""
        res = self.analyze_readiness()
        status_md = "\n".join([f"- **{k}:** {v}" for k, v in res["status_distribution"].items()]) or "- *None*"
        class_md = "\n".join([f"- **{k}:** {v}" for k, v in res["classification_distribution"].items()])
        lang_md = "\n".join([f"- **{k}:** {v}" for k, v in res["language_distribution"].items()])
        vlevel_md = "\n".join([f"- **{k}:** {v}" for k, v in res["verification_level_distribution"].items()])
        reasons_md = "\n".join([f"1. {r}" for r in res["blocking_reasons"]]) or "*(None — Ready for training)*"

        return f"""# Real-World Evidence Readiness Analysis

- **Target Database:** `{res['db_path']}`
- **Gate Verdict:** **`{res['gate_verdict']}`**
- **Total Registered Evidence:** {res['total_evidence_count']}
- **Corroborated Items:** {res['corroborated_count']} (Independently Corroborated: {res['independently_corroborated_count']})
- **Independent Campaigns:** {res['independent_campaign_count']}
- **Campaign Conflicts:** {res['campaign_conflict_count']}

### Status Distribution
{status_md}

### Classification Distribution
{class_md}

### Verification Levels
{vlevel_md}

### Language Representation
{lang_md}

### Blocking Reasons & Deficits
{reasons_md}
"""
