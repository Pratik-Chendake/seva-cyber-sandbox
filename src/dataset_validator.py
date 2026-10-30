"""
Dataset Schema Validator, Provenance Quality Assurance & Role Partitioner for Seva Cyber Sandbox.

SCHEMA SPECIFICATION & TAXONOMY:
- Record ID: Unique alphanumeric string identifier (e.g., 'eval_phish_001').
- Text: Raw message string, non-empty, maximum 10,000 characters.
- Ground-Truth Label:
    * 'phishing': Deceptive or fraudulent intent (credentials, APK dropper, extortion, tasks).
    * 'legitimate': Genuine benign message (receipts, notices, personal chat).
    * 'protective_advisory': Official awareness notices warning citizens NOT to share OTPs/APKs.
    * 'ambiguous_needs_review': Insufficient, conflicting, or partial information.
- Language: 'mr' (Marathi), 'mr-Latn' (Romanized Marathi), 'mr-en' (Mixed), 'en' (English).
- Script: 'Devanagari', 'Latin', 'Mixed'.
- Provenance Category:
    * 'public_benchmark': Sourced from open verified public repositories or regulatory advisories.
    * 'human_reviewed_curated': Observed regional lure templates sanitized and reviewed by analysts.
    * 'synthetic_test_case': Explicitly generated unit test fixtures (e.g., zero-width, numeral tests).
    * 'unreviewed_flagged': Citizen forwards awaiting formal verification.
- Provenance Verification Status:
    * 'verified_official_source': Direct match to published regulatory/police circular or bulletin.
    * 'curated_exemplar': Representative social-engineering lure reconstructed from reported regional scams.
    * 'synthetic_fixture': Engineered test vector for specific syntax or evasion logic.
    * 'unverified_intake': Raw citizen forward awaiting forensic verification.
- Review Status: 'reviewed', 'unreviewed', 'provisional'.
- Campaign / Group ID: Source group identifier for leak-free group-aware splitting.
- Dataset Role:
    * 'development': Used by engineers to explore regex patterns, add rules, and train prototype models.
    * 'validation': Used to compare configurations, optimize thresholds, and evaluate candidate rules.
    * 'locked_test': Cryptographically frozen evaluation partition never used during development or tuning.
"""

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

SCHEMA_VERSION = "1.1.0"

VALID_LABELS = {
    "phishing",
    "legitimate",
    "protective_advisory",
    "ambiguous_needs_review",
}

VALID_PROVENANCES = {
    "public_benchmark",
    "human_reviewed_curated",
    "synthetic_test_case",
    "unreviewed_flagged",
}

VALID_PROVENANCE_STATUSES = {
    "verified_official_source",
    "curated_exemplar",
    "synthetic_fixture",
    "unverified_intake",
}

VALID_LANGUAGES = {"mr", "mr-Latn", "mr-en", "en"}
VALID_SCRIPTS = {"Devanagari", "Latin", "Mixed"}
VALID_REVIEW_STATUSES = {"reviewed", "unreviewed", "provisional"}
VALID_DATASET_ROLES = {"development", "validation", "qualification", "locked_test"}

REQUIRED_FIELDS = {
    "record_id",
    "text",
    "ground_truth_label",
    "language",
    "script",
    "provenance_category",
    "provenance_verification_status",
    "source_reference",
    "license_info",
    "collection_date",
    "review_status",
    "campaign_id",
    "dataset_role",
}

LOCKED_TEST_MANIFEST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "locked_test_manifest.json",
)


class DatasetValidationError(Exception):
    """Raised when an evaluation dataset fails schema validation or integrity check."""
    pass


def validate_record(record: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validates a single record against the Seva Cyber Sandbox evaluation schema.
    Returns (is_valid, list_of_error_reasons).
    """
    errors: List[str] = []
    if not isinstance(record, dict):
        return False, ["Record must be a JSON object (dictionary)."]

    # 1. Required fields
    for field in REQUIRED_FIELDS:
        if field not in record or record[field] is None:
            errors.append(f"Missing required field: '{field}'")

    if errors:
        return False, errors

    # 2. Record ID validation
    rid = str(record.get("record_id", "")).strip()
    if not rid or not re.match(r"^[a-zA-Z0-9_\-]+$", rid):
        errors.append(f"Invalid record_id '{rid}': must be non-empty alphanumeric with hyphens/underscores.")

    # 3. Text validation
    text = record.get("text")
    if not isinstance(text, str) or not text.strip():
        errors.append("Field 'text' must be a non-empty string.")
    elif len(text) > 10000:
        errors.append(f"Field 'text' exceeds max limit of 10000 characters ({len(text)} chars).")

    # 4. Ground-truth label validation
    label = str(record.get("ground_truth_label", "")).strip().lower()
    if label not in VALID_LABELS:
        errors.append(
            f"Invalid ground_truth_label '{label}'. Must be one of: {sorted(VALID_LABELS)}"
        )

    # 5. Provenance category validation
    prov = str(record.get("provenance_category", "")).strip().lower()
    if prov not in VALID_PROVENANCES:
        errors.append(
            f"Invalid provenance_category '{prov}'. Must be one of: {sorted(VALID_PROVENANCES)}"
        )

    # 6. Provenance verification status validation
    prov_stat = str(record.get("provenance_verification_status", "")).strip().lower()
    if prov_stat not in VALID_PROVENANCE_STATUSES:
        errors.append(
            f"Invalid provenance_verification_status '{prov_stat}'. Must be one of: {sorted(VALID_PROVENANCE_STATUSES)}"
        )

    # 7. Language and Script validation
    lang = str(record.get("language", "")).strip()
    if lang not in VALID_LANGUAGES:
        errors.append(f"Invalid language '{lang}'. Must be one of: {sorted(VALID_LANGUAGES)}")

    script = str(record.get("script", "")).strip()
    if script not in VALID_SCRIPTS:
        errors.append(f"Invalid script '{script}'. Must be one of: {sorted(VALID_SCRIPTS)}")

    # 8. Review status validation
    status = str(record.get("review_status", "")).strip().lower()
    if status not in VALID_REVIEW_STATUSES:
        errors.append(
            f"Invalid review_status '{status}'. Must be one of: {sorted(VALID_REVIEW_STATUSES)}"
        )

    # 9. Campaign / Group ID validation
    camp = str(record.get("campaign_id", "")).strip()
    if not camp:
        errors.append("Field 'campaign_id' must be a non-empty string.")

    # 10. Dataset Role validation
    role = str(record.get("dataset_role", "")).strip().lower()
    if role not in VALID_DATASET_ROLES:
        errors.append(
            f"Invalid dataset_role '{role}'. Must be one of: {sorted(VALID_DATASET_ROLES)}"
        )
    elif role == "locked_test" and prov_stat == "unverified_intake":
        errors.append(
            "Records with provenance_verification_status='unverified_intake' cannot be assigned to locked_test partition."
        )

    # 11. Source reference and license presence
    if not str(record.get("source_reference", "")).strip():
        errors.append("Field 'source_reference' must be documented.")
    if not str(record.get("license_info", "")).strip():
        errors.append("Field 'license_info' must be documented.")

    # 12. Privacy sanity check (must not contain unmasked 10-digit Indian phone numbers or 12-digit Aadhaar)
    raw_text = str(text or "")
    if re.search(r"\b[6-9]\d{9}\b", raw_text) and not any(
        test_val in raw_text for test_val in ("9800000000", "9811000000", "9822000000")
    ):
        errors.append("Potential unmasked personal phone number detected in record text.")
    if re.search(r"\b\d{4}\s\d{4}\s\d{4}\b", raw_text):
        errors.append("Potential unmasked Aadhaar number detected in record text.")

    return len(errors) == 0, errors


def detect_near_duplicates(
    records: List[Dict[str, Any]], jaccard_threshold: float = 0.80
) -> List[Dict[str, Any]]:
    """
    Detects near-duplicate messages within the dataset using character/word token overlap.
    Returns pairs exceeding jaccard_threshold.
    """
    near_dups: List[Dict[str, Any]] = []

    def get_tokens(s: str) -> Set[str]:
        return set(re.findall(r"\w+", s.lower()))

    token_sets = [(r["record_id"], get_tokens(r["text"]), r["campaign_id"]) for r in records if "text" in r]

    for i in range(len(token_sets)):
        id_a, tokens_a, camp_a = token_sets[i]
        if not tokens_a:
            continue
        for j in range(i + 1, len(token_sets)):
            id_b, tokens_b, camp_b = token_sets[j]
            if not tokens_b:
                continue
            intersection = len(tokens_a & tokens_b)
            union = len(tokens_a | tokens_b)
            similarity = (intersection / union) if union > 0 else 0.0
            if similarity >= jaccard_threshold:
                near_dups.append({
                    "record_a": id_a,
                    "record_b": id_b,
                    "campaign_a": camp_a,
                    "campaign_b": camp_b,
                    "jaccard_similarity": round(similarity, 4),
                    "same_campaign": (camp_a == camp_b),
                })

    return near_dups


def compute_locked_test_hash(records: List[Dict[str, Any]]) -> str:
    """Computes a deterministic canonical SHA-256 hash of the locked_test partition."""
    locked = sorted(
        [r for r in records if r.get("dataset_role") == "locked_test"],
        key=lambda x: str(x.get("record_id", "")),
    )
    canonical_bytes = json.dumps(locked, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_locked_test_integrity(
    records: List[Dict[str, Any]],
    expected_hash: Optional[str] = None,
) -> Tuple[bool, List[str]]:
    """
    Verifies that the locked_test partition has not been tampered with or modified.
    """
    issues: List[str] = []
    locked_recs = [r for r in records if r.get("dataset_role") == "locked_test"]
    if not locked_recs:
        issues.append("No records found with dataset_role='locked_test'.")
        return False, issues

    # Campaign boundary isolation check: locked test campaigns must not appear in dev or validation
    other_recs = [r for r in records if r.get("dataset_role") != "locked_test"]
    locked_camps = {r["campaign_id"] for r in locked_recs}
    other_camps = {r["campaign_id"] for r in other_recs}
    leakage = locked_camps & other_camps
    if leakage:
        issues.append(f"Campaign leakage detected between locked_test and other partitions: {sorted(leakage)}")

    actual_hash = compute_locked_test_hash(records)

    target_hash = expected_hash
    if not target_hash and os.path.exists(LOCKED_TEST_MANIFEST_PATH):
        try:
            with open(LOCKED_TEST_MANIFEST_PATH, "r", encoding="utf-8") as f:
                manifest = json.load(f)
                target_hash = manifest.get("sha256_checksum")
        except Exception:
            pass

    if target_hash and actual_hash != target_hash:
        issues.append(
            f"Locked test partition SHA-256 mismatch! Expected '{target_hash}', computed '{actual_hash}'. "
            "Data tampering or unauthorized modification detected."
        )

    return len(issues) == 0, issues


def validate_dataset(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validates an entire evaluation dataset collection.
    Checks individual record schemas, duplicate IDs, exact text duplicates,
    near duplicates, campaign-role consistency, and partition distributions.
    """
    if not isinstance(records, list):
        return {
            "is_valid": False,
            "total_records": 0,
            "errors": ["Dataset root must be a JSON array of record objects."],
            "warnings": [],
            "stats": {},
        }

    errors: List[str] = []
    warnings: List[str] = []
    seen_ids: Set[str] = set()
    seen_texts: Dict[str, str] = {}

    label_counts: Dict[str, int] = {k: 0 for k in VALID_LABELS}
    prov_counts: Dict[str, int] = {k: 0 for k in VALID_PROVENANCES}
    prov_stat_counts: Dict[str, int] = {k: 0 for k in VALID_PROVENANCE_STATUSES}
    lang_counts: Dict[str, int] = {k: 0 for k in VALID_LANGUAGES}
    script_counts: Dict[str, int] = {k: 0 for k in VALID_SCRIPTS}
    role_counts: Dict[str, int] = {k: 0 for k in VALID_DATASET_ROLES}
    campaign_counts: Dict[str, int] = {}
    campaign_to_role: Dict[str, str] = {}

    for idx, rec in enumerate(records):
        valid, rec_errors = validate_record(rec)
        if not valid:
            for err in rec_errors:
                errors.append(f"Record #{idx} ('{rec.get('record_id', 'unknown')}'): {err}")
            continue

        rid = rec["record_id"]
        if rid in seen_ids:
            errors.append(f"Duplicate record_id '{rid}' detected at record #{idx}.")
        else:
            seen_ids.add(rid)

        # Exact text duplication check
        clean_text = " ".join(str(rec["text"]).split()).lower()
        if clean_text in seen_texts:
            warnings.append(
                f"Exact duplicate text found between record '{rid}' and earlier record '{seen_texts[clean_text]}'."
            )
        else:
            seen_texts[clean_text] = rid

        # Campaign-Role Consistency Check (Strict zero campaign split across roles)
        camp_id = rec["campaign_id"]
        role = rec["dataset_role"]
        if camp_id in campaign_to_role and campaign_to_role[camp_id] != role:
            errors.append(
                f"Campaign leakage: campaign '{camp_id}' is assigned to both '{campaign_to_role[camp_id]}' "
                f"and '{role}' (at record '{rid}'). All records in a campaign must share the same dataset role."
            )
        else:
            campaign_to_role[camp_id] = role

        lbl = rec["ground_truth_label"]
        label_counts[lbl] = label_counts.get(lbl, 0) + 1

        prv = rec["provenance_category"]
        prov_counts[prv] = prov_counts.get(prv, 0) + 1

        pstat = rec["provenance_verification_status"]
        prov_stat_counts[pstat] = prov_stat_counts.get(pstat, 0) + 1

        lng = rec["language"]
        lang_counts[lng] = lang_counts.get(lng, 0) + 1

        scr = rec["script"]
        script_counts[scr] = script_counts.get(scr, 0) + 1

        role_counts[role] = role_counts.get(role, 0) + 1
        campaign_counts[camp_id] = campaign_counts.get(camp_id, 0) + 1

    # Check near-duplicates
    near_dups = detect_near_duplicates(records, jaccard_threshold=0.85)
    for nd in near_dups:
        if not nd["same_campaign"]:
            warnings.append(
                f"Cross-campaign near-duplicate ({nd['jaccard_similarity']*100:.1f}%): "
                f"'{nd['record_a']}' ({nd['campaign_a']}) vs '{nd['record_b']}' ({nd['campaign_b']})."
            )

    total_valid = len(seen_ids)
    if total_valid < 10:
        warnings.append(
            f"Dataset has only {total_valid} valid records. Sample size is small for statistical reliability."
        )

    # Check locked test partition integrity if present
    locked_valid, locked_issues = verify_locked_test_integrity(records)
    if not locked_valid:
        for iss in locked_issues:
            errors.append(f"Locked test partition integrity error: {iss}")

    stats = {
        "total_records": len(records),
        "valid_records": total_valid,
        "labels": label_counts,
        "provenance_categories": prov_counts,
        "provenance_verification_statuses": prov_stat_counts,
        "languages": lang_counts,
        "scripts": script_counts,
        "dataset_roles": role_counts,
        "unique_campaigns": len(campaign_counts),
        "campaign_distribution": campaign_counts,
        "near_duplicates_count": len(near_dups),
        "locked_test_sha256": compute_locked_test_hash(records) if role_counts.get("locked_test", 0) > 0 else None,
    }

    return {
        "is_valid": len(errors) == 0,
        "total_records": len(records),
        "errors": errors,
        "warnings": warnings,
        "stats": stats,
    }


def load_and_validate_dataset(
    filepath: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Loads JSON records from filepath and runs full schema validation.
    Defaults to data/phishing_eval_dataset.json.
    Raises DatasetValidationError if invalid.
    """
    if filepath is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filepath = os.path.join(base_dir, "data", "phishing_eval_dataset.json")

    if not os.path.exists(filepath):
        raise DatasetValidationError(f"Evaluation dataset not found at path: {filepath}")

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise DatasetValidationError(f"Failed to read evaluation dataset: {exc}") from exc

    validation_report = validate_dataset(data)
    if not validation_report["is_valid"]:
        error_msg = "\n".join(validation_report["errors"][:10])
        raise DatasetValidationError(
            f"Dataset failed schema validation ({len(validation_report['errors'])} errors):\n{error_msg}"
        )

    return data, validation_report
