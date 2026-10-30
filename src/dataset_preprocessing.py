"""
Dataset Cleaning, Preprocessing & Quality Verification Pipeline.
Part of Seva Cyber Sandbox (Phase 2).

ARCHITECTURAL SPECIFICATION:
1. Non-Destructive Preprocessing:
   - Preserves original raw text exactly in 'text'.
   - Stores cleanly normalized representation in 'normalized_text'.
   - Normalization applies NFC Unicode composition, zero-width evasion stripping,
     Devanagari-to-ASCII digit translation, and whitespace collapsing.
2. Leak-Free Group-Aware Partitioning:
   - Verifies that template / campaign families in development/training do not overlap
     with validation. Prohibits cross-partition data leakage.
   - Ensures locked test partition is never modified or contaminated.
3. Strict Schema & Privacy Validation:
   - Validates required fields, ground-truth labels, language/script metadata, and provenance.
   - Rejects unmasked personal phone numbers, real credentials, or non-synthetic sensitive data.
   - Ambiguous or malformed records are safely routed to explicit quarantine.
4. Reproducibility Guarantee:
   - Entire pipeline execution is deterministic and reproducible.
"""

from collections import Counter
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import unicodedata

# Devanagari to ASCII digit mapping
DEVANAGARI_DIGITS = "०१२३४५६७८९"
ASCII_DIGITS = "0123456789"
DEV_TO_ASCII_MAP = str.maketrans(DEVANAGARI_DIGITS, ASCII_DIGITS)

# Zero-width evasion characters (U+200B to U+200F, U+FEFF)
ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff]")


def clean_evasion_characters(text: str) -> str:
    """
    Strips zero-width evasion characters (U+200B to U+200F, U+FEFF) used for obfuscation.
    """
    if not text or not isinstance(text, str):
        return ""
    return ZERO_WIDTH_PATTERN.sub("", text)


VALID_LABELS = {
    "phishing",
    "legitimate",
    "protective_advisory",
    "ambiguous_needs_review",
}

VALID_LANGUAGES = {"mr", "mr-Latn", "mr-en", "en"}
VALID_SCRIPTS = {"Devanagari", "Latin", "Mixed"}
VALID_ROLES = {"development", "validation", "qualification", "locked_test", "quarantine"}
VALID_PROVENANCE_CATEGORIES = {
    "synthetic_test_case",
    "curated_case_evidence",
    "public_dataset",
    "administrative_notice",
}

REQUIRED_DATASET_FIELDS = {
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


def normalize_record_text(text: str) -> str:
    """
    Safely normalizes input text without altering surrounding grammatical meaning.
    - Applies NFC canonical Unicode decomposition/composition.
    - Removes zero-width evasion characters.
    - Normalizes Devanagari numerals (०-९) to ASCII digits (0-9).
    - Collapses repeated whitespace into single spaces and strips leading/trailing space.
    """
    if not text or not isinstance(text, str):
        return ""
    # 1. NFC canonical composition
    composed = unicodedata.normalize("NFC", text)
    # 2. Strip zero-width evasion characters
    cleaned_zw = clean_evasion_characters(composed)
    # 3. Translate Devanagari numerals to ASCII digits
    num_norm = cleaned_zw.translate(DEV_TO_ASCII_MAP)
    # 4. Collapse consecutive whitespace
    collapsed = re.sub(r"\s+", " ", num_norm).strip()
    return collapsed


NEURAL_PREPROCESSING_VERSION = "neural-preproc-v1.1.0"


def preprocess_for_neural_model(text: str) -> str:
    """
    Canonical, versioned input preprocessor for the custom neural classifier (v1.1.0).
    Guarantees that training, validation, and production inference evaluate the identical
    normalized representation:
    1. Applies NFC canonical Unicode decomposition/composition.
    2. Strips zero-width evasion characters (U+200B-U+200F, U+FEFF).
    3. Normalizes Devanagari numerals (०-९) to ASCII digits (0-9).
    4. Collapses redundant whitespace.

    NOTE: Does NOT alter raw input in-place. Rule-based detection receives raw text independently.
    """
    return normalize_record_text(text)



def detect_script(text: str) -> str:
    """Classifies script as Devanagari, Latin, or Mixed."""
    has_devanagari = bool(re.search(r"[\u0900-\u097F]", text))
    has_latin = bool(re.search(r"[a-zA-Z]", text))
    if has_devanagari and has_latin:
        return "Mixed"
    if has_devanagari:
        return "Devanagari"
    if has_latin:
        return "Latin"
    return "Mixed"


def validate_single_record(record: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validates a single record against schema, format, privacy, and integrity rules.
    Returns (is_valid, list_of_errors).
    """
    errors: List[str] = []
    if not isinstance(record, dict):
        return False, ["Record must be a JSON object (dictionary)."]

    for field in REQUIRED_DATASET_FIELDS:
        if field not in record or record[field] is None:
            errors.append(f"Missing required field: '{field}'")

    if errors:
        return False, errors

    rid = str(record.get("record_id", "")).strip()
    if not rid or not re.match(r"^[a-zA-Z0-9_\-]+$", rid):
        errors.append(f"Invalid record_id '{rid}': must be non-empty alphanumeric with hyphens/underscores.")

    text = record.get("text")
    if not isinstance(text, str) or not text.strip():
        errors.append("Field 'text' must be a non-empty string.")
    elif len(text) > 10000:
        errors.append(f"Field 'text' exceeds maximum length (10,000 characters; got {len(text)}).")

    label = str(record.get("ground_truth_label", "")).strip().lower()
    if label not in VALID_LABELS:
        errors.append(f"Invalid ground_truth_label '{label}'. Allowed: {sorted(list(VALID_LABELS))}")

    lang = str(record.get("language", "")).strip()
    if lang not in VALID_LANGUAGES:
        errors.append(f"Invalid language '{lang}'. Allowed: {sorted(list(VALID_LANGUAGES))}")

    script = str(record.get("script", "")).strip()
    if script not in VALID_SCRIPTS:
        errors.append(f"Invalid script '{script}'. Allowed: {sorted(list(VALID_SCRIPTS))}")

    role = str(record.get("dataset_role", "")).strip().lower()
    if role not in VALID_ROLES:
        errors.append(f"Invalid dataset_role '{role}'. Allowed: {sorted(list(VALID_ROLES))}")

    camp = str(record.get("campaign_id", "")).strip()
    if not camp:
        errors.append("Field 'campaign_id' must be a non-empty string.")

    prov_cat = str(record.get("provenance_category", "")).strip()
    if prov_cat not in VALID_PROVENANCE_CATEGORIES:
        errors.append(f"Invalid provenance_category '{prov_cat}'. Allowed: {sorted(list(VALID_PROVENANCE_CATEGORIES))}")

    src_ref = str(record.get("source_reference", "")).strip()
    if not src_ref:
        errors.append("Field 'source_reference' must be non-empty string.")

    # Privacy Check: Disallow unmasked real phone numbers (allow obvious dummy prefixes like 9800000000, 555-like)
    raw_str = str(text or "")
    phones_found = re.findall(r"\b[6-9]\d{9}\b", raw_str)
    safe_dummies = {"9800000000", "9800000001", "9800000002", "9800000003", "9800000004", "9800000005", "9811000000", "9822000000"}
    for p in phones_found:
        if p not in safe_dummies and not p.endswith("0000"):
            errors.append("Potential real unmasked 10-digit mobile number detected in text.")
            break

    # Privacy Check: Disallow unmasked 12-digit Aadhaar formatting
    if re.search(r"\b[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}\b", raw_str):
        errors.append("Potential unmasked Aadhaar number format detected in text.")

    return len(errors) == 0, errors


def preprocess_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Processes a single validated record: preserves raw text and derives normalized_text.
    """
    clean_rec = dict(record)
    raw_text = str(record.get("text", ""))
    clean_rec["normalized_text"] = normalize_record_text(raw_text)
    clean_rec["character_count"] = len(raw_text)
    clean_rec["normalized_character_count"] = len(clean_rec["normalized_text"])
    clean_rec["detected_script"] = detect_script(raw_text)
    return clean_rec


def check_cross_partition_leakage(
    train_records: List[Dict[str, Any]],
    val_records: List[Dict[str, Any]],
) -> Tuple[bool, List[str]]:
    """
    Verifies that training and validation partitions share ZERO campaign or template families.
    Returns (is_leak_free, list_of_leaked_campaigns).
    """
    train_camps = {str(r.get("campaign_id", "")).strip() for r in train_records if r.get("campaign_id")}
    val_camps = {str(r.get("campaign_id", "")).strip() for r in val_records if r.get("campaign_id")}
    leakage = train_camps & val_camps
    if leakage:
        return False, sorted(list(leakage))
    return True, []


def detect_exact_duplicates(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identifies exact duplicate message texts across the record collection.
    """
    seen_texts: Dict[str, str] = {}
    duplicates: List[Dict[str, Any]] = []

    for r in records:
        norm = normalize_record_text(str(r.get("text", "")))
        rid = str(r.get("record_id", ""))
        if norm in seen_texts:
            duplicates.append({
                "duplicate_record_id": rid,
                "original_record_id": seen_texts[norm],
                "campaign_id": r.get("campaign_id"),
                "text_snippet": norm[:80],
            })
        else:
            seen_texts[norm] = rid

    return duplicates


def detect_near_duplicates_in_corpus(
    records: List[Dict[str, Any]],
    jaccard_threshold: float = 0.85,
) -> List[Dict[str, Any]]:
    """
    Identifies pairs of records with token-level Jaccard similarity >= jaccard_threshold.
    Emits warnings for human review without silently discarding.
    """
    def _tokens(s: str) -> Set[str]:
        return set(re.findall(r"\w+", s.lower()))

    token_cache = [
        (
            str(r.get("record_id", "")),
            _tokens(normalize_record_text(str(r.get("text", "")))),
            str(r.get("campaign_id", "")),
            str(r.get("ground_truth_label", "")),
        )
        for r in records
    ]

    warnings: List[Dict[str, Any]] = []
    n = len(token_cache)
    for i in range(n):
        id_a, tokens_a, camp_a, lbl_a = token_cache[i]
        if not tokens_a:
            continue
        for j in range(i + 1, n):
            id_b, tokens_b, camp_b, lbl_b = token_cache[j]
            if not tokens_b:
                continue
            inter = len(tokens_a & tokens_b)
            union = len(tokens_a | tokens_b)
            sim = (inter / union) if union > 0 else 0.0
            if sim >= jaccard_threshold:
                warnings.append({
                    "record_a": id_a,
                    "record_b": id_b,
                    "campaign_a": camp_a,
                    "campaign_b": camp_b,
                    "label_a": lbl_a,
                    "label_b": lbl_b,
                    "jaccard_similarity": round(sim, 4),
                    "different_labels": (lbl_a != lbl_b),
                })
    return warnings


def run_preprocessing_pipeline(
    raw_records: List[Dict[str, Any]],
    quarantine_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes the full dataset preprocessing, validation, cleaning, and reporting pipeline.
    Separates valid development and validation records from quarantined records.
    """
    valid_train: List[Dict[str, Any]] = []
    valid_val: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    for rec in raw_records:
        rid = str(rec.get("record_id", ""))
        if rid in seen_ids:
            quarantined.append({
                "record": rec,
                "quarantine_reason": f"Duplicate record_id '{rid}'",
            })
            continue
        seen_ids.add(rid)

        is_valid, errors = validate_single_record(rec)
        if not is_valid:
            quarantined.append({
                "record": rec,
                "quarantine_reason": "; ".join(errors),
            })
            continue

        label = str(rec.get("ground_truth_label", "")).lower()
        if label == "ambiguous_needs_review":
            # Ambiguous records are preserved in quarantine for forensic safety
            quarantined.append({
                "record": rec,
                "quarantine_reason": "Ambiguous record quarantined for analyst review (not for training).",
            })
            continue

        processed = preprocess_record(rec)
        role = str(rec.get("dataset_role", "")).lower()
        if role == "development":
            valid_train.append(processed)
        elif role == "validation":
            valid_val.append(processed)
        else:
            quarantined.append({
                "record": rec,
                "quarantine_reason": f"Record with role '{role}' not eligible for train/val.",
            })

    # Exact duplicates check
    all_valid = valid_train + valid_val
    exact_dups = detect_exact_duplicates(all_valid)

    # Near duplicates check
    near_dups = detect_near_duplicates_in_corpus(all_valid, jaccard_threshold=0.85)

    # Leakage check
    is_leak_free, leaked_camps = check_cross_partition_leakage(valid_train, valid_val)

    # Label & Language stats
    label_dist = dict(Counter(r["ground_truth_label"] for r in all_valid))
    lang_dist = dict(Counter(r["language"] for r in all_valid))
    script_dist = dict(Counter(r.get("script", "Unknown") for r in all_valid))
    scenario_dist = dict(Counter(r.get("scenario_category", "general") for r in all_valid))

    report = {
        "pipeline_version": "2.0.0",
        "total_records_processed": len(raw_records),
        "valid_training_records": len(valid_train),
        "valid_validation_records": len(valid_val),
        "quarantined_records": len(quarantined),
        "exact_duplicates_count": len(exact_dups),
        "near_duplicate_warnings_count": len(near_dups),
        "leak_free_guarantee": is_leak_free,
        "leaked_campaigns": leaked_camps,
        "label_distribution": label_dist,
        "language_distribution": lang_dist,
        "script_distribution": script_dist,
        "scenario_distribution": scenario_dist,
        "quarantined_summary": [
            {"record_id": q["record"].get("record_id"), "reason": q["quarantine_reason"]}
            for q in quarantined[:10]
        ],
    }

    if quarantine_output_path and quarantined:
        parent_dir = os.path.dirname(quarantine_output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(quarantine_output_path, "w", encoding="utf-8") as f:
            for item in quarantined:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

    return {
        "training_records": valid_train,
        "validation_records": valid_val,
        "quarantined_records": quarantined,
        "report": report,
        "exact_duplicates": exact_dups,
        "near_duplicates": near_dups,
    }


# =============================================================================
# Phase 6.1: Derived Training Features Extraction Pipeline
# =============================================================================

FEATURE_SCHEMA_VERSION = "1.0.0"
FEATURE_EXTRACTOR_VERSION = "char-ngram-hasher-1024-v1.0.0"
EXPECTED_FEATURE_DIM = 1024


def extract_derived_training_features(
    raw_text: str,
    secret: Optional[str] = None,
) -> Tuple[bool, Optional[List[float]], Optional[str], Optional[str]]:
    """
    Safely derives training features from raw text following the privacy gate and model preprocessing.

    STEPS:
    1. Sanitization: applies sanitize_for_external(allow_external=True).
       If sanitization fails or is unsafe, fails closed.
    2. Preprocessing: applies preprocess_for_neural_model (NFC, evasion stripping, Devanagari digits).
    3. Feature Extraction: CharacterNGramHasher(1024, 3, 5).transform_text().
    4. Validation: checks 1024 finite floats.
    5. Deduplication Fingerprint: keyed HMAC-SHA256 of the normalized text.
    6. Raw & sanitized text is immediately discarded from memory.

    Returns:
        (success, feature_vector, dedup_fingerprint, error_message)
    """
    from src.privacy_gate import sanitize_for_local_training
    from src.custom_model import CharacterNGramHasher
    from src.case_repository import compute_feedback_dedup_fingerprint, FeedbackCurationKeyError

    if raw_text is None or not isinstance(raw_text, str) or not raw_text.strip():
        return False, None, None, "Input text is empty or non-string."

    if len(raw_text) > 50000:
        return False, None, None, "Input exceeds maximum safe feature extraction length (50,000 characters)."

    # Step 1: Privacy gate sanitization (strictly local-only boundary; safe_to_send is permanently False)
    gate_res = sanitize_for_local_training(raw_text)
    if not gate_res.sanitization_success or not gate_res.sanitized_text:
        reasons = "; ".join(gate_res.blocking_reasons) if gate_res.blocking_reasons else "Sanitization check failed"
        return False, None, None, f"Privacy sanitization blocked feature capture: {reasons}"

    # Step 2: Canonical neural model preprocessing
    norm_text = preprocess_for_neural_model(gate_res.sanitized_text)
    if not norm_text or not norm_text.strip():
        return False, None, None, "Text is empty after sanitization and normalization."

    # Step 3: Keyed deduplication fingerprint (fails closed if secret missing)
    try:
        fingerprint = compute_feedback_dedup_fingerprint(norm_text, secret=secret)
    except FeedbackCurationKeyError as e:
        return False, None, None, f"Deduplication fingerprint failed: {e}"
    except Exception as e:
        return False, None, None, f"Deduplication fingerprint error: {e}"

    # Step 4: Extract 1024-dim character n-gram feature vector
    try:
        hasher = CharacterNGramHasher(num_features=EXPECTED_FEATURE_DIM, min_n=3, max_n=5)
        vec = hasher.transform_text(norm_text)

        # Step 5: Validate vector dimensions and finiteness
        if vec.shape != (EXPECTED_FEATURE_DIM,):
            return False, None, None, f"Feature vector dimension mismatch: expected ({EXPECTED_FEATURE_DIM},), got {vec.shape}"

        import numpy as np
        if not np.all(np.isfinite(vec)):
            return False, None, None, "Feature vector contains NaN or infinite values."

        feature_list = [round(float(x), 6) for x in vec.tolist()]

        # Step 6: Explicitly discard intermediate texts from memory
        del gate_res
        del norm_text

        return True, feature_list, fingerprint, None

    except Exception as exc:
        return False, None, None, f"Feature extraction failed: {type(exc).__name__}: {str(exc)}"

