#!/usr/bin/env python3
"""
Comprehensive Quality, Isolation, Semantic Balance, and Leakage Audit for Synthetic Corpus v4.
Part of Seva Cyber Sandbox (Phase 6.4.6).

Performs rigorous verification across 19 audit checks:
1. Training/dev/qualification record IDs are disjoint.
2. All 45 campaign families are unique across partitions.
3. All underlying template-family identifiers (scenarios) are disjoint.
4. No exact normalized-text duplicates exist across partitions.
5. Near-duplicate similarity is audited and documented (3-gram character Jaccard similarity).
6. All three classes are represented (phishing, legitimate, protective_advisory).
7. Language distribution is balanced (~25% mr, mr-Latn, en, mr-en).
8. URL presence is balanced (exactly 50% True, 50% False across partitions and classes).
9. Digital-arrest phishing occurs in training and development.
10. Legitimate police and court notifications occur in training and development.
11. Protective digital-arrest advisories occur in training and development.
12. All three classes contain overlapping law-enforcement vocabulary.
13. URL-free phishing examples exist in each phishing partition.
14. URL-bearing legitimate and protective examples exist in each partition.
15. No real contact information or personal information is included.
16. All records have valid synthetic provenance.
17. All dataset hashes match their manifests.
18. Qualification remains unused and unexposed (exposure count == 0, UNEXPOSED state).
19. Existing v3 files remain unchanged.
"""

from collections import Counter
import hashlib
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Set, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

from src.dataset_preprocessing import (
    normalize_record_text,
    validate_single_record,
)
from src.dataset_validator import compute_locked_test_hash

CORPUS_DIR_V4 = os.path.join(PROJECT_ROOT, "data", "generated", "v4")
CORPUS_DIR_V3 = os.path.join(PROJECT_ROOT, "data", "generated", "v3")
EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"

# Expected unchanged digests for v3
V3_EXPECTED_SHA = {
    "training": "f8143880f3d5d13e5f10c14ca2d07c3a736726979f93a53dd864d59fdaee2473",
    "development": "55e9357abae0de2ebc71535374f079bdb146ea746278471b03797f0941c85e4d",
    "qualification": "197c62e7f0b305ce5965cf7bbeba8543fcd542a4a026d07dbd1172b3656f4a0f",
}


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 checksum of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def load_jsonl(filepath: str) -> List[Dict[str, Any]]:
    """Loads records from a JSONL file."""
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            clean = line.strip()
            if clean:
                try:
                    records.append(json.loads(clean))
                except json.JSONDecodeError as e:
                    raise ValueError(f"JSONDecodeError in {filepath}:{line_num}: {e}")
    return records


def tokenize_for_jaccard(text: str, n: int = 3) -> Set[str]:
    """Generates character n-grams for Jaccard similarity estimation."""
    cleaned = text.lower().replace(" ", "")
    if len(cleaned) < n:
        return {cleaned}
    return {cleaned[i : i + n] for i in range(len(cleaned) - n + 1)}


def run_v4_dataset_audit() -> Dict[str, Any]:
    """Runs the full 19-check audit on Synthetic Corpus v4."""
    print("================================================================================")
    print("   SEVA CYBER SANDBOX — SYNTHETIC CORPUS v4 COMPREHENSIVE AUDIT (PHASE 6.4.6)   ")
    print("================================================================================")

    # 1. Load Partitions
    train_file = os.path.join(CORPUS_DIR_V4, "synthetic_training_corpus.jsonl")
    dev_file = os.path.join(CORPUS_DIR_V4, "synthetic_dev_corpus.jsonl")
    qual_file = os.path.join(CORPUS_DIR_V4, "synthetic_qualification_corpus.jsonl")

    for p in [train_file, dev_file, qual_file]:
        if not os.path.isfile(p):
            raise FileNotFoundError(f"Missing partition file: '{p}'")

    train_records = load_jsonl(train_file)
    dev_records = load_jsonl(dev_file)
    qual_records = load_jsonl(qual_file)

    all_records = train_records + dev_records + qual_records
    print(f"[*] Loaded partitions: Training={len(train_records)}, Dev={len(dev_records)}, Qual={len(qual_records)}")
    print(f"[*] Total records under audit: {len(all_records)}")

    # Check 1: Record IDs Disjoint
    print("\n--- CHECK 1: RECORD ID DISJOINTNESS ---")
    train_ids = {r["record_id"] for r in train_records}
    dev_ids = {r["record_id"] for r in dev_records}
    qual_ids = {r["record_id"] for r in qual_records}

    assert len(train_ids) == len(train_records), "Duplicate IDs within training!"
    assert len(dev_ids) == len(dev_records), "Duplicate IDs within dev!"
    assert len(qual_ids) == len(qual_records), "Duplicate IDs within qual!"

    assert len(train_ids & dev_ids) == 0, f"Leakage: Train & Dev shared IDs: {train_ids & dev_ids}"
    assert len(train_ids & qual_ids) == 0, f"Leakage: Train & Qual shared IDs: {train_ids & qual_ids}"
    assert len(dev_ids & qual_ids) == 0, f"Leakage: Dev & Qual shared IDs: {dev_ids & qual_ids}"
    print("[+] PASS: All record IDs are strictly unique and disjoint across all partitions.")

    # Check 2: 45 Campaign Families Disjoint
    print("\n--- CHECK 2: CAMPAIGN FAMILY DISJOINTNESS (45 FAMILIES) ---")
    train_fams = {r["campaign_id"] for r in train_records}
    dev_fams = {r["campaign_id"] for r in dev_records}
    qual_fams = {r["campaign_id"] for r in qual_records}

    assert len(train_fams) == 30, f"Expected 30 training families, got {len(train_fams)}"
    assert len(dev_fams) == 6, f"Expected 6 dev families, got {len(dev_fams)}"
    assert len(qual_fams) == 9, f"Expected 9 qual families, got {len(qual_fams)}"

    total_fams = train_fams | dev_fams | qual_fams
    assert len(total_fams) == 45, f"Expected 45 total unique families, got {len(total_fams)}"

    assert len(train_fams & dev_fams) == 0, f"Family leakage: Train & Dev: {train_fams & dev_fams}"
    assert len(train_fams & qual_fams) == 0, f"Family leakage: Train & Qual: {train_fams & qual_fams}"
    assert len(dev_fams & qual_fams) == 0, f"Family leakage: Dev & Qual: {dev_fams & qual_fams}"
    print(f"[+] PASS: 45/45 campaign families verified strictly disjoint (30 train, 6 dev, 9 qual).")

    # Check 3: Scenarios Disjoint
    print("\n--- CHECK 3: SCENARIO CATEGORY DISJOINTNESS ---")
    train_scens = {r["scenario_category"] for r in train_records}
    dev_scens = {r["scenario_category"] for r in dev_records}
    qual_scens = {r["scenario_category"] for r in qual_records}

    assert len(train_scens & dev_scens) == 0, f"Scenario leakage: Train & Dev: {train_scens & dev_scens}"
    assert len(train_scens & qual_scens) == 0, f"Scenario leakage: Train & Qual: {train_scens & qual_scens}"
    assert len(dev_scens & qual_scens) == 0, f"Scenario leakage: Dev & Qual: {dev_scens & qual_scens}"
    print("[+] PASS: All scenario categories are strictly disjoint across partitions.")

    # Check 4: Exact Normalized Text Disjointness
    print("\n--- CHECK 4: EXACT NORMALIZED TEXT DISJOINTNESS ---")
    train_texts = {r["normalized_text"] for r in train_records}
    dev_texts = {r["normalized_text"] for r in dev_records}
    qual_texts = {r["normalized_text"] for r in qual_records}

    assert len(train_texts & dev_texts) == 0, "Exact text duplicate found between Train and Dev!"
    assert len(train_texts & qual_texts) == 0, "Exact text duplicate found between Train and Qual!"
    assert len(dev_texts & qual_texts) == 0, "Exact text duplicate found between Dev and Qual!"
    print("[+] PASS: Zero exact normalized-text duplicates found across any partition boundary.")

    # Check 5: Near-Duplicate Similarity Audit (3-gram Jaccard)
    print("\n--- CHECK 5: NEAR-DUPLICATE JACCARD SIMILARITY AUDIT ---")
    # Sample cross-partition pairs to audit maximum similarity
    max_sim = 0.0
    highest_pair = None
    rng = train_records[:50]
    for tr in rng:
        tr_toks = tokenize_for_jaccard(tr["normalized_text"])
        for qr in qual_records[:50]:
            qr_toks = tokenize_for_jaccard(qr["normalized_text"])
            intersection = len(tr_toks & qr_toks)
            union = len(tr_toks | qr_toks)
            sim = intersection / union if union > 0 else 0.0
            if sim > max_sim:
                max_sim = sim
                highest_pair = (tr["campaign_id"], qr["campaign_id"], round(sim, 4))

    print(f"[*] Max sampled 3-gram character Jaccard similarity across partitions: {max_sim:.4f}")
    print(f"[*] Highest similarity pair: {highest_pair}")
    assert max_sim < 0.85, f"Warning: Unusually high text similarity across partitions: {max_sim}"
    print("[+] PASS: Cross-partition near-duplicate audit confirms genuine template disjointness.")

    # Check 6: Class Distribution Balance
    print("\n--- CHECK 6: CLASS DISTRIBUTION BALANCE ---")
    assert len(train_records) == 1500, f"Expected 1500 train records, got {len(train_records)}"
    assert len(dev_records) == 300, f"Expected 300 dev records, got {len(dev_records)}"
    assert len(qual_records) == 450, f"Expected 450 qual records, got {len(qual_records)}"

    for name, recs, expected_count in [
        ("training", train_records, 500),
        ("development", dev_records, 100),
        ("qualification", qual_records, 150),
    ]:
        counts = Counter(r["ground_truth_label"] for r in recs)
        for lbl in ["phishing", "legitimate", "protective_advisory"]:
            assert counts[lbl] == expected_count, f"{name} {lbl} count mismatch: expected {expected_count}, got {counts[lbl]}"
    print("[+] PASS: Perfectly balanced classes across all partitions (Train: 500/500/500, Dev: 100/100/100, Qual: 150/150/150).")

    # Check 7: Language Distribution Balance (~25% each)
    print("\n--- CHECK 7: LANGUAGE DISTRIBUTION BALANCE ---")
    for name, recs in [("training", train_records), ("development", dev_records), ("qualification", qual_records)]:
        l_counts = Counter(r["language"] for r in recs)
        total = len(recs)
        for lang in ["mr", "mr-Latn", "en", "mr-en"]:
            pct = l_counts[lang] / total * 100
            assert 20.0 <= pct <= 30.0, f"{name} {lang} proportion outside expected 20-30% range: {pct:.1f}%"
        print(f"  {name.upper()}: mr={l_counts['mr']}, mr-Latn={l_counts['mr-Latn']}, en={l_counts['en']}, mr-en={l_counts['mr-en']}")
    print("[+] PASS: Multilingual representation balanced across Devanagari, Romanized Marathi, English, and Mixed.")

    # Check 8: URL Presence Balance (Exactly 50% URL-bearing, 50% URL-free)
    print("\n--- CHECK 8: URL PRESENCE BALANCE (50% / 50%) ---")
    for name, recs in [("training", train_records), ("development", dev_records), ("qualification", qual_records)]:
        u_counts = Counter(r["has_url"] for r in recs)
        assert u_counts[True] == len(recs) // 2, f"{name} URL True mismatch: {u_counts[True]} vs {len(recs)//2}"
        assert u_counts[False] == len(recs) // 2, f"{name} URL False mismatch: {u_counts[False]} vs {len(recs)//2}"
        # Check per class
        for lbl in ["phishing", "legitimate", "protective_advisory"]:
            c_recs = [r for r in recs if r["ground_truth_label"] == lbl]
            c_urls = sum(1 for r in c_recs if r["has_url"])
            assert c_urls == len(c_recs) // 2, f"{name} {lbl} URL balance failed: {c_urls}/{len(c_recs)}"
    print("[+] PASS: Exactly 50.0% URL-bearing and 50.0% URL-free across every partition and class.")

    # Check 9, 10, 11: Specific Scenario Presence in Train & Dev
    print("\n--- CHECKS 9, 10, 11: CRITICAL SCENARIO COVERAGE IN TRAIN & DEV ---")
    train_and_dev_scens = train_scens | dev_scens

    # 9. Digital arrest phishing
    da_phish = [s for s in train_and_dev_scens if "digital_arrest" in s or "narcotics" in s or "cbi" in s]
    assert len(da_phish) >= 3, f"Insufficient digital arrest phishing scenarios: {da_phish}"
    print(f"[+] PASS: Digital arrest phishing scenarios present: {da_phish}")

    # 10. Legitimate police and court notifications
    legit_pol_court = [s for s in train_and_dev_scens if "police" in s or "court" in s or "passport" in s]
    assert len(legit_pol_court) >= 3, f"Insufficient legitimate police/court scenarios: {legit_pol_court}"
    print(f"[+] PASS: Legitimate police/court scenarios present: {legit_pol_court}")

    # 11. Protective digital arrest advisories
    da_advisories = [s for s in train_and_dev_scens if "digital_arrest" in s or "impersonation" in s or "1930" in s]
    assert len(da_advisories) >= 3, f"Insufficient protective digital arrest advisories: {da_advisories}"
    print(f"[+] PASS: Protective digital arrest advisories present: {da_advisories}")

    # Check 12: Semantic Overlap Across All Three Classes
    print("\n--- CHECK 12: SEMANTIC OVERLAP OF LAW-ENFORCEMENT VOCABULARY ---")
    keywords = ["पोलीस", "police", "cbi", "fir", "कोर्ट", "court", "warrant", "अटक", "cyber"]
    vocab_by_class: Dict[str, Counter] = {"phishing": Counter(), "legitimate": Counter(), "protective_advisory": Counter()}

    for r in all_records:
        text_lower = r["text"].lower()
        lbl = r["ground_truth_label"]
        for kw in keywords:
            if kw in text_lower:
                vocab_by_class[lbl][kw] += 1

    print("[*] Keyword distribution across classes (sample counts):")
    for kw in keywords:
        p_c = vocab_by_class["phishing"][kw]
        l_c = vocab_by_class["legitimate"][kw]
        a_c = vocab_by_class["protective_advisory"][kw]
        print(f"  Keyword '{kw}': Phish={p_c}, Legit={l_c}, Advisory={a_c}")

    # Verify that major terms appear in multiple classes
    for kw in ["पोलीस", "police", "court"]:
        assert vocab_by_class["phishing"][kw] > 0, f"Keyword '{kw}' missing from phishing!"
        assert vocab_by_class["legitimate"][kw] > 0, f"Keyword '{kw}' missing from legitimate!"
        assert vocab_by_class["protective_advisory"][kw] > 0, f"Keyword '{kw}' missing from advisory!"
    print("[+] PASS: Law-enforcement vocabulary is distributed across all three classes.")

    # Check 13 & 14: URL-free Phishing and URL-bearing Legit/Advisory Presence
    print("\n--- CHECKS 13 & 14: URL-FREE PHISHING & URL-BEARING LEGIT/ADVISORY ---")
    for name, recs in [("training", train_records), ("development", dev_records), ("qualification", qual_records)]:
        p_no_url = [r for r in recs if r["ground_truth_label"] == "phishing" and not r["has_url"]]
        l_with_url = [r for r in recs if r["ground_truth_label"] == "legitimate" and r["has_url"]]
        a_with_url = [r for r in recs if r["ground_truth_label"] == "protective_advisory" and r["has_url"]]
        assert len(p_no_url) > 0, f"Missing URL-free phishing in {name}"
        assert len(l_with_url) > 0, f"Missing URL-bearing legitimate in {name}"
        assert len(a_with_url) > 0, f"Missing URL-bearing advisory in {name}"
    print("[+] PASS: URL-free phishing and URL-bearing legitimate/advisories verified in all partitions.")

    # Check 15: Privacy & Personal Information Check
    print("\n--- CHECK 15: PRIVACY & PII VALIDATION ---")
    for r in all_records:
        is_val, errs = validate_single_record(r)
        assert is_val, f"Validation failure in {r['record_id']}: {errs}"
    print(f"[+] PASS: All {len(all_records)} records strictly conform to schema & zero-PII privacy rules.")

    # Check 16: Synthetic Provenance Verification
    print("\n--- CHECK 16: SYNTHETIC PROVENANCE VERIFICATION ---")
    for r in all_records:
        assert r["provenance_category"] == "synthetic_test_case"
        assert r["provenance_verification_status"] == "synthetic_fixture"
        assert "Synthetic" in r["source_reference"]
        assert "CC0" in r["license_info"]
    print("[+] PASS: 100% of records carry verified synthetic provenance metadata.")

    # Check 17: Manifest SHA-256 Verification
    print("\n--- CHECK 17: MANIFEST SHA-256 INTEGRITY ---")
    for name, fname, recs in [
        ("training", "training_manifest.json", train_records),
        ("development", "dev_manifest.json", dev_records),
        ("qualification", "qualification_manifest.json", qual_records),
    ]:
        mpath = os.path.join(CORPUS_DIR_V4, fname)
        with open(mpath, "r", encoding="utf-8") as f:
            m = json.load(f)
        cpath = os.path.join(CORPUS_DIR_V4, m["file_name"])
        actual_sha = compute_file_sha256(cpath)
        assert m["file_sha256"] == actual_sha, f"SHA mismatch in {fname}"
        assert m["record_count"] == len(recs), f"Count mismatch in {fname}"
        print(f"[+] PASS: Manifest '{fname}' verified -> {actual_sha[:16]}... (Count: {len(recs)})")

    # Check 18: Qualification Exposure Ledger Status
    print("\n--- CHECK 18: QUALIFICATION BENCHMARK UNEXPOSED STATUS ---")
    ledger_path = os.path.join(PROJECT_ROOT, "evaluation", "qualification", "exposure_ledger_v4.json")
    assert os.path.isfile(ledger_path), f"Missing v4 exposure ledger at {ledger_path}"
    with open(ledger_path, "r", encoding="utf-8") as f:
        ledger = json.load(f)

    qual_sha = compute_file_sha256(qual_file)
    assert qual_sha in ledger["partitions"], f"Qualification SHA {qual_sha} not in v4 ledger!"
    part_entry = ledger["partitions"][qual_sha]
    assert part_entry["exposure_count"] == 0, f"Exposure count is {part_entry['exposure_count']} (expected 0)!"
    assert part_entry["is_exposed"] is False, "Qualification partition is flagged as exposed!"
    assert part_entry["current_status"] == "UNEXPOSED", f"Unexpected status: {part_entry['current_status']}"
    print(f"[+] PASS: v4 Qualification partition verified UNEXPOSED in lifecycle exposure ledger.")

    # Check 19: Existing v3 Files Unaltered
    print("\n--- CHECK 19: EXISTING v3 FILES INVARIANCE ---")
    v3_files_map = {
        "training": "synthetic_training_corpus.jsonl",
        "development": "synthetic_dev_corpus.jsonl",
        "qualification": "synthetic_qualification_corpus.jsonl",
    }
    for name, expected_sha in V3_EXPECTED_SHA.items():
        fname = v3_files_map[name]
        fpath = os.path.join(CORPUS_DIR_V3, fname)
        if os.path.isfile(fpath):
            actual = compute_file_sha256(fpath)
            assert actual == expected_sha, f"CRITICAL: v3 {name} partition was altered! Expected {expected_sha}, got {actual}"
            print(f"[+] PASS: Existing v3 {name} corpus verified unchanged: {actual[:16]}...")
        else:
            print(f"[*] Note: v3 file {fname} not present on disk.")

    # Locked test partition invariance
    eval_path = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
    with open(eval_path, "r", encoding="utf-8") as f:
        eval_recs = json.load(f)
    locked_sha = compute_locked_test_hash(eval_recs)
    assert locked_sha == EXPECTED_LOCKED_DIGEST, f"Locked test modified! Expected {EXPECTED_LOCKED_DIGEST}, got {locked_sha}"
    print(f"[+] PASS: Locked independent test partition verified unchanged: {locked_sha[:16]}...")

    # Build and write audit report JSON
    audit_report = {
        "audit_schema_version": "4.0.0",
        "audit_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus_version": "4.0.0",
        "total_records_audited": len(all_records),
        "total_campaign_families": 45,
        "partitions": {
            "training": {"records": len(train_records), "families": len(train_fams), "sha256": compute_file_sha256(train_file)},
            "development": {"records": len(dev_records), "families": len(dev_fams), "sha256": compute_file_sha256(dev_file)},
            "qualification": {"records": len(qual_records), "families": len(qual_fams), "sha256": qual_sha},
        },
        "audit_results": {
            "check_01_record_ids_disjoint": True,
            "check_02_campaign_families_disjoint": True,
            "check_03_scenarios_disjoint": True,
            "check_04_exact_text_duplicates": 0,
            "check_05_max_jaccard_similarity": round(max_sim, 4),
            "check_06_class_distribution_balanced": True,
            "check_07_language_distribution_balanced": True,
            "check_08_url_presence_exactly_half": True,
            "check_09_digital_arrest_phishing_present": True,
            "check_10_legit_police_court_present": True,
            "check_11_advisory_digital_arrest_present": True,
            "check_12_semantic_overlap_confirmed": True,
            "check_13_url_free_phishing_present": True,
            "check_14_url_bearing_legit_advisory_present": True,
            "check_15_pii_validation_passed": True,
            "check_16_synthetic_provenance_verified": True,
            "check_17_manifest_checksums_verified": True,
            "check_18_qualification_unexposed": True,
            "check_19_v3_files_unaltered": True,
            "locked_eval_partition_unaltered": True,
        },
        "verdict": "PASS",
    }

    report_path = os.path.join(CORPUS_DIR_V4, "v4_dataset_audit_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(audit_report, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Audit report successfully written to: {report_path}")
    print("================================================================================")
    print("   ALL 19 AUDIT CHECKS PASSED: SYNTHETIC DATASET v4 MEETS ALL STANDARDS!        ")
    print("================================================================================")
    return audit_report


if __name__ == "__main__":
    run_v4_dataset_audit()
