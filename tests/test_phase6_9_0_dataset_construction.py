"""
Phase 6.9.0 — Trusted Real-World Dataset Construction Test Suite.

Verifies:
1. Operational database construction is blocked by readiness gate (zero fake data).
2. Campaign-family isolation: All items in a campaign are assigned to exactly one split.
3. Ineligible items (withdrawn, uncorroborated, unconsented) are routed to excluded.jsonl.
4. Cryptographic SHA-256 manifest matches disk artifacts exactly.
"""

import hashlib
import json
import os
import tempfile
import pytest

from src.dataset_constructor import RealWorldDatasetConstructor
from src.case_repository import CaseRepository


def test_operational_database_dataset_construction_blocked():
    """Confirms that attempting to construct a dataset from empty production DB is blocked."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as out_dir:
        constructor = RealWorldDatasetConstructor(
            db_path="instance/seva_cases.sqlite3",
            output_dir=out_dir,
        )
        res = constructor.construct_dataset()

        assert res["status"] == "CONSTRUCTION_BLOCKED"
        assert res["reason"] == "BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE"
        assert os.path.exists(res["manifest_path"])
        with open(res["manifest_path"], "r", encoding="utf-8") as f:
            manifest = json.load(f)
        assert manifest["status"] == "CONSTRUCTION_BLOCKED"
        assert manifest["total_records"] == 0


def test_campaign_family_isolation_and_zero_leakage():
    """Verifies campaign-family isolation with zero cross-split leakage."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "test_partition.sqlite3")
    out_dir = os.path.join(temp_dir.name, "output_splits")

    repo = CaseRepository(db_path=db_path)

    # Create 4 distinct campaigns
    camps = [
        repo.create_or_get_campaign_cluster("url_domain", f"campaign-{i}.org", campaign_name=f"Camp {i}")
        for i in range(1, 5)
    ]

    # Create 3 items per campaign (total 12 items)
    for i, camp in enumerate(camps):
        cls = "phishing" if i % 2 == 0 else "legitimate"
        for j in range(3):
            ev = repo.register_evidence_provenance(
                case_id=f"CASE-{i}-{j}",
                evidence_origin="user_reported",
                evidence_type="message_text",
                user_classification=cls,
                consent_given=True,
                metadata={"text": f"Sample {i}-{j}", "language": "en"},
            )
            repo.assign_campaign_cluster(ev["evidence_id"], camp["campaign_id"], operator_username="system")
            repo.transition_evidence_status(ev["evidence_id"], "awaiting_review", "u1", "Triage")
            repo.transition_evidence_status(ev["evidence_id"], "under_review", "u1", "Review", reviewer_classification=cls)
            repo.corroborate_evidence(
                ev["evidence_id"],
                "u2",
                f"Independent verification of item {i}-{j}.",
                cls,
                "official_gazette_scheme_crosscheck",
                [f"REF-{i}-{j}"],
            )

    constructor = RealWorldDatasetConstructor(
        db_path=db_path,
        output_dir=out_dir,
        seed=123,
    )
    res = constructor.construct_dataset(allow_insufficient=True)

    assert res["status"] == "CONSTRUCTED"
    manifest = res["manifest"]
    assert manifest["campaign_isolation_verified"] is True

    # Read each split and collect campaign IDs
    def get_campaigns_in_file(path: str):
        c_set = set()
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                c_set.add(rec["campaign_id"])
        return c_set

    train_c = get_campaigns_in_file(os.path.join(out_dir, "train.jsonl"))
    dev_c = get_campaigns_in_file(os.path.join(out_dir, "dev.jsonl"))
    eval_c = get_campaigns_in_file(os.path.join(out_dir, "sealed_eval.jsonl"))

    # Assert zero overlap between any pair of splits
    assert train_c.isdisjoint(dev_c), f"Leakage: train and dev share campaigns {train_c & dev_c}"
    assert train_c.isdisjoint(eval_c), f"Leakage: train and eval share campaigns {train_c & eval_c}"
    assert dev_c.isdisjoint(eval_c), f"Leakage: dev and eval share campaigns {dev_c & eval_c}"

    # Verify total campaigns equals 4
    assert len(train_c | dev_c | eval_c) == 4


def test_ineligible_records_routed_to_excluded():
    """Verifies that uncorroborated, withdrawn, or unconsented evidence goes to excluded."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "test_excluded.sqlite3")
    out_dir = os.path.join(temp_dir.name, "output_splits")

    repo = CaseRepository(db_path=db_path)

    # 1. Unconsented item
    e1 = repo.register_evidence_provenance(
        case_id="CASE-NO-CONSENT",
        evidence_origin="user_reported",
        evidence_type="url",
        user_classification="phishing",
        consent_given=False,
    )

    # 2. Submitted but uncorroborated item
    e2 = repo.register_evidence_provenance(
        case_id="CASE-UNCORROBORATED",
        evidence_origin="user_reported",
        evidence_type="url",
        user_classification="phishing",
        consent_given=True,
    )

    # 3. Withdrawn item
    e3 = repo.register_evidence_provenance(
        case_id="CASE-WITHDRAWN",
        evidence_origin="user_reported",
        evidence_type="url",
        user_classification="phishing",
        consent_given=True,
    )
    repo.withdraw_evidence(e3["evidence_id"], operator_username="citizen", reason="User revoked report.")

    constructor = RealWorldDatasetConstructor(
        db_path=db_path,
        output_dir=out_dir,
    )
    res = constructor.construct_dataset(allow_insufficient=True)

    excluded_path = os.path.join(out_dir, "excluded.jsonl")
    assert os.path.exists(excluded_path)

    excluded_ids = set()
    with open(excluded_path, "r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            excluded_ids.add(r["evidence_id"])
            assert "exclusion_reason" in r

    assert e1["evidence_id"] in excluded_ids
    assert e2["evidence_id"] in excluded_ids
    assert e3["evidence_id"] in excluded_ids


def test_split_cryptographic_hashes_match_files():
    """Confirms manifest SHA-256 matches disk contents byte-for-byte."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "test_hashes.sqlite3")
    out_dir = os.path.join(temp_dir.name, "output_splits")

    repo = CaseRepository(db_path=db_path)
    c1 = repo.create_or_get_campaign_cluster("url_domain", "camp1.in")

    ev = repo.register_evidence_provenance(
        case_id="CASE-HASH",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        metadata={"text": "Hello world", "language": "en"},
    )
    repo.assign_campaign_cluster(ev["evidence_id"], c1["campaign_id"], operator_username="system")
    repo.transition_evidence_status(ev["evidence_id"], "awaiting_review", "u1", "Triage")
    repo.transition_evidence_status(ev["evidence_id"], "under_review", "u1", "Review", reviewer_classification="phishing")
    repo.corroborate_evidence(ev["evidence_id"], "u2", "Verified phishing payload.", "phishing", "official_gazette_scheme_crosscheck", ["REF-01"])

    constructor = RealWorldDatasetConstructor(
        db_path=db_path,
        output_dir=out_dir,
    )
    res = constructor.construct_dataset(allow_insufficient=True)

    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    for split in ["train", "dev", "sealed_eval", "excluded"]:
        expected_sha = manifest["split_summary"][split]["sha256"]
        split_file = os.path.join(out_dir, f"{split}.jsonl")
        with open(split_file, "rb") as f:
            actual_sha = hashlib.sha256(f.read()).hexdigest()
        assert actual_sha == expected_sha, f"SHA mismatch for split {split}!"
