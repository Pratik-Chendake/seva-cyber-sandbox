"""
Phase 6.8.5 — Operational Workflow and Human Investigation Verification Suite.

Tests:
1. Review queue filtering (by status, campaign, origin).
2. Multi-field classification preservation:
   - user_classification
   - rule_assessment
   - model_prediction
   - reviewer_classification
   - corroborated_conclusion
3. Reviewer assignment and reassignment workflow with audit logging.
4. Two-Person Rule enforcement:
   - Primary submitter cannot independently corroborate their own submission.
   - Primary reviewer cannot corroborate their own review independently.
   - Distinct second reviewer achieves 'independently_corroborated'.
5. Single-operator fallback:
   - Records 'self_reviewed' or 'single_reviewed' without claiming independent corroboration.
6. Append-only audit trail verification.
"""

import os
import tempfile
import pytest
from src.case_repository import (
    CaseRepository,
    SelfApprovalProhibitedError,
    InvalidStateTransitionError,
    EvidenceGovernanceError,
    CorroborationError,
)
from src.case_manager import SessionCaseStore
from src.operator_auth import OperatorAuthService


@pytest.fixture
def test_env():
    """Isolated test repository and case store with initialized operator accounts."""
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "test_investigation.sqlite3")
    repo = CaseRepository(db_path=db_path)
    store = SessionCaseStore(session_id="TEST_WORKFLOW_2026", repository=repo)
    auth = OperatorAuthService(db_path=db_path)

    # Register initial admin operator
    auth.register_initial_operator("admin_root", "AdminRootP@ssw0rd!123", role="admin")
    admin_login = auth.login("admin_root", "AdminRootP@ssw0rd!123")
    admin_token = admin_login["session_token"]

    # Create operators
    auth.create_operator(admin_token, "alice_analyst", "AliceP@ssw0rd!123", role="analyst")
    auth.create_operator(admin_token, "bob_reviewer", "BobP@ssw0rd!456", role="reviewer")
    auth.create_operator(admin_token, "charlie_senior", "CharlieP@ssw0rd!789", role="senior_reviewer")
    auth.create_operator(admin_token, "dana_submitter", "DanaP@ssw0rd!101", role="submitter")

    yield {"repo": repo, "store": store, "auth": auth, "db_path": db_path}
    try:
        temp_dir.cleanup()
    except Exception:
        pass


def test_review_queue_filtering(test_env):
    """Verifies review queue filtering by status, origin, and campaign."""
    store = test_env["store"]

    # Register campaign
    camp = store.create_or_get_campaign("url_domain", "fake-pm-kisan.in", campaign_name="PM Kisan Phishing")

    # Submit 3 cases with evidence
    e1 = store.repository.register_evidence_provenance(
        case_id="CASE-001",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        submitted_by="citizen_user_1",
    )
    store.assign_campaign(e1["evidence_id"], camp["campaign_id"], operator_username="alice_analyst")

    e2 = store.repository.register_evidence_provenance(
        case_id="CASE-002",
        evidence_origin="user_reported",
        evidence_type="url",
        user_classification="suspicious",
        consent_given=True,
        submitted_by="citizen_user_2",
    )

    e3 = store.repository.register_evidence_provenance(
        case_id="CASE-003",
        evidence_origin="analyst_submitted",
        evidence_type="apk_binary",
        user_classification="legitimate",
        consent_given=True,
        submitted_by="analyst_user_3",
    )

    # Transition e2 to under_review via assignment
    store.assign_reviewer(e2["evidence_id"], reviewer_username="bob_reviewer", assigned_by="alice_analyst")

    # Filter by lifecycle_status
    submitted_items = store.list_evidence(lifecycle_status="submitted")
    assert any(x["evidence_id"] == e1["evidence_id"] for x in submitted_items)
    assert not any(x["evidence_id"] == e2["evidence_id"] for x in submitted_items)

    under_review_items = store.list_evidence(lifecycle_status="under_review")
    assert any(x["evidence_id"] == e2["evidence_id"] for x in under_review_items)

    # Filter by origin
    analyst_items = store.list_evidence(origin="analyst_submitted")
    assert len(analyst_items) == 1
    assert analyst_items[0]["evidence_id"] == e3["evidence_id"]

    # Filter by campaign
    camp_items = store.list_evidence(campaign_id=camp["campaign_id"])
    assert len(camp_items) == 1
    assert camp_items[0]["evidence_id"] == e1["evidence_id"]


def test_multi_field_classification_preservation(test_env):
    """
    Verifies that all 5 classification dimensions are distinct and preserved:
    1. user_classification (citizen)
    2. rule_assessment (deterministic engine)
    3. model_prediction (shadow neural model)
    4. reviewer_classification (first human reviewer)
    5. corroborated_conclusion (independent second human corroborator)
    """
    store = test_env["store"]

    evid = store.repository.register_evidence_provenance(
        case_id="CASE-MULTI-01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="suspicious",
        rule_assessment="high_risk_urgency",
        model_prediction="phishing",
        consent_given=True,
        submitted_by="citizen_user",
    )

    # Initial registration assertions
    assert evid["user_classification"] == "suspicious"
    assert evid["rule_assessment"] == "high_risk_urgency"
    assert evid["model_prediction"] == "phishing"
    assert evid["reviewer_classification"] is None
    assert evid["corroborated_conclusion"] is None

    # Step 1: Advance submitted -> awaiting_review
    store.transition_evidence(
        evidence_id=evid["evidence_id"],
        to_status="awaiting_review",
        operator_username="alice_analyst",
        transition_reason="Queued for primary triage analysis.",
    )

    # Step 2: First reviewer investigates and sets reviewer_classification
    store.transition_evidence(
        evidence_id=evid["evidence_id"],
        to_status="under_review",
        operator_username="alice_analyst",
        transition_reason="Beginning formal human investigation.",
        reviewer_classification="phishing",
    )

    mid_evid = store.repository.get_evidence_provenance(evid["evidence_id"])
    assert mid_evid["user_classification"] == "suspicious"
    assert mid_evid["rule_assessment"] == "high_risk_urgency"
    assert mid_evid["model_prediction"] == "phishing"
    assert mid_evid["reviewer_classification"] == "phishing"
    assert mid_evid["corroborated_conclusion"] is None

    # Step 3: Independent second reviewer corroborates
    store.corroborate_evidence(
        evidence_id=evid["evidence_id"],
        operator_username="charlie_senior",
        rationale="Independent technical analysis verified fraudulent URL impersonating Maharashtra government.",
        conclusion="phishing",
        verification_method="official_gazette_scheme_crosscheck",
        supporting_references=["GR-MAHA-2024-TEST-01", "DNS-WHOIS-ANOMALY-01"],
        require_independent=True,
        operator_role="senior_reviewer",
    )

    final_evid = store.repository.get_evidence_provenance(evid["evidence_id"])
    assert final_evid["user_classification"] == "suspicious"
    assert final_evid["rule_assessment"] == "high_risk_urgency"
    assert final_evid["model_prediction"] == "phishing"
    assert final_evid["reviewer_classification"] == "phishing"
    assert final_evid["corroborated_conclusion"] == "phishing"
    assert final_evid["verification_level"] == "independently_corroborated"
    assert final_evid["corroborated_by"] == "charlie_senior"
    assert final_evid["reviewed_by"] == "alice_analyst"


def test_reviewer_assignment_and_reassignment(test_env):
    """Verifies investigator assignment, status advancement to under_review, and reassignment."""
    store = test_env["store"]

    evid = store.repository.register_evidence_provenance(
        case_id="CASE-ASSIGN-01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        submitted_by="citizen_user",
    )
    assert evid["lifecycle_status"] == "submitted"
    assert evid["reviewed_by"] is None

    # Assign reviewer (advances to under_review)
    assigned = store.assign_reviewer(
        evidence_id=evid["evidence_id"],
        reviewer_username="alice_analyst",
        assigned_by="charlie_senior",
        notes="Urgent investigation required for beneficiary fraud.",
    )
    assert assigned["lifecycle_status"] == "under_review"
    assert assigned["reviewed_by"] == "alice_analyst"

    # Reassign reviewer while still under_review
    reassigned = store.assign_reviewer(
        evidence_id=evid["evidence_id"],
        reviewer_username="bob_reviewer",
        assigned_by="charlie_senior",
        notes="Reassigned due to investigator shift change.",
    )
    assert reassigned["lifecycle_status"] == "under_review"
    assert reassigned["reviewed_by"] == "bob_reviewer"

    # Verify audit history
    history = store.get_evidence_history(evid["evidence_id"])
    assign_events = [h for h in history if "Assigned reviewer" in h["transition_reason"]]
    assert len(assign_events) == 2
    assert assign_events[0]["details"]["assigned_to"] == "alice_analyst"
    assert assign_events[1]["details"]["assigned_to"] == "bob_reviewer"


def test_two_person_rule_enforcement(test_env):
    """Verifies that self-approval is strictly prevented for both submitters and primary reviewers."""
    store = test_env["store"]

    # 1. Submitter cannot corroborate own submission
    evid1 = store.repository.register_evidence_provenance(
        case_id="CASE-2P-01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        submitted_by="dana_submitter",
    )

    with pytest.raises(SelfApprovalProhibitedError) as exc1:
        store.corroborate_evidence(
            evidence_id=evid1["evidence_id"],
            operator_username="dana_submitter",
            rationale="I submitted this and I am confirming it is phishing.",
            conclusion="phishing",
            verification_method="official_gazette_scheme_crosscheck",
            supporting_references=["REF-SELF-01"],
            require_independent=True,
            operator_role="reviewer",
        )
    assert "Self-approval prohibited" in str(exc1.value)

    # 2. Primary reviewer cannot independently corroborate own primary review
    evid2 = store.repository.register_evidence_provenance(
        case_id="CASE-2P-02",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        submitted_by="citizen_anon",
    )
    store.assign_reviewer(evid2["evidence_id"], reviewer_username="alice_analyst", assigned_by="system")

    with pytest.raises(SelfApprovalProhibitedError) as exc2:
        store.corroborate_evidence(
            evidence_id=evid2["evidence_id"],
            operator_username="alice_analyst",
            rationale="I triaged this and now I am independently corroborating it.",
            conclusion="phishing",
            verification_method="official_gazette_scheme_crosscheck",
            supporting_references=["REF-PRIMARY-01"],
            require_independent=True,
            operator_role="analyst",
        )
    assert "Self-approval prohibited" in str(exc2.value)

    # 3. Distinct second reviewer succeeds
    corroborated = store.corroborate_evidence(
        evidence_id=evid2["evidence_id"],
        operator_username="bob_reviewer",
        rationale="Independent cross-verification completed against state portal.",
        conclusion="phishing",
        verification_method="official_gazette_scheme_crosscheck",
        supporting_references=["MAHA-CYBER-ADVISORY-2024-09"],
        require_independent=True,
        operator_role="reviewer",
    )
    assert corroborated["lifecycle_status"] == "corroborated"
    assert corroborated["verification_level"] == "independently_corroborated"
    assert corroborated["reviewed_by"] == "alice_analyst"
    assert corroborated["corroborated_by"] == "bob_reviewer"


def test_single_operator_mode_fallback(test_env):
    """
    Verifies that when require_independent=False (single operator / resource-constrained),
    the system honestly records 'single_reviewed' or 'self_reviewed' rather than claiming
    independent corroboration.
    """
    store = test_env["store"]

    evid = store.repository.register_evidence_provenance(
        case_id="CASE-SOLO-01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        submitted_by="alice_analyst",
    )

    # Single operator reviews and corroborates own submission in single-operator mode
    res = store.corroborate_evidence(
        evidence_id=evid["evidence_id"],
        operator_username="alice_analyst",
        rationale="Single operator triage and verification of state portal spoofing.",
        conclusion="phishing",
        verification_method="official_gazette_scheme_crosscheck",
        supporting_references=["SOLO-REF-01"],
        require_independent=False,
        operator_role="analyst",
    )

    assert res["lifecycle_status"] == "corroborated"
    assert res["verification_level"] == "self_reviewed"
    assert res["corroborated_by"] is None

    # Verify that self_reviewed evidence reflects the honest verification level and is not Tier 1
    eligibility = store.check_training_eligibility(evid["evidence_id"])
    assert eligibility["verification_level"] == "self_reviewed"
    assert eligibility["eligibility_tier"] != "independently_corroborated_evaluation_candidate"


def test_append_only_audit_trail(test_env):
    """Verifies that evidence lifecycle events are strictly append-only and chronological."""
    store = test_env["store"]

    evid = store.repository.register_evidence_provenance(
        case_id="CASE-AUDIT-01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        submitted_by="citizen_user",
    )

    # Step 1: Assignment to alice_analyst (transitions submitted -> under_review)
    store.assign_reviewer(evid["evidence_id"], "alice_analyst", "system", notes="Auto-assigned on intake")

    # Step 2: Reassign to bob_reviewer with investigation notes
    store.assign_reviewer(evid["evidence_id"], "bob_reviewer", "alice_analyst", notes="Escalated to senior analyst")

    # Step 3: Independent Corroboration by charlie_senior
    store.corroborate_evidence(
        evidence_id=evid["evidence_id"],
        operator_username="charlie_senior",
        rationale="Confirmed malicious intent matching statewide credential harvest campaign.",
        conclusion="phishing",
        verification_method="official_gazette_scheme_crosscheck",
        supporting_references=["CERT-IN-ADVISORY-2024-X"],
        require_independent=True,
        operator_role="senior_reviewer",
    )

    history = store.get_evidence_history(evid["evidence_id"])
    assert len(history) >= 4  # Initial creation + 2 assignments + 1 corroboration

    # Check sequence
    assert history[0]["to_status"] == "submitted"
    assert history[1]["to_status"] == "under_review"
    assert history[-1]["to_status"] == "corroborated"

    # Verify immutability: all audit events have valid non-empty audit_id and ISO timestamps
    for h in history:
        assert h["audit_id"].startswith("AUD-")
        assert len(h["timestamp_utc"]) >= 19
        assert h["operator_username"] in ("system", "alice_analyst", "charlie_senior")
