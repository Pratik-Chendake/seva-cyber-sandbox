-- =============================================================================
-- SEVA CYBER SANDBOX — SUPABASE POSTGRESQL PRODUCTION SCHEMA
-- Migration: 001_initial_schema.sql
-- Compatible with PostgreSQL 15+ / Supabase
-- Preserves ALL 16 operational tables, relationships, indexes, and constraints
-- =============================================================================

-- Enable UUID extension if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Schema Version Tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT NOT NULL
);

-- 2. Threat Cases (Primary Evidence Submissions)
CREATE TABLE IF NOT EXISTS threat_cases (
    case_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    analysis_type TEXT NOT NULL,
    analysis_status TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_category TEXT NOT NULL,
    badge_color TEXT NOT NULL,
    indicator_count INTEGER NOT NULL DEFAULT 0,
    sha256_hash TEXT,
    hash_algorithm TEXT,
    target_identifier TEXT NOT NULL,
    recommended_action TEXT,
    source_type TEXT NOT NULL DEFAULT 'web_simulator',
    dedup_key TEXT,
    observed_evidence_json TEXT NOT NULL DEFAULT '[]',
    heuristic_inferences_json TEXT NOT NULL DEFAULT '[]',
    extracted_urls_json TEXT NOT NULL DEFAULT '[]',
    official_sources_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    evidence_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_pg_cases_session ON threat_cases(session_id);
CREATE INDEX IF NOT EXISTS idx_pg_cases_created ON threat_cases(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pg_cases_type ON threat_cases(analysis_type);
CREATE INDEX IF NOT EXISTS idx_pg_cases_risk ON threat_cases(risk_score);
CREATE INDEX IF NOT EXISTS idx_pg_cases_dedup ON threat_cases(dedup_key);
CREATE INDEX IF NOT EXISTS idx_pg_cases_evidence ON threat_cases(evidence_id);

-- 3. Campaign Clusters (Cross-Case Threat Aggregation)
CREATE TABLE IF NOT EXISTS campaign_clusters (
    campaign_id TEXT PRIMARY KEY,
    campaign_name TEXT NOT NULL,
    cluster_type TEXT NOT NULL,
    cluster_key TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL DEFAULT 'system',
    is_shared_infrastructure INTEGER NOT NULL DEFAULT 0,
    infrastructure_notes TEXT NOT NULL DEFAULT '',
    has_conflicting_classifications INTEGER NOT NULL DEFAULT 0,
    quarantined_from_training INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_campaign_key ON campaign_clusters(cluster_type, cluster_key);
CREATE INDEX IF NOT EXISTS idx_pg_campaign_created ON campaign_clusters(created_at_utc DESC);

-- 4. Evidence Provenance & Lifecycle State Machine
CREATE TABLE IF NOT EXISTS evidence_provenance (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES threat_cases(case_id) ON DELETE CASCADE,
    evidence_origin TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    lifecycle_status TEXT NOT NULL DEFAULT 'submitted',
    user_classification TEXT,
    model_prediction TEXT,
    rule_assessment TEXT,
    reviewer_classification TEXT,
    corroborated_conclusion TEXT,
    corroboration_rationale TEXT NOT NULL DEFAULT '',
    campaign_id TEXT REFERENCES campaign_clusters(campaign_id) ON DELETE SET NULL,
    consent_given INTEGER NOT NULL DEFAULT 0,
    consent_timestamp_utc TIMESTAMPTZ,
    sanitization_status TEXT NOT NULL DEFAULT 'unverified',
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    submitted_by TEXT,
    reviewed_by TEXT,
    corroborated_by TEXT,
    verification_level TEXT NOT NULL DEFAULT 'unverified',
    verification_method TEXT,
    supporting_references_json TEXT NOT NULL DEFAULT '[]',
    conflicting_evidence_json TEXT NOT NULL DEFAULT '[]',
    relationship_strength TEXT NOT NULL DEFAULT 'unrelated_evidence',
    poisoning_risk_flags_json TEXT NOT NULL DEFAULT '[]',
    eligibility_tier TEXT NOT NULL DEFAULT 'not_eligible',
    artifact_sha256 TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_evid_case ON evidence_provenance(case_id);
CREATE INDEX IF NOT EXISTS idx_pg_evid_status ON evidence_provenance(lifecycle_status);
CREATE INDEX IF NOT EXISTS idx_pg_evid_origin ON evidence_provenance(evidence_origin);
CREATE INDEX IF NOT EXISTS idx_pg_evid_campaign ON evidence_provenance(campaign_id);

-- 5. Evidence Lifecycle Audit Log
CREATE TABLE IF NOT EXISTS evidence_lifecycle_audit (
    audit_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence_provenance(evidence_id) ON DELETE CASCADE,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    operator_username TEXT NOT NULL,
    transition_reason TEXT NOT NULL,
    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_evid_audit_evid ON evidence_lifecycle_audit(evidence_id);
CREATE INDEX IF NOT EXISTS idx_pg_evid_audit_time ON evidence_lifecycle_audit(timestamp_utc DESC);

-- 6. Threat Indicators Knowledge Base
CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator_id TEXT PRIMARY KEY,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    indicator_hash TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'analyst_curated',
    confidence_score INTEGER NOT NULL DEFAULT 50,
    severity TEXT NOT NULL DEFAULT 'medium',
    review_state TEXT NOT NULL DEFAULT 'unreviewed',
    is_active INTEGER NOT NULL DEFAULT 1,
    first_seen_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    notes TEXT NOT NULL DEFAULT '',
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_ind_type ON threat_indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_pg_ind_value ON threat_indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_pg_ind_hash ON threat_indicators(indicator_hash);
CREATE INDEX IF NOT EXISTS idx_pg_ind_review ON threat_indicators(review_state);

-- 7. Indicator Audit Trail
CREATE TABLE IF NOT EXISTS indicator_audit_log (
    log_id TEXT PRIMARY KEY,
    indicator_id TEXT,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_ind_audit_time ON indicator_audit_log(timestamp_utc DESC);

-- 8. Operator Accounts & Authentication
CREATE TABLE IF NOT EXISTS operator_accounts (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_utc TIMESTAMPTZ,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until_utc TIMESTAMPTZ,
    is_active INTEGER NOT NULL DEFAULT 1
);

-- 9. Operator Active Sessions
CREATE TABLE IF NOT EXISTS operator_sessions (
    session_token TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES operator_accounts(username) ON DELETE CASCADE,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at_utc TIMESTAMPTZ NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '127.0.0.1',
    user_agent TEXT NOT NULL DEFAULT 'local_client',
    is_revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pg_sessions_user ON operator_sessions(username);
CREATE INDEX IF NOT EXISTS idx_pg_sessions_expires ON operator_sessions(expires_at_utc);

-- 10. Human Review Desk
CREATE TABLE IF NOT EXISTS human_reviews (
    review_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES threat_cases(case_id) ON DELETE CASCADE,
    review_state TEXT NOT NULL DEFAULT 'pending',
    outcome_category TEXT,
    confidence_rating TEXT DEFAULT 'medium',
    reviewer_label TEXT NOT NULL DEFAULT 'local_operator',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_reviews_case ON human_reviews(case_id);
CREATE INDEX IF NOT EXISTS idx_pg_reviews_state ON human_reviews(review_state);
CREATE INDEX IF NOT EXISTS idx_pg_reviews_outcome ON human_reviews(outcome_category);
CREATE INDEX IF NOT EXISTS idx_pg_reviews_updated ON human_reviews(updated_at DESC);

-- 11. Review Audit Log
CREATE TABLE IF NOT EXISTS review_audit_log (
    log_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'local_operator',
    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_review_audit_rev ON review_audit_log(review_id);
CREATE INDEX IF NOT EXISTS idx_pg_review_audit_time ON review_audit_log(timestamp_utc DESC);
CREATE INDEX IF NOT EXISTS idx_pg_review_audit_action ON review_audit_log(action);

-- 12. Training Feature Records (ML Preprocessing Telemetry)
CREATE TABLE IF NOT EXISTS training_feature_records (
    feature_record_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    feature_schema_version TEXT NOT NULL,
    preprocessing_version TEXT NOT NULL,
    feature_extractor_version TEXT NOT NULL,
    feature_vector_json TEXT NOT NULL DEFAULT '[]',
    feature_dim INTEGER NOT NULL,
    consent_given INTEGER NOT NULL DEFAULT 0,
    consent_timestamp_utc TIMESTAMPTZ NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    eligibility_state TEXT NOT NULL DEFAULT 'pending_review',
    dedup_fingerprint TEXT NOT NULL,
    provenance_category TEXT NOT NULL DEFAULT 'local_curated_feedback',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_features_case ON training_feature_records(case_id);
CREATE INDEX IF NOT EXISTS idx_pg_features_fingerprint ON training_feature_records(dedup_fingerprint);
CREATE INDEX IF NOT EXISTS idx_pg_features_eligibility ON training_feature_records(eligibility_state);
CREATE INDEX IF NOT EXISTS idx_pg_features_created ON training_feature_records(created_at_utc DESC);

-- 13. Model Disagreement Events (Shadow AI Monitoring)
CREATE TABLE IF NOT EXISTS model_disagreement_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    rule_decision TEXT NOT NULL,
    model_prediction TEXT,
    model_version TEXT,
    rule_engine_version TEXT,
    model_confidence REAL,
    model_confidence_bucket TEXT,
    rule_score INTEGER,
    rule_score_bucket TEXT,
    language_category TEXT DEFAULT 'unknown',
    script_category TEXT DEFAULT 'unknown',
    message_length_bucket TEXT DEFAULT 'short (<100)',
    review_state TEXT NOT NULL DEFAULT 'pending',
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consent_given INTEGER NOT NULL DEFAULT 0,
    feature_record_id TEXT,
    case_id TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_disagree_review_state ON model_disagreement_events(review_state);
CREATE INDEX IF NOT EXISTS idx_pg_disagree_created ON model_disagreement_events(created_at_utc DESC);
CREATE INDEX IF NOT EXISTS idx_pg_disagree_event_type ON model_disagreement_events(event_type);

-- 14. Disagreement Reviews (Human Assessment of AI Discrepancies)
CREATE TABLE IF NOT EXISTS disagreement_reviews (
    review_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES model_disagreement_events(event_id) ON DELETE CASCADE,
    review_state TEXT NOT NULL DEFAULT 'completed',
    outcome_label TEXT NOT NULL,
    reviewer_assessment TEXT NOT NULL,
    confidence_rating TEXT NOT NULL DEFAULT 'medium',
    reviewer_label TEXT NOT NULL DEFAULT 'local_operator_unauthenticated',
    notes TEXT NOT NULL DEFAULT '',
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_superseded INTEGER NOT NULL DEFAULT 0,
    superseded_by TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_disagree_rev_event ON disagreement_reviews(event_id);
CREATE INDEX IF NOT EXISTS idx_pg_disagree_rev_state ON disagreement_reviews(review_state);

-- 15. Disagreement Review Audit Log
CREATE TABLE IF NOT EXISTS disagreement_review_audit (
    audit_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'local_operator_unauthenticated',
    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_pg_disagree_audit_event ON disagreement_review_audit(event_id);
CREATE INDEX IF NOT EXISTS idx_pg_disagree_audit_time ON disagreement_review_audit(timestamp_utc DESC);

-- 16. Schema Migrations Log
CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_id TEXT PRIMARY KEY,
    applied_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT NOT NULL
);

-- Initial Version Stamp
INSERT INTO schema_version (version, applied_at, description)
VALUES (1, NOW(), 'Supabase PostgreSQL comprehensive production schema migration (16 tables parity)')
ON CONFLICT (version) DO NOTHING;
