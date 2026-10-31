"""
Safe Database Migration and Rollback Service for Seva Cyber Sandbox.

DESIGN & SAFETY GUARANTEES:
1. Transaction-Enclosed Operations: Every schema migration runs inside an explicit SQLite transaction.
   If an error occurs, the transaction rolls back cleanly.
2. Pre-Migration Backups: Creates a timestamped atomic copy of the target database before executing
   any DDL statements.
3. Zero Historical Data Loss: Existing threat cases, indicators, reviews, and feature records are
   strictly preserved without alteration or deletion.
4. Non-Destructive DDL: Uses `ALTER TABLE ADD COLUMN` and `CREATE TABLE IF NOT EXISTS` with proper
   indexes and foreign keys. Existing tables are never dropped or rewritten.
5. Reversibility: Provides `rollback_migration(backup_path, target_path)` for safe restoration from backup.
6. Schema Version Tracking: Records migrations in `schema_migrations` to prevent duplicate applications.
"""

from datetime import datetime, timezone
import os
import shutil
import sqlite3
from typing import Any, Dict, List, Optional


MIGRATION_VERSION_V2 = "20261031_01_evidence_governance_v2"
MIGRATION_VERSION_V3 = "20261031_02_evidence_trust_hardening_v3"


class MigrationError(Exception):
    """Base exception for database migration and rollback failures."""
    pass


def get_utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_database_backup(db_path: str, backup_dir: Optional[str] = None) -> str:
    """
    Creates an atomic timestamped file backup of an existing SQLite database.
    Returns the absolute path to the backup file.
    """
    if not os.path.exists(db_path):
        raise MigrationError(f"Database file does not exist at '{db_path}' for backup.")

    target_dir = backup_dir or os.path.dirname(os.path.abspath(db_path))
    os.makedirs(target_dir, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = os.path.basename(db_path)
    backup_filename = f"{base_name}.bak_migration_{timestamp_str}"
    backup_path = os.path.join(target_dir, backup_filename)

    try:
        shutil.copy2(db_path, backup_path)
        return backup_path
    except OSError as exc:
        raise MigrationError(f"Failed to create database backup at '{backup_path}': {exc}") from exc


def rollback_migration(backup_path: str, target_db_path: str) -> Dict[str, Any]:
    """
    Rolls back a database to a pre-migration backup file.
    """
    if not os.path.exists(backup_path):
        raise MigrationError(f"Backup file not found at '{backup_path}'.")

    try:
        shutil.copy2(backup_path, target_db_path)
        return {
            "success": True,
            "restored_from": backup_path,
            "target_path": target_db_path,
            "timestamp_utc": get_utc_now_iso(),
            "message": "Database safely restored from backup.",
        }
    except OSError as exc:
        raise MigrationError(f"Failed to restore database from '{backup_path}': {exc}") from exc


def get_applied_migrations(db_path: str) -> List[Dict[str, Any]]:
    """Returns list of applied migrations from schema_migrations."""
    if not os.path.exists(db_path):
        return []

    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        # Check if schema_migrations table exists
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations';"
        )
        if not cur.fetchone():
            return []

        cur = conn.execute(
            "SELECT migration_id, applied_at_utc, description FROM schema_migrations ORDER BY applied_at_utc ASC;"
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def migrate_to_evidence_governance_v2(
    db_path: str,
    create_backup: bool = True,
    backup_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes Phase 6.8.2 Evidence Governance schema migration in a safe, transaction-protected manner.
    """
    backup_path = None
    if os.path.exists(db_path) and create_backup:
        backup_path = create_database_backup(db_path, backup_dir=backup_dir)

    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("BEGIN TRANSACTION;")

        # 1. Migration metadata tracking table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id TEXT PRIMARY KEY,
                applied_at_utc TEXT NOT NULL,
                description TEXT NOT NULL
            );
            """
        )

        cur = conn.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?;",
            (MIGRATION_VERSION_V2,),
        )
        if cur.fetchone()[0] > 0:
            conn.commit()
            return {
                "success": True,
                "already_applied": True,
                "migration_id": MIGRATION_VERSION_V2,
                "backup_path": backup_path,
                "message": "Migration already applied previously.",
            }

        # 2. Upgrade threat_cases to include evidence_id if missing
        cur = conn.execute("PRAGMA table_info(threat_cases);")
        columns = [row["name"] for row in cur.fetchall()]
        if columns and "evidence_id" not in columns:
            conn.execute("ALTER TABLE threat_cases ADD COLUMN evidence_id TEXT;")

        # 3. Create evidence_provenance table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_provenance (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_origin TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                lifecycle_status TEXT NOT NULL DEFAULT 'submitted',
                user_classification TEXT,
                model_prediction TEXT,
                rule_assessment TEXT,
                reviewer_classification TEXT,
                corroborated_conclusion TEXT,
                corroboration_rationale TEXT NOT NULL DEFAULT '',
                campaign_id TEXT,
                consent_given INTEGER NOT NULL DEFAULT 0,
                consent_timestamp_utc TEXT,
                sanitization_status TEXT NOT NULL DEFAULT 'unverified',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evid_case ON evidence_provenance(case_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evid_origin ON evidence_provenance(evidence_origin);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evid_status ON evidence_provenance(lifecycle_status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evid_campaign ON evidence_provenance(campaign_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evid_created ON evidence_provenance(created_at_utc DESC);")

        # 4. Create evidence_lifecycle_audit table (append-only transition log)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_lifecycle_audit (
                audit_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                from_status TEXT NOT NULL,
                to_status TEXT NOT NULL,
                operator_username TEXT NOT NULL,
                transition_reason TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (evidence_id) REFERENCES evidence_provenance(evidence_id)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evid_audit_evid ON evidence_lifecycle_audit(evidence_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evid_audit_time ON evidence_lifecycle_audit(timestamp_utc DESC);")

        # 5. Create operator_accounts and operator_sessions tables
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS operator_accounts (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                created_at_utc TEXT NOT NULL,
                last_login_utc TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS operator_sessions (
                session_token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL,
                is_revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (username) REFERENCES operator_accounts(username)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON operator_sessions(username);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON operator_sessions(expires_at_utc);")

        # 6. Create campaign_clusters table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS campaign_clusters (
                campaign_id TEXT PRIMARY KEY,
                campaign_name TEXT NOT NULL,
                cluster_type TEXT NOT NULL,
                cluster_key TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                created_by TEXT NOT NULL DEFAULT 'system',
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign_key ON campaign_clusters(cluster_type, cluster_key);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign_created ON campaign_clusters(created_at_utc DESC);")

        # 7. Record migration entry
        now_iso = get_utc_now_iso()
        conn.execute(
            """
            INSERT INTO schema_migrations (migration_id, applied_at_utc, description)
            VALUES (?, ?, ?);
            """,
            (
                MIGRATION_VERSION_V2,
                now_iso,
                "Phase 6.8.2 Evidence governance, provenance tracking, lifecycle state machine, and operator authentication tables.",
            ),
        )

        conn.commit()
        return {
            "success": True,
            "already_applied": False,
            "migration_id": MIGRATION_VERSION_V2,
            "backup_path": backup_path,
            "applied_at_utc": now_iso,
            "message": "Phase 6.8.2 Evidence Governance schema migration applied successfully.",
        }
    except Exception as exc:
        conn.rollback()
        raise MigrationError(f"Migration to v2 failed: {exc}") from exc
    finally:
        conn.close()


def migrate_to_evidence_trust_hardening_v3(
    db_path: str,
    create_backup: bool = True,
    backup_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes Phase 6.8.3 Evidence Trust, Authentication, and Anti-Poisoning Security Hardening
    schema migration in a safe, transaction-protected manner.
    """
    # 1. Ensure v2 is applied first
    if os.path.exists(db_path):
        v2_status = migrate_to_evidence_governance_v2(
            db_path, create_backup=create_backup, backup_dir=backup_dir
        )
        backup_path = v2_status.get("backup_path")
    else:
        backup_path = None
        migrate_to_evidence_governance_v2(db_path, create_backup=False)

    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("BEGIN TRANSACTION;")

        cur = conn.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = ?;",
            (MIGRATION_VERSION_V3,),
        )
        if cur.fetchone()[0] > 0:
            conn.commit()
            return {
                "success": True,
                "already_applied": True,
                "migration_id": MIGRATION_VERSION_V3,
                "backup_path": backup_path,
                "message": "Migration v3 already applied previously.",
            }

        # Helper to check columns
        def get_existing_columns(table_name: str) -> List[str]:
            c = conn.execute(f"PRAGMA table_info({table_name});")
            return [r["name"] for r in c.fetchall()]

        # 2. Operator accounts hardening columns
        op_cols = get_existing_columns("operator_accounts")
        if "failed_login_count" not in op_cols:
            conn.execute("ALTER TABLE operator_accounts ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;")
        if "locked_until_utc" not in op_cols:
            conn.execute("ALTER TABLE operator_accounts ADD COLUMN locked_until_utc TEXT;")

        # 3. Operator sessions context binding columns
        sess_cols = get_existing_columns("operator_sessions")
        if "client_ip" not in sess_cols:
            conn.execute("ALTER TABLE operator_sessions ADD COLUMN client_ip TEXT NOT NULL DEFAULT '127.0.0.1';")
        if "user_agent" not in sess_cols:
            conn.execute("ALTER TABLE operator_sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT 'local_client';")

        # 4. Evidence provenance hardening columns
        evid_cols = get_existing_columns("evidence_provenance")
        new_evid_cols = [
            ("submitted_by", "TEXT"),
            ("reviewed_by", "TEXT"),
            ("corroborated_by", "TEXT"),
            ("verification_level", "TEXT NOT NULL DEFAULT 'unverified'"),
            ("verification_method", "TEXT"),
            ("supporting_references_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("conflicting_evidence_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("relationship_strength", "TEXT NOT NULL DEFAULT 'unrelated_evidence'"),
            ("poisoning_risk_flags_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("eligibility_tier", "TEXT NOT NULL DEFAULT 'not_eligible'"),
            ("artifact_sha256", "TEXT"),
        ]
        for col_name, col_def in new_evid_cols:
            if col_name not in evid_cols:
                conn.execute(f"ALTER TABLE evidence_provenance ADD COLUMN {col_name} {col_def};")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_evid_vlevel ON evidence_provenance(verification_level);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evid_tier ON evidence_provenance(eligibility_tier);")

        # 5. Campaign clusters shared infrastructure and quarantine columns
        camp_cols = get_existing_columns("campaign_clusters")
        new_camp_cols = [
            ("is_shared_infrastructure", "INTEGER NOT NULL DEFAULT 0"),
            ("infrastructure_notes", "TEXT NOT NULL DEFAULT ''"),
            ("has_conflicting_classifications", "INTEGER NOT NULL DEFAULT 0"),
            ("quarantined_from_training", "INTEGER NOT NULL DEFAULT 0"),
        ]
        for col_name, col_def in new_camp_cols:
            if col_name not in camp_cols:
                conn.execute(f"ALTER TABLE campaign_clusters ADD COLUMN {col_name} {col_def};")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign_shared ON campaign_clusters(is_shared_infrastructure);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_campaign_quarantine ON campaign_clusters(quarantined_from_training);")

        # 6. Record migration entry
        now_iso = get_utc_now_iso()
        conn.execute(
            """
            INSERT INTO schema_migrations (migration_id, applied_at_utc, description)
            VALUES (?, ?, ?);
            """,
            (
                MIGRATION_VERSION_V3,
                now_iso,
                "Phase 6.8.3 Evidence trust, two-person rule, anti-poisoning, shared-infrastructure awareness, and 4-tier training eligibility.",
            ),
        )

        conn.commit()
        return {
            "success": True,
            "already_applied": False,
            "migration_id": MIGRATION_VERSION_V3,
            "backup_path": backup_path,
            "applied_at_utc": now_iso,
            "message": "Phase 6.8.3 Evidence Trust Security Hardening schema migration applied successfully.",
        }
    except Exception as exc:
        conn.rollback()
        raise MigrationError(f"Migration to v3 failed: {exc}") from exc
    finally:
        conn.close()
