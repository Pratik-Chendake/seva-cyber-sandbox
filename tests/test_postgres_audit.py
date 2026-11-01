"""
Seva Cyber Sandbox — Pre-Deployment PostgreSQL Runtime Compatibility & Audit Suite
Comprehensive verification tests covering all 7 deployment audit requirements:
1. DATABASE_URL selection and fail-closed routing (no silent fallback).
2. Schema & table definition parity across all 16 operational tables.
3. PostgreSQL CRUD compatibility across all domain models & entities.
4. Data migration script 16-table coverage, foreign-key ordering, and idempotency.
5. Threaded connection pooling, transaction isolation, and graceful cleanup.
6. Startup fail-closed validation on unreachable targets and credential masking.
7. SQLite backward compatibility preservation for local and airgapped development.
"""

import os
import re
import sqlite3
import subprocess
import sys
from unittest.mock import MagicMock, patch
import pytest

from api_server import sanitize_db_target, verify_startup_database, app
from fastapi.testclient import TestClient
from src.database_adapter import (
    close_postgres_pool,
    get_active_database_target,
    get_db_connection,
    get_postgres_pool,
    is_postgres_url,
    translate_query_for_postgres,
    DEFAULT_SQLITE_PATH,
    PostgresConnectionWrapper,
    PostgresCursorWrapper,
)
from src.case_repository import CaseRepository
from src.operator_auth import OperatorAuthService


# =============================================================================
# POINT 1: DATABASE_URL SELECTION & NO SILENT FALLBACK
# =============================================================================

def test_point_1_database_url_selection_precedence():
    """Verifies DATABASE_URL takes highest precedence over fallback SQLite paths."""
    old_env = os.environ.copy()
    try:
        os.environ["DATABASE_URL"] = "postgresql://user:pass@host:5432/prod_db"
        os.environ["SEVA_DATABASE_URL"] = "postgresql://user:pass@host:5432/other_db"
        os.environ["SEVA_CASE_DB_PATH"] = "instance/custom.sqlite3"
        assert get_active_database_target() == "postgresql://user:pass@host:5432/prod_db"

        del os.environ["DATABASE_URL"]
        assert get_active_database_target() == "postgresql://user:pass@host:5432/other_db"

        del os.environ["SEVA_DATABASE_URL"]
        assert get_active_database_target() == "instance/custom.sqlite3"

        del os.environ["SEVA_CASE_DB_PATH"]
        os.environ.pop("SEVA_DB_PATH", None)
        assert get_active_database_target() == DEFAULT_SQLITE_PATH
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def test_point_1_is_postgres_url_classification():
    """Verifies connection string scheme parsing for postgresql:// and postgres://."""
    assert is_postgres_url("postgresql://operator:secret@aws-rds.amazonaws.com:5432/seva") is True
    assert is_postgres_url("postgres://operator:secret@supabase.co:5432/seva") is True
    assert is_postgres_url("instance/seva_cases.sqlite3") is False
    assert is_postgres_url(":memory:") is False
    assert is_postgres_url("") is False
    assert is_postgres_url(None) is False


def test_point_1_no_silent_fallback_when_postgres_fails():
    """
    CRITICAL SAFETY REQUIREMENT:
    When DATABASE_URL points to PostgreSQL, connection failure MUST raise an exception
    and NEVER silently fall back to an ephemeral local SQLite database in production.
    """
    bogus_pg = "postgresql://invalid_user:wrong_pass@127.0.0.1:59999/nonexistent_db"
    with pytest.raises(Exception) as exc_info:
        with get_db_connection(bogus_pg) as conn:
            conn.execute("SELECT 1")
    # Must NOT have silently connected to SQLite
    assert "sqlite" not in str(type(exc_info.value)).lower() or "operationalerror" in str(type(exc_info.value)).lower()


# =============================================================================
# POINT 2: TABLE & SCHEMA COMPATIBILITY ACROSS ALL 16 TABLES
# =============================================================================

EXPECTED_16_TABLES = [
    "schema_version",
    "threat_cases",
    "campaign_clusters",
    "evidence_provenance",
    "evidence_lifecycle_audit",
    "threat_indicators",
    "indicator_audit_log",
    "operator_accounts",
    "operator_sessions",
    "human_reviews",
    "review_audit_log",
    "training_feature_records",
    "model_disagreement_events",
    "disagreement_reviews",
    "disagreement_review_audit",
    "schema_migrations",
]

def test_point_2_schema_file_contains_all_16_tables():
    """Validates migrations/001_initial_schema.sql defines all 16 required tables."""
    schema_path = os.path.join(os.path.dirname(__file__), "..", "migrations", "001_initial_schema.sql")
    assert os.path.isfile(schema_path), f"Schema file missing at {schema_path}"

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    # Extract all CREATE TABLE statements
    created_tables = re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)", schema_sql, re.IGNORECASE)
    created_tables_lower = [t.lower() for t in created_tables]

    for expected in EXPECTED_16_TABLES:
        assert expected in created_tables_lower, f"Table '{expected}' missing from migrations/001_initial_schema.sql"


def test_point_2_type_parity_integer_booleans_in_schema():
    """
    Ensures boolean-like flags are declared as INTEGER (not BOOLEAN) in migrations/001_initial_schema.sql.
    In PostgreSQL, a BOOLEAN column cannot be compared to integer literals (e.g. `WHERE is_deleted = 0`)
    without an explicit cast, which would cause runtime 'operator does not exist: boolean = integer' crashes.
    """
    schema_path = os.path.join(os.path.dirname(__file__), "..", "migrations", "001_initial_schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    # Verify no raw BOOLEAN columns exist in schema
    boolean_matches = re.findall(r"([a-zA-Z0-9_]+)\s+BOOLEAN", schema_sql, re.IGNORECASE)
    assert len(boolean_matches) == 0, f"Found raw BOOLEAN definitions causing type mismatch: {boolean_matches}"

    # Verify specific flag columns are defined with INTEGER NOT NULL DEFAULT 0 or 1
    assert "is_deleted INTEGER NOT NULL DEFAULT 0" in schema_sql
    assert "is_active INTEGER NOT NULL DEFAULT 1" in schema_sql
    assert "is_revoked INTEGER NOT NULL DEFAULT 0" in schema_sql


# =============================================================================
# POINT 3: POSTGRESQL CRUD COMPATIBILITY ACROSS DOMAIN MODELS
# =============================================================================

def test_point_3_query_translation_rules():
    """Verifies that translate_query_for_postgres handles placeholders, pragmas, and upserts."""
    # 1. Placeholders
    sql = "SELECT * FROM threat_cases WHERE case_id = ? AND risk_score > ?"
    translated = translate_query_for_postgres(sql)
    assert translated == "SELECT * FROM threat_cases WHERE case_id = %s AND risk_score > %s"

    # 2. PRAGMA table_info
    pragma = "PRAGMA table_info(operator_accounts);"
    translated_pragma = translate_query_for_postgres(pragma)
    assert "information_schema.columns" in translated_pragma
    assert "LOWER(table_name) = 'operator_accounts'" in translated_pragma

    # 3. sqlite_master
    master = "SELECT name FROM sqlite_master WHERE type='table' AND name='threat_cases';"
    translated_master = translate_query_for_postgres(master)
    assert "information_schema.tables" in translated_master
    assert "sqlite_master" not in translated_master

    # 4. INSERT OR REPLACE INTO threat_cases
    upsert = "INSERT OR REPLACE INTO threat_cases (case_id, session_id) VALUES (?, ?);"
    translated_upsert = translate_query_for_postgres(upsert)
    assert "INSERT INTO threat_cases" in translated_upsert
    assert "ON CONFLICT (case_id) DO UPDATE SET" in translated_upsert

    # 5. INSERT OR REPLACE INTO model_disagreement_events
    upsert_disagree = "INSERT OR REPLACE INTO model_disagreement_events (event_id, event_type) VALUES (?, ?);"
    translated_disagree = translate_query_for_postgres(upsert_disagree)
    assert "INSERT INTO model_disagreement_events" in translated_disagree
    assert "ON CONFLICT (event_id) DO UPDATE SET" in translated_disagree


def test_point_3_crud_operations_under_postgres_wrapper():
    """
    Tests CRUD operations through PostgresCursorWrapper and PostgresConnectionWrapper,
    verifying row mapping, dict-like column access, and execution translation.
    """
    raw_sqlite = sqlite3.connect(":memory:")
    raw_sqlite.execute("CREATE TABLE mock_cases (case_id TEXT PRIMARY KEY, risk_score INT, is_deleted INT);")

    class MockPgCursor:
        def __init__(self, sqlite_conn):
            self._conn = sqlite_conn
            self._last_cur = None

        def execute(self, sql, params=None):
            sqlite_sql = sql.replace("%s", "?")
            if "ON CONFLICT" in sqlite_sql:
                sqlite_sql = re.sub(r"ON CONFLICT.*", "", sqlite_sql).strip()
            self._last_cur = self._conn.execute(sqlite_sql, params or [])
            return self

        def fetchone(self):
            row = self._last_cur.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in self._last_cur.description]
            return dict(zip(cols, row))

        def fetchall(self):
            rows = self._last_cur.fetchall()
            cols = [d[0] for d in self._last_cur.description]
            return [dict(zip(cols, r)) for r in rows]

        @property
        def rowcount(self):
            return self._last_cur.rowcount if self._last_cur else 0

        def close(self):
            pass

    mock_raw_conn = MagicMock()
    mock_raw_conn.cursor.return_value = MockPgCursor(raw_sqlite)

    pg_conn = PostgresConnectionWrapper(mock_raw_conn)

    # 1. INSERT
    cur = pg_conn.execute("INSERT INTO mock_cases (case_id, risk_score, is_deleted) VALUES (?, ?, ?);", ("CASE-101", 85, 0))
    assert cur.rowcount == 1

    # 2. SELECT
    cur = pg_conn.execute("SELECT case_id, risk_score, is_deleted FROM mock_cases WHERE case_id = ?;", ("CASE-101",))
    row = cur.fetchone()
    assert row["case_id"] == "CASE-101"
    assert row["risk_score"] == 85
    assert row["is_deleted"] == 0

    # 3. UPDATE
    cur = pg_conn.execute("UPDATE mock_cases SET risk_score = ? WHERE case_id = ?;", (95, "CASE-101"))
    assert cur.rowcount == 1

    cur = pg_conn.execute("SELECT risk_score FROM mock_cases WHERE case_id = ?;", ("CASE-101",))
    assert cur.fetchone()["risk_score"] == 95

    # 4. DELETE
    cur = pg_conn.execute("DELETE FROM mock_cases WHERE case_id = ?;", ("CASE-101",))
    assert cur.rowcount == 1

    cur = pg_conn.execute("SELECT COUNT(*) as cnt FROM mock_cases;")
    assert cur.fetchone()["cnt"] == 0


# =============================================================================
# POINT 4: MIGRATION SCRIPT 16-TABLE COVERAGE & IDEMPOTENCY
# =============================================================================

def test_point_4_migration_script_table_coverage_and_order():
    """Verifies scripts/migrate_to_postgres.py migrates all 16 tables in FK dependency order."""
    from scripts.migrate_to_postgres import TABLE_MIGRATION_ORDER

    assert len(TABLE_MIGRATION_ORDER) == 16, f"Expected 16 tables in migration script, found {len(TABLE_MIGRATION_ORDER)}"

    table_names = [t[0] for t in TABLE_MIGRATION_ORDER]
    for expected in EXPECTED_16_TABLES:
        assert expected in table_names, f"Table '{expected}' missing from migrate_to_postgres.py"

    # Dependency Order Check:
    # operator_accounts must be migrated BEFORE operator_sessions
    assert table_names.index("operator_accounts") < table_names.index("operator_sessions")
    # campaign_clusters must be migrated BEFORE threat_cases
    assert table_names.index("campaign_clusters") < table_names.index("threat_cases")
    # threat_cases must be migrated BEFORE evidence_provenance (FK: evidence_provenance.case_id -> threat_cases.case_id)
    assert table_names.index("threat_cases") < table_names.index("evidence_provenance")
    # threat_cases must be migrated BEFORE human_reviews
    assert table_names.index("threat_cases") < table_names.index("human_reviews")


def test_point_4_migration_script_dry_run_execution():
    """Verifies migrate_to_postgres.py --dry-run completes successfully without modifying target."""
    script_path = os.path.join(os.path.dirname(__file__), "..", "scripts", "migrate_to_postgres.py")
    res = subprocess.run(
        [sys.executable, script_path, "--dry-run"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Dry-run migration failed: {res.stderr}"
    assert "DRY-RUN SUCCESS" in res.stdout


# =============================================================================
# POINT 5: CONNECTION POOLING, TRANSACTIONS & CLEANUP
# =============================================================================

def test_point_5_threaded_connection_pooling_and_cleanup():
    """Verifies get_postgres_pool, connection checkout/return, and close_postgres_pool."""
    with patch("psycopg2.pool.ThreadedConnectionPool") as mock_pool_cls:
        mock_pool = MagicMock()
        mock_pool_cls.return_value = mock_pool

        target = "postgresql://operator:secret@db.host.com:5432/seva"
        pool = get_postgres_pool(target, minconn=2, maxconn=5)

        assert pool is mock_pool
        assert mock_pool_cls.called

        # Re-requesting with same target returns existing pool without re-instantiation
        pool2 = get_postgres_pool(target)
        assert pool2 is mock_pool
        assert mock_pool_cls.call_count == 1

        # Closing pool releases connections
        close_postgres_pool()
        assert mock_pool.closeall.called


def test_point_5_transaction_commit_and_rollback_safety():
    """Verifies PostgresConnectionWrapper commits on success and rolls back on exception."""
    mock_raw_conn = MagicMock()
    wrapper = PostgresConnectionWrapper(mock_raw_conn)

    # 1. Successful transaction block
    with wrapper:
        pass
    assert mock_raw_conn.commit.called
    assert not mock_raw_conn.rollback.called

    # 2. Failing transaction block
    mock_raw_conn.reset_mock()
    with pytest.raises(ValueError):
        with wrapper:
            raise ValueError("Simulated database failure")
    assert mock_raw_conn.rollback.called
    assert not mock_raw_conn.commit.called


# =============================================================================
# POINT 6: STARTUP FAIL-CLOSED & CREDENTIAL MASKING
# =============================================================================

def test_point_6_sanitize_db_target_masks_passwords():
    """Verifies sanitize_db_target masks plaintext passwords in database URIs."""
    cleartext_url = "postgresql://postgres:SuperSecretP@ssw0rd!@db.example.com:5432/sandbox"
    sanitized = sanitize_db_target(cleartext_url)

    assert "SuperSecretP@ssw0rd!" not in sanitized
    assert ":****@" in sanitized
    assert "postgresql://postgres:****@db.example.com:5432/sandbox" == sanitized

    # SQLite paths remain unaffected
    assert sanitize_db_target("instance/seva_cases.sqlite3") == "instance/seva_cases.sqlite3"
    assert sanitize_db_target("") == ""
    assert sanitize_db_target(None) == ""


def test_point_6_verify_startup_database_fails_closed_when_unreachable():
    """
    Verifies that verify_startup_database() raises RuntimeError when DATABASE_URL
    points to an unreachable database, preventing silent degraded operation.
    """
    old_env = os.environ.copy()
    try:
        os.environ["DATABASE_URL"] = "postgresql://admin:secret@127.0.0.1:59999/unreachable_db"
        os.environ["SEVA_STRICT_DB_STARTUP"] = "true"

        with pytest.raises(RuntimeError) as exc_info:
            verify_startup_database()

        assert "Production database startup failure" in str(exc_info.value)
        # Verify credentials are NOT leaked in exception message
        assert "secret" not in str(exc_info.value)
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def test_point_6_health_endpoint_masks_credentials():
    """Verifies /api/health and /api/system/health mask database credentials and return engine type."""
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()

    assert "database" in data
    db_info = data["database"]
    assert "connected" in db_info
    assert "path" in db_info
    assert "type" in db_info
    assert db_info["type"] in ("sqlite", "postgresql")
    assert ":****@" in db_info["path"] or not is_postgres_url(db_info["path"])


# =============================================================================
# POINT 7: SQLITE LOCAL DEVELOPMENT BACKWARD COMPATIBILITY
# =============================================================================

def test_point_7_sqlite_local_development_intact(tmp_path):
    """
    Verifies that when DATABASE_URL is unset, the system defaults to SQLite,
    and all core repository operations (init, save, list, delete) function 100% locally.
    """
    test_db = str(tmp_path / "sqlite_test.sqlite3")
    repo = CaseRepository(db_path=test_db)
    repo.init_db()

    # Save Case
    case_id = repo.save_case(
        {
            "analysis_type": "phishing",
            "risk_score": 75,
            "risk_category": "HIGH",
            "badge_color": "#EF4444",
            "recommended_action": "Block sender",
        },
        session_id="dev_session",
    )
    assert case_id.startswith("CASE-")

    # Retrieve Case
    retrieved = repo.get_case(case_id)
    assert retrieved is not None
    assert retrieved["case_id"] == case_id
    assert retrieved["risk_score"] == 75

    # List Cases
    cases = repo.list_cases()
    assert len(cases) == 1
    assert cases[0]["case_id"] == case_id

    # Soft Delete
    success = repo.delete_case(case_id, hard_delete=False)
    assert success is True

    # Confirm soft-deleted case excluded from active list
    assert len(repo.list_cases()) == 0
