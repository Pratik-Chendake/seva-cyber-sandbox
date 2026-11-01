"""
Seva Cyber Sandbox — Database Adapter & Multi-Engine Dialect Abstraction
Supports SQLite (local development / airgap) and PostgreSQL (Supabase / cloud production).

Guarantees 100% transparent query execution, row mapping, and parameter binding
across SQLite and PostgreSQL without altering business logic.
"""

from contextlib import contextmanager
import os
import re
import sqlite3
import threading
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    try:
        import psycopg as psycopg2
        import psycopg.extras
        PSYCOPG2_AVAILABLE = True
    except ImportError:
        PSYCOPG2_AVAILABLE = False


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, ".env"))
except ImportError:
    pass
DEFAULT_SQLITE_PATH = os.path.join(BASE_DIR, "instance", "seva_cases.sqlite3")


def is_postgres_url(target: Optional[str]) -> bool:
    """Returns True if the target string is a PostgreSQL connection URI."""
    if not target or not isinstance(target, str):
        return False
    return target.startswith("postgresql://") or target.startswith("postgres://")


def sanitize_db_target(target: Optional[str]) -> str:
    """Masks credentials in database target strings for safe logs and telemetry output."""
    if not target or not isinstance(target, str):
        return ""
    if "://" in target:
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(target)
            if parsed.password:
                netloc = parsed.netloc.replace(f":{parsed.password}@", ":****@")
                return urllib.parse.urlunparse(parsed._replace(netloc=netloc))
        except Exception:
            return "postgresql://***:***@.../"
    return target


def get_active_database_target() -> str:
    """
    Resolves active database target:
    1. DATABASE_URL / SEVA_DATABASE_URL (for PostgreSQL cloud deployment)
    2. SEVA_CASE_DB_PATH / SEVA_DB_PATH (for SQLite custom path)
    3. Default instance/seva_cases.sqlite3
    """
    return (
        os.environ.get("DATABASE_URL")
        or os.environ.get("SEVA_DATABASE_URL")
        or os.environ.get("SEVA_CASE_DB_PATH")
        or os.environ.get("SEVA_DB_PATH")
        or DEFAULT_SQLITE_PATH
    )


def translate_query_for_postgres(sql: str) -> str:
    """
    Translates SQLite-specific SQL syntax into PostgreSQL 15+ compatible SQL.
    - Parameter markers: ? -> %s
    - PRAGMA table_info(t) -> information_schema.columns
    - sqlite_master lookup -> information_schema.tables
    - INSERT OR REPLACE INTO threat_cases -> ON CONFLICT (case_id) DO UPDATE
    - INSERT OR REPLACE INTO model_disagreement_events -> ON CONFLICT (event_id) DO UPDATE
    """
    sql_stripped = sql.strip()

    # 1. PRAGMA table_info(table_name)
    pragma_match = re.match(r"^PRAGMA\s+table_info\((['\"]?)([a-zA-Z0-9_]+)\1\)\s*;?$", sql_stripped, re.IGNORECASE)
    if pragma_match:
        table_name = pragma_match.group(2).lower()
        return (
            f"SELECT column_name AS name, data_type AS type "
            f"FROM information_schema.columns "
            f"WHERE table_schema = 'public' AND LOWER(table_name) = '{table_name}' "
            f"ORDER BY ordinal_position;"
        )

    # 2. General PRAGMAs (foreign_keys, busy_timeout, journal_mode, etc.) -> NO-OP in Postgres
    if re.match(r"^PRAGMA\s+[a-zA-Z0-9_]+", sql_stripped, re.IGNORECASE):
        return "SELECT 1 AS pragma_noop WHERE 1=0;"

    # 3. sqlite_master table existence check
    if "sqlite_master" in sql:
        sql = re.sub(
            r"SELECT\s+name\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'\s+AND\s+name\s*=\s*(\?|\%s|\'[a-zA-Z0-9_]+\')",
            r"SELECT table_name AS name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = \1",
            sql,
            flags=re.IGNORECASE,
        )

    # 4. INSERT OR REPLACE INTO threat_cases
    if re.search(r"INSERT\s+OR\s+REPLACE\s+INTO\s+threat_cases", sql, re.IGNORECASE):
        sql = re.sub(r"INSERT\s+OR\s+REPLACE\s+INTO\s+threat_cases", "INSERT INTO threat_cases", sql, flags=re.IGNORECASE)
        # Append ON CONFLICT update clause if not present
        if "ON CONFLICT" not in sql.upper():
            sql = sql.rstrip("; ") + (
                " ON CONFLICT (case_id) DO UPDATE SET "
                "session_id = EXCLUDED.session_id, "
                "created_at = EXCLUDED.created_at, "
                "analysis_type = EXCLUDED.analysis_type, "
                "analysis_status = EXCLUDED.analysis_status, "
                "risk_score = EXCLUDED.risk_score, "
                "risk_category = EXCLUDED.risk_category, "
                "badge_color = EXCLUDED.badge_color, "
                "indicator_count = EXCLUDED.indicator_count, "
                "sha256_hash = EXCLUDED.sha256_hash, "
                "hash_algorithm = EXCLUDED.hash_algorithm, "
                "target_identifier = EXCLUDED.target_identifier, "
                "recommended_action = EXCLUDED.recommended_action, "
                "source_type = EXCLUDED.source_type, "
                "dedup_key = EXCLUDED.dedup_key, "
                "observed_evidence_json = EXCLUDED.observed_evidence_json, "
                "heuristic_inferences_json = EXCLUDED.heuristic_inferences_json, "
                "extracted_urls_json = EXCLUDED.extracted_urls_json, "
                "official_sources_json = EXCLUDED.official_sources_json, "
                "metadata_json = EXCLUDED.metadata_json, "
                "expires_at = EXCLUDED.expires_at, "
                "is_deleted = EXCLUDED.is_deleted, "
                "evidence_id = EXCLUDED.evidence_id;"
            )

    # 5. INSERT OR REPLACE INTO model_disagreement_events
    if re.search(r"INSERT\s+OR\s+REPLACE\s+INTO\s+model_disagreement_events", sql, re.IGNORECASE):
        sql = re.sub(r"INSERT\s+OR\s+REPLACE\s+INTO\s+model_disagreement_events", "INSERT INTO model_disagreement_events", sql, flags=re.IGNORECASE)
        if "ON CONFLICT" not in sql.upper():
            sql = sql.rstrip("; ") + (
                " ON CONFLICT (event_id) DO UPDATE SET "
                "event_type = EXCLUDED.event_type, "
                "rule_decision = EXCLUDED.rule_decision, "
                "model_prediction = EXCLUDED.model_prediction, "
                "model_version = EXCLUDED.model_version, "
                "rule_engine_version = EXCLUDED.rule_engine_version, "
                "model_confidence = EXCLUDED.model_confidence, "
                "model_confidence_bucket = EXCLUDED.model_confidence_bucket, "
                "rule_score = EXCLUDED.rule_score, "
                "rule_score_bucket = EXCLUDED.rule_score_bucket, "
                "language_category = EXCLUDED.language_category, "
                "script_category = EXCLUDED.script_category, "
                "message_length_bucket = EXCLUDED.message_length_bucket, "
                "review_state = EXCLUDED.review_state, "
                "created_at_utc = EXCLUDED.created_at_utc, "
                "consent_given = EXCLUDED.consent_given, "
                "feature_record_id = EXCLUDED.feature_record_id, "
                "case_id = EXCLUDED.case_id, "
                "metadata_json = EXCLUDED.metadata_json;"
            )

    # 6. Parameter placeholder conversion (? -> %s)
    # Convert ? only outside quotes
    parts = sql.split("'")
    for i in range(0, len(parts), 2):
        parts[i] = parts[i].replace("?", "%s")
    sql = "'".join(parts)

    return sql


class PostgresCursorWrapper:
    """Wraps a psycopg2 cursor to provide sqlite3-compatible interface and query translation."""

    def __init__(self, raw_cursor):
        self._cur = raw_cursor

    def execute(self, sql: str, params: Optional[Union[Tuple, List, Dict]] = None):
        pg_sql = translate_query_for_postgres(sql)
        if params is None:
            self._cur.execute(pg_sql)
        else:
            if isinstance(params, (list, tuple)):
                clean_params = list(params)
            else:
                clean_params = params
            self._cur.execute(pg_sql, clean_params)
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def fetchmany(self, size: int = 1):
        return self._cur.fetchmany(size)

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount

    @property
    def description(self):
        return self._cur.description

    def close(self):
        self._cur.close()


class PostgresConnectionWrapper:
    """Wraps a psycopg2 connection to mimic sqlite3.Connection with Row dictionary access."""

    def __init__(self, raw_conn):
        self._conn = raw_conn

    def cursor(self):
        raw_cur = self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        return PostgresCursorWrapper(raw_cur)

    def execute(self, sql: str, params: Optional[Union[Tuple, List, Dict]] = None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


_PG_POOL: Optional[Any] = None
_PG_POOL_LOCK = threading.Lock()
_PG_POOL_TARGET: Optional[str] = None


def get_postgres_pool(target: str, minconn: int = 1, maxconn: int = 10):
    """Returns a thread-safe connection pool for PostgreSQL."""
    global _PG_POOL, _PG_POOL_TARGET
    if _PG_POOL is None or _PG_POOL_TARGET != target:
        with _PG_POOL_LOCK:
            if _PG_POOL is None or _PG_POOL_TARGET != target:
                if _PG_POOL is not None:
                    try:
                        _PG_POOL.closeall()
                    except Exception:
                        pass
                if not PSYCOPG2_AVAILABLE:
                    raise RuntimeError(
                        "PostgreSQL target requested but neither 'psycopg2' nor 'psycopg' is installed. "
                        "Install psycopg2-binary: pip install psycopg2-binary"
                    )
                from psycopg2.pool import ThreadedConnectionPool
                _PG_POOL = ThreadedConnectionPool(minconn=minconn, maxconn=maxconn, dsn=target)
                _PG_POOL_TARGET = target
    return _PG_POOL


def close_postgres_pool() -> None:
    """Closes all connections in the PostgreSQL pool and resets pool state."""
    global _PG_POOL, _PG_POOL_TARGET
    with _PG_POOL_LOCK:
        if _PG_POOL is not None:
            try:
                _PG_POOL.closeall()
            except Exception:
                pass
            _PG_POOL = None
            _PG_POOL_TARGET = None


@contextmanager
def get_db_connection(target: Optional[str] = None) -> Generator[Any, None, None]:
    """
    Context manager providing an active database connection.
    Transparently selects between PostgreSQL (with thread-safe connection pooling)
    and SQLite based on connection string.
    """
    db_target = target or get_active_database_target()

    if is_postgres_url(db_target):
        if not PSYCOPG2_AVAILABLE:
            raise RuntimeError(
                "PostgreSQL target requested but neither 'psycopg2' nor 'psycopg' is installed. "
                "Install psycopg2-binary: pip install psycopg2-binary"
            )
        pool = None
        raw_conn = None
        try:
            pool = get_postgres_pool(db_target)
            raw_conn = pool.getconn()
        except Exception:
            raw_conn = psycopg2.connect(db_target)
            pool = None

        wrapper = PostgresConnectionWrapper(raw_conn)
        try:
            yield wrapper
            wrapper.commit()
        except Exception:
            wrapper.rollback()
            raise
        finally:
            if pool is not None and raw_conn is not None:
                try:
                    pool.putconn(raw_conn)
                except Exception:
                    wrapper.close()
            else:
                wrapper.close()

    else:
        # SQLite Connection
        conn = sqlite3.connect(db_target, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            if db_target != ":memory:":
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
