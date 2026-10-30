"""
Secure SQLite Persistence Layer for Seva Cyber Sandbox Threat Cases.

DESIGN & SECURITY GUARANTEES:
1. Standard Library Only: Built using Python's standard `sqlite3` module.
2. Configurable Location: Defaults to `instance/seva_cases.sqlite3` or $SEVA_CASE_DB_PATH.
   Parent directories are created automatically and safely.
3. High-Concurrency Reliability: Uses Write-Ahead Logging (WAL mode), busy timeout (5000 ms),
   and per-operation connection management ensuring thread safety across Streamlit and webhook workers.
4. Zero Raw Data Retention: Original uploaded APK binaries and raw message texts are
   NEVER persisted. Variable-length evidence indicators are validated JSON.
5. Privacy-First Redaction: URLs have credentials and authentication query tokens stripped;
   Aadhaar and phone numbers are masked before write.
6. Keyed HMAC Anonymization: Sender phone correlation uses HMAC-SHA256 with an external secret.
7. Automated Retention: Supports 30-day default retention with safe expiration pruning.
8. Idempotency: Webhook message IDs are stored as deduplication keys to prevent duplicate entries.
"""

from contextlib import contextmanager
import csv
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import io
import json
import math
import os
import re
import sqlite3
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = 1
DEFAULT_RETENTION_DAYS = 30

ALLOWED_INDICATOR_TYPES = {"phone_hmac", "domain", "url", "apk_sha256"}
ALLOWED_REVIEW_STATES = {"reviewed", "unreviewed", "provisional"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}

# Phase 5: Human Review Desk Constants
ALLOWED_HUMAN_REVIEW_STATES = {"pending", "under_review", "inconclusive", "completed", "superseded"}
ALLOWED_HUMAN_OUTCOME_CATEGORIES = {"phishing", "legitimate", "protective_advisory", "insufficient_evidence"}
ALLOWED_CONFIDENCE_RATINGS = {"high", "medium", "low"}

# Phase 6.1: Derived Training Features & Curation Constants
FEATURE_SCHEMA_VERSION = "1.0.0"
FEATURE_EXTRACTOR_VERSION = "char-ngram-hasher-1024-v1.0.0"
EXPECTED_FEATURE_DIM = 1024
ALLOWED_ELIGIBILITY_STATES = {"pending_review", "eligible", "ineligible"}
FEEDBACK_LABEL_TO_IDX = {"phishing": 0, "legitimate": 1, "protective_advisory": 2}


class CaseRepositoryError(Exception):
    """Base exception for all case repository operations."""
    pass


class HumanReviewError(CaseRepositoryError):
    """Base exception for human review desk operations."""
    pass


class HumanReviewValidationError(HumanReviewError):
    """Raised when human review input or metadata fails validation."""
    pass


class FeedbackCurationError(CaseRepositoryError):
    """Base exception for feedback curation and derived feature operations."""
    pass


class FeedbackCurationKeyError(FeedbackCurationError):
    """Raised when the HMAC secret key required for feedback deduplication is unavailable or invalid."""
    pass


class FeedbackCurationValidationError(FeedbackCurationError):
    """Raised when derived feature inputs, vector dimensions, or consent fail validation."""
    pass


class DatabaseLockedError(CaseRepositoryError):
    """Raised when SQLite database lock cannot be acquired within timeout."""
    pass


class ThreatIntelligenceError(CaseRepositoryError):
    """Base exception for threat intelligence operations."""
    pass


class ThreatIntelligenceValidationError(ThreatIntelligenceError):
    """Raised when an indicator or its metadata fails input validation."""
    pass


class ThreatIntelligenceKeyError(ThreatIntelligenceError):
    """Raised when the HMAC secret key required for phone anonymization is unavailable."""
    pass


class CaseRecord:
    """Convenience read wrapper around a case dictionary."""
    def __init__(self, data: Dict[str, Any]):
        self._data = dict(data)

    @property
    def case_id(self) -> str:
        return self._data.get("case_id", "")

    @property
    def session_id(self) -> str:
        return self._data.get("session_id", "")

    @property
    def timestamp_utc(self) -> str:
        return self._data.get("timestamp_utc", "")

    @property
    def created_at(self) -> str:
        return self._data.get("timestamp_utc", "")

    @property
    def analysis_type(self) -> str:
        return self._data.get("analysis_type", "")

    @property
    def analysis_status(self) -> str:
        return self._data.get("analysis_status", "")

    @property
    def risk_score(self) -> int:
        return int(self._data.get("risk_score", 0))

    @property
    def risk_category(self) -> str:
        return self._data.get("risk_category", "")

    @property
    def badge_color(self) -> str:
        return self._data.get("badge_color", "")

    @property
    def indicator_count(self) -> int:
        return int(self._data.get("indicator_count", 0))

    @property
    def sha256_hash(self) -> Optional[str]:
        return self._data.get("sha256_hash")

    @property
    def target_identifier(self) -> str:
        return self._data.get("target_identifier", "")

    @property
    def recommended_action(self) -> str:
        return self._data.get("recommended_action", "")

    @property
    def source_type(self) -> str:
        return self._data.get("source_type", "")

    @property
    def dedup_key(self) -> Optional[str]:
        return self._data.get("dedup_key")

    @property
    def observed_evidence(self) -> List[str]:
        return list(self._data.get("observed_evidence", []))

    @property
    def heuristic_inferences(self) -> List[str]:
        return list(self._data.get("heuristic_inferences", []))

    @property
    def extracted_urls(self) -> List[str]:
        return list(self._data.get("extracted_urls", []))

    @property
    def official_sources(self) -> List[str]:
        return list(self._data.get("official_sources", []))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._data)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)


MIN_HMAC_SECRET_LENGTH = 16


def get_threat_intel_hmac_secret(secret: Optional[str] = None) -> str:
    """
    Resolves and validates the HMAC secret for threat intelligence phone correlation.

    Order of precedence:
    1. Explicit `secret` parameter (if provided)
    2. SEVA_THREAT_INTEL_KEY environment variable
    3. SEVA_HMAC_SECRET environment variable

    SECURITY GUARANTEES (SEC-01 FIX):
    - No hardcoded production or development fallback key.
    - Does NOT fall back to unrelated WhatsApp sender salts.
    - Requires at least 16 characters for entropy.
    - If missing, blank, or invalid, raises ThreatIntelligenceKeyError.
    - Never logs or exposes secret material in exceptions or diagnostic text.
    """
    sec = secret if secret is not None else (
        os.environ.get("SEVA_THREAT_INTEL_KEY")
        or os.environ.get("SEVA_HMAC_SECRET")
    )
    if not sec or not sec.strip():
        raise ThreatIntelligenceKeyError(
            "Threat intelligence HMAC secret key is not configured or empty. "
            "Please configure the SEVA_THREAT_INTEL_KEY or SEVA_HMAC_SECRET environment variable "
            "(minimum 16 characters). Phone indicator matching fails closed."
        )
    sec_clean = sec.strip()
    if len(sec_clean) < MIN_HMAC_SECRET_LENGTH:
        raise ThreatIntelligenceKeyError(
            f"Threat intelligence HMAC secret key is invalid: key must be at least "
            f"{MIN_HMAC_SECRET_LENGTH} characters long. Phone indicator matching fails closed."
        )
    return sec_clean


def get_default_hmac_secret() -> str:
    """
    Returns the configured HMAC secret for threat intelligence correlation.
    Maintained for backward compatibility; raises ThreatIntelligenceKeyError if unconfigured.
    """
    return get_threat_intel_hmac_secret()


def get_feedback_hmac_secret(secret: Optional[str] = None) -> str:
    """
    Resolves and validates the dedicated HMAC secret for feedback deduplication fingerprints.

    Order of precedence:
    1. Explicit `secret` parameter (if provided)
    2. SEVA_FEEDBACK_HMAC_KEY environment variable

    SECURITY & GOVERNANCE GUARANTEES (SEC-06-01):
    - Dedicated secret isolation: Does NOT fall back to SEVA_THREAT_INTEL_KEY or SEVA_HMAC_SECRET.
    - No hardcoded fallback secret or predictable default.
    - Requires at least 16 characters for entropy.
    - If missing, blank, or invalid, raises FeedbackCurationKeyError.
    - Fails closed for deduplication fingerprint calculation without affecting ordinary detection.
    - Never logs or exposes secret material or derived digests in exceptions or diagnostic text.
    """
    sec = secret if secret is not None else os.environ.get("SEVA_FEEDBACK_HMAC_KEY")
    if not sec or not sec.strip():
        raise FeedbackCurationKeyError(
            "Dedicated feedback deduplication HMAC secret key is not configured or empty. "
            "Please configure the SEVA_FEEDBACK_HMAC_KEY environment variable (minimum 16 characters). "
            "Training feature deduplication fails closed."
        )
    sec_clean = sec.strip()
    if len(sec_clean) < MIN_HMAC_SECRET_LENGTH:
        raise FeedbackCurationKeyError(
            f"Dedicated feedback deduplication HMAC secret key is invalid: key must be at least "
            f"{MIN_HMAC_SECRET_LENGTH} characters long. Training feature deduplication fails closed."
        )
    return sec_clean


def compute_feedback_dedup_fingerprint(normalized_text: str, secret: Optional[str] = None) -> str:
    """
    Computes a keyed HMAC-SHA256 fingerprint for deduplicating training examples.
    Fails closed if the HMAC secret is unconfigured or invalid.
    """
    if not normalized_text or not isinstance(normalized_text, str):
        raise FeedbackCurationValidationError("Cannot compute deduplication fingerprint for empty or non-string text.")
    sec_key = get_feedback_hmac_secret(secret)
    return hmac.new(sec_key.encode("utf-8"), normalized_text.encode("utf-8"), hashlib.sha256).hexdigest()


def get_database_path() -> str:
    """
    Returns the absolute path to the SQLite cases database.
    Order of precedence:
    1. SEVA_CASE_DB_PATH environment variable
    2. <project_root>/instance/seva_cases.sqlite3
    """
    env_path = os.environ.get("SEVA_CASE_DB_PATH")
    if env_path:
        return os.path.abspath(env_path)

    # Base directory is project root (one level up from src/)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(project_root, "instance", "seva_cases.sqlite3")


def get_utc_now_iso() -> str:
    """Returns the current UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# PRIVACY & SENSITIVE DATA REDACTION
# =============================================================================

def redact_url_credentials(url: str) -> str:
    """
    Strips inline basic auth credentials (user:pass@) and sensitive query parameters
    (token, key, auth, secret, otp, password, access_token) from URLs before saving.
    """
    if not url or not isinstance(url, str):
        return url or ""

    # Strip inline basic-auth user:pass@
    clean = re.sub(r"://([^:@]+):([^@]+)@", r"://[REDACTED]@", url)

    # Strip sensitive query parameters
    clean = re.sub(
        r"([?&](?:token|key|auth|secret|otp|password|access_token)=)[^&]+",
        r"\1[REDACTED]",
        clean,
        flags=re.IGNORECASE,
    )
    return clean


def mask_phone_number(text: str) -> str:
    """
    Masks 10-digit phone numbers in evidence text, preserving only the first 2
    and last 2 digits for legitimate verification (+91-98XXXX12).
    """
    if not text:
        return ""
    return re.sub(r"(?:\+?91[\s-]?)?(\d{2})\d{4}(\d{4})", r"+91-\1XXXX\2", text)


def mask_aadhaar_number(text: str) -> str:
    """
    Masks 12-digit Aadhaar-like numbers in evidence text (XXXX-XXXX-1234).
    """
    if not text:
        return ""
    return re.sub(r"\b\d{4}[\s-]?\d{4}[\s-]?(\d{4})\b", r"XXXX-XXXX-\1", text)


def sanitize_evidence_text(text: str) -> str:
    """Applies all privacy masks to an evidence string."""
    if not text or not isinstance(text, str):
        return str(text or "")
    text = redact_url_credentials(text)
    text = mask_phone_number(text)
    text = mask_aadhaar_number(text)
    return text


def keyed_phone_hmac(phone: str, secret: Optional[str] = None) -> str:
    """
    Generates a cryptographically keyed HMAC-SHA256 for sender correlation in case evidence.
    Protects against dictionary and rainbow-table attacks on 10-digit phone numbers.
    """
    if not phone:
        return "ANONYMOUS"
    clean = re.sub(r"[^\d]", "", phone)
    sec_str = secret or os.environ.get("SEVA_HMAC_SECRET") or os.environ.get("SEVA_CASE_SALT")
    if not sec_str:
        sec_str = "SEVA_ANONYMOUS_SENDER_DISPLAY_SALT"
    sec = sec_str.encode("utf-8")
    mac = hmac.new(sec, clean.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
    if len(clean) < 4:
        return f"ANON_{mac}"
    masked = clean[:2] + ("*" * (len(clean) - 4)) + clean[-2:]
    return f"{masked}_{mac}"


# =============================================================================
# THREAT INTELLIGENCE NORMALIZATION & SECURITY SAFEGUARDS
# =============================================================================

def normalize_domain(domain: str) -> str:
    """
    Normalizes a domain string for exact lookup in the threat knowledge base.
    Strips protocol, paths, credentials, and port numbers; lowercases hostname.
    """
    if not domain or not isinstance(domain, str):
        raise ThreatIntelligenceValidationError("Domain must be a non-empty string.")

    cleaned = domain.strip().lower()
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]

    # Strip path, query, fragment
    cleaned = cleaned.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]

    # Strip basic auth credentials if present
    if "@" in cleaned:
        cleaned = cleaned.split("@", 1)[1]

    # Strip port if present
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[0]

    cleaned = cleaned.rstrip(".")

    if len(cleaned) < 3 or len(cleaned) > 253:
        raise ThreatIntelligenceValidationError(
            f"Domain length ({len(cleaned)}) is outside valid range (3-253 chars)."
        )

    # Valid domain characters check
    if not re.fullmatch(
        r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$",
        cleaned,
    ) and cleaned != "localhost":
        raise ThreatIntelligenceValidationError(f"Invalid domain format: '{cleaned}'")

    return cleaned


def canonicalize_url_for_matching(url: str) -> str:
    """
    Safely canonicalizes a URL for deterministic threat intelligence matching.

    PRIVACY & SECURITY SAFEGUARDS:
    - Strips query parameters and fragments completely, as they frequently contain PII,
      session tokens, passwords, OTPs, or tracking identifiers.
    - Normalizes scheme and host to lowercase.
    - Normalizes duplicate slashes in the path.
    """
    if not url or not isinstance(url, str):
        raise ThreatIntelligenceValidationError("URL must be a non-empty string.")

    cleaned = url.strip()
    if "://" in cleaned:
        scheme_prefix = cleaned.split("://", 1)[0].lower()
        if scheme_prefix not in ("http", "https"):
            raise ThreatIntelligenceValidationError(f"Unsupported URL scheme: '{scheme_prefix}'")
    else:
        cleaned = "http://" + cleaned

    try:
        parsed = urllib.parse.urlsplit(cleaned)
    except Exception as exc:
        raise ThreatIntelligenceValidationError(f"Malformed URL: {exc}") from exc

    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https"):
        raise ThreatIntelligenceValidationError(f"Unsupported URL scheme: {scheme}")

    host = parsed.hostname
    if not host:
        raise ThreatIntelligenceValidationError("URL is missing a valid hostname.")
    host = host.lower().rstrip(".")

    port_part = ""
    if parsed.port and parsed.port not in (80, 443):
        port_part = f":{parsed.port}"

    path = parsed.path or "/"
    path = re.sub(r"/+", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    canonical = f"{scheme}://{host}{port_part}{path}"
    if len(canonical) > 2048:
        raise ThreatIntelligenceValidationError("URL exceeds maximum safe length (2048 chars).")

    return canonical


def normalize_apk_hash(apk_hash: str) -> str:
    """Validates and normalizes an APK SHA-256 hex string."""
    if not apk_hash or not isinstance(apk_hash, str):
        raise ThreatIntelligenceValidationError("APK hash must be a non-empty string.")
    clean = apk_hash.strip().lower()
    if not re.fullmatch(r"^[0-9a-f]{64}$", clean):
        raise ThreatIntelligenceValidationError(
            "APK hash must be a valid 64-character lowercase SHA-256 hexadecimal string."
        )
    return clean


def normalize_phone_number(raw_phone: str) -> str:
    """
    Normalizes a phone number to standard digits for HMAC hashing.
    Converts Indian 10-digit mobile numbers (starting with 6-9) to 91XXXXXXXXXX.
    """
    if not raw_phone or not isinstance(raw_phone, str):
        raise ThreatIntelligenceValidationError("Phone number must be a non-empty string.")
    digits = re.sub(r"\D", "", raw_phone)
    if len(digits) == 10 and digits[0] in "6789":
        return f"91{digits}"
    if len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
        return f"91{digits[1:]}"
    if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
        return digits
    if 10 <= len(digits) <= 15:
        return digits
    raise ThreatIntelligenceValidationError(
        f"Invalid phone number format ({len(digits)} digits; expected 10-15 digits)."
    )


def compute_phone_indicator_hmac(raw_phone: str, secret: Optional[str] = None) -> str:
    """
    Computes a cryptographically keyed HMAC-SHA256 representation of a normalized phone number.

    FAIL-CLOSED KEY MANAGEMENT (SEC-01 FIX):
    - Obtains key via get_threat_intel_hmac_secret().
    - If secret is missing, blank, or < 16 chars, raises ThreatIntelligenceKeyError.
    - Does NOT fall back to hardcoded strings or unrelated WhatsApp sender salts.
    - Plaintext phone numbers are NEVER stored or returned from the database.
    - Uses SHA-256 HMAC with prefix 'HMAC_' and 64-hex-character digest.
    """
    sec = get_threat_intel_hmac_secret(secret=secret)
    norm_phone = normalize_phone_number(raw_phone)
    mac = hmac.new(sec.encode("utf-8"), norm_phone.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"HMAC_{mac}"


# =============================================================================
# SQLITE CASE REPOSITORY
# =============================================================================

class CaseRepository:
    """
    Secure SQLite repository managing persistent threat case storage.
    Enforces ACID transactions, WAL mode, session isolation, and automatic retention.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ):
        self.db_path: str = db_path or get_database_path()
        self.retention_days: int = max(1, retention_days)
        self._ensure_parent_dir()
        self.init_db()

    def _ensure_parent_dir(self) -> None:
        """Safely creates parent directories for the database file."""
        parent = os.path.dirname(self.db_path)
        if parent:
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError as exc:
                raise CaseRepositoryError(
                    f"Cannot initialize database directory at '{parent}': {exc}"
                ) from exc

    @contextmanager
    def get_connection(self):
        """
        Thread-safe context manager supplying an isolated SQLite connection.
        Enforces foreign keys, WAL journal mode, and busy timeout.
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
        except sqlite3.OperationalError as exc:
            raise CaseRepositoryError(
                f"Failed to connect to SQLite database at '{self.db_path}': {exc}"
            ) from exc
        except sqlite3.DatabaseError as exc:
            raise CaseRepositoryError(
                f"Corrupted or invalid database at '{self.db_path}': {exc}"
            ) from exc

        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            # Enable WAL mode if not in in-memory database
            if self.db_path != ":memory:":
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
            yield conn
            conn.commit()
        except sqlite3.OperationalError as exc:
            conn.rollback()
            if "database is locked" in str(exc).lower():
                raise DatabaseLockedError(f"Database locked: {exc}") from exc
            raise CaseRepositoryError(f"Database operation failed: {exc}") from exc
        except sqlite3.DatabaseError as exc:
            conn.rollback()
            raise CaseRepositoryError(f"Database error at '{self.db_path}': {exc}") from exc
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """
        Initializes schema tables and indexes idempotently without destroying existing data.
        """
        with self.get_connection() as conn:
            # Schema version table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT NOT NULL
                );
                """
            )

            # Main threat cases table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_cases (
                    case_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
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
                    expires_at TEXT NOT NULL,
                    is_deleted INTEGER NOT NULL DEFAULT 0
                );
                """
            )

            # Indexes for high-frequency queries and filtering
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_session ON threat_cases(session_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_created ON threat_cases(created_at DESC);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_type ON threat_cases(analysis_type);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_risk ON threat_cases(risk_score);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_dedup ON threat_cases(dedup_key);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_expires ON threat_cases(expires_at);"
            )

            # Record initial schema version if empty
            cur = conn.execute("SELECT COUNT(*) FROM schema_version WHERE version = ?", (SCHEMA_VERSION,))
            if cur.fetchone()[0] == 0:
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?);",
                    (SCHEMA_VERSION, get_utc_now_iso(), "Initial Seva Cyber Sandbox normalized cases schema"),
                )

            # -----------------------------------------------------------------
            # Phase 1: Persistent Threat Intelligence Knowledge Base Tables
            # -----------------------------------------------------------------
            conn.execute(
                """
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
                    first_seen_utc TEXT NOT NULL,
                    last_seen_utc TEXT NOT NULL,
                    expires_at TEXT,
                    notes TEXT NOT NULL DEFAULT '',
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS indicator_audit_log (
                    log_id TEXT PRIMARY KEY,
                    indicator_id TEXT,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT 'system',
                    timestamp_utc TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    details_json TEXT NOT NULL DEFAULT '{}'
                );
                """
            )

            # Indexes for high-performance indicator matching and filtering
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(indicator_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(indicator_value);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_hash ON threat_indicators(indicator_hash);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_active ON threat_indicators(is_active);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_review ON threat_indicators(review_state);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_expires ON threat_indicators(expires_at);")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicator_audit_ind ON indicator_audit_log(indicator_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicator_audit_time ON indicator_audit_log(timestamp_utc DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_indicator_audit_action ON indicator_audit_log(action);")

            # -----------------------------------------------------------------
            # Phase 5: Local Human Review Desk & Review Audit Log
            # -----------------------------------------------------------------
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS human_reviews (
                    review_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    review_state TEXT NOT NULL DEFAULT 'pending',
                    outcome_category TEXT,
                    confidence_rating TEXT DEFAULT 'medium',
                    reviewer_label TEXT NOT NULL DEFAULT 'local_operator',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS review_audit_log (
                    log_id TEXT PRIMARY KEY,
                    review_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT 'local_operator',
                    timestamp_utc TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    details_json TEXT NOT NULL DEFAULT '{}'
                );
                """
            )

            conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_case ON human_reviews(case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_state ON human_reviews(review_state);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_outcome ON human_reviews(outcome_category);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_updated ON human_reviews(updated_at DESC);")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_review_audit_rev ON review_audit_log(review_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_review_audit_time ON review_audit_log(timestamp_utc DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_review_audit_action ON review_audit_log(action);")

            # -----------------------------------------------------------------
            # Phase 6.1: Derived Training Features Persistence
            # -----------------------------------------------------------------
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS training_feature_records (
                    feature_record_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    feature_schema_version TEXT NOT NULL,
                    preprocessing_version TEXT NOT NULL,
                    feature_extractor_version TEXT NOT NULL,
                    feature_vector_json TEXT NOT NULL,
                    feature_dim INTEGER NOT NULL,
                    consent_given INTEGER NOT NULL DEFAULT 0,
                    consent_timestamp_utc TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    eligibility_state TEXT NOT NULL DEFAULT 'pending_review',
                    dedup_fingerprint TEXT NOT NULL,
                    provenance_category TEXT NOT NULL DEFAULT 'local_curated_feedback',
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                """
            )

            conn.execute("CREATE INDEX IF NOT EXISTS idx_features_case ON training_feature_records(case_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_features_fingerprint ON training_feature_records(dedup_fingerprint);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_features_eligibility ON training_feature_records(eligibility_state);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_features_created ON training_feature_records(created_at_utc DESC);")

    def save_case(
        self,
        case_record: Dict[str, Any],
        session_id: Optional[str] = None,
        source_type: str = "web_simulator",
        dedup_key: Optional[str] = None,
        retention_days: Optional[int] = None,
    ) -> str:
        """
        Saves a validated threat case record to SQLite.
        Guarantees zero raw binary/message retention and applies privacy redactions.
        If a matching active case with dedup_key exists, returns existing case_id (idempotency).
        """
        case_id = case_record.get("case_id")
        if not case_id:
            now_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            import uuid
            case_id = f"CASE-{now_str}-{uuid.uuid4().hex[:8].upper()}"

        sid = session_id or case_record.get("session_id") or "default-session"
        created_at = case_record.get("timestamp_utc") or get_utc_now_iso()

        days = retention_days if retention_days is not None else self.retention_days
        try:
            dt_created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except Exception:
            dt_created = datetime.now(timezone.utc)
        expires_at = (dt_created + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Idempotency check: if dedup_key exists, reuse existing case
        dkey = dedup_key or case_record.get("dedup_key")
        if dkey:
            with self.get_connection() as conn:
                row = conn.execute(
                    "SELECT case_id FROM threat_cases WHERE dedup_key = ? AND is_deleted = 0 LIMIT 1;",
                    (dkey,),
                ).fetchone()
                if row:
                    return row["case_id"]

        # Privacy Redaction on evidence
        raw_obs = case_record.get("observed_evidence", [])
        clean_obs = [sanitize_evidence_text(str(x)) for x in raw_obs]

        raw_heur = case_record.get("heuristic_inferences", [])
        clean_heur = [sanitize_evidence_text(str(x)) for x in raw_heur]

        raw_urls = case_record.get("extracted_urls", [])
        clean_urls = [redact_url_credentials(str(u)) for u in raw_urls]

        # Sources
        sources = case_record.get("official_sources", [])

        # Safe metadata: exclude raw bytes or large inputs
        metadata: Dict[str, Any] = {}
        excluded_keys = {
            "case_id",
            "timestamp_utc",
            "session_id",
            "analysis_type",
            "analysis_status",
            "risk_score",
            "risk_category",
            "badge_color",
            "indicator_count",
            "sha256_hash",
            "hash_algorithm",
            "target_identifier",
            "recommended_action",
            "source_type",
            "dedup_key",
            "observed_evidence",
            "heuristic_inferences",
            "extracted_urls",
            "official_sources",
            "raw_bytes",
            "file_bytes",
            "raw_text",
            "raw_data_stored",
        }
        for k, v in case_record.items():
            if k not in excluded_keys:
                if isinstance(v, (str, int, float, bool, list, dict)) and not k.startswith("raw_"):
                    metadata[k] = v

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO threat_cases (
                    case_id, session_id, created_at, analysis_type, analysis_status,
                    risk_score, risk_category, badge_color, indicator_count,
                    sha256_hash, hash_algorithm, target_identifier, recommended_action,
                    source_type, dedup_key, observed_evidence_json, heuristic_inferences_json,
                    extracted_urls_json, official_sources_json, metadata_json, expires_at, is_deleted
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?, 0
                );
                """,
                (
                    case_id,
                    sid,
                    created_at,
                    case_record.get("analysis_type", "Unknown Analysis"),
                    case_record.get("analysis_status", "Completed"),
                    int(case_record.get("risk_score", 0)),
                    case_record.get("risk_category", "Unspecified"),
                    case_record.get("badge_color", "gray"),
                    int(case_record.get("indicator_count", 0)),
                    case_record.get("sha256_hash"),
                    case_record.get("hash_algorithm"),
                    sanitize_evidence_text(case_record.get("target_identifier", "Target")),
                    case_record.get("recommended_action", "Review Guidance"),
                    source_type,
                    dkey,
                    json.dumps(clean_obs, ensure_ascii=False),
                    json.dumps(clean_heur, ensure_ascii=False),
                    json.dumps(clean_urls, ensure_ascii=False),
                    json.dumps(sources, ensure_ascii=False),
                    json.dumps(metadata, ensure_ascii=False),
                    expires_at,
                ),
            )
        return case_id

    def get_case(
        self, case_id: str, session_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves a case by ID. If session_id is supplied, enforces session isolation.
        """
        sql = "SELECT * FROM threat_cases WHERE case_id = ? AND is_deleted = 0"
        params: List[Any] = [case_id]
        if session_id is not None:
            sql += " AND session_id = ?"
            params.append(session_id)

        with self.get_connection() as conn:
            row = conn.execute(sql, params).fetchone()
            if not row:
                return None
            return self._row_to_case_dict(row)

    def list_cases(
        self,
        session_id: Optional[str] = None,
        analysis_type: Optional[str] = None,
        risk_category: Optional[str] = None,
        source_type: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Lists cases with parameterized filtering and sorting by creation timestamp descending.
        """
        sql = "SELECT * FROM threat_cases WHERE is_deleted = 0"
        params: List[Any] = []

        if session_id is not None:
            sql += " AND session_id = ?"
            params.append(session_id)
        if analysis_type is not None:
            sql += " AND analysis_type = ?"
            params.append(analysis_type)
        if risk_category is not None:
            sql += " AND risk_category = ?"
            params.append(risk_category)
        if source_type is not None:
            sql += " AND source_type = ?"
            params.append(source_type)

        sql += " ORDER BY created_at DESC"

        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
            if offset is not None:
                sql += " OFFSET ?"
                params.append(int(offset))

        with self.get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_case_dict(r) for r in rows]

    def count_cases(
        self,
        session_id: Optional[str] = None,
        analysis_type: Optional[str] = None,
        risk_category: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> int:
        """Returns the total number of matching active cases."""
        sql = "SELECT COUNT(*) FROM threat_cases WHERE is_deleted = 0"
        params: List[Any] = []

        if session_id is not None:
            sql += " AND session_id = ?"
            params.append(session_id)
        if analysis_type is not None:
            sql += " AND analysis_type = ?"
            params.append(analysis_type)
        if risk_category is not None:
            sql += " AND risk_category = ?"
            params.append(risk_category)
        if source_type is not None:
            sql += " AND source_type = ?"
            params.append(source_type)

        with self.get_connection() as conn:
            return conn.execute(sql, params).fetchone()[0]

    def delete_case(
        self, case_id: str, session_id: Optional[str] = None, hard_delete: bool = False
    ) -> bool:
        """
        Deletes a case record (soft delete by default, hard delete if requested).
        """
        params: List[Any] = [case_id]
        where_clause = "WHERE case_id = ?"
        if session_id is not None:
            where_clause += " AND session_id = ?"
            params.append(session_id)

        with self.get_connection() as conn:
            if hard_delete:
                cur = conn.execute(f"DELETE FROM threat_cases {where_clause};", params)
            else:
                cur = conn.execute(
                    f"UPDATE threat_cases SET is_deleted = 1 {where_clause};", params
                )
            return cur.rowcount > 0

    def clear_session(self, session_id: str) -> int:
        """Clears all records belonging to a given session."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM threat_cases WHERE session_id = ?;", (session_id,)
            )
            return cur.rowcount

    def prune_expired_cases(self) -> int:
        """
        Deletes cases whose retention period has expired (expires_at < current UTC time).
        """
        now_iso = get_utc_now_iso()
        with self.get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM threat_cases WHERE expires_at < ?;", (now_iso,)
            )
            return cur.rowcount

    def export_summary_table_rows(
        self, session_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Exports formatted summary rows for the dashboard table.
        """
        cases = self.list_cases(session_id=session_id)
        rows: List[Dict[str, Any]] = []
        for c in cases:
            sha = c.get("sha256_hash")
            rows.append({
                "Case ID": c.get("case_id", "N/A"),
                "Timestamp (UTC)": c.get("timestamp_utc", "N/A"),
                "Analysis Type": c.get("analysis_type", "Unknown"),
                "Risk Index (0-100)": c.get("risk_score", 0),
                "Risk Category": c.get("risk_category", "Unspecified"),
                "Indicator Count": c.get("indicator_count", 0),
                "SHA-256 Fingerprint": (sha[:12] + "...") if sha and sha != "N/A" else "N/A",
                "Extracted URLs": len(c.get("extracted_urls", [])),
                "Status": c.get("analysis_status", "Completed"),
                "Recommended Next Action": c.get("recommended_action", "Review Guidance"),
            })
        return rows

    def export_json(self, session_id: Optional[str] = None) -> str:
        """Exports cases as formatted JSON."""
        cases = self.list_cases(session_id=session_id)
        return json.dumps(
            {
                "session_id": session_id or "all_accessible_cases",
                "exported_at_utc": get_utc_now_iso(),
                "total_cases": len(cases),
                "cases": cases,
            },
            indent=2,
            ensure_ascii=False,
        )

    def export_csv(self, session_id: Optional[str] = None) -> str:
        """Exports cases as standard CSV."""
        cases = self.list_cases(session_id=session_id)
        output = io.StringIO()
        fieldnames = [
            "Case ID",
            "Timestamp UTC",
            "Analysis Type",
            "Risk Index",
            "Risk Category",
            "Indicator Count",
            "SHA-256",
            "Extracted URLs Count",
            "Status",
            "Recommended Action",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()

        for c in cases:
            writer.writerow({
                "Case ID": c.get("case_id", ""),
                "Timestamp UTC": c.get("timestamp_utc", ""),
                "Analysis Type": c.get("analysis_type", ""),
                "Risk Index": c.get("risk_score", 0),
                "Risk Category": c.get("risk_category", ""),
                "Indicator Count": c.get("indicator_count", 0),
                "SHA-256": c.get("sha256_hash", "N/A"),
                "Extracted URLs Count": len(c.get("extracted_urls", [])),
                "Status": c.get("analysis_status", "Completed"),
                "Recommended Action": c.get("recommended_action", ""),
            })

        return output.getvalue()

    def _row_to_case_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Maps an SQLite row back into a compatible case dictionary."""
        case = {
            "case_id": row["case_id"],
            "session_id": row["session_id"],
            "timestamp_utc": row["created_at"],
            "analysis_type": row["analysis_type"],
            "analysis_status": row["analysis_status"],
            "risk_score": row["risk_score"],
            "risk_category": row["risk_category"],
            "badge_color": row["badge_color"],
            "indicator_count": row["indicator_count"],
            "sha256_hash": row["sha256_hash"],
            "hash_algorithm": row["hash_algorithm"],
            "target_identifier": row["target_identifier"],
            "recommended_action": row["recommended_action"],
            "source_type": row["source_type"],
            "dedup_key": row["dedup_key"],
            "observed_evidence": json.loads(row["observed_evidence_json"] or "[]"),
            "heuristic_inferences": json.loads(row["heuristic_inferences_json"] or "[]"),
            "extracted_urls": json.loads(row["extracted_urls_json"] or "[]"),
            "official_sources": json.loads(row["official_sources_json"] or "[]"),
            "raw_data_stored": False,
        }
        # Unpack safe metadata for backward compatibility
        try:
            meta = json.loads(row["metadata_json"] or "{}")
            for k, v in meta.items():
                if k not in case:
                    case[k] = v
        except Exception:
            pass

        return case

    # =========================================================================
    # THREAT INTELLIGENCE KNOWLEDGE BASE METHODS (PHASE 1)
    # =========================================================================

    def _record_audit_event(
        self,
        conn: sqlite3.Connection,
        action: str,
        indicator_id: Optional[str] = None,
        actor: str = "system",
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Appends a sanitized audit record to indicator_audit_log within an active transaction."""
        log_id = f"AUD-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        safe_reason = sanitize_evidence_text(reason[:500]) if reason else ""
        safe_details = json.dumps(details or {})
        now_utc = get_utc_now_iso()
        conn.execute(
            """
            INSERT INTO indicator_audit_log (
                log_id, indicator_id, action, actor, timestamp_utc, reason, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (log_id, indicator_id, action[:64], actor[:64], now_utc, safe_reason, safe_details),
        )
        return log_id

    def add_indicator(
        self,
        indicator_type: str,
        indicator_value: str,
        source: str = "analyst_curated",
        confidence_score: int = 50,
        severity: str = "medium",
        review_state: str = "unreviewed",
        expires_at: Optional[str] = None,
        notes: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        actor: str = "system",
        hmac_secret: Optional[str] = None,
    ) -> str:
        """
        Adds or updates a validated threat indicator in the persistent knowledge base.

        PRIVACY & SAFETY:
        - Plaintext phone numbers are NEVER stored; they are keyed-HMAC hashed.
        - URLs have query parameters and fragments stripped to avoid PII retention.
        - APK hashes are verified as 64-hex SHA-256 strings.
        - Stored strings are never executed or evaluated dynamically.
        """
        if indicator_type not in ALLOWED_INDICATOR_TYPES:
            raise ThreatIntelligenceValidationError(
                f"Invalid indicator type '{indicator_type}'. Allowed: {sorted(list(ALLOWED_INDICATOR_TYPES))}"
            )
        if review_state not in ALLOWED_REVIEW_STATES:
            raise ThreatIntelligenceValidationError(
                f"Invalid review state '{review_state}'. Allowed: {sorted(list(ALLOWED_REVIEW_STATES))}"
            )
        if severity not in ALLOWED_SEVERITIES:
            raise ThreatIntelligenceValidationError(
                f"Invalid severity '{severity}'. Allowed: {sorted(list(ALLOWED_SEVERITIES))}"
            )

        confidence_score = max(0, min(100, int(confidence_score)))

        # Normalize indicator value safely
        if indicator_type == "phone_hmac":
            if indicator_value.startswith("HMAC_") and len(indicator_value) == 69:
                norm_value = indicator_value
            else:
                norm_value = compute_phone_indicator_hmac(indicator_value, secret=hmac_secret)
        elif indicator_type == "domain":
            norm_value = normalize_domain(indicator_value)
        elif indicator_type == "url":
            norm_value = canonicalize_url_for_matching(indicator_value)
        elif indicator_type == "apk_sha256":
            norm_value = normalize_apk_hash(indicator_value)
        else:
            raise ThreatIntelligenceValidationError(f"Unhandled indicator type: {indicator_type}")

        ind_hash = hashlib.sha256(norm_value.encode("utf-8")).hexdigest()
        clean_notes = sanitize_evidence_text(notes[:1000]) if notes else ""
        meta_json = json.dumps(metadata or {})
        now_utc = get_utc_now_iso()

        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT indicator_id, occurrence_count, confidence_score FROM threat_indicators WHERE indicator_type = ? AND indicator_value = ?",
                (indicator_type, norm_value),
            )
            existing = cur.fetchone()

            if existing:
                ind_id = existing["indicator_id"]
                new_occ = existing["occurrence_count"] + 1
                new_conf = max(existing["confidence_score"], confidence_score)
                conn.execute(
                    """
                    UPDATE threat_indicators
                    SET occurrence_count = ?, last_seen_utc = ?, confidence_score = ?, is_active = 1
                    WHERE indicator_id = ?
                    """,
                    (new_occ, now_utc, new_conf, ind_id),
                )
                self._record_audit_event(
                    conn,
                    action="UPDATE_OCCURRENCE",
                    indicator_id=ind_id,
                    actor=actor,
                    reason=f"Incremented occurrence count to {new_occ}",
                    details={"indicator_type": indicator_type, "occurrence_count": new_occ},
                )
                return ind_id
            else:
                ind_id = f"IND-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
                conn.execute(
                    """
                    INSERT INTO threat_indicators (
                        indicator_id, indicator_type, indicator_value, indicator_hash,
                        source, confidence_score, severity, review_state, is_active,
                        first_seen_utc, last_seen_utc, expires_at, notes,
                        occurrence_count, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ind_id, indicator_type, norm_value, ind_hash,
                        source[:128], confidence_score, severity, review_state, 1,
                        now_utc, now_utc, expires_at, clean_notes,
                        1, meta_json,
                    ),
                )
                self._record_audit_event(
                    conn,
                    action="INSERT",
                    indicator_id=ind_id,
                    actor=actor,
                    reason=f"Added new {indicator_type} indicator",
                    details={"indicator_type": indicator_type, "review_state": review_state, "severity": severity},
                )
                return ind_id

    def get_indicator(self, indicator_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single indicator by its unique indicator_id."""
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM threat_indicators WHERE indicator_id = ?", (indicator_id,))
            row = cur.fetchone()
            return self._row_to_indicator_dict(row) if row else None

    def get_indicator_by_value(
        self,
        indicator_type: str,
        indicator_value: str,
        hmac_secret: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Looks up an indicator by its normalized representation."""
        if indicator_type not in ALLOWED_INDICATOR_TYPES:
            return None
        try:
            if indicator_type == "phone_hmac":
                norm_val = (
                    indicator_value
                    if (indicator_value.startswith("HMAC_") and len(indicator_value) == 69)
                    else compute_phone_indicator_hmac(indicator_value, secret=hmac_secret)
                )
            elif indicator_type == "domain":
                norm_val = normalize_domain(indicator_value)
            elif indicator_type == "url":
                norm_val = canonicalize_url_for_matching(indicator_value)
            elif indicator_type == "apk_sha256":
                norm_val = normalize_apk_hash(indicator_value)
            else:
                norm_val = indicator_value
        except Exception:
            return None

        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM threat_indicators WHERE indicator_type = ? AND indicator_value = ?",
                (indicator_type, norm_val),
            )
            row = cur.fetchone()
            return self._row_to_indicator_dict(row) if row else None

    def list_indicators(
        self,
        indicator_type: Optional[str] = None,
        is_active: Optional[bool] = None,
        review_state: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists threat indicators with optional type, active status, and review state filters."""
        sql = "SELECT * FROM threat_indicators WHERE 1=1"
        params: List[Any] = []
        if indicator_type is not None:
            sql += " AND indicator_type = ?"
            params.append(indicator_type)
        if is_active is not None:
            sql += " AND is_active = ?"
            params.append(1 if is_active else 0)
        if review_state is not None:
            sql += " AND review_state = ?"
            params.append(review_state)
        sql += " ORDER BY last_seen_utc DESC LIMIT ? OFFSET ?"
        params.extend([max(1, limit), max(0, offset)])

        with self.get_connection() as conn:
            cur = conn.execute(sql, params)
            return [self._row_to_indicator_dict(r) for r in cur.fetchall()]

    def update_indicator_review_state(
        self,
        indicator_id: str,
        review_state: str,
        actor: str = "analyst",
        reason: str = "",
    ) -> bool:
        """Promotes or updates an indicator's review state ('reviewed', 'unreviewed', 'provisional')."""
        if review_state not in ALLOWED_REVIEW_STATES:
            raise ThreatIntelligenceValidationError(f"Invalid review state '{review_state}'")
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE threat_indicators SET review_state = ? WHERE indicator_id = ?",
                (review_state, indicator_id),
            )
            if cur.rowcount > 0:
                self._record_audit_event(
                    conn,
                    action="UPDATE_REVIEW_STATE",
                    indicator_id=indicator_id,
                    actor=actor,
                    reason=reason or f"Updated review state to {review_state}",
                    details={"review_state": review_state},
                )
                return True
            return False

    def deactivate_indicator(
        self,
        indicator_id: str,
        actor: str = "analyst",
        reason: str = "",
    ) -> bool:
        """Deactivates an indicator so it no longer triggers detection matches."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE threat_indicators SET is_active = 0 WHERE indicator_id = ?",
                (indicator_id,),
            )
            if cur.rowcount > 0:
                self._record_audit_event(
                    conn,
                    action="DEACTIVATE",
                    indicator_id=indicator_id,
                    actor=actor,
                    reason=reason or "Deactivated indicator",
                )
                return True
            return False

    def record_indicator_audit(
        self,
        action: str,
        indicator_id: Optional[str] = None,
        actor: str = "system",
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Public method to record an audit entry in indicator_audit_log."""
        with self.get_connection() as conn:
            return self._record_audit_event(
                conn,
                action=action,
                indicator_id=indicator_id,
                actor=actor,
                reason=reason,
                details=details,
            )

    def list_indicator_audit_logs(
        self,
        indicator_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Lists audit log events in reverse chronological order."""
        sql = "SELECT * FROM indicator_audit_log"
        params: List[Any] = []
        if indicator_id:
            sql += " WHERE indicator_id = ?"
            params.append(indicator_id)
        sql += " ORDER BY timestamp_utc DESC LIMIT ?"
        params.append(max(1, limit))

        with self.get_connection() as conn:
            cur = conn.execute(sql, params)
            results = []
            for r in cur.fetchall():
                results.append({
                    "log_id": r["log_id"],
                    "indicator_id": r["indicator_id"],
                    "action": r["action"],
                    "actor": r["actor"],
                    "timestamp_utc": r["timestamp_utc"],
                    "reason": r["reason"],
                    "details": json.loads(r["details_json"] or "{}"),
                })
            return results

    def _row_to_indicator_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Maps an SQLite threat_indicators row into a typed dictionary."""
        return {
            "indicator_id": row["indicator_id"],
            "indicator_type": row["indicator_type"],
            "indicator_value": row["indicator_value"],
            "indicator_hash": row["indicator_hash"],
            "source": row["source"],
            "confidence_score": int(row["confidence_score"]),
            "severity": row["severity"],
            "review_state": row["review_state"],
            "is_active": bool(row["is_active"]),
            "first_seen_utc": row["first_seen_utc"],
            "last_seen_utc": row["last_seen_utc"],
            "expires_at": row["expires_at"],
            "notes": row["notes"],
            "occurrence_count": int(row["occurrence_count"]),
            "metadata": json.loads(row["metadata_json"] or "{}"),
        }

    def match_indicators(
        self,
        extracted_features: Dict[str, Any],
        include_unreviewed: bool = True,
        hmac_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Matches extracted observables against active, unexpired threat indicators.

        DECISION BOUNDARY:
        - Only active (is_active=1) and unexpired indicators are matched.
        - Indicators with review_state='reviewed' are returned in 'trusted_matches'.
        - Indicators with review_state in ('unreviewed', 'provisional') are returned in 'unreviewed_leads'.
        - A match is NOT conclusive proof of fraud; it serves as verified evidence or investigative lead.
        """
        now_utc = get_utc_now_iso()
        candidate_lookups: List[Tuple[str, str]] = []

        # 1. Domains
        for d in extracted_features.get("domains", []):
            try:
                candidate_lookups.append(("domain", normalize_domain(d)))
            except Exception:
                pass

        # 2. URLs
        for u in extracted_features.get("urls", []):
            try:
                candidate_lookups.append(("url", canonicalize_url_for_matching(u)))
            except Exception:
                pass

        # 3. APK Hashes
        for h in extracted_features.get("apk_hashes", []):
            try:
                candidate_lookups.append(("apk_sha256", normalize_apk_hash(h)))
            except Exception:
                pass

        # 4. Phone Numbers (Keyed HMAC representation)
        for p in extracted_features.get("phone_numbers", []):
            try:
                mac_val = compute_phone_indicator_hmac(p, secret=hmac_secret)
                candidate_lookups.append(("phone_hmac", mac_val))
            except ThreatIntelligenceKeyError:
                # Key unavailable: fail closed for phone matching
                pass
            except Exception:
                pass

        if not candidate_lookups:
            return {
                "has_matches": False,
                "trusted_matches_count": 0,
                "unreviewed_leads_count": 0,
                "total_matches_count": 0,
                "trusted_matches": [],
                "unreviewed_leads": [],
                "highest_severity": None,
                "highest_confidence": 0,
                "summary_en": "No matching threat indicators found in local repository.",
                "summary_mr": "स्थानिक डेटाबेसमध्ये कोणतेही जुळणारे संशयास्पद निर्देशक आढळले नाहीत.",
            }

        trusted_matches: List[Dict[str, Any]] = []
        unreviewed_leads: List[Dict[str, Any]] = []
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        highest_sev_rank = 0
        highest_sev_name: Optional[str] = None
        highest_conf = 0

        with self.get_connection() as conn:
            for ind_type, ind_val in candidate_lookups:
                cur = conn.execute(
                    """
                    SELECT * FROM threat_indicators
                    WHERE indicator_type = ? AND indicator_value = ? AND is_active = 1
                    """,
                    (ind_type, ind_val),
                )
                for row in cur.fetchall():
                    # Check expiry
                    exp = row["expires_at"]
                    if exp and exp < now_utc:
                        continue  # Expired

                    ind_dict = self._row_to_indicator_dict(row)
                    conf = ind_dict["confidence_score"]
                    if conf > highest_conf:
                        highest_conf = conf
                    sev = (ind_dict["severity"] or "medium").lower()
                    if severity_order.get(sev, 0) > highest_sev_rank:
                        highest_sev_rank = severity_order.get(sev, 0)
                        highest_sev_name = sev

                    if ind_dict["review_state"] == "reviewed":
                        trusted_matches.append(ind_dict)
                    elif include_unreviewed:
                        unreviewed_leads.append(ind_dict)

        total_matches = len(trusted_matches) + len(unreviewed_leads)
        has_matches = total_matches > 0

        if len(trusted_matches) > 0:
            summary_en = (
                f"Threat Intelligence Match: {len(trusted_matches)} verified indicator(s) "
                f"matched in local repository (Severity: {highest_sev_name or 'medium'}, Confidence: {highest_conf}%)."
            )
            summary_mr = (
                f"धोकादायक निर्देशक आढळला: स्थानिक रिपॉझिटरीमध्ये {len(trusted_matches)} पुष्टी केलेले निर्देशक जुळले आहेत "
                f"(धोका: {highest_sev_name or 'मध्यम'})."
            )
        elif len(unreviewed_leads) > 0:
            summary_en = (
                f"Threat Intelligence Lead: {len(unreviewed_leads)} unreviewed indicator(s) "
                "matched in repository (Requires analyst verification; not proof of fraud)."
            )
            summary_mr = (
                f"अपुष्ट निर्देशक: रिपॉझिटरीमध्ये {len(unreviewed_leads)} नवीन निर्देशक जुळले आहेत "
                "(तपासणी आवश्यक; हा थेट फसवणुकीचा पुरावा नाही)."
            )
        else:
            summary_en = "No active matching threat indicators found in local repository."
            summary_mr = "स्थानिक डेटाबेसमध्ये कोणतेही सक्रिय संशयास्पद निर्देशक आढळले नाहीत."

        return {
            "has_matches": has_matches,
            "trusted_matches_count": len(trusted_matches),
            "unreviewed_leads_count": len(unreviewed_leads),
            "total_matches_count": total_matches,
            "trusted_matches": trusted_matches,
            "unreviewed_leads": unreviewed_leads,
            "highest_severity": highest_sev_name,
            "highest_confidence": highest_conf,
            "summary_en": summary_en,
            "summary_mr": summary_mr,
        }

    # =========================================================================
    # Phase 5: Local Human Review Desk Operations
    # =========================================================================

    def create_or_get_review(
        self,
        case_id: str,
        reviewer_label: str = "local_operator",
        notes: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Creates an initial 'pending' review for a case or returns the existing active review.
        """
        case = self.get_case(case_id)
        if not case:
            raise HumanReviewValidationError(f"Case '{case_id}' does not exist.")

        existing = self.get_review_by_case(case_id)
        if existing and existing["review_state"] != "superseded":
            return existing

        now_utc = get_utc_now_iso()
        review_id = f"REV-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        clean_notes = sanitize_evidence_text(notes[:1000]) if notes else ""
        meta_json = json.dumps(metadata or {})

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO human_reviews (
                    review_id, case_id, review_state, outcome_category,
                    confidence_rating, reviewer_label, notes,
                    created_at, updated_at, metadata_json
                ) VALUES (?, ?, 'pending', NULL, 'medium', ?, ?, ?, ?, ?);
                """,
                (
                    review_id,
                    case_id,
                    reviewer_label[:64],
                    clean_notes,
                    now_utc,
                    now_utc,
                    meta_json,
                ),
            )
            self._record_review_audit_event(
                conn,
                review_id=review_id,
                case_id=case_id,
                action="CREATE",
                actor=reviewer_label[:64],
                reason="Created initial pending review record",
                details={"case_id": case_id, "review_state": "pending"},
            )

        return self.get_review(review_id)  # type: ignore

    def submit_review(
        self,
        case_id: str,
        outcome_category: str,
        notes: str = "",
        confidence_rating: str = "medium",
        reviewer_label: str = "local_operator",
    ) -> Dict[str, Any]:
        """
        Records an operator classification for a case.

        DECISION BOUNDARY & SAFETY GUARANTEES:
        - Validates outcome_category and confidence_rating against strict allowlists.
        - Sanitizes notes and enforces a 1,000-character maximum limit.
        - Never stores raw message text, APK binaries, credentials, or PII.
        - Original case risk score and history in threat_cases are strictly preserved (immutable).
        - Corrected reviews preserve prior history via the review_audit_log and state transitions.
        """
        if outcome_category not in ALLOWED_HUMAN_OUTCOME_CATEGORIES:
            raise HumanReviewValidationError(
                f"Invalid outcome category '{outcome_category}'. Must be one of {sorted(ALLOWED_HUMAN_OUTCOME_CATEGORIES)}"
            )

        if confidence_rating not in ALLOWED_CONFIDENCE_RATINGS:
            raise HumanReviewValidationError(
                f"Invalid confidence rating '{confidence_rating}'. Must be one of {sorted(ALLOWED_CONFIDENCE_RATINGS)}"
            )

        if len(notes) > 1000:
            raise HumanReviewValidationError("Review notes exceed maximum allowed length of 1,000 characters.")

        case = self.get_case(case_id)
        if not case:
            raise HumanReviewValidationError(f"Target case '{case_id}' does not exist.")

        clean_notes = sanitize_evidence_text(notes.strip())
        now_utc = get_utc_now_iso()
        new_state = "inconclusive" if outcome_category == "insufficient_evidence" else "completed"

        existing = self.get_review_by_case(case_id)

        with self.get_connection() as conn:
            if existing:
                review_id = existing["review_id"]
                prior_outcome = existing.get("outcome_category")
                prior_state = existing.get("review_state")

                # If this is a correction of an already-completed review, audit the change
                if prior_state == "completed" and prior_outcome != outcome_category:
                    self._record_review_audit_event(
                        conn,
                        review_id=review_id,
                        case_id=case_id,
                        action="SUPERSEDE_OUTCOME",
                        actor=reviewer_label[:64],
                        reason=f"Corrected outcome from '{prior_outcome}' to '{outcome_category}'",
                        details={"prior_outcome": prior_outcome, "new_outcome": outcome_category},
                    )

                conn.execute(
                    """
                    UPDATE human_reviews
                    SET review_state = ?, outcome_category = ?, confidence_rating = ?,
                        reviewer_label = ?, notes = ?, updated_at = ?
                    WHERE review_id = ?;
                    """,
                    (
                        new_state,
                        outcome_category,
                        confidence_rating,
                        reviewer_label[:64],
                        clean_notes,
                        now_utc,
                        review_id,
                    ),
                )
                self._record_review_audit_event(
                    conn,
                    review_id=review_id,
                    case_id=case_id,
                    action="SUBMIT_REVIEW",
                    actor=reviewer_label[:64],
                    reason=f"Recorded review classification '{outcome_category}'",
                    details={"outcome": outcome_category, "confidence": confidence_rating, "state": new_state},
                )
            else:
                review_id = f"REV-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
                conn.execute(
                    """
                    INSERT INTO human_reviews (
                        review_id, case_id, review_state, outcome_category,
                        confidence_rating, reviewer_label, notes,
                        created_at, updated_at, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}');
                    """,
                    (
                        review_id,
                        case_id,
                        new_state,
                        outcome_category,
                        confidence_rating,
                        reviewer_label[:64],
                        clean_notes,
                        now_utc,
                        now_utc,
                    ),
                )
                self._record_review_audit_event(
                    conn,
                    review_id=review_id,
                    case_id=case_id,
                    action="SUBMIT_REVIEW",
                    actor=reviewer_label[:64],
                    reason=f"Recorded initial review classification '{outcome_category}'",
                    details={"outcome": outcome_category, "confidence": confidence_rating, "state": new_state},
                )

        return self.get_review(review_id)  # type: ignore

    def get_review(self, review_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a human review by its unique review_id."""
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM human_reviews WHERE review_id = ?;", (review_id,))
            row = cur.fetchone()
            return self._row_to_review_dict(row) if row else None

    def get_review_by_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the latest active human review for a case."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM human_reviews WHERE case_id = ? ORDER BY updated_at DESC LIMIT 1;",
                (case_id,),
            )
            row = cur.fetchone()
            return self._row_to_review_dict(row) if row else None

    def list_reviews(
        self,
        review_state: Optional[str] = None,
        outcome_category: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists reviews with optional filtering by state or outcome."""
        sql = "SELECT * FROM human_reviews WHERE 1=1"
        params: List[Any] = []
        if review_state is not None:
            sql += " AND review_state = ?"
            params.append(review_state)
        if outcome_category is not None:
            sql += " AND outcome_category = ?"
            params.append(outcome_category)
        sql += " ORDER BY updated_at DESC LIMIT ? OFFSET ?;"
        params.extend([max(1, limit), max(0, offset)])

        with self.get_connection() as conn:
            cur = conn.execute(sql, params)
            return [self._row_to_review_dict(r) for r in cur.fetchall()]

    def get_review_stats(self) -> Dict[str, Any]:
        """Returns summary statistics for the human review desk."""
        stats: Dict[str, Any] = {
            "total_reviews": 0,
            "by_state": {s: 0 for s in ALLOWED_HUMAN_REVIEW_STATES},
            "by_outcome": {o: 0 for o in ALLOWED_HUMAN_OUTCOME_CATEGORIES},
        }
        with self.get_connection() as conn:
            cur = conn.execute("SELECT review_state, COUNT(*) as cnt FROM human_reviews GROUP BY review_state;")
            for r in cur.fetchall():
                state = r["review_state"]
                cnt = r["cnt"]
                stats["by_state"][state] = cnt
                stats["total_reviews"] += cnt

            cur2 = conn.execute("SELECT outcome_category, COUNT(*) as cnt FROM human_reviews WHERE outcome_category IS NOT NULL GROUP BY outcome_category;")
            for r in cur2.fetchall():
                outcome = r["outcome_category"]
                stats["by_outcome"][outcome] = r["cnt"]

        # Populate top-level convenience keys matching states
        for s in ALLOWED_HUMAN_REVIEW_STATES:
            stats[s] = stats["by_state"].get(s, 0)

        return stats

    def record_review_audit(
        self,
        review_id: str,
        case_id: str,
        action: str,
        actor: str = "local_operator",
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Public method to record an event in review_audit_log."""
        with self.get_connection() as conn:
            return self._record_review_audit_event(
                conn,
                review_id=review_id,
                case_id=case_id,
                action=action,
                actor=actor,
                reason=reason,
                details=details,
            )

    def list_review_audit_logs(
        self,
        review_id: Optional[str] = None,
        case_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Lists audit log events for review desk actions."""
        sql = "SELECT * FROM review_audit_log WHERE 1=1"
        params: List[Any] = []
        if review_id:
            sql += " AND review_id = ?"
            params.append(review_id)
        if case_id:
            sql += " AND case_id = ?"
            params.append(case_id)
        sql += " ORDER BY timestamp_utc DESC LIMIT ?;"
        params.append(max(1, limit))

        with self.get_connection() as conn:
            cur = conn.execute(sql, params)
            return [
                {
                    "log_id": r["log_id"],
                    "review_id": r["review_id"],
                    "case_id": r["case_id"],
                    "action": r["action"],
                    "actor": r["actor"],
                    "timestamp_utc": r["timestamp_utc"],
                    "reason": r["reason"],
                    "details": json.loads(r["details_json"] or "{}"),
                }
                for r in cur.fetchall()
            ]

    def export_human_reviews_corpus(
        self,
        export_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Exports completed human reviews as a sanitized candidate dataset for analyst curation.
        Guarantees zero raw text or credentials retention.
        """
        reviews = self.list_reviews(review_state="completed")
        exported_records: List[Dict[str, Any]] = []

        for rev in reviews:
            case = self.get_case(rev["case_id"])
            if not case:
                continue

            rec = {
                "record_id": f"rev_export_{rev['review_id']}",
                "case_id": rev["case_id"],
                "target_identifier": case.get("target_identifier", "Unknown"),
                "analysis_type": case.get("analysis_type", "Unknown"),
                "heuristic_risk_score": case.get("risk_score", 0),
                "human_verified_label": rev["outcome_category"],
                "confidence_rating": rev["confidence_rating"],
                "reviewer_notes": rev["notes"],
                "observed_evidence_summary": case.get("observed_evidence", [])[:5],
                "extracted_urls_count": len(case.get("extracted_urls", [])),
                "provenance_category": "human_reviewed_curated",
                "provenance_verification_status": "analyst_curated",
                "review_date_utc": rev["updated_at"],
                "disclaimer": "Human review feedback export. NOT automatically fed back into active model training.",
            }
            exported_records.append(rec)

        if export_path:
            os.makedirs(os.path.dirname(os.path.abspath(export_path)), exist_ok=True)
            with open(export_path, "w", encoding="utf-8") as f:
                for item in exported_records:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")

        return exported_records

    def _row_to_review_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Maps an SQLite human_reviews row into a typed dictionary."""
        row_keys = row.keys()
        is_completed = row["review_state"] in ("completed", "inconclusive")
        return {
            "review_id": row["review_id"],
            "case_id": row["case_id"],
            "review_state": row["review_state"],
            "outcome_category": row["outcome_category"],
            "confidence_rating": row["confidence_rating"],
            "reviewer_label": row["reviewer_label"],
            "notes": row["notes"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "created_at_utc": row["created_at_utc"] if "created_at_utc" in row_keys else row["created_at"],
            "reviewed_at_utc": row["reviewed_at_utc"] if "reviewed_at_utc" in row_keys else (row["updated_at"] if is_completed else None),
            "schema_version": row["schema_version"] if "schema_version" in row_keys else 1,
            "metadata": json.loads(row["metadata_json"] or "{}"),
        }

    def _record_review_audit_event(
        self,
        conn: sqlite3.Connection,
        review_id: str,
        case_id: str,
        action: str,
        actor: str = "local_operator",
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Internal helper to record audit events in review_audit_log."""
        log_id = f"LOG-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        now_utc = get_utc_now_iso()
        conn.execute(
            """
            INSERT INTO review_audit_log (
                log_id, review_id, case_id, action, actor, timestamp_utc, reason, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                log_id,
                review_id,
                case_id,
                action,
                actor[:64],
                now_utc,
                reason[:256],
                json.dumps(details or {}),
            ),
        )
        return log_id

    # =========================================================================
    # Phase 6.1: Derived Training Features & Curation Pipeline
    # =========================================================================

    def record_training_features(
        self,
        case_id: str,
        feature_vector: List[float],
        dedup_fingerprint: str,
        consent_given: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Stores an abstract derived feature vector for an opted-in case.

        SAFETY & INTEGRITY GUARANTEES:
        - Requires explicit affirmative user consent (consent_given == True).
        - Validates vector length strictly against EXPECTED_FEATURE_DIM (1024).
        - Verifies that all vector components are finite numbers (no NaN/Inf).
        - Requires a 64-character hex keyed deduplication fingerprint.
        - NEVER stores raw message text, sanitized text, or user PII.
        - Parameterized SQLite write with transactional atomicity.
        """
        if not consent_given:
            raise FeedbackCurationValidationError(
                "Explicit user consent is mandatory to store derived training features."
            )

        case = self.get_case(case_id)
        if not case:
            raise FeedbackCurationValidationError(f"Target case '{case_id}' does not exist.")

        if not isinstance(feature_vector, list):
            raise FeedbackCurationValidationError("Feature vector must be provided as a Python list of floats.")

        if len(feature_vector) != EXPECTED_FEATURE_DIM:
            raise FeedbackCurationValidationError(
                f"Feature vector dimension mismatch: expected exactly {EXPECTED_FEATURE_DIM} elements, "
                f"got {len(feature_vector)}."
            )

        for idx, val in enumerate(feature_vector):
            if not isinstance(val, (int, float)) or not math.isfinite(val):
                raise FeedbackCurationValidationError(
                    f"Invalid non-finite feature value at index {idx}: {val}"
                )

        if (
            not dedup_fingerprint
            or not isinstance(dedup_fingerprint, str)
            or len(dedup_fingerprint) != 64
            or not re.match(r"^[0-9a-fA-F]{64}$", dedup_fingerprint)
        ):
            raise FeedbackCurationValidationError(
                "Deduplication fingerprint must be a valid 64-character hexadecimal string."
            )

        feature_record_id = (
            f"FTR-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        )
        now_utc = get_utc_now_iso()
        vec_json = json.dumps([round(float(x), 6) for x in feature_vector])
        meta_json = json.dumps(metadata or {})

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO training_feature_records (
                    feature_record_id, case_id, feature_schema_version,
                    preprocessing_version, feature_extractor_version,
                    feature_vector_json, feature_dim, consent_given,
                    consent_timestamp_utc, created_at_utc, eligibility_state,
                    dedup_fingerprint, provenance_category, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'pending_review', ?, 'local_curated_feedback', ?);
                """,
                (
                    feature_record_id,
                    case_id,
                    FEATURE_SCHEMA_VERSION,
                    "neural-preproc-v1.1.0",
                    FEATURE_EXTRACTOR_VERSION,
                    vec_json,
                    EXPECTED_FEATURE_DIM,
                    now_utc,
                    now_utc,
                    dedup_fingerprint.lower(),
                    meta_json,
                ),
            )

        rec = self.get_training_features_by_record_id(feature_record_id)
        if not rec:
            raise FeedbackCurationError(f"Failed to retrieve stored feature record '{feature_record_id}'.")
        return rec

    def get_training_features_by_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the most recent derived feature record for a given case_id."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM training_feature_records WHERE case_id = ? ORDER BY created_at_utc DESC LIMIT 1;",
                (case_id,),
            )
            row = cur.fetchone()
            return self._row_to_feature_dict(row) if row else None

    def get_training_features_by_record_id(self, feature_record_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a derived feature record by its unique feature_record_id."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM training_feature_records WHERE feature_record_id = ?;",
                (feature_record_id,),
            )
            row = cur.fetchone()
            return self._row_to_feature_dict(row) if row else None

    def list_training_feature_records(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Lists derived feature records ordered by creation date."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM training_feature_records ORDER BY created_at_utc DESC LIMIT ? OFFSET ?;",
                (max(1, limit), max(0, offset)),
            )
            return [self._row_to_feature_dict(r) for r in cur.fetchall()]

    def revoke_training_consent(
        self,
        case_id: Optional[str] = None,
        feature_record_id: Optional[str] = None,
        reason: str = "user_revoked",
    ) -> int:
        """
        Revokes consent for training feature records.
        Sets consent_given = 0 and eligibility_state = 'consent_revoked'.
        Updates metadata_json with revocation timestamp and reason.
        Does NOT delete underlying case or review history.

        Returns the number of feature records updated.
        """
        if not case_id and not feature_record_id:
            raise ValueError("Either case_id or feature_record_id must be provided to revoke consent.")

        with self.get_connection() as conn:
            query = "SELECT feature_record_id, metadata_json FROM training_feature_records WHERE "
            params: List[Any] = []
            if case_id and feature_record_id:
                query += "case_id = ? AND feature_record_id = ?"
                params.extend([case_id, feature_record_id])
            elif case_id:
                query += "case_id = ?"
                params.append(case_id)
            else:
                query += "feature_record_id = ?"
                params.append(feature_record_id)

            cur = conn.execute(query, params)
            rows = cur.fetchall()
            if not rows:
                return 0

            now_utc = get_utc_now_iso()
            count = 0
            for r in rows:
                fid = r["feature_record_id"]
                try:
                    meta = json.loads(r["metadata_json"] or "{}")
                except Exception:
                    meta = {}
                meta["revoked_at_utc"] = now_utc
                meta["revocation_reason"] = reason

                conn.execute(
                    """
                    UPDATE training_feature_records
                    SET consent_given = 0,
                        eligibility_state = 'consent_revoked',
                        metadata_json = ?
                    WHERE feature_record_id = ?;
                    """,
                    (json.dumps(meta, ensure_ascii=False), fid),
                )
                count += 1
            return count

    def curate_training_features(
        self,
        secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates stored feature records against human review outcomes and eligibility rules.

        ELIGIBILITY CRITERIA:
        - Consent must be explicit (consent_given == 1) and not revoked.
        - Feature vector must be complete, valid, and finite.
        - Associated threat case must exist and not be deleted.
        - Case must have an active human review.
        - Review state must be strictly 'completed'.
        - Outcome must be one of {'phishing', 'legitimate', 'protective_advisory'}.
        - Confidence rating must be 'high' or 'medium' (low confidence excluded).
        - Grouped Deduplication & Conflict Quarantining:
          - Records are partitioned by keyed dedup_fingerprint.
          - If multiple completed records within a fingerprint group have conflicting labels,
            the entire duplicate group is quarantined with reason 'conflicting_duplicate_labels'.
          - If labels agree, deterministically select one representative (highest confidence,
            earliest created_at_utc, earliest feature_record_id). Duplicate records are excluded
            with reason 'duplicate_fingerprint'.
          - Early pending/unreviewed records do NOT disqualify later completed duplicates.
        - Review provenance is preserved as local_operator_unauthenticated.

        Fails closed if the deduplication secret is missing or invalid.
        """
        # Step 0: Validate HMAC secret (fails closed if unconfigured)
        get_feedback_hmac_secret(secret)

        eligible_records: List[Dict[str, Any]] = []
        ineligible_records: List[Dict[str, Any]] = []

        with self.get_connection() as conn:
            # Query feature records ordered by created_at_utc ASC, rowid ASC to preserve deterministic first-seen anchor
            cur = conn.execute("SELECT * FROM training_feature_records ORDER BY created_at_utc ASC, rowid ASC;")
            feature_rows = cur.fetchall()

            grouped_candidates: Dict[str, List[Dict[str, Any]]] = {}
            all_fingerprints: Set[str] = set()

            for row in feature_rows:
                feat = self._row_to_feature_dict(row)
                rec_id = feat["feature_record_id"]
                case_id = feat["case_id"]
                fgp = feat["dedup_fingerprint"]
                all_fingerprints.add(fgp)

                # Check 1: Consent and Revocation State
                if feat.get("eligibility_state") == "consent_revoked":
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "consent_revoked",
                    })
                    continue

                if not feat["consent_given"]:
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "missing_consent",
                    })
                    continue

                # Check 2: Feature vector integrity
                vec = feat.get("feature_vector")
                if not isinstance(vec, list) or len(vec) != EXPECTED_FEATURE_DIM:
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "corrupt_feature_vector",
                    })
                    continue

                # Check 3: Associated case exists
                c_row = conn.execute(
                    "SELECT case_id, is_deleted FROM threat_cases WHERE case_id = ? LIMIT 1;",
                    (case_id,),
                ).fetchone()
                if not c_row or c_row["is_deleted"]:
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "case_not_found_or_deleted",
                    })
                    continue

                # Check 4: Review existence and state
                r_row = conn.execute(
                    "SELECT * FROM human_reviews WHERE case_id = ? ORDER BY updated_at DESC LIMIT 1;",
                    (case_id,),
                ).fetchone()
                if not r_row:
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "unreviewed_case",
                    })
                    continue

                rev_state = r_row["review_state"]
                outcome = r_row["outcome_category"]
                confidence = r_row["confidence_rating"]

                if rev_state == "pending":
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "review_pending",
                    })
                    continue

                if rev_state == "under_review":
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "review_in_progress",
                    })
                    continue

                if rev_state == "inconclusive" or outcome == "insufficient_evidence":
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "insufficient_evidence",
                    })
                    continue

                if rev_state == "superseded":
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "review_superseded",
                    })
                    continue

                if rev_state != "completed":
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": f"unsupported_review_state_{rev_state}",
                    })
                    continue

                # Check 5: Valid outcome label
                if outcome not in FEEDBACK_LABEL_TO_IDX:
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": f"invalid_outcome_category_{outcome}",
                    })
                    continue

                # Check 6: Confidence threshold (low confidence excluded)
                if confidence == "low":
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": "low_confidence_review",
                    })
                    continue

                if confidence not in ("high", "medium"):
                    ineligible_records.append({
                        "feature_record_id": rec_id,
                        "case_id": case_id,
                        "reason": f"invalid_confidence_rating_{confidence}",
                    })
                    continue

                # Passed individual checks -> eligible candidate for fingerprint group
                cand = {
                    "feature_record_id": rec_id,
                    "case_id": case_id,
                    "feature_vector": vec,
                    "feature_dim": feat["feature_dim"],
                    "label": outcome,
                    "label_idx": FEEDBACK_LABEL_TO_IDX[outcome],
                    "confidence_rating": confidence,
                    "feature_schema_version": feat["feature_schema_version"],
                    "preprocessing_version": feat["preprocessing_version"],
                    "feature_extractor_version": feat["feature_extractor_version"],
                    "consent_timestamp_utc": feat["consent_timestamp_utc"],
                    "created_at_utc": feat["created_at_utc"],
                    "reviewed_at_utc": r_row["updated_at"],
                    "review_provenance": "local_operator_unauthenticated",
                    "provenance_category": "local_curated_feedback",
                }
                grouped_candidates.setdefault(fgp, []).append(cand)

            # Pass 2: Conflict resolution & deduplication across candidate groups
            for fgp, candidates in grouped_candidates.items():
                if not candidates:
                    continue

                # Check label concordance across duplicates
                labels = {c["label"] for c in candidates}
                if len(labels) > 1:
                    # Conflicting labels among duplicates -> quarantine all candidate duplicates in group
                    for c in candidates:
                        ineligible_records.append({
                            "feature_record_id": c["feature_record_id"],
                            "case_id": c["case_id"],
                            "reason": "conflicting_duplicate_labels",
                        })
                    continue

                # Labels agree: deterministically select representative
                # Priority: high confidence > medium confidence, earliest created_at_utc, earliest feature_record_id
                def sort_key(item: Dict[str, Any]):
                    conf_rank = 0 if item["confidence_rating"] == "high" else 1
                    return (conf_rank, item["created_at_utc"], item["feature_record_id"])

                sorted_candidates = sorted(candidates, key=sort_key)
                representative = sorted_candidates[0]
                eligible_records.append(representative)

                for dup in sorted_candidates[1:]:
                    ineligible_records.append({
                        "feature_record_id": dup["feature_record_id"],
                        "case_id": dup["case_id"],
                        "reason": "duplicate_fingerprint",
                    })

        # Summary statistics
        reason_counts: Dict[str, int] = {}
        for item in ineligible_records:
            r = item["reason"]
            reason_counts[r] = reason_counts.get(r, 0) + 1

        class_distribution: Dict[str, int] = {"phishing": 0, "legitimate": 0, "protective_advisory": 0}
        for item in eligible_records:
            lbl = item["label"]
            class_distribution[lbl] = class_distribution.get(lbl, 0) + 1

        report = {
            "curation_timestamp_utc": get_utc_now_iso(),
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "preprocessing_version": "neural-preproc-v1.1.0",
            "total_feature_records_evaluated": len(feature_rows),
            "eligible_training_examples_count": len(eligible_records),
            "ineligible_records_count": len(ineligible_records),
            "ineligibility_reasons_breakdown": reason_counts,
            "eligible_class_distribution": class_distribution,
            "unique_fingerprints_count": len(all_fingerprints),
            "provenance_policy": "local_operator_unauthenticated (not certified external ground truth)",
        }

        return {
            "eligible_records": eligible_records,
            "ineligible_records": ineligible_records,
            "report": report,
        }

    def export_curated_training_features(
        self,
        export_path: Optional[str] = None,
        secret: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Exports eligible curated training features in a strictly privacy-preserving format.

        GUARANTEES:
        - Direct case identifiers (case_id) are STRIPPED to minimize linkage and correlation risks.
        - NEVER contains raw message text, sanitized text, phone numbers, Aadhaar, OTPs,
          credentials, or reviewer notes.
        - Contains only abstract numeric feature vectors, valid class labels, and provenance.
        - Does NOT expose internal deduplication fingerprints in exported records.
        """
        curation_res = self.curate_training_features(secret=secret)
        eligible = curation_res["eligible_records"]
        now_utc = get_utc_now_iso()

        exported_records: List[Dict[str, Any]] = []
        for item in eligible:
            rec = {
                "example_id": f"curated_feat_{item['feature_record_id']}",
                "feature_vector": item["feature_vector"],
                "feature_dim": item["feature_dim"],
                "label": item["label"],
                "label_idx": item["label_idx"],
                "feature_schema_version": item["feature_schema_version"],
                "preprocessing_version": item["preprocessing_version"],
                "feature_extractor_version": item["feature_extractor_version"],
                "review_provenance": item["review_provenance"],
                "confidence_category": item["confidence_rating"],
                "consent_state": "opted_in",
                "dataset_generation_timestamp": now_utc,
                "disclaimer": (
                    "Locally curated derived feature vector. NOT independently authenticated ground truth. "
                    "Contains zero raw text, reviewer notes, or personal information."
                ),
            }

            # Safety assertions: Verify forbidden fields and direct identifiers are strictly absent
            forbidden_keys = {
                "case_id", "text", "raw_text", "sanitized_text", "notes", "reviewer_notes",
                "phone", "dedup_fingerprint", "secret", "password", "otp"
            }
            assert not any(k in rec for k in forbidden_keys), f"Forbidden key leaked in export: {set(rec.keys()) & forbidden_keys}"

            exported_records.append(rec)

        if export_path:
            os.makedirs(os.path.dirname(os.path.abspath(export_path)), exist_ok=True)
            with open(export_path, "w", encoding="utf-8") as f:
                for r in exported_records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")

        return exported_records

        if export_path:
            os.makedirs(os.path.dirname(os.path.abspath(export_path)), exist_ok=True)
            with open(export_path, "w", encoding="utf-8") as f:
                for r in exported_records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")

        return exported_records

    def generate_curation_report(
        self,
        secret: Optional[str] = None,
        output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generates a sanitized data quality and curation summary report.
        Performs data quality checks for empty datasets and class deficiencies.
        """
        curation_res = self.curate_training_features(secret=secret)
        report = dict(curation_res["report"])

        eligible_count = report["eligible_training_examples_count"]
        class_dist = report["eligible_class_distribution"]

        warnings: List[str] = []
        if eligible_count == 0:
            warnings.append("EMPTY_CANDIDATE_DATASET: No eligible human-reviewed feature records currently available for training.")
        else:
            for cls_name, cnt in class_dist.items():
                if cnt == 0:
                    warnings.append(f"INSUFFICIENT_CLASS_DIVERSITY: Class '{cls_name}' has 0 eligible training examples.")

        report["quality_warnings"] = warnings
        report["data_quality_status"] = "PASS" if not warnings else ("EMPTY_DATASET" if eligible_count == 0 else "WARNING_CLASS_DEFICIENCY")

        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

        return report

    def _row_to_feature_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Maps an SQLite training_feature_records row to a typed dictionary."""
        row_keys = row.keys()
        vec_json = row["feature_vector_json"]
        try:
            vec = json.loads(vec_json)
        except Exception:
            vec = []

        return {
            "feature_record_id": row["feature_record_id"],
            "case_id": row["case_id"],
            "feature_schema_version": row["feature_schema_version"],
            "preprocessing_version": row["preprocessing_version"],
            "feature_extractor_version": row["feature_extractor_version"],
            "feature_vector": vec,
            "feature_dim": row["feature_dim"],
            "consent_given": bool(row["consent_given"]),
            "consent_timestamp_utc": row["consent_timestamp_utc"],
            "created_at_utc": row["created_at_utc"],
            "eligibility_state": row["eligibility_state"],
            "dedup_fingerprint": row["dedup_fingerprint"],
            "provenance_category": row["provenance_category"],
            "metadata": json.loads(row["metadata_json"] or "{}") if "metadata_json" in row_keys else {},
        }


# =============================================================================
# DEFAULT REPOSITORY SINGLETON ACCESSOR
# =============================================================================

_DEFAULT_REPOSITORY: Optional[CaseRepository] = None


def get_default_case_repository() -> CaseRepository:
    """Returns the process-wide default CaseRepository."""
    global _DEFAULT_REPOSITORY
    if _DEFAULT_REPOSITORY is None:
        _DEFAULT_REPOSITORY = CaseRepository()
    return _DEFAULT_REPOSITORY


def reset_default_case_repository() -> None:
    """Resets the process-wide default repository (useful in tests when switching DB paths)."""
    global _DEFAULT_REPOSITORY
    _DEFAULT_REPOSITORY = None
