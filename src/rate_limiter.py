"""
Seva Cyber Sandbox — Multi-Worker & Distributed Shared Rate Limiter
Supports single-process in-memory caching and cross-worker shared persistence
via SQLite / PostgreSQL database without requiring Redis or paid external services.
"""

from collections import defaultdict
import os
import threading
import time
import uuid
from typing import Dict, List, Optional, Tuple

_IN_MEMORY_LOCK = threading.Lock()
_IN_MEMORY_TIMESTAMPS: Dict[str, List[float]] = defaultdict(list)

# Route-specific rate limits: (max_requests, window_seconds)
RATE_LIMIT_RULES: Dict[str, Tuple[int, int]] = {
    "/api/auth/login": (15, 60),      # 15 attempts / min
    "/api/auth/setup-admin": (5, 60), # 5 setup attempts / min
    "/api/storage/upload": (30, 60),  # 30 uploads / min
    "/api/analyze/": (120, 60),       # 120 analysis calls / min
}


def check_rate_limit(
    client_ip: str,
    path: str,
    db_conn=None,
) -> bool:
    """
    Evaluates whether the client has exceeded rate limits for the given path.
    Returns True if RATE LIMITED (should return 429), False if allowed.
    """
    if os.environ.get("DISABLE_RATE_LIMITING") == "1":
        return False

    rule = None
    for prefix, r in RATE_LIMIT_RULES.items():
        if path.startswith(prefix):
            rule = r
            break
    if not rule:
        return False

    max_reqs, window_seconds = rule
    now = time.time()
    key = f"{client_ip}:{prefix}"

    # 1. First check shared database table if connection is supplied
    if db_conn is not None:
        try:
            # Ensure table exists
            db_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limit_events (
                    event_id TEXT PRIMARY KEY,
                    limit_key TEXT NOT NULL,
                    timestamp_utc REAL NOT NULL
                );
                """
            )
            # Prune expired events for this key
            cutoff = now - window_seconds
            db_conn.execute(
                "DELETE FROM rate_limit_events WHERE limit_key = ? AND timestamp_utc < ?;",
                (key, cutoff),
            )
            # Count recent events
            cur = db_conn.execute(
                "SELECT COUNT(*) FROM rate_limit_events WHERE limit_key = ?;",
                (key,),
            )
            count = cur.fetchone()[0]
            if count >= max_reqs:
                return True

            # Record this event
            db_conn.execute(
                "INSERT INTO rate_limit_events (event_id, limit_key, timestamp_utc) VALUES (?, ?, ?);",
                (uuid.uuid4().hex, key, now),
            )
            return False
        except Exception:
            # Gracefully degrade to in-memory sliding window if DB is locked or busy
            pass

    # 2. In-Memory Sliding Window (Fallback or Local Dev)
    with _IN_MEMORY_LOCK:
        history = _IN_MEMORY_TIMESTAMPS[key]
        cutoff = now - window_seconds
        _IN_MEMORY_TIMESTAMPS[key] = [t for t in history if t > cutoff]
        if len(_IN_MEMORY_TIMESTAMPS[key]) >= max_reqs:
            return True
        _IN_MEMORY_TIMESTAMPS[key].append(now)
        return False
