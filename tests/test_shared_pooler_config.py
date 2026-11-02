"""
Unit tests verifying the Supabase Shared Pooler (Session Mode) configuration.
"""

import os
from urllib.parse import parse_qs, urlparse
import pytest

from src.database_adapter import (
    get_active_database_target,
    is_postgres_url,
    DEFAULT_SQLITE_PATH,
)
from scripts.test_postgres_connection import (
    ensure_ssl_require,
    sanitize_url,
    sanitize_error_message,
)


def test_shared_pooler_uri_structure_in_env_example():
    """Verifies that .env.example documents the exact Shared Pooler Session Mode format."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    example_path = os.path.join(base_dir, ".env.example")
    with open(example_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "aws-0-eu-central-2.pooler.supabase.com:5432" in content
    assert "postgres.vqbqvrlyinieakosgalm" in content
    assert "sslmode=require" in content
    assert "Shared Pooler" in content


def test_shared_pooler_uri_structure_in_root_env():
    """Verifies that .env contains the Shared Pooler Session Mode placeholder."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(base_dir, ".env")
    with open(env_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "aws-0-eu-central-2.pooler.supabase.com:5432" in content
    assert "postgres.vqbqvrlyinieakosgalm" in content
    assert "sslmode=require" in content
    assert "Shared Pooler" in content
    # Ensure no old direct connection references exist
    assert "db.vqbqvrlyinieakosgalm.supabase.co" not in content


def test_is_postgres_url_with_shared_pooler():
    """Verifies is_postgres_url correctly identifies Shared Pooler URIs."""
    pooler_uri = "postgresql://postgres.vqbqvrlyinieakosgalm:secret@aws-0-eu-central-2.pooler.supabase.com:5432/postgres?sslmode=require"
    assert is_postgres_url(pooler_uri) is True


def test_ensure_ssl_require_adds_query_param():
    """Verifies that ensure_ssl_require injects sslmode=require if missing."""
    url_without_ssl = "postgresql://postgres.vqbqvrlyinieakosgalm:secret@aws-0-eu-central-2.pooler.supabase.com:5432/postgres"
    url_with_ssl = ensure_ssl_require(url_without_ssl)
    parsed = urlparse(url_with_ssl)
    qs = parse_qs(parsed.query)
    assert qs.get("sslmode") == ["require"]


def test_sanitize_url_masks_password():
    """Verifies that diagnostic sanitizer masks real passwords in pooler URIs."""
    url = "postgresql://postgres.vqbqvrlyinieakosgalm:P%40ssw0rd123@aws-0-eu-central-2.pooler.supabase.com:5432/postgres?sslmode=require"
    sanitized = sanitize_url(url)
    assert "P%40ssw0rd123" not in sanitized
    assert ":****@" in sanitized
    assert "postgres.vqbqvrlyinieakosgalm" in sanitized
    assert "aws-0-eu-central-2.pooler.supabase.com" in sanitized


def test_sanitize_error_message():
    """Verifies that sanitize_error_message removes passwords from exception traces."""
    url = "postgresql://postgres.vqbqvrlyinieakosgalm:SuperSecretPass!@aws-0-eu-central-2.pooler.supabase.com:5432/postgres?sslmode=require"
    exc = Exception("password authentication failed for user SuperSecretPass! at aws-0-eu-central-2.pooler.supabase.com")
    cleaned = sanitize_error_message(exc, url)
    assert "SuperSecretPass!" not in cleaned
    assert "****" in cleaned


def test_render_yaml_has_database_url_unsynced():
    """Verifies render.yaml configures DATABASE_URL with sync: false."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    render_path = os.path.join(base_dir, "render.yaml")
    with open(render_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "key: DATABASE_URL" in content
    assert "sync: false" in content
