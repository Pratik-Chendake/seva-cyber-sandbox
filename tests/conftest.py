"""
Pytest configuration and global fixtures for Seva Cyber Sandbox.
Ensures every test runs against a clean, isolated SQLite test database.
"""

import pytest
from src.case_repository import reset_default_case_repository


@pytest.fixture(autouse=True)
def isolated_test_database(tmp_path, monkeypatch):
    """
    Directs SEVA_CASE_DB_PATH to a temporary SQLite file per test and resets the
    singleton repository, guaranteeing test isolation and zero pollution of instance/.
    Clears external cloud DATABASE_URL from test environment unless explicitly configured.
    """
    test_db = tmp_path / "test_seva_cases.sqlite3"
    monkeypatch.setenv("SEVA_CASE_DB_PATH", str(test_db))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SEVA_DATABASE_URL", raising=False)
    reset_default_case_repository()
    yield
    reset_default_case_repository()
