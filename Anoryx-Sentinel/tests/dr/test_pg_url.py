from __future__ import annotations

import pytest

from dr.pg_url import parse_pg_url


def test_parse_plain_postgresql_url():
    conn = parse_pg_url("postgresql://sentinel:s3cr3t@dbhost:5432/sentinel_dev")
    assert conn.host == "dbhost"
    assert conn.port == 5432
    assert conn.user == "sentinel"
    assert conn.password == "s3cr3t"
    assert conn.dbname == "sentinel_dev"


def test_parse_strips_driver_suffix():
    conn = parse_pg_url("postgresql+asyncpg://sentinel:s3cr3t@dbhost:5432/sentinel_dev")
    assert conn.host == "dbhost"
    assert conn.dbname == "sentinel_dev"


def test_default_port():
    conn = parse_pg_url("postgresql://sentinel:pw@dbhost/sentinel_dev")
    assert conn.port == 5432


def test_no_password():
    conn = parse_pg_url("postgresql://sentinel@dbhost:5432/sentinel_dev")
    assert conn.password is None


def test_url_encoded_credentials_are_decoded():
    conn = parse_pg_url("postgresql://sen%40tinel:p%40ss@dbhost:5432/sentinel_dev")
    assert conn.user == "sen@tinel"
    assert conn.password == "p@ss"


def test_malformed_url_raises():
    with pytest.raises(ValueError):
        parse_pg_url("not-a-url")
    with pytest.raises(ValueError):
        parse_pg_url("postgresql://dbhost:5432/db")  # missing user


def test_cli_args_shape():
    conn = parse_pg_url("postgresql://sentinel:pw@dbhost:5432/sentinel_dev")
    assert conn.cli_args() == ["-h", "dbhost", "-p", "5432", "-U", "sentinel", "-d", "sentinel_dev"]


def test_password_never_in_cli_args():
    conn = parse_pg_url("postgresql://sentinel:s3cr3t-password@dbhost:5432/sentinel_dev")
    assert "s3cr3t-password" not in conn.cli_args()


def test_env_sets_pgpassword_without_mutating_base():
    conn = parse_pg_url("postgresql://sentinel:s3cr3t@dbhost:5432/sentinel_dev")
    base = {"PATH": "/usr/bin"}
    env = conn.env(base)
    assert env["PGPASSWORD"] == "s3cr3t"
    assert "PGPASSWORD" not in base  # base dict untouched
