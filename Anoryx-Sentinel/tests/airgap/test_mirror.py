"""Offline mirror config validation (F-036, ADR-0041)."""

from __future__ import annotations

import pytest

from airgap.mirror import MirrorConfigError, is_internal_host, validate_mirror_config

SUFFIXES = (".internal", ".svc", "mirror.corp.example")


def test_internal_config_passes():
    cfg = {
        "internal_suffixes": list(SUFFIXES),
        "pip_index_url": "https://mirror.corp.example/simple",
        "pip_extra_index_urls": ["https://pypi.internal/extra"],
        "container_registries": ["registry.internal:5000", "10.0.0.5:5000"],
    }
    hosts = validate_mirror_config(cfg)
    assert "mirror.corp.example" in hosts
    assert "registry.internal" in hosts
    assert "10.0.0.5" in hosts


@pytest.mark.parametrize(
    "url",
    [
        "https://pypi.org/simple",
        "https://files.pythonhosted.org/simple",
        "https://ghcr.io/anoryx/sentinel",
        "docker.io/library/postgres",
        "https://8.8.8.8/simple",  # public IP
    ],
)
def test_public_host_rejected(url):
    cfg = {"internal_suffixes": list(SUFFIXES), "pip_index_url": url}
    with pytest.raises(MirrorConfigError):
        validate_mirror_config(cfg)


def test_empty_config_rejected():
    with pytest.raises(MirrorConfigError):
        validate_mirror_config({"internal_suffixes": list(SUFFIXES)})


def test_unknown_host_not_matching_suffix_rejected():
    cfg = {"internal_suffixes": list(SUFFIXES), "pip_index_url": "https://random.example.com/x"}
    with pytest.raises(MirrorConfigError):
        validate_mirror_config(cfg)


@pytest.mark.parametrize(
    "host,expected",
    [
        ("10.1.2.3", True),
        ("192.168.1.1", True),
        ("172.16.0.1", True),
        ("127.0.0.1", True),
        ("localhost", True),
        ("mirror.internal", True),
        ("thing.svc", True),
        ("mirror.corp.example", True),
        ("pypi.org", False),
        ("8.8.8.8", False),
        ("example.com", False),
    ],
)
def test_is_internal_host(host, expected):
    assert is_internal_host(host, SUFFIXES) is expected
