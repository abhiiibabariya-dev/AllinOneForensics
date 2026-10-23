from __future__ import annotations

from pathlib import Path
from aiof.core.health import check_environment


def test_health_check() -> None:
    health = check_environment()
    assert isinstance(health, dict)
    assert "python_version" in health
    assert "healthy" in health
    assert health["python_supported"] is True
    assert health["directories_ok"] is True
