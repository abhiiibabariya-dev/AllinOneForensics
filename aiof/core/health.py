from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict


def check_environment() -> Dict[str, Any]:
    """Validates python version, dependencies, and local directories for offline execution."""
    status: Dict[str, Any] = {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "python_supported": sys.version_info >= (3, 11),
        "dependencies": {},
        "directories_ok": True,
        "errors": [],
    }

    # Check dependencies
    for pkg in ["fastapi", "uvicorn", "docx", "reportlab", "pydantic"]:
        try:
            __import__(pkg)
            status["dependencies"][pkg] = True
        except ImportError:
            status["dependencies"][pkg] = False
            status["errors"].append(f"Optional or required dependency missing: {pkg}")

    # Check config dirs
    from aiof.core.config import DEFAULT_CONFIG
    try:
        DEFAULT_CONFIG.ensure_dirs()
        status["cases_dir"] = str(DEFAULT_CONFIG.cases_dir)
    except Exception as e:
        status["directories_ok"] = False
        status["errors"].append(str(e))

    status["healthy"] = status["python_supported"] and status["directories_ok"]
    return status
