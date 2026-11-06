from __future__ import annotations

import os
import subprocess
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(environment: dict[str, str], expression: str) -> None:
    env = os.environ.copy()
    env.update(environment)
    subprocess.run([sys.executable, "-c", expression], cwd=ROOT, env=env, check=True)


run(
    {"AIOF_ENV": "demo", "AIOF_DEMO_ONLY": "true", "AIOF_REQUIRE_AUTH": "false"},
    "from aiof.core.config import Config; c=Config(); assert c.environment == 'demo'; assert c.demo_only and not c.require_auth",
)
run(
    {
        "AIOF_ENV": "production",
        "AIOF_DEMO_ONLY": "false",
        "AIOF_REQUIRE_AUTH": "true",
        "AIOF_API_TOKEN": "test-token",
        "AIOF_AUDIT_SECRET": "test-audit-secret",
        "AIOF_CASES_DIR": "/tmp/aiof-production-cases",
    },
    "from aiof.core.config import Config; from aiof.core.audit import AuditLogger; c=Config(); assert c.environment == 'production'; assert c.require_auth and not c.demo_only; assert c.cases_dir.as_posix() == '/tmp/aiof-production-cases'; AuditLogger(secret_key=b'test-audit-secret')",
)
print("environment matrix passed")
