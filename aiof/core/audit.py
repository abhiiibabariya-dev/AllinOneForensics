from __future__ import annotations

import hashlib
import json
import hmac
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from aiof.core.config import DEFAULT_CONFIG


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogger:
    def __init__(self, log_path: Optional[Path] = None, secret_key: bytes = b"aiof-enterprise-audit-secret"):
        self.log_path = log_path or (Path(DEFAULT_CONFIG.cases_dir).parent / "audit_trail.jsonl")
        self.secret_key = secret_key
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_last_entry(self) -> Optional[Dict[str, Any]]:
        if not self.log_path.exists():
            return None
        lines = self.log_path.read_text(encoding="utf-8").strip().splitlines()
        if not lines:
            return None
        try:
            return json.loads(lines[-1])
        except Exception:
            return None

    def log_event(self, actor: str, role: str, action: str, target: str, details: Dict[str, Any] = None) -> Dict[str, Any]:
        last = self._get_last_entry()
        seq = (last.get("seq", 0) + 1) if last else 1
        prev_hash = last.get("current_hash", "0" * 64) if last else "0" * 64
        timestamp = _utc_now()

        payload = {
            "seq": seq,
            "timestamp": timestamp,
            "actor": actor,
            "role": role,
            "action": action,
            "target": target,
            "details": details or {},
            "prev_hash": prev_hash,
        }

        # Canonicalize payload for hashing
        canonical_str = json.dumps(payload, sort_keys=True, default=str)
        current_hash = hmac.new(self.secret_key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

        entry = {**payload, "current_hash": current_hash}

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

        return entry

    def verify_chain(self) -> bool:
        if not self.log_path.exists():
            return True
        lines = self.log_path.read_text(encoding="utf-8").strip().splitlines()
        if not lines:
            return True

        expected_prev = "0" * 64
        expected_seq = 1

        for line in lines:
            try:
                entry = json.loads(line)
            except Exception:
                return False

            if entry.get("seq") != expected_seq:
                return False
            if entry.get("prev_hash") != expected_prev:
                return False

            # Verify hash
            current_hash = entry.pop("current_hash")
            canonical_str = json.dumps(entry, sort_keys=True, default=str)
            computed_hash = hmac.new(self.secret_key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

            if current_hash != computed_hash:
                return False

            expected_prev = current_hash
            expected_seq += 1

        return True
