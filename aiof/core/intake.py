from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from aiof.core.case import Case, _utc_now


class Alert:
    def __init__(
        self,
        alert_id: Optional[str] = None,
        title: str = "Untitled Alert",
        source: str = "Webhook",
        severity: str = "Medium",
        description: str = "",
        status: str = "new",  # new, triaged, escalated, closed
        assigned_case_id: Optional[str] = None,
        iocs: Optional[List[Dict[str, str]]] = None,
        assets: Optional[List[Dict[str, Any]]] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
    ):
        self.alert_id = alert_id or str(uuid.uuid4())[:8]
        self.title = title
        self.source = source
        self.severity = severity
        self.description = description
        self.status = status
        self.assigned_case_id = assigned_case_id
        self.iocs = iocs or []
        self.assets = assets or []
        self.raw_payload = raw_payload or {}
        self.created_at = created_at or _utc_now()

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "source": self.source,
            "severity": self.severity,
            "description": self.description,
            "status": self.status,
            "assigned_case_id": self.assigned_case_id,
            "iocs": self.iocs,
            "assets": self.assets,
            "raw_payload": self.raw_payload,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        return cls(
            alert_id=data.get("alert_id"),
            title=data.get("title", "Untitled Alert"),
            source=data.get("source", "Webhook"),
            severity=data.get("severity", "Medium"),
            description=data.get("description", ""),
            status=data.get("status", "new"),
            assigned_case_id=data.get("assigned_case_id"),
            iocs=data.get("iocs", []),
            assets=data.get("assets", []),
            raw_payload=data.get("raw_payload", {}),
            created_at=data.get("created_at"),
        )


class AlertIntakeManager:
    """Manages webhook ingestion, alert triage, asset/observable registry, and auto-case creation."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = storage_dir or (Path.home() / ".aiof" / "alerts")
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _alert_path(self, alert_id: str) -> Path:
        return self.storage_dir / f"{alert_id}.json"

    def save_alert(self, alert: Alert) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        path = self._alert_path(alert.alert_id)
        path.write_text(json.dumps(alert.to_dict(), indent=2, default=str), encoding="utf-8")

    def load_alert(self, alert_id: str) -> Optional[Alert]:
        path = self._alert_path(alert_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Alert.from_dict(data)
        except Exception:
            return None

    def list_alerts(self) -> List[Alert]:
        if not self.storage_dir.exists():
            return []
        alerts = []
        for p in sorted(self.storage_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                alerts.append(Alert.from_dict(data))
            except Exception:
                continue
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts

    def ingest_webhook(self, payload: Dict[str, Any], auto_create_case: bool = True) -> Alert:
        title = payload.get("title") or payload.get("alert_name") or payload.get("rule_name") or "Incoming Alert"
        source = payload.get("source") or payload.get("detector") or "Webhook"
        severity = payload.get("severity") or payload.get("level") or "Medium"
        description = payload.get("description") or payload.get("msg") or str(payload)
        iocs = payload.get("iocs", [])
        assets = payload.get("assets", [])

        # Extract IOCs if nested in Sigma / EDR format
        if "indicators" in payload and isinstance(payload["indicators"], list):
            for ind in payload["indicators"]:
                if isinstance(ind, dict):
                    iocs.append(ind)

        alert = Alert(
            title=title,
            source=source,
            severity=severity,
            description=description,
            status="new",
            iocs=iocs,
            assets=assets,
            raw_payload=payload,
        )

        # Auto-create case if severity is High or Critical and requested
        if auto_create_case and severity.lower() in ("high", "critical", "sev1", "sev2", "emergency"):
            case_name = f"Alert-{alert.alert_id}: {title[:50]}"
            examiner = payload.get("examiner", "Automated Intake")
            try:
                case = Case.create(name=case_name, examiner=examiner)
                alert.assigned_case_id = case.case_id
                alert.status = "escalated"
                # Add alert as artifact in case
                case.add_artifact(f"alert_{alert.alert_id}", alert.to_dict())
                case.add_custody("alert_ingested", examiner, f"Auto-escalated alert {alert.alert_id}")
            except Exception:
                pass

        self.save_alert(alert)
        return alert
