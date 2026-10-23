from __future__ import annotations

import tempfile
from pathlib import Path
from aiof.core.intake import Alert, AlertIntakeManager


def test_alert_creation_and_dict():
    alert = Alert(
        title="Suspicious PowerShell Execution",
        source="EDR",
        severity="High",
        description="powershell.exe -enc ...",
        iocs=[{"type": "sha256", "value": "abc123xyz"}],
    )
    assert alert.title == "Suspicious PowerShell Execution"
    assert alert.severity == "High"
    assert len(alert.iocs) == 1
    d = alert.to_dict()
    assert d["alert_id"] == alert.alert_id
    assert d["source"] == "EDR"

    loaded = Alert.from_dict(d)
    assert loaded.alert_id == alert.alert_id
    assert loaded.title == alert.title


def test_alert_intake_manager():
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = AlertIntakeManager(storage_dir=Path(tmpdir) / "alerts")
        payload = {
            "title": "Brute Force Attack Detected",
            "source": "Splunk",
            "severity": "Critical",
            "description": "Multiple failed logins from 192.168.1.100",
            "iocs": [{"type": "ip", "value": "192.168.1.100"}],
        }
        alert = manager.ingest_webhook(payload, auto_create_case=False)
        assert alert.alert_id is not None
        assert alert.severity == "Critical"

        alerts = manager.list_alerts()
        assert len(alerts) == 1
        assert alerts[0].title == "Brute Force Attack Detected"

        loaded = manager.load_alert(alert.alert_id)
        assert loaded is not None
        assert loaded.description == payload["description"]
