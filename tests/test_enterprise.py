from __future__ import annotations

import pytest
from pathlib import Path
import tempfile

from aiof.core.audit import AuditLogger
from aiof.core.rbac import RBACManager, require_permission, PermissionDeniedError
from aiof.core.plugins import PluginManifest, PluginTrustManager
from aiof.core.compliance import ComplianceExporter


def test_audit_logger_chain():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit_trail.jsonl"
        logger = AuditLogger(log_path=log_path, secret_key=b"test-secret")

        e1 = logger.log_event("alice", "Admin", "create", "case-001", {"detail": "created case"})
        e2 = logger.log_event("bob", "Senior Analyst", "add_evidence", "case-001", {"file": "sample.evtx"})

        assert e1["seq"] == 1
        assert e1["prev_hash"] == "0" * 64
        assert e2["seq"] == 2
        assert e2["prev_hash"] == e1["current_hash"]

        assert logger.verify_chain() is True

        # Tamper test
        content = log_path.read_text(encoding="utf-8")
        tampered = content.replace("sample.evtx", "malicious.evtx")
        log_path.write_text(tampered, encoding="utf-8")

        assert logger.verify_chain() is False


def test_rbac_permissions():
    assert RBACManager.has_permission("Admin", "any:permission") is True
    assert RBACManager.has_permission("Junior Analyst", "case:create") is False
    assert RBACManager.has_permission("Junior Analyst", "case:read") is True
    assert RBACManager.has_permission("Auditor", "compliance:export") is True
    assert RBACManager.has_permission("Guest", "evidence:add") is False

    try:
        RBACManager.verify_access("Junior Analyst", "case:create")
        assert False, "Should have raised PermissionDeniedError"
    except PermissionDeniedError as exc:
        assert exc.status_code == 403

    assert RBACManager.verify_access("Senior Analyst", "case:read") is True


def test_plugin_trust():
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = PluginTrustManager(registry_dir=Path(tmpdir))
        manifest = PluginManifest(
            plugin_id="test_plugin",
            name="Test Plugin",
            version="1.0.0",
            author="Analyst",
            description="Test plugin",
            entrypoint="test.py",
            permissions=["read"],
            status="trusted"
        )
        manager.register_plugin(manifest)

        loaded = manager.load_plugin("test_plugin")
        assert loaded is not None
        assert loaded.name == "Test Plugin"
        assert manager.verify_plugin("test_plugin") is True

        manager.set_status("test_plugin", "untrusted")
        assert manager.verify_plugin("test_plugin") is False


def test_compliance_exporter():
    with tempfile.TemporaryDirectory() as tmpdir:
        exporter = ComplianceExporter()
        report = exporter.generate_compliance_report()
        assert "NIST_CSF_2_0" in report["frameworks"]
        assert "ISO_27001_2022" in report["frameworks"]
        assert report["audit_chain_integrity"] is True

        out = Path(tmpdir) / "compliance.json"
        res = exporter.export_package(out)
        assert res.exists()
