from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List

from aiof.core.case import Case
from aiof.core.audit import AuditLogger


NIST_CSF_MAPPINGS = {
    "DE.AE-1": "A security monitoring and alert intake process is established (AlertIntakeManager).",
    "DE.CM-1": "Continuous network and host event monitoring via forensic adapters (Hayabusa, Chainsaw, Volatility3, Yara).",
    "RS.RP-1": "Response execution processes are tested and documented via incident response cases and chain of custody.",
    "RS.AN-1": "Investigations are conducted with cryptographic chain of custody and artifact retention.",
    "RC.IM-2": "Integrity of forensics evidence verified via SHA-256 hashing and tamper-evident audit logs."
}

ISO_27001_MAPPINGS = {
    "A.16.1.1": "Management of security incidents and improvements (Incident Case Management).",
    "A.12.4.1": "Event logging: Audit logs are recorded with cryptographic hash chaining to ensure tamper resistance.",
    "A.12.1.2": "Change management and tool integrity verification via plugin trust manager and tool registries.",
    "A.13.1.1": "Network security and monitoring integration."
}


class ComplianceExporter:
    def __init__(self, case_id: Optional[str] = None):
        self.case_id = case_id
        self.audit_logger = AuditLogger()

    def generate_compliance_report(self) -> Dict[str, Any]:
        case_data = None
        if self.case_id:
            c = Case.load(self.case_id)
            if c:
                case_data = {
                    "case_id": c.case_id,
                    "name": c.name,
                    "examiner": c.examiner,
                    "status": c.status,
                    "evidence_count": len(c.evidence),
                    "custody_events": len(c.custody)
                }

        audit_chain_valid = self.audit_logger.verify_chain()

        report = {
            "frameworks": {
                "NIST_CSF_2_0": NIST_CSF_MAPPINGS,
                "ISO_27001_2022": ISO_27001_MAPPINGS
            },
            "audit_chain_integrity": audit_chain_valid,
            "case_context": case_data,
            "compliance_status": "COMPLIANT" if audit_chain_valid else "NON_COMPLIANT_AUDIT_TAMPER"
        }
        return report

    def export_package(self, output_path: Path) -> Path:
        report = self.generate_compliance_report()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return output_path
