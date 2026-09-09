import json
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any

from aiof.core.case import Case


class ReportGenerator:
    """Generate HTML, DOCX, and PDF reports."""

    def __init__(self, case: Case):
        self.case = case
        self.reports_dir = case.path / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_html(self, findings: List[Dict], evidence: List[Dict]) -> Path:
        """Generate HTML report."""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Report - {self.case.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #3498db; border-bottom: 2px solid #3498db; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #2c3e50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .high {{ color: #e74c3c; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #27ae60; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Digital Forensic Report</h1>
    <h2>Case Information</h2>
    <p><strong>Case ID:</strong> {self.case.case_id}</p>
    <p><strong>Case Name:</strong> {self.case.name}</p>
    <p><strong>Examiner:</strong> {self.case.examiner}</p>
    <p><strong>Created:</strong> {self.case.created_at}</p>
    <p><strong>Status:</strong> {self.case.status}</p>

    <h2>Evidence Inventory</h2>
    <table>
        <tr><th>File</th><th>Size</th><th>SHA-256</th></tr>
        {"".join(f'<tr><td>{e.get("path", "N/A")}</td><td>{e.get("size", "N/A")}</td><td>{e.get("hash", "N/A")}</td></tr>' for e in evidence)}
    </table>

    <h2>Findings</h2>
    <table>
        <tr><th>Severity</th><th>Category</th><th>Description</th></tr>
        {"".join(f'<tr><td class="{f.get("severity", "low").lower()}">{f.get("severity", "N/A")}</td><td>{f.get("category", "N/A")}</td><td>{f.get("description", "N/A")}</td></tr>' for f in findings)}
    </table>

    <h2>Methodology</h2>
    <p>This report was generated using AllinOneForensics. All evidence was processed in read-only mode with cryptographic hashes computed for chain of custody.</p>

    <h2>Chain of Custody</h2>
    <p>See evidence table above for file hashes and timestamps.</p>
</body>
</html>
"""
        report_path = self.reports_dir / f"case_report_{self.case.case_id}.html"
        report_path.write_text(html_content)
        return report_path

    def generate_docx(self, findings: List[Dict], evidence: List[Dict]) -> Path:
        """Generate DOCX report (placeholder)."""
        docx_content = {
            "case": self.case.case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "evidence": evidence,
            "findings": findings,
            "sections": [
                "Case Identification",
                "Scope and Authorization",
                "Evidence Inventory",
                "Methodology",
                "Findings",
                "IOCs",
                "Timeline",
                "Recommendations",
                "Appendix"
            ]
        }
        report_path = self.reports_dir / f"case_report_{self.case.case_id}.docx"
        report_path.write_text(json.dumps(docx_content, indent=2))
        return report_path

    def generate_pdf(self, findings: List[Dict], evidence: List[Dict]) -> Path:
        """Generate PDF report (placeholder)."""
        pdf_content = {
            "case": self.case.case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "evidence": evidence,
            "findings": findings,
            "format": "pdf_placeholder"
        }
        report_path = self.reports_dir / f"case_report_{self.case.case_id}.pdf"
        report_path.write_text(json.dumps(pdf_content, indent=2))
        return report_path
