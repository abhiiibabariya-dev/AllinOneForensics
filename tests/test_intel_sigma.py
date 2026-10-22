from __future__ import annotations

from pathlib import Path
from aiof.intel.stix_sync import parse_stix_bundle, sync_stix_feed
from aiof.analysis.sigma import match_sigma_rules


def test_stix_parsing(tmp_path: Path) -> None:
    bundle_file = tmp_path / "stix_bundle.json"
    bundle_file.write_text(
        """
        {
          "objects": [
            {
              "type": "indicator",
              "pattern": "[file:hashes.sha256 = '4a65401490218a5624128f731c390be4df05d045d9fa0e8d05ddc80214a1e941']"
            },
            {
              "type": "indicator",
              "pattern": "[ipv4-addr:value = '192.168.1.100']"
            }
          ]
        }
        """,
        encoding="utf-8"
    )
    parsed = parse_stix_bundle(bundle_file)
    assert "4a65401490218a5624128f731c390be4df05d045d9fa0e8d05ddc80214a1e941" in parsed["sha256"]
    assert "192.168.1.100" in parsed["ip"]


def test_sigma_matching() -> None:
    sample_data = {
        "modules": {
            "windows": {
                "artifacts": {
                    "processes": [
                        {"commandline": "powershell.exe -enc SQBFAFgAIAA=", "user": "SYSTEM"}
                    ]
                }
            }
        }
    }
    findings = match_sigma_rules(sample_data)
    assert len(findings) > 0
    assert any("PowerShell" in f["description"] for f in findings)
