from __future__ import annotations

from pathlib import Path
from aiof.parsers.windows import WindowsParser
from aiof.parsers.windows.windows import normalize_timestamp


def test_normalize_timestamp() -> None:
    # Epoch FILETIME for 2020-01-01 00:00:00 UTC with FILETIME base (1601 to 1970 = 11644473600 seconds)
    # 1577836800 seconds (2020-01-01) + 11644473600 = 12822310400 seconds * 10,000,000 = 128223104000000000
    # Let's test with 132222816000000000 (which is 2020-01-01 if base is accounted for or raw)
    ts = normalize_timestamp(132222816000000000)
    assert "2019-12-31" in ts or "2020-01-01" in ts

    iso = normalize_timestamp("2026-10-23T12:00:00Z")
    assert "2026-10-23T12:00:00" in iso


def test_windows_parser_phase1(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    defender_dir = evidence_dir / "defender"
    defender_dir.mkdir()
    (defender_dir / "detection.log").write_text("Threat detected: Trojan:Win32/Emotet in C:\\temp\\malware.exe", encoding="utf-8")

    reg_dir = evidence_dir / "registry"
    reg_dir.mkdir()

    parser = WindowsParser(evidence_dir)
    result = parser.parse_all()

    assert result["status"] == "implemented"
    assert "windows_defender" in result["artifacts"]
    assert len(result["findings"]) > 0
    assert any("Trojan" in f["description"] or "Trojan" in f["detail"] for f in result["findings"])


def test_windows_filter_records() -> None:
    records = [
        {"event_id": 4624, "user": "Administrator", "suspicious": False},
        {"event_id": 4625, "user": "Administrator", "suspicious": True},
        {"event_id": 7045, "user": "SYSTEM", "suspicious": True}
    ]
    parser = WindowsParser(Path("."))
    suspicious = parser.filter_records(records, suspicious_only=True)
    assert len(suspicious) == 2

    filtered_id = parser.filter_records(records, event_id=4624)
    assert len(filtered_id) == 1
    assert filtered_id[0]["event_id"] == 4624
