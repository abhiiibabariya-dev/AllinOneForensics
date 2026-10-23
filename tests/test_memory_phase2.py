from __future__ import annotations

from pathlib import Path
from aiof.parsers.memory import MemoryParser


def test_memory_parser(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    dump_file = evidence_dir / "memdump.raw"
    dump_file.write_bytes(b"MZ some dummy header with powershell -enc and connection to 192.168.1.50 and PAGE_EXECUTE_READWRITE mimikatz")

    parser = MemoryParser(evidence_dir)
    result = parser.parse_all()

    assert result["status"] == "implemented"
    assert "dump_file" in result["artifacts"]
    assert len(result["findings"]) > 0
    assert any("Suspicious" in f["description"] or "mimikatz" in f["detail"] for f in result["findings"])
