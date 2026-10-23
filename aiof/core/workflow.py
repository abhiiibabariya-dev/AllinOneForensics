from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class InvestigationWorkflow:
    """Manages notes, tasks, hypotheses, and status history for an active case."""

    def __init__(self, case_path: Path):
        self.case_path = Path(case_path)
        self.workflow_file = self.case_path / "workflow.json"
        self._data = self._load()

    def _load(self) -> Dict[str, Any]:
        if self.workflow_file.exists():
            try:
                return json.loads(self.workflow_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "notes": [],
            "tasks": [],
            "hypotheses": [],
            "custody_log": [],
        }

    def save(self) -> None:
        self.workflow_file.parent.mkdir(parents=True, exist_ok=True)
        self.workflow_file.write_text(json.dumps(self._data, indent=2, default=str), encoding="utf-8")

    def add_note(self, title: str, content: str, author: str) -> Dict[str, Any]:
        note = {
            "id": len(self._data["notes"]) + 1,
            "title": title,
            "content": content,
            "author": author,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._data["notes"].append(note)
        self.save()
        return note

    def add_task(self, title: str, assignee: str, status: str = "pending") -> Dict[str, Any]:
        task = {
            "id": len(self._data["tasks"]) + 1,
            "title": title,
            "assignee": assignee,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._data["tasks"].append(task)
        self.save()
        return task

    def add_hypothesis(self, statement: str, status: str = "under_investigation") -> Dict[str, Any]:
        hyp = {
            "id": len(self._data["hypotheses"]) + 1,
            "statement": statement,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._data["hypotheses"].append(hyp)
        self.save()
        return hyp

    def get_summary(self) -> Dict[str, Any]:
        return self._data
