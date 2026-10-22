from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_SIGMA_RULES_DIR = Path(__file__).resolve().parents[1] / "intel" / "sigma_rules"


def load_sigma_rules(rules_dir: Path | None = None) -> list[dict[str, Any]]:
    d = Path(rules_dir) if rules_dir else DEFAULT_SIGMA_RULES_DIR
    if not d.exists():
        return []
    rules: list[dict[str, Any]] = []
    for path in d.glob("**/*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                rules.extend(data)
            elif isinstance(data, dict):
                rules.append(data)
        except Exception:
            pass
    return rules


def match_sigma_rules(parsed_data: dict[str, Any], rules_dir: Path | None = None) -> list[dict[str, Any]]:
    rules = load_sigma_rules(rules_dir)
    if not rules:
        # Provide default built-in Sigma-like rules if no rule files exist on disk
        rules = [
            {
                "title": "Suspicious Process Execution via PowerShell",
                "id": "sigma-001",
                "severity": "High",
                "logsource": {"category": "process_creation"},
                "selection": {"commandline__contains": ["-enc", "downloadstring", "iex", "invoke-expression"]},
            },
            {
                "title": "Unauthorized Sudo Usage / Privilege Escalation",
                "id": "sigma-002",
                "severity": "Medium",
                "logsource": {"category": "linux_auth"},
                "selection": {"message__contains": ["sudo", "su: FAILED", "accepted publickey"]},
            },
        ]

    findings: list[dict[str, Any]] = []

    # Flatten or inspect events across modules
    events: list[dict[str, Any]] = []
    modules = parsed_data.get("modules", parsed_data)
    if isinstance(modules, dict):
        for mod_name, mod_result in modules.items():
            if isinstance(mod_result, dict):
                artifacts = mod_result.get("artifacts", {})
                if isinstance(artifacts, dict):
                    for art_name, art_list in artifacts.items():
                        if isinstance(art_list, list):
                            for item in art_list:
                                if isinstance(item, dict):
                                    item["_module"] = mod_name
                                    item["_artifact"] = art_name
                                    events.append(item)

    for rule in rules:
        title = rule.get("title", "Unknown Sigma Rule")
        rule_id = rule.get("id", "sigma-unknown")
        severity = rule.get("severity", "Medium")
        selection = rule.get("selection", {})

        for event in events:
            matched = True
            for field, expected_values in selection.items():
                field_base = field.replace("__contains", "")
                is_contains = "__contains" in field

                event_val = str(event.get(field_base, "")).lower()
                if not event_val:
                    # check all values in event dict if field not exact
                    event_val = " ".join(str(v) for v in event.values()).lower()

                if isinstance(expected_values, list):
                    cond_match = any(str(val).lower() in event_val for val in expected_values)
                else:
                    cond_match = str(expected_values).lower() in event_val

                if not cond_match:
                    matched = False
                    break

            if matched:
                findings.append({
                    "severity": severity,
                    "category": f"Sigma/{rule_id}",
                    "description": title,
                    "detail": f"Matched event in {event.get('_module', 'unknown')}/{event.get('_artifact', 'unknown')}: {json.dumps(event)[:200]}"
                })

    return findings
