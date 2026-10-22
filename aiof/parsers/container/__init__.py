from __future__ import annotations

import json
from pathlib import Path
from typing import Any

class ContainerParser:
    def __init__(self, evidence_dir: Path) -> None:
        self.evidence_dir = evidence_dir

    def parse_all(self) -> dict[str, Any]:
        artifacts: dict[str, Any] = {"k8s_audit_events": [], "container_inspects": []}
        findings: list[dict[str, Any]] = []

        if not self.evidence_dir.exists():
            return {"parser": "container", "artifacts": artifacts, "findings": findings}

        for path in self.evidence_dir.rglob("*"):
            if not path.is_file():
                continue
            name_lower = path.name.lower()
            if "k8s" in name_lower or "audit" in name_lower or name_lower.endswith(".json"):
                try:
                    content = path.read_text(encoding="utf-8", errors="ignore")
                    for line in content.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except Exception:
                            continue

<<<<<<< HEAD
=======
                        # Check Kubernetes audit event structure
>>>>>>> b9ef8aa (Fix test sample path using tmp_path and add container parser for CI)
                        verb = event.get("verb", "")
                        uri = event.get("requestURI", "")
                        user = event.get("user", {}).get("username", "")
                        object_ref = event.get("objectRef", {})
                        resource = object_ref.get("resource", "")

                        artifacts["k8s_audit_events"].append({
                            "source": path.name,
                            "user": user,
                            "verb": verb,
                            "uri": uri,
                            "resource": resource,
                            "time": event.get("stageTimestamp") or event.get("requestReceivedTimestamp")
                        })

<<<<<<< HEAD
=======
                        # Heuristics for high risk K8s actions
>>>>>>> b9ef8aa (Fix test sample path using tmp_path and add container parser for CI)
                        if user in {"system:unauthenticated", "anonymous"}:
                            findings.append({
                                "severity": "Critical",
                                "category": "Container/K8s",
                                "description": f"Unauthenticated Kubernetes API access by {user}",
                                "detail": f"Verb: {verb}, URI: {uri} in {path.name}"
                            })
                        elif "clusterrolebindings" in resource.lower() and verb in {"create", "update", "patch"}:
                            findings.append({
                                "severity": "High",
                                "category": "Container/K8s",
                                "description": f"ClusterRoleBinding modification/creation by {user}",
                                "detail": f"Resource: {resource}, Verb: {verb} in {path.name}"
                            })
                        elif resource == "pods" and verb in {"create", "update"} and "exec" in uri:
                            findings.append({
                                "severity": "High",
                                "category": "Container/K8s",
                                "description": f"Sensitive Pod Exec/Attach activity detected",
                                "detail": f"User: {user}, URI: {uri}"
                            })
                except Exception:
                    pass

            if "inspect" in name_lower or "docker" in name_lower:
                try:
                    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                    containers = data if isinstance(data, list) else [data]
                    for c in containers:
                        name = c.get("Name", c.get("Id", "unknown"))
                        host_config = c.get("HostConfig", {})
                        privileged = host_config.get("Privileged", False)
                        pid_mode = host_config.get("PidMode", "")
                        network_mode = host_config.get("NetworkMode", "")
                        binds = host_config.get("Binds", []) or []

                        artifacts["container_inspects"].append({
                            "container": name,
                            "privileged": privileged,
                            "pid_mode": pid_mode,
                            "network_mode": network_mode,
                            "binds": binds
                        })

                        if privileged:
                            findings.append({
                                "severity": "High",
                                "category": "Container",
                                "description": f"Privileged container detected: {name}",
                                "detail": "Container runs with full host capabilities (Privileged=true)"
                            })

                        for bind in binds:
                            if bind.startswith("/:") or bind.startswith("/var") or bind.startswith("/etc"):
                                findings.append({
                                "severity": "High",
                                "category": "Container",
                                "description": f"Dangerous host volume mount in container {name}",
                                "detail": f"Mount bind: {bind}"
                            })
                except Exception:
                    pass

        return {
            "parser": "container",
            "artifacts": artifacts,
            "findings": findings
        }
