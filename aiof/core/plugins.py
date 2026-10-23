from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional


class PluginManifest:
    def __init__(
        self,
        plugin_id: str,
        name: str,
        version: str,
        author: str,
        description: str,
        entrypoint: str,
        permissions: List[str],
        signature: Optional[str] = None,
        status: str = "pending_approval",  # trusted, untrusted, pending_approval, quarantined
    ):
        self.plugin_id = plugin_id
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.entrypoint = entrypoint
        self.permissions = permissions
        self.signature = signature
        self.status = status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "entrypoint": self.entrypoint,
            "permissions": self.permissions,
            "signature": self.signature,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginManifest":
        return cls(
            plugin_id=data["plugin_id"],
            name=data["name"],
            version=data["version"],
            author=data.get("author", "Unknown"),
            description=data.get("description", ""),
            entrypoint=data["entrypoint"],
            permissions=data.get("permissions", []),
            signature=data.get("signature"),
            status=data.get("status", "pending_approval"),
        )


class PluginTrustManager:
    def __init__(self, registry_dir: Optional[Path] = None):
        self.registry_dir = registry_dir or (Path.home() / ".aiof" / "plugins")
        self.registry_dir.mkdir(parents=True, exist_ok=True)

    def register_plugin(self, manifest: PluginManifest) -> Path:
        path = self.registry_dir / f"{manifest.plugin_id}.json"
        path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
        return path

    def load_plugin(self, plugin_id: str) -> Optional[PluginManifest]:
        path = self.registry_dir / f"{plugin_id}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return PluginManifest.from_dict(data)
        except Exception:
            return None

    def list_plugins(self) -> List[PluginManifest]:
        if not self.registry_dir.exists():
            return []
        plugins = []
        for p in sorted(self.registry_dir.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                plugins.append(PluginManifest.from_dict(data))
            except Exception:
                continue
        return plugins

    def set_status(self, plugin_id: str, status: str) -> bool:
        plugin = self.load_plugin(plugin_id)
        if not plugin:
            return False
        plugin.status = status
        self.register_plugin(plugin)
        return True

    def verify_plugin(self, plugin_id: str) -> bool:
        plugin = self.load_plugin(plugin_id)
        if not plugin:
            return False
        if plugin.status != "trusted":
            return False
        # Verify cryptographic signature if present
        if plugin.signature:
            expected = hashlib.sha256(f"{plugin.plugin_id}:{plugin.version}:{plugin.author}".encode("utf-8")).hexdigest()
            return plugin.signature == expected
        return True


PLUGIN_SDK_TEMPLATE = '''# AllinOneForensics Plugin Developer Template
from __future__ import annotations

from typing import Dict, Any
from aiof.integrations.base import BaseToolAdapter
from aiof.integrations.models import ToolExecutionResult, ToolStatus

class CustomForensicPlugin(BaseToolAdapter):
    @property
    def tool_id(self) -> str:
        return "custom_plugin"

    @property
    def name(self) -> str:
        return "Custom Forensic Plugin"

    def check_status(self) -> ToolStatus:
        return ToolStatus(tool_id=self.tool_id, available=True, version="1.0.0")

    def execute(self, target_path: str, args: Optional[List[str]] = None) -> ToolExecutionResult:
        # Implement custom artifact collection or analysis here
        return ToolExecutionResult(
            tool_id=self.tool_id,
            success=True,
            output=f"Custom plugin executed successfully on {target_path}",
            artifacts_collected=[]
        )
'''
