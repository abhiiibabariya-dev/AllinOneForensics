from typing import Dict, List, Optional
from .base import BaseToolAdapter
from .models import ToolStatus

class ToolRegistry:
    def __init__(self):
        self._adapters: Dict[str, BaseToolAdapter] = {}

    def register(self, adapter: BaseToolAdapter) -> None:
        self._adapters[adapter.tool_id] = adapter

    def get(self, tool_id: str) -> Optional[BaseToolAdapter]:
        return self._adapters.get(tool_id)

    def list_all(self) -> List[BaseToolAdapter]:
        return list(self._adapters.values())

    def check_health_all(self) -> Dict[str, ToolStatus]:
        statuses = {}
        for tool_id, adapter in self._adapters.items():
            statuses[tool_id] = adapter.check_status()
        return statuses

    def register_defaults(self) -> "ToolRegistry":
        from .hayabusa import HayabusaAdapter
        from .chainsaw import ChainsawAdapter
        from .volatility3 import Volatility3Adapter
        from .yara_adapter import YaraAdapter
        self.register(HayabusaAdapter())
        self.register(ChainsawAdapter())
        self.register(Volatility3Adapter())
        self.register(YaraAdapter())
        return self

registry = ToolRegistry()
