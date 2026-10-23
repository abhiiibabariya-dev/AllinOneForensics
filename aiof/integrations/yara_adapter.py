from typing import Optional, List
from .base import BaseToolAdapter
from .models import ToolExecutionResult

class YaraAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__(tool_id="yara", name="YARA", binary_names=["yara", "yarac"])

    def get_version(self) -> Optional[str]:
        res = self.run_command(["--version"], timeout=10)
        if res.success and res.stdout:
            return res.stdout.strip().split("\n")[0]
        return None

    def execute(self, target_path: str, rules_path: str) -> ToolExecutionResult:
        args = ["-r", rules_path, target_path]
        return self.run_command(args, timeout=120)
