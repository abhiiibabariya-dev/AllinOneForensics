from typing import Optional, List
from .base import BaseToolAdapter
from .models import ToolExecutionResult

class ChainsawAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__(tool_id="chainsaw", name="Chainsaw", binary_names=["chainsaw", "chainsaw-x64"])

    def get_version(self) -> Optional[str]:
        res = self.run_command(["--version"], timeout=10)
        if res.success and res.stdout:
            return res.stdout.strip().split("\n")[0]
        return "unknown"

    def execute(self, evtx_path: str, mapping_file: str, sigma_rules_dir: str) -> ToolExecutionResult:
        args = ["hunt", evtx_path, "-m", mapping_file, "-s", sigma_rules_dir, "--json"]
        return self.run_command(args, timeout=300)
