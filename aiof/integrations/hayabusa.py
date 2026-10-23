from typing import Optional, List
from .base import BaseToolAdapter
from .models import ToolExecutionResult

class HayabusaAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__(tool_id="hayabusa", name="Hayabusa", binary_names=["hayabusa", "hayabusa-lin-x64", "hayabusa.exe"])

    def get_version(self) -> Optional[str]:
        res = self.run_command(["--version"], timeout=10)
        if res.success and res.stdout:
            return res.stdout.strip().split("\n")[0]
        return "unknown"

    def execute(self, evtx_path: str, output_csv: Optional[str] = None, profile: str = "normal") -> ToolExecutionResult:
        args = ["csv-timeline", "-f", evtx_path, "--profile", profile]
        if output_csv:
            args.extend(["-o", output_csv])
        return self.run_command(args, timeout=300)
