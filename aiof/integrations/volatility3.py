from typing import Optional, List
from .base import BaseToolAdapter
from .models import ToolExecutionResult

class Volatility3Adapter(BaseToolAdapter):
    def __init__(self):
        super().__init__(tool_id="volatility3", name="Volatility 3", binary_names=["vol", "vol3", "volatility3"])

    def get_version(self) -> Optional[str]:
        res = self.run_command(["-h"], timeout=10)
        if res.success and res.stdout:
            for line in res.stdout.split("\n"):
                if "Volatility" in line or "Version" in line:
                    return line.strip()
            return "Volatility 3 available"
        return None

    def execute(self, image_path: str, plugin: str) -> ToolExecutionResult:
        args = ["-f", image_path, plugin]
        return self.run_command(args, timeout=300)
