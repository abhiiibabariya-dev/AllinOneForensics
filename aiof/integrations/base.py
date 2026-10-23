import abc
import subprocess
import shutil
import time
from typing import List, Dict, Any, Optional
from .models import ToolExecutionResult, ToolStatus

class BaseToolAdapter(abc.ABC):
    def __init__(self, tool_id: str, name: str, binary_names: List[str]):
        self.tool_id = tool_id
        self.name = name
        self.binary_names = binary_names

    def get_path(self) -> Optional[str]:
        for binary in self.binary_names:
            path = shutil.which(binary)
            if path:
                return path
        return None

    @abc.abstractmethod
    def get_version(self) -> Optional[str]:
        pass

    def check_status(self) -> ToolStatus:
        path = self.get_path()
        available = path is not None
        version = None
        error = None
        if available:
            try:
                version = self.get_version()
            except Exception as e:
                error = str(e)
        else:
            error = f"Binary not found in PATH: {self.binary_names}"

        return ToolStatus(
            tool_id=self.tool_id,
            name=self.name,
            available=available,
            version=version,
            path=path,
            error=error
        )

    def run_command(self, args: List[str], timeout: int = 120) -> ToolExecutionResult:
        path = self.get_path()
        if not path:
            return ToolExecutionResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Tool {self.name} not available in PATH.",
                errors=[f"Binary missing: {self.binary_names}"],
                command_args=args
            )

        full_args = [path] + args
        start_time = time.time()
        try:
            res = subprocess.run(
                full_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            duration = time.time() - start_time
            success = (res.returncode == 0)
            return ToolExecutionResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                success=success,
                exit_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                duration_seconds=duration,
                command_args=full_args,
                errors=[res.stderr] if res.stderr and not success else []
            )
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ToolExecutionResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                success=False,
                exit_code=-2,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds.",
                duration_seconds=duration,
                command_args=full_args,
                errors=["TimeoutExpired"]
            )
        except Exception as e:
            duration = time.time() - start_time
            return ToolExecutionResult(
                tool_id=self.tool_id,
                tool_name=self.name,
                success=False,
                exit_code=-3,
                stdout="",
                stderr=str(e),
                duration_seconds=duration,
                command_args=full_args,
                errors=[str(e)]
            )

    @abc.abstractmethod
    def execute(self, *args, **kwargs) -> ToolExecutionResult:
        pass
