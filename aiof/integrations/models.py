from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class ToolExecutionResult:
    tool_id: str
    tool_name: str
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float = 0.0
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    command_args: List[str] = field(default_factory=list)

@dataclass
class ToolStatus:
    tool_id: str
    name: str
    available: bool
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None
    supported_platforms: List[str] = field(default_factory=list)
