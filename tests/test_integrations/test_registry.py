import pytest
from aiof.integrations.registry import ToolRegistry
from aiof.integrations.models import ToolExecutionResult, ToolStatus
from aiof.integrations.base import BaseToolAdapter

class DummyAdapter(BaseToolAdapter):
    def __init__(self, tool_id="dummy"):
        super().__init__(tool_id=tool_id, name="Dummy Tool", binary_names=["dummy-tool"])
    def get_version(self):
        return "1.0.0"
    def execute(self, *args, **kwargs):
        return ToolExecutionResult(
            tool_id=self.tool_id, tool_name=self.name, success=True, exit_code=0, stdout="", stderr="", errors=[]
        )

def test_registry_register_and_get():
    reg = ToolRegistry()
    adapter = DummyAdapter("dummy1")
    reg.register(adapter)
    assert reg.get("dummy1") is adapter
    assert reg.get("missing") is None

def test_tool_status_creation():
    status = ToolStatus(tool_id="x", name="X", available=False)
    assert status.available is False
    assert status.version is None

def test_dummy_execute_returns_success():
    adapter = DummyAdapter("dummy2")
    res = adapter.execute()
    assert res.success is True
