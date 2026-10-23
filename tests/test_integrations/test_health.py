import pytest
from unittest.mock import patch
from aiof.integrations.registry import ToolRegistry
from aiof.integrations.models import ToolStatus
from aiof.integrations.base import BaseToolAdapter

class FakeAdapter(BaseToolAdapter):
    def __init__(self, tool_id, name, version="1.0", error=None):
        super().__init__(tool_id=tool_id, name=name, binary_names=["fakebin"])
        self.fake_version = version
        self.fake_error = error
    def get_version(self):
        if self.fake_error:
            raise RuntimeError(self.fake_error)
        return self.fake_version
    def execute(self, *args, **kwargs):
        raise NotImplementedError

@patch("shutil.which")
def test_check_status_unavailable(mock_which):
    mock_which.return_value = None
    adapter = FakeAdapter("fake_missing", "FakeMissing", error="Binary not found")
    status = adapter.check_status()
    assert status.available is False
    assert status.error is not None
    assert status.version is None

@patch("shutil.which")
def test_check_status_available(mock_which):
    mock_which.return_value = "/usr/bin/fakebin"
    adapter = FakeAdapter("fake_ok", "FakeOk", version="2.3.4")
    status = adapter.check_status()
    assert status.available is True
    assert status.version == "2.3.4"
