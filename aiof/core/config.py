import os
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    def __init__(self):
        self.cases_dir = Path(os.getenv("AIOF_CASES_DIR", str(Path.home() / ".aiof" / "cases"))).expanduser()
        self.online_mode = False
        self.ui_host = "127.0.0.1"
        self.ui_port = 8088
        self.environment = os.getenv("AIOF_ENV", "development").strip().lower()
        self.demo_only = _env_bool("AIOF_DEMO_ONLY", False)
        self.max_request_bytes = int(os.getenv("AIOF_MAX_REQUEST_BYTES", "1048576"))
        self.allowed_origins = tuple(
            origin.strip() for origin in os.getenv("AIOF_ALLOWED_ORIGINS", "").split(",") if origin.strip()
        )
        self.api_token = os.getenv("AIOF_API_TOKEN", "")
        self.require_auth = _env_bool("AIOF_REQUIRE_AUTH", bool(self.api_token))
        self.audit_secret = os.getenv("AIOF_AUDIT_SECRET", "")

    def ensure_dirs(self) -> None:
        self.cases_dir.mkdir(parents=True, exist_ok=True)

    def load(self, path: Path) -> None:
        import json

        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if "cases_dir" in data:
            self.cases_dir = Path(data["cases_dir"]).expanduser()
        if "online_mode" in data:
            self.online_mode = bool(data["online_mode"])
        if "ui_host" in data:
            self.ui_host = str(data["ui_host"])
        if "ui_port" in data:
            self.ui_port = int(data["ui_port"])
        if "demo_only" in data:
            self.demo_only = bool(data["demo_only"])
        if "max_request_bytes" in data:
            self.max_request_bytes = int(data["max_request_bytes"])
        if "allowed_origins" in data:
            self.allowed_origins = tuple(str(item) for item in data["allowed_origins"])
        if "require_auth" in data:
            self.require_auth = bool(data["require_auth"])


DEFAULT_CONFIG = Config()
