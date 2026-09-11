from pathlib import Path


class Config:
    def __init__(self):
        self.cases_dir = Path.home() / ".aiof" / "cases"
        self.online_mode = False
        self.ui_host = "127.0.0.1"
        self.ui_port = 8088

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


DEFAULT_CONFIG = Config()
