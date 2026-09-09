from pathlib import Path


class Config:
    def __init__(self):
        self.cases_dir = Path.cwd() / "cases"
        self.online_mode = False
        self.ui_host = "127.0.0.1"
        self.ui_port = 8088

    def ensure_dirs(self):
        self.cases_dir.mkdir(parents=True, exist_ok=True)


DEFAULT_CONFIG = Config()
