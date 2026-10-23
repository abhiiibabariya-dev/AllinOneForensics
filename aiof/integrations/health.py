from typing import Dict, Any
from .registry import registry

def get_system_health() -> Dict[str, Any]:
    statuses = registry.check_health_all()
    summary = {
        "total_tools": len(statuses),
        "available_tools": sum(1 for s in statuses.values() if s.available),
        "unavailable_tools": sum(1 for s in statuses.values() if not s.available),
        "tools": {tid: {"name": s.name, "available": s.available, "version": s.version, "path": s.path, "error": s.error} for tid, s in statuses.items()}
    }
    return summary
