from typing import Any, Type

_REGISTRY: dict[str, tuple[Type[Any], list[str]]] = {}

def register(connector_type: str, connector_class: Type[Any], required_keys: list[str] | None = None):
    _REGISTRY[connector_type] = (connector_class, required_keys or [])

def get_connector(connector_type: str) -> tuple[Type[Any], list[str]]:
    return _REGISTRY[connector_type]

def list_connector_types() -> list[str]:
    return list(_REGISTRY.keys())

def connector_for_target(target: dict[str, Any]) -> tuple[Type[Any], list[str]] | None:
    t = target.get("type", "")
    if t == "database":
        driver = (target.get("driver") or "").split("+")[0].lower()
        if driver in _REGISTRY:
            return get_connector(driver)
        for alias in ("postgresql", "mysql", "sqlite", "mssql", "oracle", "mongodb", "redis"):
            if alias in driver or driver == alias:
                _try = _REGISTRY.get(alias)
                if _try:
                    return _try
        return None
    return _REGISTRY.get(t)
