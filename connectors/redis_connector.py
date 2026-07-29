"""
Redis connector: connect, scan keys, detect PII in key names and values.
Install: pip install redis
"""
from __future__ import annotations

from typing import Any
from connectors.connector_registry import register

try:
    import redis as redis_mod
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis_mod = None


class RedisConnector:
    def __init__(self, target_config: dict[str, Any], scanner: Any, sample_limit: int = 100):
        self.config = target_config
        self.scanner = scanner
        self.sample_limit = sample_limit
        self._client = None

    def connect(self):
        if not HAS_REDIS:
            raise RuntimeError("redis not installed. pip install redis")
        self._client = redis_mod.Redis(
            host=self.config.get("host", "localhost"),
            port=int(self.config.get("port", 6379)),
            password=self.config.get("pass") or self.config.get("password") or None,
            decode_responses=True,
            socket_connect_timeout=10,
            socket_timeout=30,
        )

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def run(self) -> list[dict]:
        findings = []
        target_name = self.config.get("name", "redis")
        try:
            self.connect()
        except Exception as e:
            return [{"tag": "CONNECTOR_ERROR", "description": f"Redis connection failed: {e}",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        try:
            keys = []
            for k in self._client.scan_iter(count=self.sample_limit):
                keys.append(k)
                if len(keys) >= self.sample_limit:
                    break
            combined = " ".join(keys)
            for key in keys[:50]:
                res = self.scanner.scan_column_text(key, combined)
                if not res or res.get("sensitivity_level") == "LOW":
                    try:
                        val = self._client.get(key)
                        if val:
                            res = self.scanner.scan_column_text(f"{key}:value", str(val)[:500])
                    except Exception:
                        pass
                if res and res.get("sensitivity_level") and res["sensitivity_level"] != "LOW":
                    findings.append({
                        "tag": res.get("pattern_detected", "PII"),
                        "description": f"Redis key: {key}",
                        "sensitivity": res["sensitivity_level"],
                        "regulation": res.get("regulation", "DPDP Act 2023"),
                        "raw_value": key,
                        "masked_value": key,
                        "line_number": 0,
                        "context": f"Redis: {target_name} | Key: {key}",
                        "confidence": res.get("confidence", 80),
                        "detection_method": "Redis Connector",
                        "file_name": f"{target_name}/keys.{key}",
                        "file_path": "", "file_type": "key",
                        "file_size": 0, "last_modified": "", "sha256": "",
                    })
        except Exception as e:
            findings.append({
                "tag": "CONNECTOR_ERROR", "description": f"Redis scan failed: {e}",
                "sensitivity": "MEDIUM", "file_name": target_name})
        finally:
            self.close()
        return findings


register("redis", RedisConnector, ["name", "type"])
