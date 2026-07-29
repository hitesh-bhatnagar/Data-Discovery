"""
MongoDB connector: connect, list collections, sample documents, detect PII.
Install: pip install pymongo
"""
from __future__ import annotations

from typing import Any
from connectors.connector_registry import register

try:
    from pymongo import MongoClient
    HAS_MONGO = True
except ImportError:
    HAS_MONGO = False
    MongoClient = None


class MongoDBConnector:
    def __init__(self, target_config: dict[str, Any], scanner: Any, sample_limit: int = 5):
        self.config = target_config
        self.scanner = scanner
        self.sample_limit = sample_limit
        self._client = None

    def connect(self):
        if not HAS_MONGO:
            raise RuntimeError("pymongo not installed. pip install pymongo")
        host = self.config.get("host", "localhost")
        port = int(self.config.get("port", 27017))
        user = self.config.get("user") or self.config.get("username", "")
        password = self.config.get("pass") or self.config.get("password", "")
        database = self.config.get("database", "test")
        if user and password:
            uri = f"mongodb://{user}:{password}@{host}:{port}/{database}"
        else:
            uri = f"mongodb://{host}:{port}"
        self._client = MongoClient(uri, serverSelectionTimeoutMS=10000)
        self._db = self._client[database]

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def run(self) -> list[dict]:
        findings = []
        target_name = self.config.get("name", "mongodb")
        try:
            self.connect()
        except Exception as e:
            return [{"tag": "CONNECTOR_ERROR", "description": f"MongoDB connection failed: {e}",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        try:
            for coll_name in self._db.list_collection_names():
                sample_docs = list(self._db[coll_name].find().limit(self.sample_limit))
                if not sample_docs:
                    continue
                all_keys = set()
                combined = []
                for doc in sample_docs:
                    for k, v in doc.items():
                        if k.startswith("_"):
                            continue
                        all_keys.add(k)
                        if v is not None:
                            combined.append(f"{k}:{v}")
                text = " ".join(combined)
                for key in all_keys:
                    res = self.scanner.scan_column_text(key, text)
                    if res and res.get("sensitivity_level") and res["sensitivity_level"] != "LOW":
                        findings.append({
                            "tag": res.get("pattern_detected", "PII"),
                            "description": f"MongoDB {coll_name}.{key}",
                            "sensitivity": res["sensitivity_level"],
                            "regulation": res.get("regulation", "DPDP Act 2023"),
                            "raw_value": key,
                            "masked_value": key,
                            "line_number": 0,
                            "context": f"MongoDB: {target_name} | Collection: {coll_name} | Key: {key}",
                            "confidence": res.get("confidence", 80),
                            "detection_method": "MongoDB Connector",
                            "file_name": f"{target_name}/{coll_name}.{key}",
                            "file_path": "", "file_type": "document",
                            "file_size": 0, "last_modified": "", "sha256": "",
                        })
        except Exception as e:
            findings.append({
                "tag": "CONNECTOR_ERROR", "description": f"MongoDB scan failed: {e}",
                "sensitivity": "MEDIUM", "file_name": target_name})
        finally:
            self.close()
        return findings


register("mongodb", MongoDBConnector, ["name", "type"])
