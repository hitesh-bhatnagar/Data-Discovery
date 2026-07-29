"""
SQL database connector: connect to PostgreSQL, MySQL, MariaDB, SQLite, MSSQL, Oracle.
Discovers schemas/tables/columns, samples values, runs PII detection.
Install driver: pip install sqlalchemy pymysql psycopg2-binary pymssql oracledb
"""
from __future__ import annotations

import datetime
import hashlib
from typing import Any

from connectors.connector_registry import register

try:
    from sqlalchemy import create_engine, inspect, text
    HAS_SQLA = True
except ImportError:
    HAS_SQLA = False

DRIVER_DIALECT_MAP = {
    "postgresql": "postgresql+psycopg2",
    "mysql": "mysql+pymysql",
    "mariadb": "mariadb+pymysql",
    "sqlite": "sqlite",
    "mssql": "mssql+pymssql",
    "oracle": "oracle+oracledb",
}

SKIP_SCHEMAS = frozenset({
    "information_schema", "sys", "pg_catalog", "performance_schema",
    "mysql", "SYS", "SYSTEM", "OUTLN", "DBSNMP", "XDB",
})


class SQLConnector:
    def __init__(self, target_config: dict[str, Any], scanner: Any, sample_limit: int = 5):
        self.config = target_config
        self.scanner = scanner
        self.sample_limit = sample_limit
        self.engine = None

    def _resolve_driver(self) -> str:
        raw = (self.config.get("driver") or "postgresql").strip().lower()
        base = raw.split("+")[0] if "+" in raw else raw
        return DRIVER_DIALECT_MAP.get(base, raw)

    def _build_url(self) -> str:
        drivername = self._resolve_driver()
        if self.config.get("url"):
            return self.config["url"]
        if "sqlite" in drivername:
            return f"sqlite:///{self.config.get('database', 'audit.db')}"
        user = self.config.get("user", "")
        password = self.config.get("pass", self.config.get("password", ""))
        host = self.config.get("host", "localhost")
        port = self.config.get("port", 5432)
        database = self.config.get("database", "")
        return f"{drivername}://{user}:{password}@{host}:{port}/{database}"

    def connect(self):
        if not HAS_SQLA:
            raise RuntimeError("SQLAlchemy not installed. pip install sqlalchemy")
        url = self._build_url()
        self.engine = create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 25})

    def close(self):
        if self.engine:
            self.engine.dispose()
            self.engine = None

    def discover(self) -> list[dict]:
        inspector = inspect(self.engine)
        dialect = self.engine.dialect.name if self.engine else ""
        result = []
        try:
            for schema in inspector.get_schema_names():
                if schema.upper() in SKIP_SCHEMAS or schema.lower() in SKIP_SCHEMAS:
                    continue
                for table in inspector.get_table_names(schema=schema):
                    columns = inspector.get_columns(table, schema=schema)
                    result.append({
                        "schema": schema or "",
                        "table": table,
                        "columns": [{"name": c["name"], "type": str(c["type"])} for c in columns],
                    })
        except Exception:
            pass
        if not result:
            for table in inspector.get_table_names():
                columns = inspector.get_columns(table)
                result.append({
                    "schema": "",
                    "table": table,
                    "columns": [{"name": c["name"], "type": str(c["type"])} for c in columns],
                })
        return result

    def sample_column(self, schema: str, table: str, column: str) -> str:
        dialect = self.engine.dialect.name if self.engine else ""
        safe_col = column.replace('"', '""')
        safe_table = table.replace('"', '""')
        safe_schema = (schema or "").replace('"', '""')
        limit = max(1, min(self.sample_limit, 50))
        if dialect == "mysql":
            query = text(f"SELECT `{safe_col}` FROM `{safe_table}` LIMIT {limit}")
        elif safe_schema:
            query = text(f'SELECT "{safe_col}" FROM "{safe_schema}"."{safe_table}" LIMIT {limit}')
        else:
            query = text(f'SELECT "{safe_col}" FROM "{safe_table}" LIMIT {limit}')
        try:
            with self.engine.connect() as conn:
                rows = conn.execute(query).fetchall()
            return " ".join(str(r[0])[:200] for r in rows if r[0] is not None)
        except Exception:
            return ""

    def run(self) -> list[dict]:
        findings = []
        target_name = self.config.get("name", "database")
        try:
            self.connect()
        except Exception as e:
            return [{"tag": "CONNECTOR_ERROR", "description": f"Connection failed: {e}",
                      "sensitivity": "MEDIUM", "file_name": target_name, "file_path": "",
                      "raw_value": str(e), "masked_value": str(e), "line_number": 0,
                      "context": f"Database: {target_name}", "confidence": 100,
                      "detection_method": "Database Connector", "regulation": "N/A"}]
        try:
            for item in self.discover():
                schema, table = item["schema"], item["table"]
                for col in item["columns"]:
                    sample = self.sample_column(schema, table, col["name"])
                    if not sample:
                        continue
                    loc = f"{schema}.{table}.{col['name']}" if schema else f"{table}.{col['name']}"
                    res = self.scanner.scan_column_text(col["name"], sample)
                    if res and res.get("sensitivity_level") and res["sensitivity_level"] != "LOW":
                        findings.append({
                            "tag": res.get("pattern_detected", "PII"),
                            "description": f"PII in DB column: {loc}",
                            "sensitivity": res["sensitivity_level"],
                            "regulation": res.get("regulation", "DPDP Act 2023"),
                            "raw_value": loc,
                            "masked_value": loc,
                            "line_number": 0,
                            "context": f"Database: {target_name} | Column: {loc} | Type: {col['type']}",
                            "confidence": res.get("confidence", 80),
                            "detection_method": "Database Connector",
                            "file_name": f"{target_name}/{loc}",
                            "file_path": "",
                            "file_type": col["type"],
                            "file_size": 0,
                            "last_modified": "",
                            "sha256": "",
                        })
        except Exception as e:
            findings.append({
                "tag": "CONNECTOR_ERROR", "description": f"Scan failed: {e}",
                "sensitivity": "MEDIUM", "file_name": target_name, "file_path": "",
                "raw_value": str(e), "masked_value": str(e), "line_number": 0,
                "context": f"Database: {target_name}", "confidence": 100,
                "detection_method": "Database Connector", "regulation": "N/A",
            })
        finally:
            self.close()
        return findings


for _t in ("postgresql", "mysql", "mariadb", "sqlite", "mssql", "oracle"):
    register(_t, SQLConnector, ["name", "type"])
