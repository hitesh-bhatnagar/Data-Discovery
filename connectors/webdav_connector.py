"""
WebDAV connector: connect to WebDAV share, list files, download to temp, scan for PII.
Install: pip install webdavclient3
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any
from connectors.connector_registry import register

try:
    import webdav3.client as wc
    HAS_WEBDAV = True
except ImportError:
    HAS_WEBDAV = False
    wc = None

SUPPORTED_EXTENSIONS = {".txt",".csv",".tsv",".json",".xml",".yaml",".yml",".log",".sql",
                        ".env",".ini",".conf",".cfg",".md",".html",".htm",".rtf",
                        ".pdf",".docx",".doc",".xlsx",".xls",".pptx"}


class WebDAVConnector:
    def __init__(self, target_config: dict[str, Any], scanner: Any, sample_limit: int = 5):
        self.config = target_config
        self.scanner = scanner

    def run(self) -> list[dict]:
        findings = []
        target_name = self.config.get("name", "WebDAV")
        if not HAS_WEBDAV:
            return [{"tag": "CONNECTOR_ERROR", "description": "webdavclient3 not installed. pip install webdavclient3",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        base_url = self.config.get("url", "").strip()
        if not base_url:
            return [{"tag": "CONNECTOR_ERROR", "description": "WebDAV URL not configured",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        options = {
            "webdav_hostname": base_url,
            "webdav_login": self.config.get("user", ""),
            "webdav_password": self.config.get("pass", self.config.get("password", "")),
        }
        client = wc.Client(options)
        remote_path = self.config.get("path", "/")
        try:
            files = client.list(remote_path, get_info=True)
            for f in files:
                if f.get("isdir"):
                    continue
                name = f.get("name", "")
                ext = Path(name).suffix.lower()
                if ext not in SUPPORTED_EXTENSIONS:
                    continue
                remote_file = remote_path.rstrip("/") + "/" + name.lstrip("/")
                try:
                    content = client.download_resource(remote_file)
                    if isinstance(content, str):
                        content = content.encode("utf-8", errors="replace")
                except Exception:
                    continue
                fd, tmp = tempfile.mkstemp(suffix=ext)
                try:
                    os.write(fd, content); os.close(fd)
                    text, ftype, error, _ = self.scanner.extract_text_wrapper(tmp)
                    if text:
                        file_findings = self.scanner.scan_text(text)
                        for ff in file_findings:
                            ff["file_name"] = name
                            ff["file_path"] = remote_file
                            ff["detection_method"] = "WebDAV Connector"
                            findings.append(ff)
                finally:
                    try: os.unlink(tmp)
                    except Exception: pass
        except Exception as e:
            findings.append({"tag": "CONNECTOR_ERROR", "description": f"WebDAV scan failed: {e}",
                             "sensitivity": "MEDIUM", "file_name": target_name})
        return findings


if HAS_WEBDAV:
    register("webdav", WebDAVConnector, ["name", "url"])
