"""
NFS connector: scan NFS-mounted shares via local mount point.
Requires NFS client mounted on the system.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from connectors.connector_registry import register

SUPPORTED_EXTENSIONS = {".txt",".csv",".tsv",".json",".xml",".yaml",".yml",".log",".sql",
                        ".env",".ini",".conf",".cfg",".md",".html",".htm",".rtf",
                        ".pdf",".docx",".doc",".xlsx",".xls",".pptx"}


class NFSConnector:
    def __init__(self, target_config: dict[str, Any], scanner: Any, sample_limit: int = 5):
        self.config = target_config
        self.scanner = scanner

    def run(self) -> list[dict]:
        findings = []
        target_name = self.config.get("name", "NFS")
        mount_path = self.config.get("path", "").strip()
        if not mount_path:
            return [{"tag": "CONNECTOR_ERROR", "description": "NFS mount path not configured",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        root = Path(mount_path)
        if not root.is_dir():
            return [{"tag": "CONNECTOR_ERROR", "description": f"NFS path not found: {mount_path}",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        try:
            for dirpath, _dirs, files in os.walk(root):
                for fn in files:
                    ext = Path(fn).suffix.lower()
                    if ext not in SUPPORTED_EXTENSIONS:
                        continue
                    fp = Path(dirpath) / fn
                    text, ftype, error, _ = self.scanner.extract_text_wrapper(str(fp))
                    if text:
                        file_findings = self.scanner.scan_text(text)
                        for ff in file_findings:
                            ff["file_name"] = fn
                            ff["file_path"] = str(fp)
                            ff["detection_method"] = "NFS Connector"
                            findings.append(ff)
        except Exception as e:
            findings.append({"tag": "CONNECTOR_ERROR", "description": f"NFS scan failed: {e}",
                             "sensitivity": "MEDIUM", "file_name": target_name})
        return findings


register("nfs", NFSConnector, ["name", "path"])
