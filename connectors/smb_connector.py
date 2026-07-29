"""
SMB/CIFS connector: connect to Windows/Samba shares, list files, download to temp, scan for PII.
Install: pip install smbprotocol
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any
from connectors.connector_registry import register

try:
    import smbclient
    HAS_SMB = True
except ImportError:
    HAS_SMB = False
    smbclient = None

SUPPORTED_EXTENSIONS = {".txt",".csv",".tsv",".json",".xml",".yaml",".yml",".log",".sql",
                        ".env",".ini",".conf",".cfg",".md",".html",".htm",".rtf",
                        ".pdf",".docx",".doc",".xlsx",".xls",".pptx"}


class SMBConnector:
    def __init__(self, target_config: dict[str, Any], scanner: Any, sample_limit: int = 5):
        self.config = target_config
        self.scanner = scanner
        self.sample_limit = sample_limit

    def _unc_path(self, *parts: str) -> str:
        host = self.config.get("host", "").strip()
        share = (self.config.get("share", "") or "").strip().replace("/", "\\")
        path = "\\".join(p for p in parts if p).replace("/", "\\")
        base = f"\\\\{host}\\{share}"
        return base + "\\" + path.lstrip("\\") if path else base

    def run(self) -> list[dict]:
        findings = []
        target_name = self.config.get("name", "SMB")
        if not HAS_SMB:
            return [{"tag": "CONNECTOR_ERROR", "description": "smbprotocol not installed. pip install smbprotocol",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        host = self.config.get("host", "").strip()
        share = (self.config.get("share", "") or "").strip()
        if not host or not share:
            return [{"tag": "CONNECTOR_ERROR", "description": "Missing host or share", "sensitivity": "MEDIUM", "file_name": target_name}]
        user = self.config.get("user", self.config.get("username", ""))
        password = self.config.get("pass", self.config.get("password", ""))
        domain = self.config.get("domain", "")
        if domain and user and "\\" not in user:
            user = f"{domain}\\{user}"
        port = int(self.config.get("port", 445))
        path_in_share = (self.config.get("path", "") or "").strip().replace("/", "\\").strip("\\")
        try:
            smbclient.register_session(host, username=user, password=password, port=port)
        except Exception as e:
            return [{"tag": "CONNECTOR_ERROR", "description": f"SMB auth failed: {e}", "sensitivity": "MEDIUM", "file_name": target_name}]
        root = self._unc_path(path_in_share) if path_in_share else self._unc_path("")
        try:
            for dirpath, _dirnames, filenames in smbclient.walk(root):
                for filename in filenames:
                    ext = Path(filename).suffix.lower()
                    if ext not in SUPPORTED_EXTENSIONS:
                        continue
                    unc_file = dirpath + "\\" + filename
                    try:
                        with smbclient.open_file(unc_file, mode="rb") as f:
                            content = f.read()
                    except Exception:
                        continue
                    fd, tmp = tempfile.mkstemp(suffix=ext)
                    try:
                        os.write(fd, content); os.close(fd)
                        text, ftype, error, _ = self.scanner.extract_text_wrapper(tmp)
                        if text:
                            file_findings = self.scanner.scan_text(text)
                            for ff in file_findings:
                                ff["file_name"] = filename
                                ff["file_path"] = unc_file
                                ff["detection_method"] = "SMB Connector"
                                findings.append(ff)
                    finally:
                        try: os.unlink(tmp)
                        except Exception: pass
        except Exception as e:
            findings.append({"tag": "CONNECTOR_ERROR", "description": f"SMB scan failed: {e}",
                             "sensitivity": "MEDIUM", "file_name": target_name})
        return findings


if HAS_SMB:
    register("smb", SMBConnector, ["name", "host", "share"])
    register("cifs", SMBConnector, ["name", "host", "share"])
