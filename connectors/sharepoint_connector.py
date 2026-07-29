"""
SharePoint connector: connect to SharePoint via Microsoft Graph API or REST, list files, scan for PII.
Install: pip install office365-rest-python-client
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any
from connectors.connector_registry import register

try:
    from office365.sharepoint.client_context import ClientContext
    from office365.runtime.auth.client_credential import ClientCredential
    HAS_SP = True
except ImportError:
    HAS_SP = False
    ClientContext = None

SUPPORTED_EXTENSIONS = {".txt",".csv",".tsv",".json",".xml",".yaml",".yml",".log",".sql",
                        ".env",".ini",".conf",".cfg",".md",".html",".htm",".rtf",
                        ".pdf",".docx",".doc",".xlsx",".xls",".pptx"}


class SharePointConnector:
    def __init__(self, target_config: dict[str, Any], scanner: Any, sample_limit: int = 5):
        self.config = target_config
        self.scanner = scanner

    def run(self) -> list[dict]:
        findings = []
        target_name = self.config.get("name", "SharePoint")
        if not HAS_SP:
            return [{"tag": "CONNECTOR_ERROR", "description": "office365-rest-python-client not installed. pip install office365-rest-python-client",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        site_url = self.config.get("url", "").strip()
        client_id = self.config.get("client_id", "")
        client_secret = self.config.get("client_secret", "")
        if not site_url or not client_id or not client_secret:
            return [{"tag": "CONNECTOR_ERROR", "description": "SharePoint url, client_id, client_secret required",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        try:
            ctx = ClientContext(site_url).with_credentials(ClientCredential(client_id, client_secret))
            web = ctx.web
            ctx.load(web).execute_query()
        except Exception as e:
            return [{"tag": "CONNECTOR_ERROR", "description": f"SharePoint auth failed: {e}",
                      "sensitivity": "MEDIUM", "file_name": target_name}]
        library_name = self.config.get("library", "Documents")
        try:
            library = ctx.web.lists.get_by_title(library_name)
            items = library.items.get().execute_query()
            for item in items:
                name = item.properties.get("FileLeafRef", "")
                ext = Path(name).suffix.lower()
                if ext not in SUPPORTED_EXTENSIONS:
                    continue
                try:
                    file_obj = item.file
                    ctx.load(file_obj).execute_query()
                    binary = file_obj.readbinary().execute_query()
                    content = binary.value if hasattr(binary, 'value') else binary
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
                            ff["file_path"] = f"{site_url}/{library_name}/{name}"
                            ff["detection_method"] = "SharePoint Connector"
                            findings.append(ff)
                finally:
                    try: os.unlink(tmp)
                    except Exception: pass
        except Exception as e:
            findings.append({"tag": "CONNECTOR_ERROR", "description": f"SharePoint scan failed: {e}",
                             "sensitivity": "MEDIUM", "file_name": target_name})
        return findings


if HAS_SP:
    register("sharepoint", SharePointConnector, ["name", "url", "client_id", "client_secret"])
