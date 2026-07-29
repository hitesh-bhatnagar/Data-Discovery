"""
Compressed archive scanning: scan inside zip, tar, tar.gz, 7z archives.
Scans inner members with supported extensions for PII.
"""
from __future__ import annotations

import io
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable

SUPPORTED_INNER_EXTENSIONS = {".txt",".csv",".tsv",".json",".xml",".yaml",".yml",".log",".sql",
                              ".env",".ini",".conf",".cfg",".md",".html",".htm",".rtf",
                              ".pdf",".docx",".doc",".xlsx",".xls",".pptx"}

try:
    import py7zr
    HAS_7Z = True
except ImportError:
    HAS_7Z = False


def detect_archive(path: Path) -> str | None:
    try:
        if zipfile.is_zipfile(path):
            return "zip"
    except Exception:
        pass
    try:
        if tarfile.is_tarfile(path):
            return "tar"
    except Exception:
        pass
    if HAS_7Z:
        try:
            if py7zr.is_7zfile(str(path)):
                return "7z"
        except Exception:
            pass
    return None


def scan_archive(
    archive_path: Path,
    scanner: Any,
    max_member_size: int = 10_000_000,
    on_error: Callable | None = None,
) -> list[dict]:
    findings = []
    atype = detect_archive(archive_path)
    if not atype:
        return findings

    members: list[tuple[str, bytes]] = []

    try:
        if atype == "zip":
            with zipfile.ZipFile(archive_path, "r") as z:
                for name in z.namelist():
                    info = z.getinfo(name)
                    if info.file_size > max_member_size:
                        continue
                    ext = Path(name).suffix.lower()
                    if ext not in SUPPORTED_INNER_EXTENSIONS:
                        continue
                    try:
                        data = z.read(name)
                        members.append((name, data))
                    except Exception:
                        if on_error:
                            on_error(f"zip read error: {name}")
        elif atype == "tar":
            with tarfile.open(archive_path, "r:*") as tar:
                for m in tar:
                    if not m.isfile():
                        continue
                    if m.size > max_member_size:
                        continue
                    ext = Path(m.name).suffix.lower()
                    if ext not in SUPPORTED_INNER_EXTENSIONS:
                        continue
                    try:
                        f = tar.extractfile(m)
                        if f:
                            data = f.read()
                            members.append((m.name, data))
                    except Exception:
                        if on_error:
                            on_error(f"tar read error: {m.name}")
        elif atype == "7z" and HAS_7Z:
            with py7zr.SevenZipFile(archive_path, "r") as sz:
                for name, bio in sz.readall().items():
                    data = bio.read()
                    ext = Path(name).suffix.lower()
                    if ext not in SUPPORTED_INNER_EXTENSIONS:
                        continue
                    if len(data) <= max_member_size:
                        members.append((name, data))
    except Exception as e:
        if on_error:
            on_error(f"archive scan error: {e}")
        return findings

    for member_name, data in members:
        ext = Path(member_name).suffix.lower()
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                tmp.write(data)
                tmp_path = Path(tmp.name)
            text, ftype, error, _ = scanner.extract_text_wrapper(str(tmp_path))
            if text:
                file_findings = scanner.scan_text(text)
                for ff in file_findings:
                    ff["file_name"] = f"{archive_path.name}|{member_name}"
                    ff["file_path"] = str(archive_path)
                    ff["detection_method"] = "Archive Scan"
                    findings.append(ff)
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    return findings
