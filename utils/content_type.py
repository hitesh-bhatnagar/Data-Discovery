"""
Content-type verification via magic bytes.
Detects renamed/mislabeled files by sniffing file signatures.
"""
from __future__ import annotations

from pathlib import Path

_MAGIC: dict[bytes, tuple[str, str]] = {
    b"%PDF": (".pdf", "PDF"),
    b"\x50\x4B\x03\x04": (".zip", "ZIP"),  # also .docx/.xlsx/.pptx
    b"\x50\x4B\x05\x06": (".zip", "ZIP"),
    b"\x50\x4B\x07\x08": (".zip", "ZIP"),
    b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A": (".png", "PNG"),
    b"\xFF\xD8\xFF": (".jpg", "JPEG"),
    b"\x47\x49\x46\x38": (".gif", "GIF"),
    b"\x42\x4D": (".bmp", "BMP"),
    b"\x49\x49\x2A\x00": (".tiff", "TIFF"),
    b"\x4D\x4D\x00\x2A": (".tiff", "TIFF"),
    b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": (".doc", "OLE2"),  # .doc/.xls
    b"\x7B\x5C\x72\x74\x66": (".rtf", "RTF"),
    b"PK\x03\x04": (".zip", "ZIP"),
}

_OFFICE_EXT_MAP = {
    b"word/": ".docx",
    b"xl/": ".xlsx",
    b"ppt/": ".pptx",
}


def sniff_extension(path: Path) -> tuple[str, str] | None:
    try:
        with open(path, "rb") as f:
            header = f.read(32)
    except Exception:
        return None
    for magic, (ext, ftype) in _MAGIC.items():
        if header.startswith(magic):
            if ext == ".zip":
                if len(header) > 30:
                    tail = header[30:]
                    for marker, office_ext in _OFFICE_EXT_MAP.items():
                        if marker in tail:
                            return (office_ext, office_ext[1:].upper())
            return (ext, ftype)
    return None


def choose_effective_extension(path: Path, declared_ext: str) -> str:
    sniffed = sniff_extension(path)
    if sniffed:
        sniffed_ext, _ = sniffed
        if sniffed_ext != declared_ext:
            return sniffed_ext
    return declared_ext
