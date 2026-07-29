"""
Steganography heuristic hint: byte-sample entropy for rich-media containers.
Heuristic only - not a stego extraction tool.
"""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

RICH_MEDIA_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif", ".gif", ".wav", ".mp3", ".flac", ".avi", ".mp4"}

_STEGO_READ_CAP = 524_288  # 512 KiB


def build_stego_hint(path: Path) -> str:
    ext = path.suffix.lower()
    if ext not in RICH_MEDIA_EXTENSIONS:
        return ""
    try:
        data = path.read_bytes()[:_STEGO_READ_CAP]
    except OSError:
        return ""
    if len(data) < 64:
        return ""
    ent = _shannon_entropy(data)
    if ent >= 7.8:
        bucket = "HIGH"
    elif ent >= 6.5:
        bucket = "MODERATE"
    else:
        bucket = "typical"
    return f"stego_hint: entropy={ent:.2f} ({bucket})"


def _shannon_entropy(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
