"""
Heatmap report generator: creates sensitivity/risk heatmap PNG from scan findings.
Uses seaborn for visualisation. Optional - degrades gracefully if matplotlib not installed.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns
    import pandas as pd
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False

_SENSITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def generate_heatmap(findings: list[dict], output_dir: str, session_id: str = "") -> str | None:
    if not HAS_PLOT or not findings:
        return None

    rows = []
    for f in findings:
        rows.append({
            "target": f.get("file_name", "unknown").split("/")[0] if "/" in f.get("file_name", "") else f.get("file_path", "unknown"),
            "source": f.get("detection_method", "Unknown"),
            "sensitivity": f.get("sensitivity", "LOW"),
        })

    df = pd.DataFrame(rows)
    if df.empty:
        return None

    pivot = df.groupby(["target", "sensitivity"]).size().unstack(fill_value=0)
    plt.figure(figsize=(10, 6))
    sns.heatmap(pivot, annot=True, cmap="YlOrRd", fmt="d", cbar_kws={"label": "Findings"})
    plt.title("PII Sensitivity / Risk Heatmap")
    plt.tight_layout()
    plt.subplots_adjust(bottom=0.15)

    footer = "PII Data Discovery Tool v3.0"
    plt.figtext(0.5, 0.02, footer, ha="center", fontsize=7, style="italic")

    sid = session_id[:12] if session_id else "report"
    out_path = Path(output_dir) / f"heatmap_{sid}.png"
    plt.savefig(out_path, bbox_inches="tight", dpi=150)
    plt.close()
    return str(out_path)
