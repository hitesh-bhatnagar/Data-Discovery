#!/usr/bin/env python3
"""
=================================================================
   PII GUARDIAN v3.0 — Executable Build Script (PyInstaller)
=================================================================
"""

import os
import sys
import shutil
import pathlib
import subprocess

BASE_DIR = pathlib.Path(__file__).parent.resolve()

def build():
    print("================================================================")
    print("   PII GUARDIAN v3.0 — STANDALONE EXECUTABLE BUILD")
    print("================================================================")
    print()

    # Ensure dependencies are available
    gui_script = BASE_DIR / "gui_app.py"
    if not gui_script.exists():
        print(f"[-] Error: {gui_script} not found.")
        sys.exit(1)

    dist_dir = BASE_DIR / "dist"
    build_dir = BASE_DIR / "build"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "-y",
        "--name=PII_Guardian",
        "--noconsole",
        "--onedir",             # Onedir distribution for instant startup
        "--clean",
        "--collect-all=customtkinter",
        "--collect-all=spacy",
        "--collect-all=en_core_web_lg",
        "--collect-all=en_core_web_sm",
        "--collect-all=sklearn",
        "--hidden-import=en_core_web_lg",
        "--hidden-import=en_core_web_sm",
        "--hidden-import=spacy",
        "--hidden-import=sklearn",
        "--hidden-import=sklearn.ensemble",
        "--hidden-import=sklearn.feature_extraction",
        "--hidden-import=sklearn.feature_extraction.text",
        "--hidden-import=sklearn.tree",
        "--hidden-import=seaborn",
        "--hidden-import=matplotlib",
        "--hidden-import=pandas",
        "--hidden-import=openpyxl",
        "--hidden-import=pypdf",
        "--hidden-import=docx",
        "--hidden-import=pptx",
        "--hidden-import=pytesseract",
        "--hidden-import=PIL",
        "--hidden-import=connectors",
        "--hidden-import=connectors.connector_registry",
        "--hidden-import=connectors.sql_connector",
        "--hidden-import=connectors.mongodb_connector",
        "--hidden-import=connectors.redis_connector",
        "--hidden-import=connectors.smb_connector",
        "--hidden-import=connectors.nfs_connector",
        "--hidden-import=connectors.webdav_connector",
        "--hidden-import=connectors.sharepoint_connector",
        "--hidden-import=connectors.archive_scan",
        "--hidden-import=connectors.stego_hint",
        "--hidden-import=utils",
        "--hidden-import=utils.ml_classifier",
        "--hidden-import=utils.content_type",
        "--hidden-import=report",
        "--hidden-import=report.heatmap_generator",
        f"--add-data={BASE_DIR / 'pii_scanner_india.py'};.",
        f"--add-data={BASE_DIR / 'connectors'};connectors/",
        f"--add-data={BASE_DIR / 'utils'};utils/",
        f"--add-data={BASE_DIR / 'report'};report/",
        str(gui_script)
    ]

    print(f"[+] Running PyInstaller build command...")
    print(f"    {' '.join(cmd)}\n")

    try:
        subprocess.run(cmd, check=True, cwd=str(BASE_DIR))
        print()
        print("================================================================")
        print("   BUILD COMPLETE!")
        print("================================================================")
        exe_path = dist_dir / "PII_Guardian" / "PII_Guardian.exe"
        print(f"  [OK] Executable location: {exe_path}")
        print("================================================================")
    except subprocess.CalledProcessError as e:
        print(f"[-] Build failed with exit code: {e.returncode}")
        sys.exit(e.returncode)

if __name__ == "__main__":
    build()
