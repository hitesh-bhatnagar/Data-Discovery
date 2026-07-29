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
        "--hidden-import=en_core_web_lg",
        "--hidden-import=en_core_web_sm",
        "--hidden-import=spacy",
        f"--add-data={BASE_DIR / 'pii_scanner_india.py'};.",
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
