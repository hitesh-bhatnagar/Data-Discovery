# PII Guardian v1.0 (India Regulatory Focus)

An enterprise-grade, **100% offline**, ML-enhanced Data Discovery desktop application designed for Indian compliance frameworks (DPDP Act 2023, DPDP Rules 2025, IT Act, RBI, SEBI, IRDAI, etc.).

---

## 🖥️ Desktop Application GUI & Standalone Executable

PII Guardian includes a modern Dark-Mode Desktop Application GUI with live risk dashboards, real-time counters, interactive findings tables, and 1-click Excel audit report launchers.

### Option A: Launch Desktop Application GUI
```powershell
# Launch Desktop GUI Application
.\run_app.ps1
```

### Option B: Standalone Executable (.exe)
Build and run the compiled Windows standalone binary without Python installed:
```powershell
# Build standalone executable (saved under dist/PII_Guardian/PII_Guardian.exe)
python build_exe.py
```

### Option C: Command Line Scanner
```powershell
# Run CLI scan on default test folder
.\run_scanner.ps1

# Run CLI scan on a custom target directory
.\run_scanner.ps1 -TargetPath "C:\path\to\your\documents"
```

---

## 📋 System Prerequisites

Before cloning and running this tool, team members need:

### 1. Software & Runtimes
- **Python**: `3.10`, `3.11`, or `3.12` installed and added to `PATH`.
- **PowerShell**: Version 5.1+ (default on Windows 10/11).
- *(Optional)* **Tesseract OCR**: If scanning text inside scanned PDF images or screenshot files (`.png`, `.jpg`, `.docx` images), install [Tesseract OCR for Windows](https://github.com/UB-Mannheim/tesseract/wiki) and add it to `PATH`.

### 2. System Hardware
- **RAM**: 4 GB minimum (8 GB recommended for spaCy large model processing).
- **Disk Space**: ~1.5 GB free disk space (for virtual environment + spaCy ML models).

---

## 🚀 Quick Start for Team Members

```powershell
# 1. Clone the repository
git clone <REPOSITORY_URL>
cd Data_discovery

# 2. Create Python virtual environment
python -m venv .venv312

# 3. Run automated setup script
.\setup.ps1

# 4. Launch Desktop GUI App
.\run_app.ps1
```

> **Note**: `setup.ps1` downloads the Python packages listed in `requirements.txt` and the `en_core_web_lg` spaCy model (~400 MB). **After setup completes, the tool runs 100% offline.**

---

## 📁 Repository Structure

```
Data_discovery/
├── gui_app.py             # Desktop GUI Application (CustomTkinter)
├── pii_scanner_india.py   # Core PII discovery engine & rules
├── build_exe.py           # PyInstaller build script for standalone .exe
├── run_app.ps1            # GUI App runner script
├── run_scanner.ps1        # CLI wrapper script
├── setup.ps1              # Automated setup script for team members
├── requirements.txt       # Python dependencies
├── pyrightconfig.json     # IDE type checker configuration
├── DOCUMENTATION.md       # Technical architecture & legal framework details
├── test/                  # Sample test documents
└── reports/               # Output directory for audit reports (git-ignored)
```

---

## 🔒 Security & Data Privacy
- **Zero Egress**: No data leaves the machine. All NER models and regex patterns execute locally.
- **Report Hygiene**: Generated Excel audit reports in `reports/` contain sensitive PII findings and are excluded from Git commits via `.gitignore`.
