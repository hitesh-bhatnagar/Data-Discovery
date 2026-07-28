# PII Data Discovery Tool v3.0 (India Regulatory Focus)

An enterprise-grade, **100% offline**, ML-enhanced Data Discovery tool designed for Indian compliance frameworks (DPDP Act 2023, DPDP Rules 2025, IT Act, RBI, SEBI, IRDAI, etc.).

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

### Step 1: Clone the Repository
```powershell
git clone <REPOSITORY_URL>
cd Data_discovery
```

### Step 2: Set up Virtual Environment & Run Setup Script
Open PowerShell in the project directory and run:

```powershell
# 1. Create Python virtual environment
python -m venv .venv312

# 2. Run automated setup script (installs requirements & spaCy NER model)
.\setup.ps1
```

> **Note**: `setup.ps1` downloads the Python packages listed in `requirements.txt` and the `en_core_web_lg` spaCy model (~400 MB). **After setup completes, the tool runs 100% offline.**

---

## 🏃 Running the PII Scanner

Run scans using the included PowerShell runner:

```powershell
# Run scan on default test folder
.\run_scanner.ps1

# Run scan on a custom target directory
.\run_scanner.ps1 -TargetPath "C:\path\to\your\documents"
```

The scan report will be generated as an Excel file under `reports/PII_Discovery_Report.xlsx`.

---

## 📁 Repository Structure

```
Data_discovery/
├── pii_scanner_india.py   # Core PII discovery engine & rules
├── setup.ps1              # Automated setup script for team members
├── run_scanner.ps1        # Execution wrapper script
├── requirements.txt       # Python dependencies
├── pyrightconfig.json     # IDE type checker configuration
├── DOCUMENTATION.md       # Technical architecture & legal framework details
├── .vscode/               # Editor environment settings
├── test/                  # Sample test documents
└── reports/               # Output directory for audit reports (git-ignored)
```

---

## 🔒 Security & Data Privacy
- **Zero Egress**: No data leaves the machine. All NER models and regex patterns execute locally.
- **Report Hygiene**: Generated Excel audit reports in `reports/` contain sensitive PII findings and are excluded from Git commits via `.gitignore`.
