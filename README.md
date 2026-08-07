# PII Guardian — Enterprise Data Discovery & Compliance

An enterprise-grade, **100% offline air-gapped**, multi-threaded Data Discovery desktop application designed for Indian compliance frameworks (**DPDP Act 2023, DPDP Rules 2025, IT Act 2000, RBI Master Directions, SEBI CSCRF 2023, IRDAI, PFRDA, TRAI, CERT-In, Aadhaar Act 2016**).

---

## ⚡ Key Performance Features

- ** Multi-Threaded Parallel Scanning**: Automatically scales file parsing across multi-core CPUs for ultra-fast data discovery.
- ** Highly Responsive Executive GUI**: Built with CustomTkinter Dark Mode, featuring incremental card rendering and display capping to eliminate window freezing ("Not Responding") even when handling tens of thousands of PII findings.
- ** Instant Search & Debouncing**: Live search filtering across findings without keystroke latency or UI lag.
- ** 6-Layer Detection Pipeline**:
  1. **Structured Indian PII Regex**: Aadhaar, PAN, Indian Passport, Voter ID, Driving License, GSTIN, IFSC Code, Indian Phone (+91/0), Email, Credit/Debit Cards, UPI VPA, IP Address, PIN Code.
  2. **Checksum Validation**: Verhoeff algorithm for Aadhaar, Luhn algorithm for Credit/Debit Cards.
  3. **ML Named Entity Recognition (NER)**: spaCy `en_core_web_lg` model for Person Names, Organisations, and Locations.
  4. **Column Header Analysis**: Automated schema keyword analysis for Excel (`.xlsx`, `.xls`) and CSV/TSV data sheets.
  5. **Confidence & Context Scoring**: Context-aware precision scoring (0-99%) with legal scope mapping.
  6. **Embedded Image & OCR Detection**: Extracts embedded screenshots and scanned ID images from PDF/DOCX files.
- ** 4-Tab Excel Audit Report**: Automatically exports professional, multi-tab audit reports (`Dashboard`, `Findings`, `File Audit Log`, `Legal Mappings`).

---

## 📦 Quick Download (Pre-built Windows Executable)

No Python installation required! End users can download the pre-compiled standalone release:

1. Go to the **[Releases](../../releases)** page on GitHub.
2. Download **`PII_Guardian_v1.0_Windows_x64.zip`**.
3. Extract the ZIP archive to any folder.
4. Double-click **`PII_Guardian.exe`** to launch the application.

---

## Developer Setup & Running from Source

### Prerequisites
- **Python**: `3.10`, `3.11`, or `3.12` installed and added to `PATH`.
- **PowerShell**: Version 5.1+ (Windows 10/11 default).
- *(Optional)* **Tesseract OCR**: Required if scanning text inside scanned PDF images or screenshots (`.png`, `.jpg`). Install [Tesseract OCR for Windows](https://github.com/UB-Mannheim/tesseract/wiki) and add it to `PATH`.

### Quick Start
```powershell
# 1. Clone the repository
git clone <REPOSITORY_URL>
cd Data_discovery

# 2. Create Python virtual environment
python -m venv .venv312

# 3. Run automated setup script (installs dependencies & spaCy ML model)
.\setup.ps1

# 4. Launch Desktop GUI Application
.\run_app.ps1
```

---

## Building Standalone Executable (.exe)

To package the application into a standalone distribution folder with PyInstaller:

```powershell
# Run the automated build script
.venv312\Scripts\python.exe build_exe.py
```
The compiled output folder will be generated at `dist/PII_Guardian/PII_Guardian.exe`.

---

## CLI Scanner Mode

For headless servers, automated scripts, or terminal workflows:

```powershell
# Run CLI scan on sample test folder
.\run_scanner.ps1

# Run CLI scan on a custom target directory
.\run_scanner.ps1 -TargetPath "C:\path\to\your\documents"
```

---

## Repository Structure

```
Data_discovery/
├── gui_app.py             # Executive Desktop GUI (CustomTkinter)
├── pii_scanner_india.py   # Core PII detection engine & rules
├── build_exe.py           # PyInstaller build script for standalone EXE
├── PII_Guardian.spec      # PyInstaller build specification
├── run_app.ps1            # GUI runner script
├── run_scanner.ps1        # CLI wrapper script
├── setup.ps1              # Automated environment setup script
├── requirements.txt       # Python package dependencies
├── DOCUMENTATION.md       # Technical architecture & regulatory framework details
├── test/                  # Sample test documents & benchmarks
└── reports/               # Output directory for Excel audit reports (git-ignored)
```

---

## Security & Data Privacy

- **100% Air-Gapped Air Privacy**: Zero network calls or external API connections. All NER models, regex patterns, and OCR operations run strictly on the local machine.
- **Report Hygiene**: Generated Excel audit reports in `reports/` contain sensitive masked PII and are automatically ignored by Git (`.gitignore`).
