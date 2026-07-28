<#
.SYNOPSIS
    One-time setup for PII Data Discovery Tool v3.0

.DESCRIPTION
    Installs all Python dependencies and downloads the spaCy NER model
    (en_core_web_lg for highest accuracy, with en_core_web_sm as fallback).
    After this, the tool works 100% offline — no internet required.

.EXAMPLE
    .\setup.ps1
#>

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pythonExe = Join-Path $scriptDir ".venv312\Scripts\python.exe"
$pipExe    = Join-Path $scriptDir ".venv312\Scripts\pip.exe"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   PII DATA DISCOVERY TOOL v3.0 — SETUP" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $pythonExe)) {
    Write-Host "[-] Python not found at: $pythonExe" -ForegroundColor Red
    Write-Host "    Please create a virtual environment first:" -ForegroundColor Yellow
    Write-Host "    python -m venv .venv312" -ForegroundColor Yellow
    Exit 1
}

# Step 1: Install Python packages from requirements.txt
Write-Host "[1/3] Installing Python dependencies from requirements.txt..." -ForegroundColor Yellow
$reqFile = Join-Path $scriptDir "requirements.txt"
& $pipExe install -r "$reqFile"

# Step 2: Download spaCy English NER model (large for highest accuracy)
Write-Host ""
Write-Host "[2/3] Downloading spaCy English NER model (en_core_web_lg)..." -ForegroundColor Yellow
Write-Host "       This is ~400 MB and provides the highest accuracy for NER." -ForegroundColor Gray
& $pythonExe -m spacy download en_core_web_lg

# Step 3: Verify installation
Write-Host ""
Write-Host "[3/3] Verifying installation..." -ForegroundColor Yellow
& $pythonExe -c @"
import spacy
# Try large model first, then small
for model in ('en_core_web_lg', 'en_core_web_sm'):
    try:
        nlp = spacy.load(model)
        print(f'[OK] spaCy NER model loaded: {model}')
        break
    except:
        continue
import openpyxl; print('[OK] openpyxl ready')
import pypdf; print('[OK] pypdf ready')
try:
    from docx import Document; print('[OK] python-docx ready')
except: print('[--] python-docx not available')
try:
    from PIL import Image; print('[OK] Pillow (OCR) ready')
except: print('[--] Pillow not available')
try:
    import pytesseract; print('[OK] pytesseract ready')
except: print('[--] pytesseract not available')
"@

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "   SETUP COMPLETE — Tool is ready for 100% offline use!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Run the scanner:" -ForegroundColor Cyan
Write-Host "  .\run_scanner.ps1" -ForegroundColor White
Write-Host "  .\run_scanner.ps1 -TargetPath 'C:\path\to\folder'" -ForegroundColor White
Write-Host ""
