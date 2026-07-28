<#
.SYNOPSIS
    PII Data Discovery Tool v2.0 — Scanner Launcher

.DESCRIPTION
    Runs the India-focused PII discovery scanner on a target folder
    and generates a professional Excel audit report.

.EXAMPLE
    .\run_scanner.ps1
    .\run_scanner.ps1 -TargetPath "C:\Users\Hitesh\Documents"
#>

param (
    [string]$TargetPath = "",
    [string]$OutputDir = ""
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pythonExe = Join-Path $scriptDir ".venv312\Scripts\python.exe"
$scanner   = Join-Path $scriptDir "pii_scanner_india.py"

if (-not (Test-Path $pythonExe)) {
    Write-Host "[-] Python not found. Run setup.ps1 first." -ForegroundColor Red
    Exit 1
}

# Check spaCy model
$nerCheck = & $pythonExe -c "import spacy; spacy.load('en_core_web_sm'); print('OK')" 2>&1
if ($nerCheck -notlike "*OK*") {
    Write-Host "[!] spaCy NER model not found. Running setup..." -ForegroundColor Yellow
    & $pythonExe -m spacy download en_core_web_sm
}

# Build arguments
$cmdArgs = @($scanner)
if ($TargetPath -ne "") {
    if (Test-Path $TargetPath) {
        $cmdArgs += "--target"
        $cmdArgs += $TargetPath
    } else {
        Write-Host "[-] Path not found: $TargetPath" -ForegroundColor Red
        Exit 1
    }
}
if ($OutputDir -ne "") {
    $cmdArgs += "--output"
    $cmdArgs += $OutputDir
}

& $pythonExe @cmdArgs
