<#
.SYNOPSIS
    Launcher script for PII Guardian Desktop GUI Application
#>

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pythonExe = Join-Path $scriptDir ".venv312\Scripts\python.exe"
$guiScript = Join-Path $scriptDir "gui_app.py"

if (-not (Test-Path $pythonExe)) {
    Write-Host "[-] Python environment not found at: $pythonExe" -ForegroundColor Red
    Write-Host "    Please run setup.ps1 first." -ForegroundColor Yellow
    Exit 1
}

Write-Host "Launching PII Guardian Desktop Application..." -ForegroundColor Cyan
& $pythonExe "$guiScript"
