$ErrorActionPreference = 'Stop'
Set-Location "$PSScriptRoot\analysis-service"

if (-not (Test-Path .venv)) {
  python -m venv .venv
}

$python = Join-Path $PWD '.venv\Scripts\python.exe'
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt
& $python app/ml_api.py
