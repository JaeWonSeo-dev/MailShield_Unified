$ErrorActionPreference = 'Stop'
Set-Location "$PSScriptRoot\analysis-service"

if (Test-Path .venv\Scripts\python.exe) {
  $python = Join-Path $PWD '.venv\Scripts\python.exe'
} else {
  $python = 'python'
}

& $python -m unittest discover -s tests -p "test_*.py"
