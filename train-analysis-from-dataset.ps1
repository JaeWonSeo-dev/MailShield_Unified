$ErrorActionPreference = 'Stop'
Set-Location "$PSScriptRoot\analysis-service"

if (Test-Path .venv\Scripts\python.exe) {
  $python = Join-Path $PWD '.venv\Scripts\python.exe'
} else {
  $python = 'python'
}

$datasetRoot = 'C:\Sjw_dev\Coding\PshingMail_Detection\data'

Write-Host "[PhishingMail Detection] profiling external dataset..." -ForegroundColor Cyan
& $python scripts/profile_external_dataset.py --dataset-root $datasetRoot

Write-Host "[PhishingMail Detection] training from external dataset..." -ForegroundColor Cyan
& $python scripts/train_from_external_dataset.py --dataset-root $datasetRoot --skip-preprocess
