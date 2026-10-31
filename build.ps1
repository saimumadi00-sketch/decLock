# Build the executables and, if Inno Setup is installed, the installer.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed; not building." }
python -m PyInstaller --noconfirm --clean gatekeeper.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
$iscc = @("$env:ProgramFiles\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) { & $iscc installer.iss } else { Write-Warning "Inno Setup 6 not found; skipped the installer. Executables are in dist\gatekeeper." }
