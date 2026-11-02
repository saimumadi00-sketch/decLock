# Build the executables and, if Inno Setup is installed, the installer.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
# Exact, hash-checked versions only: a tampered or unexpected package version can't slip into the build.
python -m pip install --require-hashes -r requirements.lock
if ($LASTEXITCODE -ne 0) { throw "Installing the pinned dependencies failed." }
python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed; not building." }
python -m PyInstaller --noconfirm --clean gatekeeper.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
$iscc = @("$env:ProgramFiles\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) { & $iscc installer.iss } else { Write-Warning "Inno Setup 6 not found; skipped the installer. Executables are in dist\gatekeeper." }
