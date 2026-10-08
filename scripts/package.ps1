$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    cargo build --release --locked --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Rust release build failed.' }
    $metadata = cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read package version.' }
    $version = ($metadata.packages | Where-Object { $_.name -eq 'ip-scout' }).version
    $destination = Join-Path $projectRoot "dist\IP-Scout-$version"
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Copy-Item -LiteralPath 'target\x86_64-pc-windows-msvc\release\ip-scout.exe' -Destination $destination
    Copy-Item -LiteralPath 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md' -Destination $destination
    Compress-Archive -LiteralPath $destination -DestinationPath "dist\IP-Scout-$version-Windows-x64.zip" -Force
    Get-FileHash -LiteralPath "$destination\ip-scout.exe" -Algorithm SHA256
}
finally { Pop-Location }

