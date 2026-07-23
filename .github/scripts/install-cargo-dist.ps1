$ErrorActionPreference = "Stop"

$version = $env:DIST_VERSION
if ([string]::IsNullOrWhiteSpace($version)) {
    throw "DIST_VERSION is required"
}
$expectedSha256 = $env:DIST_WINDOWS_X86_64_SHA256
if ([string]::IsNullOrWhiteSpace($expectedSha256)) {
    throw "DIST_WINDOWS_X86_64_SHA256 is required"
}

$archiveName = "cargo-dist-x86_64-pc-windows-msvc.zip"
$temporaryDirectory = Join-Path $env:RUNNER_TEMP ([guid]::NewGuid().ToString("N"))
$archive = Join-Path $temporaryDirectory $archiveName
$extracted = Join-Path $temporaryDirectory "extracted"
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

try {
    $url = "https://github.com/axodotdev/cargo-dist/releases/download/v${version}/${archiveName}"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $archive
    $actualSha256 = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        throw "cargo-dist archive checksum mismatch: $actualSha256"
    }

    Expand-Archive -LiteralPath $archive -DestinationPath $extracted
    $binaries = @(Get-ChildItem -Path $extracted -Filter "dist.exe" -File -Recurse)
    if ($binaries.Count -ne 1) {
        throw "cargo-dist archive must contain exactly one dist.exe"
    }
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME ".cargo" }
    $binDirectory = Join-Path $cargoHome "bin"
    New-Item -ItemType Directory -Path $binDirectory -Force | Out-Null
    $destination = Join-Path $binDirectory "dist.exe"
    Copy-Item -LiteralPath $binaries[0].FullName -Destination $destination -Force
    & $destination --version
    if ($LASTEXITCODE -ne 0) {
        throw "cargo-dist executable verification failed"
    }
    if ($env:GITHUB_PATH) {
        Add-Content -LiteralPath $env:GITHUB_PATH -Value $binDirectory
    }
}
finally {
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
