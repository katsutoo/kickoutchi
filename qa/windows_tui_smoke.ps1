param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$TimeoutMilliseconds = 15000
$StreamBytesMax = 4 * 1024 * 1024

foreach ($value in @($Binary, $Config, $Output)) {
    if ($value.Contains('"')) { throw "paths containing quotes are unsupported" }
}
if (Test-Path -LiteralPath $Output) { throw "refusing to overwrite $Output" }
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw "binary must be a regular file" }
$binaryStream = [IO.File]::Open($Binary, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    if ($binaryStream.Length -lt 1) { throw "binary must be nonempty" }
} finally {
    $binaryStream.Dispose()
}
if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) { throw "config must be a regular file" }

$winptyCandidates = @(@(
    (Get-Command winpty.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
    "$env:ProgramFiles\Git\usr\bin\winpty.exe"
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique)
if ($winptyCandidates.Count -lt 1) { throw "winpty.exe is unavailable" }
$winpty = $winptyCandidates[0]

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("kickoutchi-tui-" + [guid]::NewGuid().ToString("N"))
[IO.Directory]::CreateDirectory($temporary) | Out-Null
$stdoutPath = Join-Path $temporary "stdout.bin"
$stderrPath = Join-Path $temporary "stderr.bin"
$command = "(echo q)| `"$winpty`" -Xallow-non-tty `"$Binary`" --config `"$Config`" >`"$stdoutPath`" 2>`"$stderrPath`""
$process = $null
$timedOut = $false
$oversized = $false
try {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = "$env:SystemRoot\System32\cmd.exe"
    $startInfo.Arguments = "/d /s /c `"$command`""
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "failed to start WinPTY smoke" }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not $process.HasExited -and $timer.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt $StreamBytesMax) {
                $oversized = $true
                break
            }
        }
        if ($oversized) { break }
        Start-Sleep -Milliseconds 20
    }
    if (-not $process.HasExited) {
        $timedOut = -not $oversized
        & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F | Out-Null
        $process.WaitForExit()
    }
    $stdout = if (Test-Path -LiteralPath $stdoutPath) { [IO.File]::ReadAllBytes($stdoutPath) } else { [byte[]]@() }
    $stderr = if (Test-Path -LiteralPath $stderrPath) { [IO.File]::ReadAllBytes($stderrPath) } else { [byte[]]@() }
    if ($stdout.Length -gt $StreamBytesMax -or $stderr.Length -gt $StreamBytesMax) { $oversized = $true }
    $text = [Text.Encoding]::UTF8.GetString($stdout)
    $enteredAlternateScreen = $text.Contains("$([char]27)[?1049h")
    $leftAlternateScreen = $text.Contains("$([char]27)[?1049l")
    $passed = $process.ExitCode -eq 0 -and -not $timedOut -and -not $oversized -and $enteredAlternateScreen -and $leftAlternateScreen
    $report = [ordered]@{
        schema = "kickoutchi.windows_tui_smoke"
        version = 1
        status = if ($passed) { "PASS" } else { "FAIL" }
        mechanism = "winpty"
        binary_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Binary).Hash.ToLowerInvariant()
        winpty_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $winpty).Hash.ToLowerInvariant()
        exit_code = $process.ExitCode
        timed_out = $timedOut
        output_oversized = $oversized
        entered_alternate_screen = $enteredAlternateScreen
        left_alternate_screen = $leftAlternateScreen
        stdout_bytes = $stdout.Length
        stderr_bytes = $stderr.Length
        stdout_sha256 = ([BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($stdout))).Replace("-", "").ToLowerInvariant()
        stderr_sha256 = ([BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($stderr))).Replace("-", "").ToLowerInvariant()
    }
    $json = $report | ConvertTo-Json -Depth 4
    $stream = [IO.File]::Open($Output, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $writer = $null
    try {
        $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($false)))
        $writer.WriteLine($json)
        $writer.Flush()
        $stream.Flush($true)
    } finally {
        if ($null -ne $writer) { $writer.Dispose() } else { $stream.Dispose() }
    }
    if (-not $passed) { exit 1 }
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F | Out-Null
    }
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
