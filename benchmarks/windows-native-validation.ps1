param(
    [ValidateSet("qa", "benchmark", "interrupt")]
    [string]$Mode = "qa",
    [string]$Binary = "target\dist\kick.exe",
    [string]$Output = "",
    [string]$InterruptArguments = "",
    [string]$InterruptStdout = "",
    [string]$InterruptStderr = "",
    [int]$InterruptDelayMilliseconds = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ChildTimeoutMilliseconds = 10000
$BuildCommand = "cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick"
$BenchmarkCommand = "watch --address 192.0.2.1 --interval 100ms --duration 500ms --json"

function Quote-NativeArgument {
    param([string]$Value)

    if ($Value.Length -eq 0) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -ne 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -ne 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    $builder.ToString()
}

function Join-NativeArguments {
    param([string[]]$Arguments)

    (($Arguments | ForEach-Object { Quote-NativeArgument $_ }) -join " ")
}

function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [int]$TimeoutMilliseconds = $ChildTimeoutMilliseconds
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = Join-NativeArguments $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $started = [System.Diagnostics.Stopwatch]::GetTimestamp()
    if (-not $process.Start()) {
        throw "failed to start $FilePath"
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutMilliseconds)
    if ($timedOut) {
        $process.Kill()
    }
    $process.WaitForExit()
    $completed = [System.Diagnostics.Stopwatch]::GetTimestamp()
    $status = if ($timedOut) { 124 } else { $process.ExitCode }
    [pscustomobject]@{
        Status = $status
        TimedOut = $timedOut
        Stdout = $stdoutTask.Result
        Stderr = $stderrTask.Result
        LatencyNanoseconds = [int64]((($completed - $started) * 1000000000L) / [System.Diagnostics.Stopwatch]::Frequency)
        UserSeconds = $process.UserProcessorTime.TotalSeconds
        KernelSeconds = $process.PrivilegedProcessorTime.TotalSeconds
        PeakWorkingSetBytes = [int64]$process.PeakWorkingSet64
    }
}

function Start-RedirectedProcess {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$Directory,
        [string]$Name
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = Join-NativeArguments $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "failed to start $FilePath" }
    [pscustomobject]@{
        Process = $process
        StdoutTask = $process.StandardOutput.ReadToEndAsync()
        StderrTask = $process.StandardError.ReadToEndAsync()
    }
}

function Wait-RedirectedProcess {
    param(
        [object]$Running,
        [int]$TimeoutMilliseconds = $ChildTimeoutMilliseconds
    )

    if (-not $Running.Process.WaitForExit($TimeoutMilliseconds)) {
        $Running.Process.Kill()
        $Running.Process.WaitForExit()
        throw "process $($Running.Process.Id) exceeded the timeout"
    }
    $Running.Process.Refresh()
    [pscustomobject]@{
        Status = $Running.Process.ExitCode
        Stdout = $Running.StdoutTask.Result
        Stderr = $Running.StderrTask.Result
    }
}

function Wait-ForReadyLine {
    param(
        [object]$Running,
        [string]$Prefix = "READY ",
        [int]$TimeoutMilliseconds = 5000
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    while ($timer.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        if (Test-Path -LiteralPath $Running.StdoutPath) {
            $text = [IO.File]::ReadAllText($Running.StdoutPath)
            $line = ($text -split "`r?`n" | Where-Object { $_.StartsWith($Prefix) } | Select-Object -First 1)
            if ($null -ne $line) {
                return $line
            }
        }
        if ($Running.Process.HasExited) {
            $errorText = $Running.StderrTask.Result
            throw "helper exited before readiness: $errorText"
        }
        Start-Sleep -Milliseconds 20
    }
    throw "helper did not become ready within $TimeoutMilliseconds ms"
}

function Wait-ForReadyFile {
    param(
        [string]$Path,
        [object]$Running,
        [int]$TimeoutMilliseconds = 5000
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    while ($timer.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        if (Test-Path -LiteralPath $Path) {
            return [IO.File]::ReadAllText($Path)
        }
        if ($Running.Process.HasExited) {
            throw "helper exited before readiness"
        }
        Start-Sleep -Milliseconds 20
    }
    throw "helper did not become ready within $TimeoutMilliseconds ms"
}

function Start-SocketHelper {
    param(
        [ValidateSet("tcp", "udp")]
        [string]$Protocol,
        [ValidateSet("ipv4", "ipv6")]
        [string]$Family,
        [int]$Port,
        [string]$Directory,
        [string]$Name
    )

    $controlPath = Join-Path $Directory "$Name.control"
    $readyPath = Join-Path $Directory "$Name.ready"
    [IO.File]::WriteAllText($controlPath, "running")
    $address = if ($Family -eq "ipv4") { "127.0.0.1" } else { "::1" }
    $escapedControl = $controlPath.Replace("'", "''")
    $escapedReady = $readyPath.Replace("'", "''")
    $script = @"
`$ErrorActionPreference = 'Stop'
`$controlPath = '$escapedControl'
`$address = [Net.IPAddress]::Parse('$address')
`$socket = `$null
try {
    if ('$Protocol' -eq 'tcp') {
        `$socket = New-Object Net.Sockets.TcpListener(`$address, $Port)
        if ('$Family' -eq 'ipv6') { `$socket.Server.DualMode = `$false }
        `$socket.Start()
        `$boundPort = ([Net.IPEndPoint]`$socket.LocalEndpoint).Port
    } else {
        `$addressFamily = if ('$Family' -eq 'ipv4') { [Net.Sockets.AddressFamily]::InterNetwork } else { [Net.Sockets.AddressFamily]::InterNetworkV6 }
        `$socket = New-Object Net.Sockets.UdpClient(`$addressFamily)
        if ('$Family' -eq 'ipv6') { `$socket.Client.DualMode = `$false }
        `$socket.Client.Bind((New-Object Net.IPEndPoint(`$address, $Port)))
        `$boundPort = ([Net.IPEndPoint]`$socket.Client.LocalEndPoint).Port
    }
    [IO.File]::WriteAllText('$escapedReady', `$boundPort.ToString())
    while (Test-Path -LiteralPath `$controlPath) { Start-Sleep -Milliseconds 20 }
} finally {
    if (`$null -ne `$socket) {
        if ('$Protocol' -eq 'tcp') { `$socket.Stop() } else { `$socket.Dispose() }
    }
}
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $running = Start-RedirectedProcess -FilePath "powershell.exe" -Arguments @("-NoProfile", "-NonInteractive", "-EncodedCommand", $encoded) -Directory $Directory -Name $Name
    try {
        $boundPort = [int](Wait-ForReadyFile $readyPath $running)
        [pscustomobject]@{
            Protocol = $Protocol
            Family = $Family
            Address = $address
            Port = $boundPort
            ControlPath = $controlPath
            Running = $running
        }
    } catch {
        Remove-Item -LiteralPath $controlPath -Force -ErrorAction SilentlyContinue
        if (-not $running.Process.HasExited) { $running.Process.Kill() }
        throw
    }
}

function Stop-SocketHelper {
    param([object]$Helper)

    Remove-Item -LiteralPath $Helper.ControlPath -Force -ErrorAction SilentlyContinue
    if (-not $Helper.Running.Process.WaitForExit(5000)) {
        $Helper.Running.Process.Kill()
        $Helper.Running.Process.WaitForExit()
        throw "socket helper $($Helper.Running.Process.Id) did not stop"
    }
    $Helper.Running.Process.Refresh()
    $stderr = $Helper.Running.StderrTask.Result
    if ($Helper.Running.Process.ExitCode -ne 0) {
        throw "socket helper $($Helper.Protocol)/$($Helper.Family)/$($Helper.Port) exited $($Helper.Running.Process.ExitCode): $stderr"
    }
}

function Get-NdjsonRecords {
    param([string]$Text)

    $records = @()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line.Length -eq 0) { continue }
        try {
            $records += ($line | ConvertFrom-Json)
        } catch {
            throw "stdout line is not independent JSON: $line"
        }
    }
    $records
}

function Get-JsonArrayItems {
    param([string]$Text)

    $value = $Text | ConvertFrom-Json
    foreach ($item in $value) { $item }
}

function Get-FreeTcpPort {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Start-PipeHelper {
    param(
        [string]$PipeName,
        [string]$Directory,
        [string]$Name
    )

    $controlPath = Join-Path $Directory "$Name.control"
    $readyPath = Join-Path $Directory "$Name.ready"
    [IO.File]::WriteAllText($controlPath, "running")
    $escapedControl = $controlPath.Replace("'", "''")
    $escapedReady = $readyPath.Replace("'", "''")
    $script = @"
`$ErrorActionPreference = 'Stop'
`$controlPath = '$escapedControl'
`$pipe = New-Object IO.Pipes.NamedPipeServerStream('$PipeName', [IO.Pipes.PipeDirection]::Out, 1, [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::None)
try {
    [IO.File]::WriteAllText('$escapedReady', 'ready')
    `$pipe.WaitForConnection()
    while (Test-Path -LiteralPath `$controlPath) { Start-Sleep -Milliseconds 20 }
} finally {
    `$pipe.Dispose()
}
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $running = Start-RedirectedProcess -FilePath "powershell.exe" -Arguments @("-NoProfile", "-NonInteractive", "-EncodedCommand", $encoded) -Directory $Directory -Name $Name
    try {
        [void](Wait-ForReadyFile $readyPath $running)
        [pscustomobject]@{ ControlPath = $controlPath; Running = $running }
    } catch {
        Remove-Item -LiteralPath $controlPath -Force -ErrorAction SilentlyContinue
        if (-not $running.Process.HasExited) { $running.Process.Kill() }
        throw
    }
}

function Stop-PipeHelper {
    param([object]$Helper)

    Remove-Item -LiteralPath $Helper.ControlPath -Force -ErrorAction SilentlyContinue
    if (-not $Helper.Running.Process.WaitForExit(5000)) {
        $Helper.Running.Process.Kill()
        $Helper.Running.Process.WaitForExit()
        throw "pipe helper did not stop"
    }
}

function Invoke-InterruptCheck {
    param(
        [string]$Kick,
        [string[]]$Arguments,
        [string]$Directory,
        [string]$Name,
        [int]$DelayMilliseconds
    )

    $stdoutPath = Join-Path $Directory "$Name.kick.stdout"
    $stderrPath = Join-Path $Directory "$Name.kick.stderr"
    $result = Invoke-Native -FilePath "powershell.exe" -Arguments @(
        "-NoProfile",
        "-NonInteractive",
        "-File",
        $PSCommandPath,
        "-Mode",
        "interrupt",
        "-Binary",
        $Kick,
        "-InterruptArguments",
        (Join-NativeArguments $Arguments),
        "-InterruptStdout",
        $stdoutPath,
        "-InterruptStderr",
        $stderrPath,
        "-InterruptDelayMilliseconds",
        $DelayMilliseconds.ToString()
    )
    if ($result.Status -ne 0) {
        throw "interrupt helper failed: $($result.Stderr)"
    }
    $childStatus = [int]$result.Stdout.Trim()
    [pscustomobject]@{
        Status = $childStatus
        Stdout = if (Test-Path -LiteralPath $stdoutPath) { [IO.File]::ReadAllText($stdoutPath) } else { "" }
        Stderr = if (Test-Path -LiteralPath $stderrPath) { [IO.File]::ReadAllText($stderrPath) } else { "" }
    }
}

function Get-EnvironmentRecord {
    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    $power = (& powercfg /GETACTIVESCHEME) -join " "
    [ordered]@{
        windows = "$($os.Caption) $($os.Version) build $($os.BuildNumber) $($os.OSArchitecture)"
        cpu = ($cpu.Name -join "; ").Trim()
        logical_cores = [int]$computer.NumberOfLogicalProcessors
        physical_memory_bytes = [uint64]$computer.TotalPhysicalMemory
        power_mode = $power.Trim()
        rust = ((& rustc --version) -join " ").Trim()
        cargo = ((& cargo --version) -join " ").Trim()
        powershell = $PSVersionTable.PSVersion.ToString()
        python = ((& python --version 2>&1) -join " ").Trim()
        elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        antivirus = if ($null -eq $antivirus) { "unavailable" } else { (($antivirus | ForEach-Object { $_.displayName }) -join "; ") }
        background_load = ((Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 12 | ForEach-Object { "$($_.ProcessName):$($_.Id):$($_.WorkingSet64)" }) -join ",")
    }
}

if ($Mode -eq "interrupt" -or $Mode -eq "benchmark") {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class KickoutchiConsoleControl {
    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint CREATE_ALWAYS = 2;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint WAIT_TIMEOUT = 258;
    private const uint CTRL_C_EVENT = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME {
        public uint low;
        public uint high;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_MEMORY_COUNTERS {
        public uint cb;
        public uint PageFaultCount;
        public UIntPtr PeakWorkingSetSize;
        public UIntPtr WorkingSetSize;
        public UIntPtr QuotaPeakPagedPoolUsage;
        public UIntPtr QuotaPagedPoolUsage;
        public UIntPtr QuotaPeakNonPagedPoolUsage;
        public UIntPtr QuotaNonPagedPoolUsage;
        public UIntPtr PagefileUsage;
        public UIntPtr PeakPagefileUsage;
    }

    public sealed class BenchmarkResult {
        public int Status;
        public long LatencyNanoseconds;
        public ulong UserTime100Nanoseconds;
        public ulong KernelTime100Nanoseconds;
        public ulong PeakWorkingSetBytes;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetConsoleCtrlHandler(IntPtr handler, [MarshalAs(UnmanagedType.Bool)] bool add);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GenerateConsoleCtrlEvent(uint controlEvent, uint processGroupId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(IntPtr process, out FILETIME creation, out FILETIME exit, out FILETIME kernel, out FILETIME user);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessMemoryInfo(IntPtr process, ref PROCESS_MEMORY_COUNTERS counters, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private static IntPtr OpenInheritedFile(string path, uint access, uint creation) {
        SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
        security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        security.bInheritHandle = true;
        IntPtr handle = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, ref security, creation, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (handle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return handle;
    }

    private static ulong FileTimeValue(FILETIME value) {
        return ((ulong)value.high << 32) | value.low;
    }

    public static BenchmarkResult RunNull(string executable, string arguments, string currentDirectory, int timeoutMilliseconds) {
        IntPtr stdin = IntPtr.Zero;
        IntPtr output = IntPtr.Zero;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        long started = Stopwatch.GetTimestamp();
        try {
            stdin = OpenInheritedFile("NUL", GENERIC_READ, OPEN_EXISTING);
            output = OpenInheritedFile("NUL", GENERIC_WRITE, OPEN_EXISTING);
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = stdin;
            startup.hStdOutput = output;
            startup.hStdError = output;
            StringBuilder commandLine = new StringBuilder("\"" + executable + "\" " + arguments);
            if (!CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW, IntPtr.Zero, currentDirectory, ref startup, out process)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        } finally {
            if (stdin != IntPtr.Zero) CloseHandle(stdin);
            if (output != IntPtr.Zero) CloseHandle(output);
            if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
        }

        try {
            uint wait = WaitForSingleObject(process.hProcess, unchecked((uint)timeoutMilliseconds));
            int status;
            if (wait == WAIT_TIMEOUT) {
                TerminateProcess(process.hProcess, 124);
                WaitForSingleObject(process.hProcess, 5000);
                status = 124;
            } else if (wait == WAIT_OBJECT_0) {
                uint exitCode;
                if (!GetExitCodeProcess(process.hProcess, out exitCode)) throw new Win32Exception(Marshal.GetLastWin32Error());
                status = unchecked((int)exitCode);
            } else {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            long completed = Stopwatch.GetTimestamp();
            FILETIME creation, exit, kernel, user;
            if (!GetProcessTimes(process.hProcess, out creation, out exit, out kernel, out user)) throw new Win32Exception(Marshal.GetLastWin32Error());
            PROCESS_MEMORY_COUNTERS memory = new PROCESS_MEMORY_COUNTERS();
            memory.cb = unchecked((uint)Marshal.SizeOf(typeof(PROCESS_MEMORY_COUNTERS)));
            if (!GetProcessMemoryInfo(process.hProcess, ref memory, memory.cb)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new BenchmarkResult {
                Status = status,
                LatencyNanoseconds = (long)(((decimal)(completed - started) * 1000000000m) / Stopwatch.Frequency),
                UserTime100Nanoseconds = FileTimeValue(user),
                KernelTime100Nanoseconds = FileTimeValue(kernel),
                PeakWorkingSetBytes = memory.PeakWorkingSetSize.ToUInt64()
            };
        } finally {
            if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
        }
    }

    public static int Run(string executable, string arguments, string stdoutPath, string stderrPath, string currentDirectory, int delayMilliseconds, int timeoutMilliseconds) {
        IntPtr stdin = IntPtr.Zero;
        IntPtr stdout = IntPtr.Zero;
        IntPtr stderr = IntPtr.Zero;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        try {
            stdin = OpenInheritedFile("NUL", GENERIC_READ, OPEN_EXISTING);
            stdout = OpenInheritedFile(stdoutPath, GENERIC_WRITE, CREATE_ALWAYS);
            stderr = OpenInheritedFile(stderrPath, GENERIC_WRITE, CREATE_ALWAYS);
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = stdin;
            startup.hStdOutput = stdout;
            startup.hStdError = stderr;
            StringBuilder commandLine = new StringBuilder("\"" + executable + "\" " + arguments);
            if (!CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true, CREATE_NEW_CONSOLE, IntPtr.Zero, currentDirectory, ref startup, out process)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        } finally {
            if (stdin != IntPtr.Zero) CloseHandle(stdin);
            if (stdout != IntPtr.Zero) CloseHandle(stdout);
            if (stderr != IntPtr.Zero) CloseHandle(stderr);
            if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
        }

        try {
            Thread.Sleep(delayMilliseconds);
            uint early = WaitForSingleObject(process.hProcess, 0);
            if (early == WAIT_OBJECT_0) {
                uint earlyCode;
                if (!GetExitCodeProcess(process.hProcess, out earlyCode)) throw new Win32Exception(Marshal.GetLastWin32Error());
                return unchecked((int)earlyCode);
            }
            FreeConsole();
            if (!AttachConsole(process.dwProcessId)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!SetConsoleCtrlHandler(IntPtr.Zero, true)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
            FreeConsole();
            uint wait = WaitForSingleObject(process.hProcess, unchecked((uint)timeoutMilliseconds));
            if (wait == WAIT_TIMEOUT) {
                TerminateProcess(process.hProcess, 124);
                WaitForSingleObject(process.hProcess, 5000);
                return 124;
            }
            if (wait != WAIT_OBJECT_0) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint exitCode;
            if (!GetExitCodeProcess(process.hProcess, out exitCode)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return unchecked((int)exitCode);
        } finally {
            if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
        }
    }
}
'@
}

if ($Mode -eq "interrupt") {
    $resolvedBinary = (Resolve-Path -LiteralPath $Binary).Path
    $status = [KickoutchiConsoleControl]::Run(
        $resolvedBinary,
        $InterruptArguments,
        $InterruptStdout,
        $InterruptStderr,
        (Get-Location).Path,
        $InterruptDelayMilliseconds,
        $ChildTimeoutMilliseconds
    )
    [Console]::Out.WriteLine($status)
    exit 0
}

function Invoke-Qa {
    param([string]$Kick, [string]$EvidencePath)

    $resolvedKick = (Resolve-Path -LiteralPath $Kick).Path
    if (Test-Path -LiteralPath $EvidencePath) {
        throw "refusing to overwrite $EvidencePath"
    }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ("kickoutchi-windows-qa-" + [Guid]::NewGuid().ToString("N"))
    [void][IO.Directory]::CreateDirectory($temporary)
    $config = Join-Path $temporary "empty.toml"
    [IO.File]::WriteAllBytes($config, [byte[]]@())
    $helpers = New-Object System.Collections.ArrayList
    $cleanupVerified = $false
    try {
        $tcp4 = Start-SocketHelper tcp ipv4 0 $temporary "list-tcp4"
        [void]$helpers.Add($tcp4)
        $udp4 = Start-SocketHelper udp ipv4 0 $temporary "list-udp4"
        [void]$helpers.Add($udp4)

        $ipv6Supported = $true
        try {
            $tcp6 = Start-SocketHelper tcp ipv6 0 $temporary "list-tcp6"
            [void]$helpers.Add($tcp6)
            $udp6 = Start-SocketHelper udp ipv6 0 $temporary "list-udp6"
            [void]$helpers.Add($udp6)
        } catch {
            $ipv6Supported = $false
        }

        $list = Invoke-Native $resolvedKick @("--config", $config, "list", "--json")
        if ($list.Status -ne 0 -or $list.Stderr.Length -ne 0) {
            throw "list failed or wrote diagnostics: $($list.Stderr)"
        }
        $rows = @(Get-JsonArrayItems $list.Stdout)
        $tcp4Visible = @($rows | Where-Object { $_.protocol -eq "tcp" -and $_.local_addr -eq "127.0.0.1" -and $_.local_port -eq $tcp4.Port }).Count -gt 0
        $udp4Visible = @($rows | Where-Object { $_.protocol -eq "udp" -and $_.local_addr -eq "127.0.0.1" -and $_.local_port -eq $udp4.Port }).Count -gt 0
        $tcp6Visible = -not $ipv6Supported -or @($rows | Where-Object { $_.protocol -eq "tcp" -and $_.local_addr -eq "::1" -and $_.local_port -eq $tcp6.Port }).Count -gt 0
        $udp6Visible = -not $ipv6Supported -or @($rows | Where-Object { $_.protocol -eq "udp" -and $_.local_addr -eq "::1" -and $_.local_port -eq $udp6.Port }).Count -gt 0
        if (-not ($tcp4Visible -and $udp4Visible -and $tcp6Visible -and $udp6Visible)) {
            throw "list did not expose every supported helper socket"
        }

        foreach ($helper in @($helpers)) { Stop-SocketHelper $helper }
        $helpers.Clear()

        $eventPort = Get-FreeTcpPort
        $eventWatch = Start-RedirectedProcess $resolvedKick @("--config", $config, "watch", "--tcp", "--address", "127.0.0.1", "--port", $eventPort.ToString(), "--interval", "100ms", "--duration", "1800ms", "--json") $temporary "event-watch"
        Start-Sleep -Milliseconds 350
        $eventHelper = Start-SocketHelper tcp ipv4 $eventPort $temporary "event-helper"
        [void]$helpers.Add($eventHelper)
        Start-Sleep -Milliseconds 500
        Stop-SocketHelper $eventHelper
        $helpers.Remove($eventHelper)
        $eventResult = Wait-RedirectedProcess $eventWatch
        if ($eventResult.Status -ne 0 -or $eventResult.Stderr.Length -ne 0) {
            throw "event watch failed or wrote diagnostics: $($eventResult.Stderr)"
        }
        $eventRecords = @(Get-NdjsonRecords $eventResult.Stdout)
        $bindSeen = @($eventRecords | Where-Object { $_.event -eq "bind" }).Count -gt 0
        $releaseSeen = @($eventRecords | Where-Object { $_.event -eq "release" }).Count -gt 0
        if (-not ($bindSeen -and $releaseSeen)) {
            throw "watch did not report both bind and release"
        }

        $replacementPort = Get-FreeTcpPort
        $replacementA = Start-SocketHelper tcp ipv4 $replacementPort $temporary "replacement-a"
        [void]$helpers.Add($replacementA)
        $replacementWatch = Start-RedirectedProcess $resolvedKick @("--config", $config, "watch", "--tcp", "--address", "127.0.0.1", "--port", $replacementPort.ToString(), "--interval", "500ms", "--duration", "1600ms", "--json") $temporary "replacement-watch"
        Start-Sleep -Milliseconds 180
        Stop-SocketHelper $replacementA
        $helpers.Remove($replacementA)
        $replacementB = Start-SocketHelper tcp ipv4 $replacementPort $temporary "replacement-b"
        [void]$helpers.Add($replacementB)
        $replacementResult = Wait-RedirectedProcess $replacementWatch
        Stop-SocketHelper $replacementB
        $helpers.Remove($replacementB)
        if ($replacementResult.Status -ne 0 -or $replacementResult.Stderr.Length -ne 0) {
            throw "replacement watch failed or wrote diagnostics: $($replacementResult.Stderr)"
        }
        $replacementRecords = @(Get-NdjsonRecords $replacementResult.Stdout)
        $replacementSeen = @($replacementRecords | Where-Object { $_.event -eq "replacement" }).Count -gt 0

        $interruptPort = Get-FreeTcpPort
        $interruptSocket = Start-SocketHelper tcp ipv4 $interruptPort $temporary "interrupt-socket"
        [void]$helpers.Add($interruptSocket)
        $afterBaseline = Invoke-InterruptCheck $resolvedKick @("--config", $config, "watch", "--tcp", "--address", "127.0.0.1", "--port", $interruptPort.ToString(), "--interval", "100ms", "--json") $temporary "interrupt-baseline" 700
        Stop-SocketHelper $interruptSocket
        $helpers.Remove($interruptSocket)
        $afterBaselineRecords = @(Get-NdjsonRecords $afterBaseline.Stdout)
        if ($afterBaseline.Status -ne 0 -or $afterBaseline.Stderr.Length -ne 0 -or $afterBaselineRecords.Count -lt 1) {
            throw "Ctrl-C after baseline did not exit cleanly with valid NDJSON"
        }

        $pipeName = "kickoutchi-validation-" + [Guid]::NewGuid().ToString("N")
        $pipe = Start-PipeHelper $pipeName $temporary "startup-pipe"
        try {
            $duringStartup = Invoke-InterruptCheck $resolvedKick @("--config", "\\.\pipe\$pipeName", "watch", "--json") $temporary "interrupt-startup" 400
        } finally {
            Stop-PipeHelper $pipe
        }
        $duringStartupRecords = @(Get-NdjsonRecords $duringStartup.Stdout)
        if ($duringStartup.Status -ne 0 -or $duringStartup.Stderr.Length -ne 0 -or $duringStartupRecords.Count -ne 0) {
            throw "Ctrl-C during startup did not exit cleanly with empty valid stdout"
        }

        $postList = Invoke-Native $resolvedKick @("--config", $config, "list", "--json")
        if ($postList.Status -ne 0) { throw "cleanup list failed" }
        $postRows = @(Get-JsonArrayItems $postList.Stdout)
        $testedPorts = @($tcp4.Port, $udp4.Port, $eventPort, $replacementPort, $interruptPort)
        if ($ipv6Supported) { $testedPorts += @($tcp6.Port, $udp6.Port) }
        $remainingRows = @($postRows | Where-Object { $testedPorts -contains [int]$_.local_port })
        $remainingHelpers = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { @($helpers | ForEach-Object { $_.Running.Process.Id }) -contains $_.Id })
        $cleanupVerified = $remainingRows.Count -eq 0 -and $remainingHelpers.Count -eq 0
        if (-not $cleanupVerified) { throw "a helper process or socket remained after QA" }

        $record = [ordered]@{
            commit = (& git rev-parse HEAD).Trim()
            artifact = [ordered]@{
                path = $resolvedKick
                sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedKick).Hash
                bytes = (Get-Item -LiteralPath $resolvedKick).Length
            }
            environment = Get-EnvironmentRecord
            list = [ordered]@{
                ipv4_tcp = $tcp4Visible
                ipv4_udp = $udp4Visible
                ipv6_supported = $ipv6Supported
                ipv6_tcp = $tcp6Visible
                ipv6_udp = $udp6Visible
            }
            watch = [ordered]@{
                ndjson_lines = $eventRecords.Count
                every_line_valid_json = $true
                stderr_empty = $true
                bind_seen = $bindSeen
                release_seen = $releaseSeen
                replacement_safely_attempted = $true
                replacement_seen = $replacementSeen
            }
            cancellation = [ordered]@{
                after_baseline_exit = $afterBaseline.Status
                after_baseline_ndjson_lines = $afterBaselineRecords.Count
                during_startup_exit = $duringStartup.Status
                during_startup_ndjson_lines = $duringStartupRecords.Count
                malformed_or_partial_stdout = $false
            }
            cleanup_verified = $cleanupVerified
        }
        $json = $record | ConvertTo-Json -Depth 8
        [IO.File]::WriteAllText($EvidencePath, $json + "`n", (New-Object Text.UTF8Encoding($false)))
        $record
    } finally {
        foreach ($helper in @($helpers)) {
            try { Stop-SocketHelper $helper } catch { if (-not $helper.Running.Process.HasExited) { $helper.Running.Process.Kill() } }
        }
        Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-BenchmarkChild {
    param([string]$Kick, [string[]]$Arguments)

    $result = [KickoutchiConsoleControl]::RunNull(
        $Kick,
        (Join-NativeArguments $Arguments),
        (Get-Location).Path,
        $ChildTimeoutMilliseconds
    )
    [pscustomobject]@{
        status = $result.Status
        latency_ns = $result.LatencyNanoseconds
        user_seconds = $result.UserTime100Nanoseconds / 10000000.0
        kernel_seconds = $result.KernelTime100Nanoseconds / 10000000.0
        peak_working_set_bytes = [int64]$result.PeakWorkingSetBytes
    }
}

function Get-Percentile {
    param([int64[]]$SortedValues, [double]$Percentile)

    $rank = [Math]::Ceiling($Percentile * $SortedValues.Count)
    $index = [Math]::Max(0, [int]$rank - 1)
    $SortedValues[$index]
}

function Get-TrackedDiffHash {
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ("kickoutchi-diff-" + [Guid]::NewGuid().ToString("N"))
    try {
        $diff = ((& git diff --binary HEAD --) -join "`n")
        [IO.File]::WriteAllText($temporary, $diff, (New-Object Text.UTF8Encoding($false)))
        (Get-FileHash -Algorithm SHA256 -LiteralPath $temporary).Hash
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Benchmark {
    param([string]$Kick, [string]$EvidencePath)

    $resolvedKick = (Resolve-Path -LiteralPath $Kick).Path
    if (Test-Path -LiteralPath $EvidencePath) {
        throw "refusing to overwrite $EvidencePath"
    }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ("kickoutchi-windows-benchmark-" + [Guid]::NewGuid().ToString("N"))
    [void][IO.Directory]::CreateDirectory($temporary)
    try {
        $privateKick = Join-Path $temporary "kick.exe"
        Copy-Item -LiteralPath $resolvedKick -Destination $privateKick
        $config = Join-Path $temporary "empty.toml"
        [IO.File]::WriteAllBytes($config, [byte[]]@())
        $arguments = @("--config", $config, "watch", "--address", "192.0.2.1", "--interval", "100ms", "--duration", "500ms", "--json")

        $artifactBefore = Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedKick
        $privateBefore = Get-FileHash -Algorithm SHA256 -LiteralPath $privateKick
        if ($artifactBefore.Hash -ne $privateBefore.Hash) { throw "private artifact hash does not match source artifact" }
        $artifactBytes = (Get-Item -LiteralPath $resolvedKick).Length
        $sourceCommitBefore = (& git rev-parse HEAD).Trim()
        $sourceStatusBefore = ((& git status --porcelain=v1 --untracked-files=all) -join " | ")
        & git diff --quiet HEAD --
        $sourceTrackedDirty = $LASTEXITCODE -ne 0
        $trackedDiffBefore = Get-TrackedDiffHash
        $harnessHashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash

        for ($warmup = 1; $warmup -le 4; $warmup++) {
            $result = Invoke-BenchmarkChild $privateKick $arguments
            if ($result.status -ne 0) { throw "warmup $warmup failed with status $($result.status)" }
        }

        $samples = New-Object System.Collections.ArrayList
        $aggregateUser = 0.0
        $aggregateKernel = 0.0
        for ($sample = 1; $sample -le 100; $sample++) {
            $result = Invoke-BenchmarkChild $privateKick $arguments
            $aggregateUser += $result.user_seconds
            $aggregateKernel += $result.kernel_seconds
            [void]$samples.Add([pscustomobject]@{
                sample = $sample
                latency_ns = $result.latency_ns
                status = $result.status
            })
        }

        $peakSamples = New-Object System.Collections.ArrayList
        for ($sample = 1; $sample -le 20; $sample++) {
            $result = Invoke-BenchmarkChild $privateKick $arguments
            [void]$peakSamples.Add([pscustomobject]@{
                sample = $sample
                peak_working_set_bytes = $result.peak_working_set_bytes
                status = $result.status
            })
        }

        $artifactAfter = Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedKick
        $privateAfter = Get-FileHash -Algorithm SHA256 -LiteralPath $privateKick
        $sourceCommitAfter = (& git rev-parse HEAD).Trim()
        $sourceStatusAfter = ((& git status --porcelain=v1 --untracked-files=all) -join " | ")
        $trackedDiffAfter = Get-TrackedDiffHash
        $harnessHashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash
        if ($artifactBefore.Hash -ne $artifactAfter.Hash -or $privateBefore.Hash -ne $privateAfter.Hash) {
            throw "artifact identity changed during collection"
        }
        if ($sourceCommitBefore -ne $sourceCommitAfter -or $sourceStatusBefore -ne $sourceStatusAfter -or $trackedDiffBefore -ne $trackedDiffAfter -or $harnessHashBefore -ne $harnessHashAfter) {
            throw "source or harness identity changed during collection"
        }

        $latencies = [int64[]]@($samples | ForEach-Object { $_.latency_ns } | Sort-Object)
        $p50 = Get-Percentile $latencies 0.50
        $p95 = Get-Percentile $latencies 0.95
        $p99 = Get-Percentile $latencies 0.99
        $maximum = $latencies[-1]
        $failures = @($samples | Where-Object { $_.status -ne 0 }).Count
        $peakFailures = @($peakSamples | Where-Object { $_.status -ne 0 }).Count
        $peakWorkingSet = [int64](($peakSamples | Measure-Object -Property peak_working_set_bytes -Maximum).Maximum)
        $environment = Get-EnvironmentRecord

        $builder = New-Object Text.StringBuilder
        [void]$builder.AppendLine("# artifact_sha256=$($artifactBefore.Hash)")
        [void]$builder.AppendLine("# artifact_bytes=$artifactBytes")
        [void]$builder.AppendLine("# source_commit=$sourceCommitBefore")
        [void]$builder.AppendLine("# source_tracked_dirty=$sourceTrackedDirty")
        [void]$builder.AppendLine("# source_status=$sourceStatusBefore")
        [void]$builder.AppendLine("# tracked_diff_sha256=$trackedDiffBefore")
        [void]$builder.AppendLine("# harness_sha256=$harnessHashBefore")
        [void]$builder.AppendLine("# build_command=$BuildCommand")
        [void]$builder.AppendLine("# benchmark_command=$BenchmarkCommand")
        [void]$builder.AppendLine("# effective_config=explicit_empty:$config")
        foreach ($key in $environment.Keys) { [void]$builder.AppendLine("# $key=$($environment[$key])") }
        [void]$builder.AppendLine("# warmups=4")
        [void]$builder.AppendLine("# samples=100")
        [void]$builder.AppendLine("# child_timeout_seconds=10")
        [void]$builder.AppendLine("# failures=$failures")
        [void]$builder.AppendLine("# aggregate_child_user_seconds=$($aggregateUser.ToString('F6', [Globalization.CultureInfo]::InvariantCulture))")
        [void]$builder.AppendLine("# aggregate_child_kernel_seconds=$($aggregateKernel.ToString('F6', [Globalization.CultureInfo]::InvariantCulture))")
        [void]$builder.AppendLine("# latency_p50_ns=$p50")
        [void]$builder.AppendLine("# latency_p95_ns=$p95")
        [void]$builder.AppendLine("# latency_p99_ns=$p99")
        [void]$builder.AppendLine("# latency_max_ns=$maximum")
        [void]$builder.AppendLine("# p50_overhead_ns=$($p50 - 500000000L)")
        [void]$builder.AppendLine("# p99_overhead_ns=$($p99 - 500000000L)")
        [void]$builder.AppendLine("# peak_samples=20")
        [void]$builder.AppendLine("# peak_failures=$peakFailures")
        [void]$builder.AppendLine("# peak_working_set_bytes=$peakWorkingSet")
        [void]$builder.AppendLine("sample`tlatency_ns`tstatus")
        foreach ($sample in $samples) { [void]$builder.AppendLine("$($sample.sample)`t$($sample.latency_ns)`t$($sample.status)") }
        [void]$builder.AppendLine("peak_sample`tpeak_working_set_bytes`tstatus")
        foreach ($sample in $peakSamples) { [void]$builder.AppendLine("$($sample.sample)`t$($sample.peak_working_set_bytes)`t$($sample.status)") }
        [IO.File]::WriteAllText($EvidencePath, $builder.ToString(), (New-Object Text.UTF8Encoding($false)))

        [pscustomobject]@{
            p50_ns = $p50
            p95_ns = $p95
            p99_ns = $p99
            max_ns = $maximum
            p50_overhead_ns = $p50 - 500000000L
            p99_overhead_ns = $p99 - 500000000L
            failures = $failures
            aggregate_user_seconds = $aggregateUser
            aggregate_kernel_seconds = $aggregateKernel
            peak_working_set_bytes = $peakWorkingSet
            peak_failures = $peakFailures
            artifact_sha256 = $artifactBefore.Hash
            artifact_bytes = $artifactBytes
        }
    } finally {
        Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($Output.Length -eq 0) {
    $Output = if ($Mode -eq "qa") {
        "benchmarks\windows-native-qa-2026-07-22.json"
    } else {
        "benchmarks\windows-watch-2026-07-22.tsv"
    }
}

if ($Mode -eq "qa") {
    Invoke-Qa $Binary $Output | ConvertTo-Json -Depth 8
} elseif ($Mode -eq "benchmark") {
    Invoke-Benchmark $Binary $Output | Format-List
}
