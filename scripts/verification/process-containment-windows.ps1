Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8

$source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public sealed class ContainedResult {
    public string status;
    public int? exitCode;
    public string signal;
    public string stdout;
    public string stderr;
    public string error;
}

public static class WindowsContainedProcess {
    const uint CREATE_SUSPENDED = 0x4, CREATE_UNICODE_ENVIRONMENT = 0x400,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000, CREATE_NO_WINDOW = 0x08000000,
        STARTF_USESTDHANDLES = 0x100, HANDLE_FLAG_INHERIT = 0x1,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000, WAIT_OBJECT_0 = 0,
        WAIT_TIMEOUT = 0x102, WAIT_FAILED = 0xffffffff, GENERIC_READ = 0x80000000,
        FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, OPEN_EXISTING = 3;
    const int ERROR_INSUFFICIENT_BUFFER = 122;
    const int JobObjectBasicAccountingInformation = 1;
    const int JobObjectExtendedLimitInformation = 9;
    static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_JOB_LIST = new IntPtr(0x0002000D);

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
        public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information, uint informationLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryInformationJobObject(IntPtr job, int informationClass, out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information, uint informationLength, IntPtr returnLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe, ref SECURITY_ATTRIBUTES attributes, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode, ref SECURITY_ATTRIBUTES attributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll")]
    static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION processInformation);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    sealed class OutputBudget {
        readonly object gate = new object();
        readonly MemoryStream standardOutput = new MemoryStream(), standardError = new MemoryStream();
        int remaining;
        public OutputBudget(int maximum) { remaining = maximum; }
        public void Add(bool isError, byte[] bytes, int count) {
            lock (gate) {
                int retained = Math.Min(count, remaining);
                if (retained > 0) {
                    (isError ? standardError : standardOutput).Write(bytes, 0, retained);
                    remaining -= retained;
                }
            }
        }
        public string Text(bool isError) {
            byte[] bytes;
            lock (gate) { bytes = (isError ? standardError : standardOutput).ToArray(); }
            string value = Encoding.UTF8.GetString(bytes);
            while (Encoding.UTF8.GetByteCount(value) > bytes.Length && value.Length > 0)
                value = value.Substring(0, value.Length - 1);
            return value;
        }
    }

    static Task ReadPipeAsync(IntPtr handle, OutputBudget output, bool isError) {
        return Task.Factory.StartNew(
            delegate {
                using (SafeFileHandle safeHandle = new SafeFileHandle(handle, true))
                using (FileStream stream = new FileStream(safeHandle, FileAccess.Read, 4096, false)) {
                    byte[] buffer = new byte[8192];
                    while (true) {
                        int count = stream.Read(buffer, 0, buffer.Length);
                        if (count == 0) break;
                        output.Add(isError, buffer, count);
                    }
                }
            },
            TaskCreationOptions.LongRunning
        );
    }
    static string Win32Error(string operation) {
        return operation + ": " + new Win32Exception(Marshal.GetLastWin32Error()).Message;
    }
    static void CloseIfValid(ref IntPtr handle) {
        if (handle != IntPtr.Zero && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        handle = IntPtr.Zero;
    }
    static void CloseOrThrow(ref IntPtr handle, string operation) {
        if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE) {
            handle = IntPtr.Zero;
            return;
        }
        IntPtr current = handle;
        if (!CloseHandle(current)) throw new InvalidOperationException(Win32Error(operation));
        handle = IntPtr.Zero;
    }
    static void TryClose(ref IntPtr handle, string operation, List<string> failures) {
        if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE) {
            handle = IntPtr.Zero;
            return;
        }
        IntPtr current = handle;
        if (!CloseHandle(current)) {
            failures.Add(Win32Error(operation));
            return;
        }
        handle = IntPtr.Zero;
    }
    static void CreateOutputPipe(out IntPtr readHandle, out IntPtr writeHandle, ref SECURITY_ATTRIBUTES attributes) {
        readHandle = IntPtr.Zero;
        writeHandle = IntPtr.Zero;
        if (!CreatePipe(out readHandle, out writeHandle, ref attributes, 0))
            throw new InvalidOperationException(Win32Error("CreatePipe"));
        if (SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0)) return;
        string error = Win32Error("SetHandleInformation");
        List<string> cleanupFailures = new List<string>();
        TryClose(ref readHandle, "Close pipe read after SetHandleInformation failure", cleanupFailures);
        TryClose(ref writeHandle, "Close pipe write after SetHandleInformation failure", cleanupFailures);
        if (cleanupFailures.Count > 0)
            error += "; cleanup: " + String.Join("; ", cleanupFailures.ToArray());
        throw new InvalidOperationException(error);
    }
    static string QuoteArgument(string argument) {
        if (argument.Length == 0) return "\"\"";
        bool quote = false;
        foreach (char character in argument)
            if (Char.IsWhiteSpace(character) || character == '"') { quote = true; break; }
        if (!quote) return argument;
        StringBuilder result = new StringBuilder(); result.Append('"');
        int slashes = 0;
        foreach (char character in argument) {
            if (character == '\\') { slashes++; continue; }
            if (character == '"') {
                result.Append('\\', slashes * 2 + 1); result.Append('"'); slashes = 0; continue;
            }
            result.Append('\\', slashes); slashes = 0; result.Append(character);
        }
        result.Append('\\', slashes * 2); result.Append('"'); return result.ToString();
    }
    static StringBuilder BuildCommandLine(string executable, string[] arguments) {
        StringBuilder command = new StringBuilder(QuoteArgument(executable));
        foreach (string argument in arguments) { command.Append(' '); command.Append(QuoteArgument(argument)); }
        return command;
    }
    static IntPtr BuildEnvironment(IDictionary<string, string> environment) {
        List<string> names = new List<string>(environment.Keys);
        names.Sort(StringComparer.OrdinalIgnoreCase);
        StringBuilder block = new StringBuilder();
        foreach (string name in names) {
            block.Append(name); block.Append('='); block.Append(environment[name]); block.Append('\0');
        }
        block.Append('\0');
        return Marshal.StringToHGlobalUni(block.ToString());
    }
    static ContainedResult Result(string status, int? exitCode, string stdout, string stderr, string error) {
        return new ContainedResult { status = status, exitCode = exitCode, signal = null, stdout = stdout ?? "", stderr = stderr ?? "", error = error };
    }
    static void WaitForJobEmpty(IntPtr job, int timeoutMs) {
        Stopwatch stopwatch = Stopwatch.StartNew();
        while (true) {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
            if (!QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                out accounting,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)),
                IntPtr.Zero))
                throw new InvalidOperationException(Win32Error("QueryInformationJobObject"));
            if (accounting.ActiveProcesses == 0) return;
            if (stopwatch.ElapsedMilliseconds >= timeoutMs)
                throw new TimeoutException("Job cleanup did not reach zero active processes");
            Thread.Sleep(10);
        }
    }
    static void WriteHandleArray(IntPtr destination, IntPtr[] handles) {
        for (int index = 0; index < handles.Length; index++)
            Marshal.WriteIntPtr(destination, index * IntPtr.Size, handles[index]);
    }

    public static ContainedResult Run(string executable, string[] arguments, string cwd, IDictionary<string, string> environment, int timeoutMs, int maxOutputBytes) {
        IntPtr stdoutRead = IntPtr.Zero, stdoutWrite = IntPtr.Zero;
        IntPtr stderrRead = IntPtr.Zero, stderrWrite = IntPtr.Zero;
        IntPtr nullInput = IntPtr.Zero, environmentBlock = IntPtr.Zero, job = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero, handleList = IntPtr.Zero, jobList = IntPtr.Zero;
        bool attributeListInitialized = false;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        Task stdoutTask = null, stderrTask = null;
        OutputBudget output = new OutputBudget(maxOutputBytes);
        bool processStarted = false;
        Timer helperFailsafe = new Timer(
            delegate(object state) {
                Environment.FailFast("Windows containment helper exceeded its native failsafe");
            },
            null,
            checked(timeoutMs + 12000),
            Timeout.Infinite
        );
        try {
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES {
                nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
                lpSecurityDescriptor = IntPtr.Zero, bInheritHandle = true
            };
            CreateOutputPipe(out stdoutRead, out stdoutWrite, ref attributes);
            CreateOutputPipe(out stderrRead, out stderrWrite, ref attributes);
            nullInput = CreateFileW("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, ref attributes, OPEN_EXISTING, 0, IntPtr.Zero);
            if (nullInput == INVALID_HANDLE_VALUE)
                throw new InvalidOperationException(Win32Error("Open NUL stdin"));

            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
                throw new InvalidOperationException(Win32Error("CreateJobObjectW"));
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                ref limits,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
                throw new InvalidOperationException(Win32Error("SetInformationJobObject"));

            IntPtr attributeListSize = IntPtr.Zero;
            bool sizedAttributeList =
                InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref attributeListSize);
            int attributeSizingError = Marshal.GetLastWin32Error();
            if (
                sizedAttributeList ||
                attributeListSize == IntPtr.Zero ||
                attributeSizingError != ERROR_INSUFFICIENT_BUFFER)
                throw new InvalidOperationException(
                    "Size STARTUPINFOEX attribute list: unexpected Win32 result " +
                    attributeSizingError);
            attributeList = Marshal.AllocHGlobal(attributeListSize);
            if (!InitializeProcThreadAttributeList(attributeList, 2, 0, ref attributeListSize))
                throw new InvalidOperationException(Win32Error("InitializeProcThreadAttributeList"));
            attributeListInitialized = true;

            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            WriteHandleArray(handleList, new IntPtr[] { nullInput, stdoutWrite, stderrWrite });
            if (!UpdateProcThreadAttribute(
                attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleList,
                new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero))
                throw new InvalidOperationException(Win32Error("UpdateProcThreadAttribute handle list"));

            jobList = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(jobList, job);
            if (!UpdateProcThreadAttribute(
                attributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, jobList,
                new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                throw new InvalidOperationException(Win32Error("UpdateProcThreadAttribute job list"));

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = nullInput;
            startup.StartupInfo.hStdOutput = stdoutWrite;
            startup.StartupInfo.hStdError = stderrWrite;
            startup.lpAttributeList = attributeList;
            environmentBlock = BuildEnvironment(environment);
            StringBuilder commandLine = BuildCommandLine(executable, arguments);
            if (!CreateProcessW(
                executable,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                environmentBlock,
                cwd,
                ref startup,
                out process)) {
                string spawnError = Win32Error("CreateProcessW");
                CloseOrThrow(ref stdoutRead, "Close stdout read after spawn failure");
                CloseOrThrow(ref stdoutWrite, "Close stdout write after spawn failure");
                CloseOrThrow(ref stderrRead, "Close stderr read after spawn failure");
                CloseOrThrow(ref stderrWrite, "Close stderr write after spawn failure");
                CloseOrThrow(ref nullInput, "Close stdin after spawn failure");
                CloseOrThrow(ref job, "Close job after spawn failure");
                return Result("spawn-failed", null, "", "", spawnError);
            }
            processStarted = true;

            CloseOrThrow(ref stdoutWrite, "Close parent stdout write");
            CloseOrThrow(ref stderrWrite, "Close parent stderr write");
            CloseOrThrow(ref nullInput, "Close parent stdin");
            stdoutTask = ReadPipeAsync(stdoutRead, output, false); stdoutRead = IntPtr.Zero;
            stderrTask = ReadPipeAsync(stderrRead, output, true); stderrRead = IntPtr.Zero;

            if (ResumeThread(process.hThread) == 0xffffffff)
                throw new InvalidOperationException(Win32Error("ResumeThread"));
            CloseOrThrow(ref process.hThread, "Close primary thread");

            uint waitResult = WaitForSingleObject(process.hProcess, (uint)timeoutMs);
            string status;
            int? exitCode = null;
            if (waitResult == WAIT_TIMEOUT) {
                status = "timed-out";
            } else if (waitResult == WAIT_OBJECT_0) {
                status = "exited";
                uint nativeExitCode;
                if (!GetExitCodeProcess(process.hProcess, out nativeExitCode))
                    throw new InvalidOperationException(Win32Error("GetExitCodeProcess"));
                exitCode = unchecked((int)nativeExitCode);
            } else if (waitResult == WAIT_FAILED) {
                throw new InvalidOperationException(Win32Error("WaitForSingleObject"));
            } else {
                throw new InvalidOperationException("WaitForSingleObject returned unexpected value " + waitResult);
            }

            if (!TerminateJobObject(job, status == "timed-out" ? 124u : 0u))
                throw new InvalidOperationException(Win32Error("TerminateJobObject"));
            WaitForJobEmpty(job, 5000);
            Task.WaitAll(stdoutTask, stderrTask);
            CloseOrThrow(ref process.hProcess, "Close primary process");
            CloseOrThrow(ref job, "Close empty job");
            return Result(status, status == "exited" ? exitCode : null, output.Text(false), output.Text(true), null);
        } catch (Exception error) {
            List<string> cleanupFailures = new List<string>();
            if (processStarted) {
                if (job != IntPtr.Zero) {
                    if (!TerminateJobObject(job, 125))
                        cleanupFailures.Add(Win32Error("Cleanup TerminateJobObject"));
                    try { WaitForJobEmpty(job, 5000); }
                    catch (Exception cleanupError) { cleanupFailures.Add(cleanupError.GetBaseException().Message); }
                } else {
                    if (!TerminateProcess(process.hProcess, 125))
                        cleanupFailures.Add(Win32Error("Cleanup TerminateProcess"));
                    uint processWait = WaitForSingleObject(process.hProcess, 5000);
                    if (processWait == WAIT_FAILED)
                        cleanupFailures.Add(Win32Error("Cleanup process wait"));
                    else if (processWait != WAIT_OBJECT_0)
                        cleanupFailures.Add("Cleanup process wait did not signal");
                }
            }
            TryClose(ref stdoutRead, "Cleanup stdout read", cleanupFailures);
            TryClose(ref stdoutWrite, "Cleanup stdout write", cleanupFailures);
            TryClose(ref stderrRead, "Cleanup stderr read", cleanupFailures);
            TryClose(ref stderrWrite, "Cleanup stderr write", cleanupFailures);
            TryClose(ref nullInput, "Cleanup stdin", cleanupFailures);
            TryClose(ref process.hThread, "Cleanup primary thread", cleanupFailures);
            try {
                if (stdoutTask != null && stderrTask != null) Task.WaitAll(stdoutTask, stderrTask);
            } catch (Exception cleanupError) {
                cleanupFailures.Add(cleanupError.GetBaseException().Message);
            }
            TryClose(ref process.hProcess, "Cleanup primary process", cleanupFailures);
            TryClose(ref job, "Cleanup job", cleanupFailures);
            string message = error.GetBaseException().Message;
            if (cleanupFailures.Count > 0)
                message += "; cleanup: " + String.Join("; ", cleanupFailures.ToArray());
            return Result("containment-unavailable", null, output.Text(false), output.Text(true), message);
        } finally {
            helperFailsafe.Dispose();
            if (attributeListInitialized) DeleteProcThreadAttributeList(attributeList);
            if (attributeList != IntPtr.Zero) Marshal.FreeHGlobal(attributeList);
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
            if (jobList != IntPtr.Zero) Marshal.FreeHGlobal(jobList);
            if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
            CloseIfValid(ref stdoutRead); CloseIfValid(ref stdoutWrite);
            CloseIfValid(ref stderrRead); CloseIfValid(ref stderrWrite);
            CloseIfValid(ref nullInput); CloseIfValid(ref process.hThread);
            CloseIfValid(ref process.hProcess); CloseIfValid(ref job);
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $source
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $environment = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::Ordinal)
    foreach ($property in $request.env.PSObject.Properties) {
        $environment.Add([string]$property.Name, [string]$property.Value)
    }
    $result = [WindowsContainedProcess]::Run(
        [string]$request.executable,
        [string[]]@($request.args),
        [string]$request.cwd,
        $environment,
        [int]$request.timeoutMs,
        [int]$request.maxOutputBytes
    )
    $result | ConvertTo-Json -Compress -Depth 4
} catch {
    [pscustomobject]@{
        status = "containment-unavailable"
        exitCode = $null
        signal = $null
        stdout = ""
        stderr = ""
        error = [string]$_.Exception.Message
    } | ConvertTo-Json -Compress
}
