# Parent-owned reviewer lifetime only. Process observations never confer review
# approval or permission to remove inputs before the complete job has drained.

function Initialize-CrgPairedProcessNative {
  if ('CrgPairedProcess.NativeV2' -as [type]) { return }
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'paired review process ownership requires Windows' }
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace CrgPairedProcess {
  public static class NativeV2 {
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint WAIT_TIMEOUT = 0x00000102;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
      public int cb;
      public string lpReserved, lpDesktop, lpTitle;
      public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
      public int dwFillAttribute, dwFlags;
      public short wShowWindow, cbReserved2;
      public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX {
      public STARTUPINFO StartupInfo;
      public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
      public IntPtr hProcess, hThread;
      public uint dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
      public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
      public uint LimitFlags;
      public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
      public uint ActiveProcessLimit;
      public UIntPtr Affinity;
      public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS {
      public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
      public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
      public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
      public IO_COUNTERS IoInfo;
      public UIntPtr ProcessMemoryLimit, JobMemoryLimit;
      public UIntPtr PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
      public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
      public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine,
      IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
      IntPtr environment, string currentDirectory, ref STARTUPINFOEX startupInfo,
      out PROCESS_INFORMATION processInformation);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList,
      int attributeCount, uint flags, ref UIntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags,
      UIntPtr attribute, IntPtr value, UIntPtr size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass,
      ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information, uint informationLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(IntPtr job, int informationClass,
      out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information, uint informationLength, IntPtr returnLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int standardHandle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode,
      IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle,
      IntPtr targetProcess, out IntPtr targetHandle, uint desiredAccess, bool inheritHandle, uint options);

    public sealed class ProcessObservation {
      public uint ProcessId { get; internal set; }
      public bool ProcessCreated { get; internal set; }
      public bool ExitObserved { get; internal set; }
      public int? ExitCode { get; internal set; }
      public uint? ActiveProcesses { get; internal set; }
      public bool Quiescent { get; internal set; }
      public bool Closed { get; internal set; }
      public bool TerminationRequested { get; internal set; }
      public string Error { get; internal set; }
    }

    public sealed class ProcessSession {
      private readonly object sync = new object();
      private IntPtr processHandle, jobHandle;
      private uint processId;
      private bool assigned, exitObserved, quiescent, terminationRequested;
      private int? exitCode;

      internal ProcessSession(IntPtr job) {
        jobHandle = job;
      }

      public uint ProcessId { get { return processId; } }

      internal IntPtr CreateSuspended(string application, StringBuilder command, string directory,
          IntPtr environment, IntPtr standardInput, IntPtr standardOutput, IntPtr standardError) {
        STARTUPINFOEX startup = new STARTUPINFOEX();
        startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
        startup.StartupInfo.dwFlags = 0x00000100;
        startup.StartupInfo.hStdInput = standardInput;
        startup.StartupInfo.hStdOutput = standardOutput;
        startup.StartupInfo.hStdError = standardError;
        IntPtr handleList = IntPtr.Zero;
        bool attributesInitialized = false;
        try {
          // Concurrent launches must not inherit another job's transient
          // transcript duplicate. Job membership cannot revoke a leaked handle.
          List<IntPtr> handles = new List<IntPtr>();
          foreach (IntPtr handle in new IntPtr[] { standardInput, standardOutput, standardError }) {
            if (handle == IntPtr.Zero || handle == INVALID_HANDLE_VALUE) { throw new ArgumentException("review standard-stream handle is unavailable"); }
            if (!handles.Contains(handle)) { handles.Add(handle); }
          }
          UIntPtr attributeSize = UIntPtr.Zero;
          bool sized = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeSize);
          int sizeError = Marshal.GetLastWin32Error();
          if (sized || sizeError != 122 || attributeSize == UIntPtr.Zero) {
            throw new Win32Exception(sizeError, "review inherited-handle attribute sizing failed");
          }
          startup.lpAttributeList = Marshal.AllocHGlobal(checked((int)attributeSize.ToUInt64()));
          if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, ref attributeSize)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "review inherited-handle attribute initialization failed");
          }
          attributesInitialized = true;
          int handleBytes = checked(handles.Count * IntPtr.Size);
          handleList = Marshal.AllocHGlobal(handleBytes);
          for (int index = 0; index < handles.Count; index++) { Marshal.WriteIntPtr(handleList, index * IntPtr.Size, handles[index]); }
          if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, new UIntPtr(0x00020002u),
              handleList, new UIntPtr((uint)handleBytes), IntPtr.Zero, IntPtr.Zero)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "review inherited-handle allowlist failed");
          }
          PROCESS_INFORMATION process;
          if (!CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero, true,
              CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
              environment, directory, ref startup, out process)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "suspended review process creation failed");
          }
          processHandle = process.hProcess;
          processId = process.dwProcessId;
          return process.hThread;
        } finally {
          if (attributesInitialized) { DeleteProcThreadAttributeList(startup.lpAttributeList); }
          if (startup.lpAttributeList != IntPtr.Zero) { Marshal.FreeHGlobal(startup.lpAttributeList); }
          if (handleList != IntPtr.Zero) { Marshal.FreeHGlobal(handleList); }
        }
      }

      internal void Assign() {
        if (!AssignProcessToJobObject(jobHandle, processHandle)) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "private review job assignment failed; review process was not resumed");
        }
        assigned = true;
      }

      // Abandoned ownership still kills the group. Finalization is never an
      // observed drain and therefore cannot authorize caller-side file cleanup.
      ~ProcessSession() {
        if (!assigned && processHandle != IntPtr.Zero) { TerminateProcess(processHandle, 1); }
        if (jobHandle != IntPtr.Zero) { CloseHandle(jobHandle); }
        if (processHandle != IntPtr.Zero) { CloseHandle(processHandle); }
      }

      private ProcessObservation Observe() {
        string error = null;
        if (!exitObserved && processHandle != IntPtr.Zero) {
          uint wait = WaitForSingleObject(processHandle, 0);
          if (wait == WAIT_OBJECT_0) {
            uint code;
            if (GetExitCodeProcess(processHandle, out code)) {
              exitCode = unchecked((int)code);
              exitObserved = true;
            } else { error = NativeError("exit-code"); }
          } else if (wait != WAIT_TIMEOUT) { error = NativeError("root-wait"); }
        }
        uint? active = quiescent ? (uint?)0 : null;
        if (!quiescent && jobHandle != IntPtr.Zero) {
          JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
          if (QueryInformationJobObject(jobHandle, 1, out accounting,
              (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero)) {
            active = accounting.ActiveProcesses;
            // A nameless, non-inherited job with no active processes cannot
            // acquire new descendants after the retained root has exited.
            quiescent = (processId == 0 || exitObserved) && active.Value == 0;
          } else { error = AppendError(error, NativeError("job-accounting")); }
        }
        return new ProcessObservation {
          ProcessId = processId, ProcessCreated = processId != 0, ExitObserved = exitObserved, ExitCode = exitCode,
          ActiveProcesses = active, Quiescent = quiescent,
          Closed = processHandle == IntPtr.Zero && jobHandle == IntPtr.Zero,
          TerminationRequested = terminationRequested, Error = error
        };
      }

      private ProcessObservation WaitCore(int milliseconds) {
        CheckTimeout(milliseconds);
        Stopwatch elapsed = Stopwatch.StartNew();
        while (true) {
          ProcessObservation observation = Observe();
          if (observation.Quiescent || observation.Error != null) { return observation; }
          long remaining = milliseconds - elapsed.ElapsedMilliseconds;
          if (remaining <= 0) {
            observation.Error = "drain-timeout";
            return observation;
          }
          Thread.Sleep((int)Math.Min(remaining, 20));
        }
      }

      public ProcessObservation Wait(int milliseconds) {
        lock (sync) { return WaitCore(milliseconds); }
      }

      public ProcessObservation Stop(int milliseconds) {
        lock (sync) {
          CheckTimeout(milliseconds);
          ProcessObservation before = Observe();
          if (before.Quiescent) { return before; }
          terminationRequested = true;
          // The process-only path is restricted to failed suspended launches
          // that never acquired job membership and were never resumed.
          bool stopped = assigned
            ? TerminateJobObject(jobHandle, 1)
            : TerminateProcess(processHandle, 1);
          string stopError = stopped ? null : NativeError("terminate");
          ProcessObservation after = WaitCore(milliseconds);
          if (stopError != null) { after.Error = AppendError(stopError, after.Error); }
          return after;
        }
      }

      private ProcessObservation CloseCore(ProcessObservation observation) {
        if (!observation.Quiescent || (observation.ProcessCreated && !observation.ExitObserved) || observation.Error != null) { return observation; }
        if (jobHandle != IntPtr.Zero) {
          if (!CloseHandle(jobHandle)) { observation.Error = NativeError("close-job"); return observation; }
          jobHandle = IntPtr.Zero;
        }
        if (processHandle != IntPtr.Zero) {
          if (!CloseHandle(processHandle)) { observation.Error = NativeError("close-root"); return observation; }
          processHandle = IntPtr.Zero;
        }
        observation.Closed = true;
        GC.SuppressFinalize(this);
        return observation;
      }

      public ProcessObservation Complete(int milliseconds) {
        lock (sync) { return CloseCore(WaitCore(milliseconds)); }
      }

      public ProcessObservation Close() {
        lock (sync) { return CloseCore(WaitCore(0)); }
      }
    }

    private static string NativeError(string operation) {
      return operation + ":win32-" + Marshal.GetLastWin32Error().ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string AppendError(string first, string second) {
      return first == null ? second : second == null ? first : first + ";" + second;
    }

    private static void CheckTimeout(int milliseconds) {
      if (milliseconds < 0 || milliseconds > 60000) { throw new ArgumentOutOfRangeException("milliseconds"); }
    }

    private static void ValidatePath(string path, bool executable) {
      if (String.IsNullOrWhiteSpace(path) || path.IndexOf('\0') >= 0 || !Path.IsPathRooted(path) ||
          Path.GetPathRoot(path).Length < 3 ||
          !String.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase)) {
        throw new ArgumentException(executable ? "executable path must be canonical and absolute" : "working directory must be canonical and absolute");
      }
      if (executable && !String.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase)) {
        throw new ArgumentException("review process application must be an explicit executable");
      }
      FileAttributes attributes;
      try { attributes = File.GetAttributes(path); }
      catch { throw new ArgumentException(executable ? "review process executable is unavailable" : "review process working directory is unavailable"); }
      if ((attributes & FileAttributes.ReparsePoint) != 0 ||
          (((attributes & FileAttributes.Directory) != 0) == executable)) {
        throw new ArgumentException(executable ? "review process executable is not an ordinary file" : "review process working directory is not an ordinary directory");
      }
    }

    private static string QuoteArgument(string argument) {
      if (argument == null) { argument = String.Empty; }
      if (argument.IndexOf('\0') >= 0) { throw new ArgumentException("process arguments must be NUL-free"); }
      if (argument.Length > 0 && argument.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0) { return argument; }
      StringBuilder quoted = new StringBuilder();
      quoted.Append('"');
      int slashes = 0;
      foreach (char character in argument) {
        if (character == '\\') { slashes++; }
        else if (character == '"') {
          quoted.Append('\\', checked(slashes * 2 + 1));
          quoted.Append('"');
          slashes = 0;
        } else {
          quoted.Append('\\', slashes);
          slashes = 0;
          quoted.Append(character);
        }
      }
      quoted.Append('\\', checked(slashes * 2));
      quoted.Append('"');
      return quoted.ToString();
    }

    private sealed class EnvironmentEntry {
      public string Text, Name;
      public int Position;
    }

    private static string BuildEnvironmentBlock(string[] entries) {
      if (entries == null) { throw new ArgumentNullException("entries"); }
      List<EnvironmentEntry> sorted = new List<EnvironmentEntry>();
      int pathCount = 0;
      for (int position = 0; position < entries.Length; position++) {
        string entry = entries[position];
        if (String.IsNullOrEmpty(entry) || entry.IndexOf('\0') >= 0) {
          throw new ArgumentException("environment entries must be non-empty and NUL-free");
        }
        int separator = entry[0] == '=' ? entry.IndexOf('=', 1) : entry.IndexOf('=');
        int minimum = entry[0] == '=' ? 1 : 0;
        if (separator <= minimum) { throw new ArgumentException("environment entries must use name=value grammar"); }
        string name = entry.Substring(0, separator);
        if (String.Equals(name, "Path", StringComparison.OrdinalIgnoreCase)) {
          pathCount++;
          if (pathCount != 1 || !String.Equals(name, "Path", StringComparison.Ordinal) || separator == entry.Length - 1) {
            throw new ArgumentException("raw child environment requires exactly one nonempty canonical Path entry");
          }
        }
        sorted.Add(new EnvironmentEntry { Text = entry, Name = name, Position = position });
      }
      if (pathCount != 1) { throw new ArgumentException("raw child environment requires exactly one nonempty canonical Path entry"); }
      // Apart from the mandatory canonical Path, preserve hidden drive entries
      // and raw spellings. Stable ordering never rewrites environment values.
      sorted.Sort(delegate(EnvironmentEntry left, EnvironmentEntry right) {
        int order = StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name);
        return order != 0 ? order : left.Position.CompareTo(right.Position);
      });
      StringBuilder block = new StringBuilder();
      foreach (EnvironmentEntry entry in sorted) { block.Append(entry.Text).Append('\0'); }
      block.Append('\0');
      return block.ToString();
    }

    private static IntPtr DuplicateStandardHandle(int standardHandle) {
      IntPtr source = GetStdHandle(standardHandle);
      if (source == INVALID_HANDLE_VALUE) { throw new Win32Exception(Marshal.GetLastWin32Error(), "standard-stream lookup failed"); }
      bool closeSource = false;
      if (source == IntPtr.Zero) {
        uint access = standardHandle == -10 ? 0x80000000 : 0x40000000;
        source = CreateFileW("NUL", access, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (source == IntPtr.Zero || source == INVALID_HANDLE_VALUE) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "absent standard-stream NUL open failed");
        }
        closeSource = true;
      }
      IntPtr duplicate;
      IntPtr current = GetCurrentProcess();
      bool duplicated = DuplicateHandle(current, source, current, out duplicate, 0, true, 2);
      int duplicateError = duplicated ? 0 : Marshal.GetLastWin32Error();
      if (closeSource && !CloseHandle(source)) {
        int closeError = Marshal.GetLastWin32Error();
        if (duplicate != IntPtr.Zero) { CloseHandle(duplicate); }
        throw new Win32Exception(closeError, "temporary standard-stream handle close failed");
      }
      if (!duplicated) { throw new Win32Exception(duplicateError, "standard-stream duplication failed"); }
      return duplicate;
    }

    private static IntPtr DuplicateTranscriptHandle(FileStream transcript) {
      if (!transcript.CanWrite || transcript.IsAsync) {
        throw new ArgumentException("review transcript requires an open writable synchronous file stream");
      }
      SafeFileHandle source = transcript.SafeFileHandle;
      bool retained = false;
      try {
        source.DangerousAddRef(ref retained);
        if (source.IsInvalid || source.IsClosed) { throw new ArgumentException("review transcript handle is unavailable"); }
        IntPtr duplicate;
        IntPtr current = GetCurrentProcess();
        if (!DuplicateHandle(current, source.DangerousGetHandle(), current, out duplicate, 0, true, 2)) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "review transcript handle duplication failed");
        }
        return duplicate;
      } finally {
        if (retained) { source.DangerousRelease(); }
      }
    }

    private static IntPtr DuplicateInputHandle(FileStream input) {
      if (!input.CanRead || input.CanWrite || !input.CanSeek || input.IsAsync || input.Position != 0 || input.Length > 1048576) {
        throw new ArgumentException("owned input requires a bounded read-only synchronous file stream at position zero");
      }
      SafeFileHandle source = input.SafeFileHandle;
      bool retained = false;
      try {
        source.DangerousAddRef(ref retained);
        if (source.IsInvalid || source.IsClosed) { throw new ArgumentException("owned input handle is unavailable"); }
        IntPtr duplicate;
        IntPtr current = GetCurrentProcess();
        // The private scratch owner may retain write access for exact cleanup.
        // The child receives only read access, never that owner's full rights.
        if (!DuplicateHandle(current, source.DangerousGetHandle(), current, out duplicate, 0x80000000u, true, 0)) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "owned input handle duplication failed");
        }
        return duplicate;
      } finally {
        if (retained) { source.DangerousRelease(); }
      }
    }

    public static ProcessSession Start(string applicationName, string[] arguments,
        string workingDirectory, string[] environmentEntries) {
      return Start(applicationName, arguments, workingDirectory, environmentEntries, null, null, null);
    }

    public static ProcessSession Start(string applicationName, string[] arguments,
        string workingDirectory, string[] environmentEntries, FileStream transcript) {
      return Start(applicationName, arguments, workingDirectory, environmentEntries, transcript, null, null);
    }

    public static ProcessSession Start(string applicationName, string[] arguments,
        string workingDirectory, string[] environmentEntries, FileStream transcript, FileStream input) {
      return Start(applicationName, arguments, workingDirectory, environmentEntries, transcript, input, null);
    }

    public static ProcessSession Start(string applicationName, string[] arguments,
        string workingDirectory, string[] environmentEntries, FileStream transcript, FileStream input,
        FileStream standardErrorTranscript) {
      ValidatePath(applicationName, true);
      ValidatePath(workingDirectory, false);
      if (arguments == null) { throw new ArgumentNullException("arguments"); }
      StringBuilder command = new StringBuilder(QuoteArgument(applicationName));
      foreach (string argument in arguments) { command.Append(' ').Append(QuoteArgument(argument)); }
      if (command.Length >= 32767) { throw new ArgumentException("review process command line exceeds the Windows limit"); }
      string environmentBlock = BuildEnvironmentBlock(environmentEntries);
      IntPtr environment = IntPtr.Zero, job = IntPtr.Zero;
      IntPtr standardInput = IntPtr.Zero, standardOutput = IntPtr.Zero, standardError = IntPtr.Zero;
      IntPtr thread = IntPtr.Zero;
      ProcessSession session = null;
      try {
        // StringToHGlobalUni supplies the second terminator for an empty block.
        environment = Marshal.StringToHGlobalUni(environmentBlock);
        job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) { throw new Win32Exception(Marshal.GetLastWin32Error(), "private review job creation failed"); }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)))) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "private review job lifetime configuration failed");
        }
        standardInput = input == null ? DuplicateStandardHandle(-10) : DuplicateInputHandle(input);
        if (transcript == null) {
          if (standardErrorTranscript != null) { throw new ArgumentException("a separate standard-error transcript requires an owned standard-output transcript"); }
          standardOutput = DuplicateStandardHandle(-11);
          standardError = DuplicateStandardHandle(-12);
        } else {
          // The caller owns private path custody and keeps the original stream
          // through observed whole-job quiescence. The existing null-error-stream
          // contract preserves one shared stdout/stderr file position.
          standardOutput = DuplicateTranscriptHandle(transcript);
          standardError = standardErrorTranscript == null ? standardOutput : DuplicateTranscriptHandle(standardErrorTranscript);
        }
        // Allocate the retained owner before creating a process, so failed
        // launch cleanup cannot fall back to unobserved raw-handle disposal.
        session = new ProcessSession(job);
        job = IntPtr.Zero;
        thread = session.CreateSuspended(applicationName, command, workingDirectory, environment,
          standardInput, standardOutput, standardError);
        session.Assign();
        if (ResumeThread(thread) == UInt32.MaxValue) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "review process resume failed");
        }
        if (!CloseHandle(thread)) {
          throw new Win32Exception(Marshal.GetLastWin32Error(), "review process thread handle close failed");
        }
        thread = IntPtr.Zero;
        return session;
      } catch (Exception error) {
        if (session != null) {
          ProcessObservation stopped = session.Stop(10000);
          ProcessObservation closed = stopped.Quiescent ? session.Close() : stopped;
          if (!closed.Closed) {
            InvalidOperationException uncertain = new InvalidOperationException("failed review launch cleanup is unconfirmed; retained process session requires drain", error);
            uncertain.Data["CrgPairedProcessSession"] = session;
            uncertain.Data["CrgPairedProcessObservation"] = closed;
            throw uncertain;
          }
        }
        throw;
      } finally {
        if (standardInput != IntPtr.Zero) { CloseHandle(standardInput); }
        if (standardOutput != IntPtr.Zero) { CloseHandle(standardOutput); }
        if (standardError != IntPtr.Zero && standardError != standardOutput) { CloseHandle(standardError); }
        if (thread != IntPtr.Zero) { CloseHandle(thread); }
        if (job != IntPtr.Zero) { CloseHandle(job); }
        if (environment != IntPtr.Zero) { Marshal.FreeHGlobal(environment); }
      }
    }
  }
}
'@ -ErrorAction Stop
}

function Start-CrgPairedReviewProcess {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$ApplicationName,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$EnvironmentEntries,
    [AllowNull()][System.IO.FileStream]$TranscriptStream,
    [AllowNull()][System.IO.FileStream]$InputStream,
    [AllowNull()][System.IO.FileStream]$StandardErrorStream)
  Initialize-CrgPairedProcessNative
  return [CrgPairedProcess.NativeV2]::Start($ApplicationName, $Arguments, $WorkingDirectory, $EnvironmentEntries, $TranscriptStream, $InputStream, $StandardErrorStream)
}

function Assert-CrgPairedProcessSession {
  param([object]$Session)
  Initialize-CrgPairedProcessNative
  if ($Session -isnot [CrgPairedProcess.NativeV2+ProcessSession]) { throw 'paired process operation requires a retained native session' }
}

function Wait-CrgPairedReviewProcess {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Session,
    [ValidateRange(0, 60000)][int]$TimeoutMilliseconds = 10000)
  Assert-CrgPairedProcessSession -Session $Session
  return $Session.Wait($TimeoutMilliseconds)
}

function Complete-CrgPairedReviewProcess {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Session,
    [ValidateRange(0, 60000)][int]$TimeoutMilliseconds = 10000)
  Assert-CrgPairedProcessSession -Session $Session
  return $Session.Complete($TimeoutMilliseconds)
}

function Stop-CrgPairedReviewProcess {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Session,
    [ValidateRange(0, 60000)][int]$TimeoutMilliseconds = 10000)
  Assert-CrgPairedProcessSession -Session $Session
  return $Session.Stop($TimeoutMilliseconds)
}

function Close-CrgPairedReviewProcess {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object]$Session)
  Assert-CrgPairedProcessSession -Session $Session
  return $Session.Close()
}

Export-ModuleMember -Function Start-CrgPairedReviewProcess, Wait-CrgPairedReviewProcess, Complete-CrgPairedReviewProcess, Stop-CrgPairedReviewProcess, Close-CrgPairedReviewProcess
