Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('CrgTransport.NativeV2' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace CrgTransport {
public static class NativeV2 {
public sealed class DirectoryLease : IDisposable {
  internal readonly List<SafeFileHandle> Handles = new List<SafeFileHandle>();
  internal readonly List<FileStream> Files = new List<FileStream>();
  public string GitDir,CommonDir; public bool BackLink,CommonOwned;
  public object ExecutableCustody;
  public byte[] Read(string path,int maximum,bool retain) {
    try { RetainDirectory(this,Path.GetDirectoryName(path),false); }
    catch (Win32Exception error) { if (error.NativeErrorCode==2 || error.NativeErrorCode==3) return null; throw; }
    var handle=CreateFileW(@"\\?\"+path,0x80100000u,1u,IntPtr.Zero,3u,0x02200000u,IntPtr.Zero);
    if (handle.IsInvalid) {
      int error=Marshal.GetLastWin32Error(); handle.Dispose();
      if (error==2 || error==3) return null;
      throw new Win32Exception(error,"project association read failed (Win32 error "+error+")");
    }
    FileStream stream=null;
    try {
      FileInfo info;
      if (!GetFileInformationByHandle(handle,out info) || (info.Attributes&0x410u)!=0 || info.Links!=1) throw new IOException("project association requires an ordinary single-link file");
      stream=new FileStream(handle,FileAccess.Read); handle=null;
      if (stream.Length>maximum) throw new IOException("project association file exceeds its bound");
      byte[] bytes=new byte[(int)stream.Length]; int offset=0,count;
      while (offset<bytes.Length && (count=stream.Read(bytes,offset,bytes.Length-offset))>0) offset+=count;
      if (offset!=bytes.Length || stream.ReadByte()!=-1) throw new IOException("project association file changed length");
      if (retain) { Files.Add(stream); stream=null; }
      return bytes;
    } finally { if (stream!=null) stream.Dispose(); if (handle!=null) handle.Dispose(); }
  }
  public void Dispose() {
    for (int i=Files.Count-1;i>=0;i--) Files[i].Dispose(); Files.Clear();
    for (int i=Handles.Count-1;i>=0;i--) Handles[i].Dispose(); Handles.Clear();
  }
}
public sealed class Frame {
  public byte Kind; public byte[] Bytes;
}
  public const int MaximumFrame = 8388608;
  static readonly UTF8Encoding Utf8 = new UTF8Encoding(false,true);
  static readonly object InputSync = new object();
  static FieldInfo InputCache; static volatile bool InputPinned;
  public static Encoding PinHostInput() {
    lock (InputSync) {
      if (InputPinned) throw new IOException("host input encoding already has an owner");
      InputCache=typeof(Console).GetField("_inputEncoding",BindingFlags.NonPublic|BindingFlags.Static) ?? typeof(Console).GetField("s_inputEncoding",BindingFlags.NonPublic|BindingFlags.Static);
      if (InputCache==null) throw new IOException("console input encoding cache is unavailable");
      var prior=(Encoding)InputCache.GetValue(null);
      InputCache.SetValue(null,new UTF8Encoding(false)); InputPinned=true; return prior;
    }
  }
  public static void RestoreHostInput(Encoding prior) {
    lock (InputSync) { if (InputPinned) { InputCache.SetValue(null,prior); InputPinned=false; } }
  }
  sealed class ChildCustody {
    internal Process Process; internal Task Output,Error; internal DirectoryLease Lease;
    internal bool Quiescent() {
      try { return Process.HasExited && Output.Status==TaskStatus.RanToCompletion && Error.Status==TaskStatus.RanToCompletion; }
      catch { return false; }
    }
  }
  static readonly ConcurrentBag<ChildCustody> Retained = new ConcurrentBag<ChildCustody>();
  sealed class AdmissionCustody { internal DirectoryLease Lease; internal Exception Failure; }
  static readonly ConcurrentBag<AdmissionCustody> UncertainAdmissions = new ConcurrentBag<AdmissionCustody>();
  public static void RetainAdmission(DirectoryLease lease,Exception failure) { UncertainAdmissions.Add(new AdmissionCustody { Lease=lease,Failure=failure }); }
  public static int RetainedChildren() {
    var pending=new List<ChildCustody>(); ChildCustody child;
    while (Retained.TryTake(out child)) {
      if (child.Quiescent()) {
        try { child.Lease.Dispose(); child.Process.Dispose(); }
        catch { pending.Add(child); }
      }
      else pending.Add(child);
    }
    foreach (var value in pending) Retained.Add(value);
    return Retained.Count+UncertainAdmissions.Count;
  }
  [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
  [StructLayout(LayoutKind.Sequential)] struct FileInfo {
    public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;
    public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
  }
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,uint size,out uint needed);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out SafeFileHandle token);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint id);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int kind);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint id);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafePipeHandle CreateNamedPipeW(string name,uint access,uint mode,uint instances,uint output,uint input,uint timeout,ref SecurityAttributes security);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInfo info);

  static SecurityIdentifier TokenSid(IntPtr token,int kind) {
    uint needed; GetTokenInformation(token,kind,IntPtr.Zero,0,out needed);
    if (needed==0 || needed>65536) throw new IOException("invalid token identity size");
    IntPtr data=Marshal.AllocHGlobal((int)needed);
    try {
      if (!GetTokenInformation(token,kind,data,needed,out needed)) throw new Win32Exception();
      if (kind==11 && Marshal.ReadInt32(data)==0) return null;
      int offset=(kind==28 || kind==11) ? (IntPtr.Size==8 ? 8 : 4) : 0;
      if (kind==28 && Marshal.ReadInt32(data)!=1) throw new IOException("one logon identity is required");
      return new SecurityIdentifier(Marshal.ReadIntPtr(data,offset));
    } finally { Marshal.FreeHGlobal(data); }
  }
  public static string UserSid() { using (WindowsIdentity identity=WindowsIdentity.GetCurrent()) return identity.User.Value; }
  public static string LogonSid() { using (WindowsIdentity identity=WindowsIdentity.GetCurrent()) return TokenSid(identity.Token,28).Value; }
  public static string PipeName(string store) {
    string key=Path.GetFullPath(store).TrimEnd('\\').ToUpperInvariant()+"\n"+UserSid()+"\n"+LogonSid();
    using (var hash=System.Security.Cryptography.SHA256.Create()) return "crg-v1-"+BitConverter.ToString(hash.ComputeHash(Utf8.GetBytes(key))).Replace("-","").ToLowerInvariant();
  }
  public static NamedPipeServerStream Listen(string name,bool first) {
    var security=new PipeSecurity(); security.SetAccessRuleProtection(true,false);
    security.SetOwner(new SecurityIdentifier(UserSid()));
    security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(UserSid()),PipeAccessRights.FullControl,AccessControlType.Allow));
    // WindowsIdentity.Groups omits the logon SID. An explicit logon grant
    // satisfies restricted-token transport checks without filesystem grants.
    security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(LogonSid()),PipeAccessRights.ReadWrite,AccessControlType.Allow));
    byte[] descriptor=security.GetSecurityDescriptorBinaryForm(); IntPtr data=Marshal.AllocHGlobal(descriptor.Length);
    try {
      Marshal.Copy(descriptor,0,data,descriptor.Length);
      var attributes=new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=data };
      uint access=0x40000003u | (first ? 0x00080000u : 0u);
      var handle=CreateNamedPipeW(@"\\.\pipe\"+name,access,8u,16u,65536u,65536u,0u,ref attributes);
      if (handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error,"local gate endpoint could not be created (Win32 error "+error+")"); }
      try { return new NamedPipeServerStream(PipeDirection.InOut,true,false,handle); }
      catch { handle.Dispose(); throw; }
    } finally { Marshal.FreeHGlobal(data); }
  }
  public static NamedPipeClientStream Connect(string name,int timeout) {
    var pipe=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation);
    try {
      pipe.Connect(timeout); uint id;
      if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out id)) throw new Win32Exception();
      IntPtr process=OpenProcess(0x1000u,false,id);
      if (process==IntPtr.Zero) throw new Win32Exception();
      try {
        SafeFileHandle token;
        if (!OpenProcessToken(process,8u,out token)) throw new Win32Exception();
        using (token) {
          if (TokenSid(token.DangerousGetHandle(),1).Value!=UserSid() || TokenSid(token.DangerousGetHandle(),28).Value!=LogonSid() || TokenSid(token.DangerousGetHandle(),11)!=null) throw new IOException("local gate server is not the unrestricted installing account/logon");
        }
      } finally { CloseHandle(process); }
      return pipe;
    } catch { pipe.Dispose(); throw; }
  }
  static void RetainDirectory(DirectoryLease lease,string full,bool writable) {
    string cursor=Path.GetPathRoot(full); var paths=new List<string>(); paths.Add(cursor);
    foreach (string part in full.Substring(cursor.Length).Split('\\')) { cursor=Path.Combine(cursor,part); paths.Add(cursor); }
    foreach (string path in paths) {
      uint access=writable && String.Equals(path,full,StringComparison.OrdinalIgnoreCase) ? 0x00100083u : 0x001000A1u;
      var handle=CreateFileW(@"\\?\"+path,access,3u,IntPtr.Zero,3u,0x02200000u,IntPtr.Zero);
      if (handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error,"caller cannot access the selected project directory (Win32 error "+error+")"); }
      FileInfo info;
      if (!GetFileInformationByHandle(handle,out info) || (info.Attributes&0x410u)!=0x10u) { handle.Dispose(); throw new IOException("project authorization requires an ordinary no-follow directory chain"); }
      lease.Handles.Add(handle);
    }
  }
  public static string LocalPath(string path) {
    if (String.IsNullOrWhiteSpace(path) || path.Length<3 || !((path[0]>='A' && path[0]<='Z') || (path[0]>='a' && path[0]<='z')) || path[1]!=':' || (path[2]!='\\' && path[2]!='/')) throw new IOException("an explicit absolute local path is required");
    string full=Path.GetFullPath(path.Replace('/','\\')).TrimEnd('\\');
    if (full.Length<=3) throw new IOException("a drive root cannot be a project or database");
    foreach (string part in full.Substring(3).Split('\\')) {
      if (part.Length==0 || part.EndsWith(".",StringComparison.Ordinal) || part.EndsWith(" ",StringComparison.Ordinal) || part.IndexOfAny(new char[]{':','*','?','\"','<','>','|','\0'})>=0) throw new IOException("local path has an unsupported component");
    }
    return full;
  }
  public static string Indirection(byte[] bytes,string prefix,string directory) {
    string text=Decode(bytes);
    if (!text.StartsWith(prefix,StringComparison.Ordinal)) throw new IOException("invalid Git association record");
    text=text.Substring(prefix.Length).TrimEnd('\r','\n');
    if (text.Length==0 || text.IndexOfAny(new char[]{'\r','\n','\0'})>=0) throw new IOException("invalid Git association target");
    text=text.Replace('/','\\');
    if (Path.IsPathRooted(text)) return LocalPath(text);
    if (text.IndexOf(':')>=0) throw new IOException("drive-relative Git association is invalid");
    return LocalPath(Path.Combine(directory,text));
  }
  public static DirectoryLease CaptureNamespace(string root) {
    var lease=new DirectoryLease();
    try {
      RetainDirectory(lease,root,false);
      string dotGit=Path.Combine(root,".git");
      var selector=CreateFileW(@"\\?\"+dotGit,0x00100080u,3u,IntPtr.Zero,3u,0x02200000u,IntPtr.Zero);
      if (selector.IsInvalid) { int error=Marshal.GetLastWin32Error(); selector.Dispose(); throw new Win32Exception(error,"project Git selector could not be retained (Win32 error "+error+")"); }
      FileInfo info;
      if (!GetFileInformationByHandle(selector,out info) || (info.Attributes&0x400u)!=0) { selector.Dispose(); throw new IOException("project Git selector requires an ordinary file or directory"); }
      lease.Handles.Add(selector);
      if ((info.Attributes&0x10u)!=0) { RetainDirectory(lease,dotGit,false); lease.GitDir=dotGit; }
      else {
        byte[] file=lease.Read(dotGit,16384,true);
        if (file==null) throw new IOException("project Git association is absent");
        lease.GitDir=Indirection(file,"gitdir: ",root);
        RetainDirectory(lease,lease.GitDir,false);
      }
      byte[] common=lease.Read(Path.Combine(lease.GitDir,"commondir"),16384,true);
      lease.CommonDir=common==null ? lease.GitDir : Indirection(common,"",lease.GitDir);
      RetainDirectory(lease,lease.CommonDir,false);
      lease.BackLink=!String.Equals(lease.GitDir,lease.CommonDir,StringComparison.OrdinalIgnoreCase);
      if (lease.BackLink) {
        byte[] back=lease.Read(Path.Combine(lease.GitDir,"gitdir"),16384,true);
        if (back==null || !String.Equals(Indirection(back,"",lease.GitDir),dotGit,StringComparison.OrdinalIgnoreCase)) throw new IOException("Git worktree back-link does not name the admitted project");
        string worktrees=Path.Combine(lease.CommonDir,"worktrees");
        lease.CommonOwned=String.Equals(Path.GetDirectoryName(lease.GitDir),worktrees,StringComparison.OrdinalIgnoreCase);
      }
      return lease;
    } catch { lease.Dispose(); throw; }
  }
  public static DirectoryLease Authorize(NamedPipeServerStream pipe,string root) {
    DirectoryLease lease=null; string expected=UserSid();
    try {
      pipe.RunAsClient(delegate {
        using (WindowsIdentity identity=WindowsIdentity.GetCurrent(true)) {
          if (identity==null || identity.User.Value!=expected) throw new IOException("local gate caller identity differs from the installing account");
        }
        string full=LocalPath(root);
        if (full.Length<=3 || !String.Equals(full,root,StringComparison.OrdinalIgnoreCase) || full.StartsWith(@"\\",StringComparison.Ordinal)) throw new IOException("an explicit canonical local project root is required");
        lease=new DirectoryLease(); RetainDirectory(lease,full,true);
        var metadata=CaptureNamespace(full);
        lease.Handles.AddRange(metadata.Handles); metadata.Handles.Clear();
        lease.Files.AddRange(metadata.Files); metadata.Files.Clear();
        lease.GitDir=metadata.GitDir; lease.CommonDir=metadata.CommonDir; lease.BackLink=metadata.BackLink; lease.CommonOwned=metadata.CommonOwned;
      });
      return lease;
    } catch { if (lease!=null) lease.Dispose(); throw; }
  }
  public static void AuthorizeDatabase(NamedPipeServerStream pipe,DirectoryLease lease,string path,bool requireWrite) {
    path=LocalPath(path);
    pipe.RunAsClient(delegate {
      while (true) {
        try { RetainDirectory(lease,path,requireWrite); break; }
        catch (Win32Exception error) {
          if ((error.NativeErrorCode!=2 && error.NativeErrorCode!=3) || path.Length<=3) throw;
          path=Path.GetDirectoryName(path);
        }
      }
    });
  }
  public static string Decode(byte[] bytes) { return Utf8.GetString(bytes); }
  public static byte[] Encode(string text) { return Utf8.GetBytes(text); }
  public static string Digest(byte[] bytes) {
    using (var hash=System.Security.Cryptography.SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();
  }
  static void ReadExact(Stream stream,byte[] bytes,int timeout,Stopwatch watch) {
    int offset=0;
    while (offset<bytes.Length) {
      var read=stream.ReadAsync(bytes,offset,bytes.Length-offset);
      if (timeout>0 && !read.Wait(Math.Max(0,timeout-(int)Math.Min(watch.ElapsedMilliseconds,timeout)))) throw new TimeoutException("local gate frame timed out");
      int count=read.GetAwaiter().GetResult();
      if (count==0) throw new EndOfStreamException("local gate disconnected before completion");
      offset+=count;
    }
  }
  public static Frame ReadFrame(Stream stream,int timeout) {
    var watch=Stopwatch.StartNew(); byte[] header=new byte[5]; ReadExact(stream,header,timeout,watch);
    int size=BitConverter.ToInt32(header,1);
    if (size<0 || size>MaximumFrame) throw new IOException("local gate frame exceeds the protocol bound");
    byte[] bytes=new byte[size]; ReadExact(stream,bytes,timeout,watch);
    return new Frame { Kind=header[0],Bytes=bytes };
  }
  public static void WriteFrame(Stream stream,byte kind,byte[] bytes) {
    if (bytes==null || bytes.Length>MaximumFrame) throw new IOException("invalid local gate frame length");
    byte[] header=new byte[5]; header[0]=kind; Array.Copy(BitConverter.GetBytes(bytes.Length),0,header,1,4);
    CompleteWrite(stream,stream.WriteAsync(header,0,header.Length));
    CompleteWrite(stream,stream.WriteAsync(bytes,0,bytes.Length)); stream.Flush();
  }
  public static Task BeginUpload(Stream stream,byte[] bytes) {
    // Early refusals may close without reading a request larger than the pipe
    // buffer. Receive concurrently so a delivered refusal survives write failure.
    return Task.Factory.StartNew(() => WriteFrame(stream,1,bytes));
  }
  static void CompleteWrite(Stream stream,Task write) {
    bool complete;
    try { complete=write.Wait(10000); }
    catch (AggregateException) { write.GetAwaiter().GetResult(); throw; }
    if (!complete) { stream.Dispose(); throw new TimeoutException("local gate output timed out"); }
    write.GetAwaiter().GetResult();
  }
  public static byte[] ReadRequestInput(Stream stream) {
    using (var buffer=new MemoryStream()) {
      byte[] block=new byte[8192]; int count;
      while ((count=stream.Read(block,0,block.Length))>0) {
        if (buffer.Length+count>MaximumFrame) throw new IOException("local gate request exceeds its bound");
        buffer.Write(block,0,count);
      }
      return buffer.ToArray();
    }
  }
  static string Quote(string value) {
    var output=new StringBuilder("\""); int slashes=0;
    foreach (char c in value) {
      if (c=='\\') { slashes++; continue; }
      if (c=='\"') { output.Append('\\',slashes*2+1); output.Append(c); slashes=0; continue; }
      output.Append('\\',slashes); slashes=0; output.Append(c);
    }
    output.Append('\\',slashes*2); output.Append('"'); return output.ToString();
  }
  sealed class OutputWriter {
    readonly Stream Pipe; readonly object Sync=new object(); bool connected=true;
    public OutputWriter(Stream pipe) { Pipe=pipe; }
    public void Send(byte kind,byte[] bytes) {
      lock (Sync) {
        if (!connected) return;
        try { WriteFrame(Pipe,kind,bytes); } catch (IOException) { connected=false; } catch (ObjectDisposedException) { connected=false; } catch (TimeoutException) { connected=false; }
      }
    }
    public void Drain(Stream source,byte kind) {
      byte[] bytes=new byte[16384]; int count;
      while ((count=source.Read(bytes,0,bytes.Length))>0) { byte[] frame=new byte[count]; Array.Copy(bytes,frame,count); Send(kind,frame); }
    }
  }
  public static int Execute(NamedPipeServerStream pipe,string launcher,string root,string request,DirectoryLease lease) {
    var writer=new OutputWriter(pipe);
    string shell=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe");
    string[] args={"-NoProfile","-ExecutionPolicy","Bypass","-File",launcher,"-TargetRepo",root,"-Status","-CrgHostExecution","-CrgRequestStdin"};
    var text=new List<string>(); foreach (string arg in args) text.Add(Quote(arg));
    var start=new ProcessStartInfo(shell,String.Join(" ",text.ToArray())) {
      UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true
    };
    var child=new ChildCustody { Process=new Process { StartInfo=start },Lease=lease };
    bool started=false,retained=false;
    try {
      // Framework Process.Start constructs a stdin writer even when the raw
      // pipe is used. The cache is pinned before worker concurrency begins;
      // metadata readers temporarily select the same preamble-free encoding.
      if (!InputPinned || ((Encoding)InputCache.GetValue(null)).GetPreamble().Length!=0) throw new IOException("host stdin encoding lost its preamble-free lifetime owner");
      var encoding=start.GetType().GetProperty("StandardInputEncoding");
      if (encoding!=null) encoding.SetValue(start,new UTF8Encoding(false),null);
      if (!child.Process.Start()) throw new IOException("local gate child did not start");
      started=true;
      child.Output=Task.Factory.StartNew(delegate { writer.Drain(child.Process.StandardOutput.BaseStream,2); });
      child.Error=Task.Factory.StartNew(delegate { writer.Drain(child.Process.StandardError.BaseStream,3); });
      try { byte[] bytes=Encode(request); child.Process.StandardInput.BaseStream.Write(bytes,0,bytes.Length); }
      finally {
        // A disconnected client or failed stdin write cannot cancel a published
        // operation. Keep the namespace and process until exit and pipe closure.
        try { child.Process.StandardInput.Close(); }
        finally {
          Task.WaitAll(child.Output,child.Error);
          if (!child.Process.WaitForExit(5000)) throw new IOException("gate worker retains unconfirmed descendants; preserve worker custody and inspect project recovery state");
        }
      }
      writer.Send(4,BitConverter.GetBytes(child.Process.ExitCode)); return child.Process.ExitCode;
    } catch (Exception error) {
      if (started) {
        error.Data["CrgHostChildStarted"]=true;
        if (!child.Quiescent()) { Retained.Add(child); retained=true; error.Data["CrgHostRetained"]=true; }
      }
      throw;
    } finally { if (!retained) child.Process.Dispose(); }
  }
  public static void HoldUncertainWorker() {
    try { Console.Error.WriteLine("Gate worker retains unconfirmed descendants and runtime ownership; operation outcome is unknown."); Console.Error.Flush(); } catch { }
    // EOF lets the host report uncertainty without ending the process that
    // still owns runtime files, native sessions and possibly live descendants.
    if (Console.IsOutputRedirected) CloseHandle(GetStdHandle(-11));
    if (Console.IsErrorRedirected) CloseHandle(GetStdHandle(-12));
    while (true) System.Threading.Thread.Sleep(1000);
  }
}
}
'@
}

function Assert-CrgTransportProperties {
  param([object]$Value, [string[]]$Names)
  if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw 'local gate object is invalid' }
  $actual = [string[]]@($Value.PSObject.Properties.Name)
  if ($actual.Count -ne $Names.Count) { throw 'local gate object properties differ from the protocol' }
  foreach ($name in $actual) { if (-not [Linq.Enumerable]::Contains($Names, $name, [StringComparer]::Ordinal)) { throw 'local gate object has an unknown property' } }
}

function Read-CrgHostRequest {
  param([string]$Text)
  $request = ConvertFrom-Json -InputObject $Text -ErrorAction Stop
  Assert-CrgTransportProperties -Value $request -Names @('Protocol', 'TargetRepo', 'Operation')
  if ($request.Protocol -isnot [int] -or $request.Protocol -ne 1) { throw 'unsupported local gate protocol' }
  if ($request.TargetRepo -isnot [string] -or [string]::IsNullOrWhiteSpace($request.TargetRepo) -or $request.TargetRepo.Length -gt 32767 -or $request.TargetRepo -match '[\x00-\x1f\x7f]') { throw 'invalid local gate target' }
  $request.TargetRepo = [CrgTransport.NativeV2]::LocalPath($request.TargetRepo)
  $operation = $request.Operation
  Assert-CrgTransportProperties -Value $operation -Names @('Name', 'All', 'Paths', 'MessageFile', 'AuthoringAgent', 'PrivateGitDir', 'PushInput', 'PushRemoteName', 'PushRemoteLocation')
  if ($operation.Name -isnot [string] -or -not [Linq.Enumerable]::Contains([string[]]@('Status', 'Open', 'Stage', 'Commit', 'Resume', 'Attach', 'PushCheck'), $operation.Name, [StringComparer]::Ordinal)) { throw 'invalid local gate operation' }
  if ($operation.All -isnot [bool] -or $operation.Paths -isnot [array] -or $operation.Paths.Count -gt 4096) { throw 'invalid local gate path selection' }
  foreach ($path in $operation.Paths) { if ($path -isnot [string] -or [string]::IsNullOrWhiteSpace($path) -or $path.Length -gt 32767 -or $path -match '[\x00-\x1f\x7f]') { throw 'invalid local gate selected path' } }
  foreach ($name in @('MessageFile', 'AuthoringAgent', 'PrivateGitDir', 'PushRemoteName', 'PushRemoteLocation')) {
    $value = $operation.$name
    if ($null -ne $value -and ($value -isnot [string] -or $value.Length -gt 32767 -or $value -match '[\x00-\x1f\x7f]')) { throw 'invalid local gate string field' }
  }
  if ([string]::Equals($operation.Name, 'Stage', [StringComparison]::Ordinal)) {
    if ($operation.All -eq ($operation.Paths.Count -gt 0)) { throw 'Stage requires All or explicit paths' }
  } elseif ($operation.All -or $operation.Paths.Count -ne 0) { throw 'path selection requires Stage' }
  $hasMessage = [Linq.Enumerable]::Contains([string[]]@('Commit', 'Attach'), $operation.Name, [StringComparer]::Ordinal)
  if ($hasMessage) {
    if ([string]::IsNullOrWhiteSpace($operation.MessageFile) -or -not [Linq.Enumerable]::Contains([string[]]@('codex', 'claude'), [string]$operation.AuthoringAgent, [StringComparer]::Ordinal)) { throw 'Commit and Attach require a message file and author' }
    if ($operation.MessageFile -match '\A(?:[A-Za-z]:[^\\/]|[\\/])' -or $operation.MessageFile -match '\A[A-Za-z]:\z') { throw 'message paths require a project-relative path or an explicit absolute local path' }
    $messagePath = [CrgTransport.NativeV2]::LocalPath([IO.Path]::Combine($request.TargetRepo, $operation.MessageFile))
    if (-not $messagePath.StartsWith(($request.TargetRepo.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'gate message files must remain inside the admitted project' }
    $operation.MessageFile = $messagePath
  } elseif (-not [string]::IsNullOrEmpty($operation.MessageFile) -or -not [string]::IsNullOrEmpty($operation.AuthoringAgent)) { throw 'message fields require Commit or Attach' }
  if (-not [string]::Equals($operation.Name, 'Attach', [StringComparison]::Ordinal) -and -not [string]::IsNullOrEmpty($operation.PrivateGitDir)) { throw 'private database selection requires Attach' }
  if (-not [string]::IsNullOrEmpty($operation.PrivateGitDir)) { $operation.PrivateGitDir = [CrgTransport.NativeV2]::LocalPath($operation.PrivateGitDir) }
  if ([string]::Equals($operation.Name, 'PushCheck', [StringComparison]::Ordinal)) {
    if ([string]::IsNullOrWhiteSpace($operation.PushRemoteName) -or [string]::IsNullOrWhiteSpace($operation.PushRemoteLocation) -or $operation.PushInput -isnot [array] -or $operation.PushInput.Count -gt 1048576) { throw 'invalid local gate push request' }
    foreach ($value in $operation.PushInput) { if ($value -isnot [int] -or $value -lt 0 -or $value -gt 255) { throw 'invalid local gate push byte' } }
    $operation.PushInput = [byte[]]$operation.PushInput
  } elseif ($null -ne $operation.PushInput -or -not [string]::IsNullOrEmpty($operation.PushRemoteName) -or -not [string]::IsNullOrEmpty($operation.PushRemoteLocation)) { throw 'push fields require PushCheck' }
  return $request
}

function Invoke-CrgHostClient {
  param([string]$Store, [string]$TargetRepo, [object]$Operation)
  $text = ConvertTo-Json -InputObject ([pscustomobject]@{ Protocol = 1; TargetRepo = $TargetRepo; Operation = $Operation }) -Depth 8 -Compress
  $text = ConvertTo-Json -InputObject (Read-CrgHostRequest -Text $text) -Depth 8 -Compress
  $pipe = $null; $upload = $null; $accepted = $false; $submitted = $false; $reported = $false
  try {
    try { $pipe = [CrgTransport.NativeV2]::Connect([CrgTransport.NativeV2]::PipeName($Store), 3000) }
    catch { throw "Installed gate host is unavailable; no operation started. Repair or complete the gate installation. $($_.Exception.Message)" }
    $submitted = $true
    $upload = [CrgTransport.NativeV2]::BeginUpload($pipe, [CrgTransport.NativeV2]::Encode($text))
    $stdout = [Console]::OpenStandardOutput(); $stderr = [Console]::OpenStandardError()
    while ($true) {
      $frame = [CrgTransport.NativeV2]::ReadFrame($pipe, 0)
      switch ($frame.Kind) {
        2 { $stdout.Write($frame.Bytes, 0, $frame.Bytes.Length); $stdout.Flush() }
        3 { $stderr.Write($frame.Bytes, 0, $frame.Bytes.Length); $stderr.Flush() }
        4 {
          if ($frame.Bytes.Length -ne 4) { throw 'invalid local gate exit frame' }
          $global:LASTEXITCODE = [BitConverter]::ToInt32($frame.Bytes, 0)
          return
        }
        5 { $reported = $true; throw ('Gate host refused the request before starting a child: ' + [CrgTransport.NativeV2]::Decode($frame.Bytes)) }
        7 { if ($accepted -or $frame.Bytes.Length -ne 0) { throw 'invalid local gate admission frame' }; $accepted = $true }
        8 { $accepted = $true; throw ([CrgTransport.NativeV2]::Decode($frame.Bytes)) }
        default { throw 'invalid local gate response frame' }
      }
    }
  } catch {
    if ($submitted -and -not $reported) { throw "Local gate outcome is unknown; inspect project Status/Resume before repeating a mutation. $($_.Exception.Message)" }
    throw "Local gate operation was not started. $($_.Exception.Message)"
  }
  finally {
    try { if ($null -ne $pipe) { $pipe.Dispose() } }
    finally {
      # Closing the connection bounds any pending write. Observe the upload
      # task without replacing a validated response or an unknown-outcome error.
      if ($null -ne $upload) { try { $null = $upload.GetAwaiter().GetResult() } catch { } }
    }
  }
}

function Get-CrgHostSelectorPaths {
  param([object]$Binding)
  return [ordered]@{
    'public-commondir' = (Join-Path $Binding.GitDir 'commondir')
    'private-commondir' = (Join-Path $Binding.PrivateGitDir 'commondir')
    'attachment' = (Join-Path $Binding.GitDir 'crg-attachment')
    'pending' = (Join-Path $Binding.GitDir 'crg-attachment-pending')
    'handoff' = (Join-Path $Binding.GitDir 'crg-handoff')
    'pair' = (Join-Path $Binding.GitDir 'crg-pair')
  }
}

function New-CrgHostBinding {
  param([object]$Lease, [string]$Root, [string]$PrivateGitDir, [AllowNull()][byte[]]$Attachment,
    [AllowNull()][byte[]]$Pending, [AllowNull()][byte[]]$Handoff, [AllowNull()][byte[]]$Pair)
  $binding = [pscustomobject]@{ Schema = 1; Root = $Root; GitDir = $Lease.GitDir; CommonDir = $Lease.CommonDir; PrivateGitDir = $PrivateGitDir; Selectors = @() }
  $paths = Get-CrgHostSelectorPaths -Binding $binding
  $captured = @{ attachment = $Attachment; pending = $Pending; handoff = $Handoff; pair = $Pair }
  $states = foreach ($name in $paths.Keys) {
    $bytes = $null
    if ($captured.ContainsKey($name)) { $bytes = $captured[$name] } else { $bytes = $Lease.Read($paths[$name], 16384, $true) }
    if ($null -ne $bytes -and $name.EndsWith('-commondir', [StringComparison]::Ordinal)) {
      $directory = [IO.Path]::GetDirectoryName($paths[$name])
      $expected = if ([string]::Equals($name, 'public-commondir', [StringComparison]::Ordinal)) { $binding.CommonDir } else { $binding.PrivateGitDir }
      if (-not [string]::Equals([CrgTransport.NativeV2]::Indirection($bytes, '', $directory), $expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'host binding common-directory selector changed or selects another database' }
    }
    [pscustomobject]@{ Name = $name; Present = ($null -ne $bytes); Sha256 = $(if ($null -eq $bytes) { '-' } else { [CrgTransport.NativeV2]::Digest($bytes) }) }
  }
  $binding.Selectors = @($states)
  return $binding
}

function Read-CrgHostExecutionRequest {
  param([string]$Text)
  $envelope = ConvertFrom-Json -InputObject $Text -ErrorAction Stop
  Assert-CrgTransportProperties -Value $envelope -Names @('Request', 'Admission')
  $envelope.Request = Read-CrgHostRequest -Text (ConvertTo-Json -InputObject $envelope.Request -Depth 8 -Compress)
  $binding = $envelope.Admission
  Assert-CrgTransportProperties -Value $binding -Names @('Schema', 'Root', 'GitDir', 'CommonDir', 'PrivateGitDir', 'Selectors')
  if ($binding.Schema -isnot [int] -or $binding.Schema -ne 1) { throw 'invalid host admission schema' }
  foreach ($name in @('Root', 'GitDir', 'CommonDir', 'PrivateGitDir')) {
    $path = $binding.$name
    if ($path -isnot [string] -or $path.Length -gt 32767 -or $path -match '[\x00-\x1f\x7f]' -or -not [string]::Equals([CrgTransport.NativeV2]::LocalPath($path), $path, [StringComparison]::Ordinal)) { throw 'invalid host admission path' }
  }
  if (-not [string]::Equals($binding.Root, $envelope.Request.TargetRepo, [StringComparison]::OrdinalIgnoreCase)) { throw 'host admission target differs from the request' }
  if (-not [string]::IsNullOrEmpty($envelope.Request.Operation.PrivateGitDir) -and -not [string]::Equals($envelope.Request.Operation.PrivateGitDir, $binding.PrivateGitDir, [StringComparison]::OrdinalIgnoreCase)) { throw 'host admission private database differs from the explicit request' }
  $paths = Get-CrgHostSelectorPaths -Binding $binding
  if ($binding.Selectors -isnot [array] -or $binding.Selectors.Count -ne $paths.Count) { throw 'invalid host admission selectors' }
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($selector in $binding.Selectors) {
    Assert-CrgTransportProperties -Value $selector -Names @('Name', 'Present', 'Sha256')
    if ($selector.Name -isnot [string] -or -not [Linq.Enumerable]::Contains([string[]]@($paths.Keys), $selector.Name, [StringComparer]::Ordinal) -or -not $seen.Add($selector.Name) -or $selector.Present -isnot [bool] -or $selector.Sha256 -isnot [string]) { throw 'invalid host admission selector state' }
    if (($selector.Present -and $selector.Sha256 -cnotmatch '\A[0-9a-f]{64}\z') -or (-not $selector.Present -and -not [string]::Equals($selector.Sha256, '-', [StringComparison]::Ordinal))) { throw 'invalid host admission selector digest' }
  }
  return $envelope
}

function Assert-CrgHostLockedBinding {
  param([object]$State, [object]$OperationLock, [string[]]$ProjectRoots)
  $assert = @(Get-Command Assert-CrgPairedOperationLock -Module paired-diff -CommandType Function -ListImported)
  if ($assert.Count -ne 1) { throw 'host admission requires the retained operation-lock validator' }
  & $assert[0] -Lock $OperationLock
  $binding = $State.Binding
  if (-not [string]::Equals($OperationLock.PublicGitDirectory, $binding.GitDir, [StringComparison]::OrdinalIgnoreCase)) { throw 'operation lock differs from the admitted Git directory' }
  $allowed = [string[]]@($binding.Root, $binding.GitDir, $binding.CommonDir, $binding.PrivateGitDir)
  foreach ($root in $ProjectRoots) {
    if (-not [Linq.Enumerable]::Contains($allowed, $root, [StringComparer]::OrdinalIgnoreCase)) { throw 'operation roots exceed the admitted namespace' }
  }
  foreach ($previous in $State.LockStreams) { if ([object]::ReferenceEquals($previous, $OperationLock.Stream)) { return } }
  $lease = [CrgTransport.NativeV2]::CaptureNamespace($binding.Root)
  $retained = $false
  try {
    if (-not [string]::Equals($lease.GitDir, $binding.GitDir, [StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals($lease.CommonDir, $binding.CommonDir, [StringComparison]::OrdinalIgnoreCase)) { throw 'project Git namespace changed after host admission' }
    $paths = Get-CrgHostSelectorPaths -Binding $binding
    foreach ($selector in $binding.Selectors) {
      $bytes = $lease.Read($paths[$selector.Name], 65536, $selector.Name.EndsWith('-commondir', [StringComparison]::Ordinal))
      if (($null -ne $bytes) -ne $selector.Present -or ($null -ne $bytes -and -not [string]::Equals([CrgTransport.NativeV2]::Digest($bytes), $selector.Sha256, [StringComparison]::Ordinal))) { throw ('project selector changed after host admission: ' + $selector.Name) }
    }
    $State.Owners.Add($lease); $retained = $true
    $State.LockStreams.Add($OperationLock.Stream)
  } finally { if (-not $retained) { $lease.Dispose() } }
}

function Assert-CrgHostOperationRead {
  param([object]$State, [string]$Path, [object]$Record)
  if ($null -eq $Record -or $Record.Present -isnot [bool] -or ($Record.Present -and $Record.Bytes -isnot [byte[]])) { throw 'host admission requires a complete operation read record' }
  $binding = $State.Binding
  foreach ($leaf in @('crg-attachment', 'crg-attachment-pending')) {
    if ($Record.Present -and [string]::Equals($Path, (Join-Path $binding.GitDir $leaf), [StringComparison]::OrdinalIgnoreCase)) {
      $reader = @(Get-Command Read-CrgAttachmentBytes -Module private-governance -CommandType Function -ListImported)
      if ($reader.Count -ne 1) { throw 'host admission requires the retained attachment parser' }
      $attachment = & $reader[0] -Bytes $Record.Bytes
      if (-not [string]::Equals($attachment.PrivateGitDir, $binding.PrivateGitDir, [StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals($attachment.RuntimeStore, $State.Store, [StringComparison]::OrdinalIgnoreCase)) { throw 'operation attachment exceeds the admitted private database or store' }
    }
  }
  foreach ($pair in @(@($binding.GitDir, $binding.CommonDir), @($binding.PrivateGitDir, $binding.PrivateGitDir))) {
    if ($Record.Present -and [string]::Equals($Path, (Join-Path $pair[0] 'commondir'), [StringComparison]::OrdinalIgnoreCase) -and -not [string]::Equals([CrgTransport.NativeV2]::Indirection($Record.Bytes, '', $pair[0]), $pair[1], [StringComparison]::OrdinalIgnoreCase)) { throw 'operation common-directory selector exceeds the admitted database' }
  }
  return $Record
}

function New-CrgHostChildAdmission {
  param([object]$Binding, [string]$Store)
  $state = [pscustomobject]@{ Binding = $Binding; Store = $Store; Admission = $null; LockStreams = [Collections.Generic.List[IO.FileStream]]::new(); Owners = [Collections.Generic.List[object]]::new() }
  $assert = Get-Command Assert-CrgHostLockedBinding -CommandType Function
  $checkRead = Get-Command Assert-CrgHostOperationRead -CommandType Function
  $validate = { param($OperationLock, [string[]]$ProjectRoots) & $assert -State $state -OperationLock $OperationLock -ProjectRoots $ProjectRoots }.GetNewClosure()
  $protect = {
    param($Owner)
    $baseRead = $Owner.Runtime.ReadFile
    $readState = $state; $readValidator = $checkRead
    if ($baseRead -isnot [scriptblock]) { throw 'host admission cannot protect an invalid read owner' }
    $Owner.Runtime.ReadFile = {
      param([string]$Path, [int]$Maximum, [switch]$AllowAbsent)
      $record = & $baseRead -Path $Path -Maximum $Maximum -AllowAbsent:$AllowAbsent
      & $readValidator -State $readState -Path $Path -Record $record
    }.GetNewClosure()
    $Owner.Runtime | Add-Member -NotePropertyName HostAdmission -NotePropertyValue $state.Admission -Force
  }.GetNewClosure()
  $admission = [pscustomobject]@{ Binding = $Binding; State = $state; Validate = $validate; Protect = $protect }
  $state.Admission = $admission
  return $admission
}

function Close-CrgHostChildAdmission {
  param([object]$Admission)
  if ($null -ne $Admission) { for ($i = $Admission.State.Owners.Count - 1; $i -ge 0; $i--) { $Admission.State.Owners[$i].Dispose() } }
}

function Assert-CrgHostAssociation {
  param([IO.Pipes.NamedPipeServerStream]$Pipe, [object]$Lease, [object]$Request, [object]$Origin)
  foreach ($name in @('private-governance', 'paired-governance', 'paired-review-input', 'central-context', 'paired-retention', 'paired-diff', 'paired-operation')) {
    Import-Module -Name $Origin.Payloads[('scripts/' + $name + '.psm1')].Path -Force -Global -ErrorAction Stop
  }
  $root = $Request.TargetRepo; $gitDir = $Lease.GitDir; $common = $Lease.CommonDir
  $attachmentBytes = $Lease.Read((Join-Path $gitDir 'crg-attachment'), 16384, $true)
  $pendingBytes = $Lease.Read((Join-Path $gitDir 'crg-attachment-pending'), 16384, $false)
  # The 2026-10 admission attempt required mutual exclusion and blocked Resume:
  # activation precedes handoff removal and pending cleanup. Equal bytes still
  # require the retained receipt below; presence alone grants no authority.
  if ($null -ne $attachmentBytes -and $null -ne $pendingBytes -and -not [Linq.Enumerable]::SequenceEqual([byte[]]$attachmentBytes, [byte[]]$pendingBytes)) { throw 'host admission refuses conflicting active and pending attachments' }
  $associationBytes = $pendingBytes
  if ($null -ne $attachmentBytes) { $associationBytes = $attachmentBytes }
  $attachment = if ($null -ne $associationBytes) { Read-CrgAttachmentBytes -Bytes $associationBytes } else { $null }
  if ($null -ne $attachment -and -not [string]::IsNullOrEmpty($Request.Operation.PrivateGitDir) -and -not [string]::Equals($Request.Operation.PrivateGitDir, $attachment.PrivateGitDir, [StringComparison]::OrdinalIgnoreCase)) { throw 'explicit private database conflicts with the captured association' }
  $privateDir = if ($null -ne $attachment) { $attachment.PrivateGitDir } elseif (-not [string]::IsNullOrEmpty($Request.Operation.PrivateGitDir)) { $Request.Operation.PrivateGitDir } else { Join-Path $common 'crg-governance.git' }
  if ($null -ne $attachment -and -not [string]::Equals($attachment.RuntimeStore, $Origin.Store, [StringComparison]::OrdinalIgnoreCase)) { throw 'host admission attachment selects another store' }
  Assert-CrgPrivateStorageLocation -PublicRoot $root -PublicGitDir $gitDir -PublicCommonDir $common -PrivateGitDir $privateDir
  # Only a record located inside the selected common database proves that
  # database owns the worktree. A root-owned fake back-link proves nothing.
  if ($Lease.BackLink -and -not $Lease.CommonOwned) { [CrgTransport.NativeV2]::AuthorizeDatabase($Pipe, $Lease, $common, $true) }
  $pointerBytes = $Lease.Read((Join-Path $gitDir 'crg-pair'), 256, $false)
  $handoffBytes = $Lease.Read((Join-Path $gitDir 'crg-handoff'), 16384, $false)
  if ($null -eq $pointerBytes -and $null -eq $handoffBytes) {
    if ($null -ne $attachmentBytes) { throw 'host admission requires completed or recoverable attachment evidence' }
    # Main and linked worktrees have a reciprocal filesystem association. A
    # separate database without a receipt has no root binding; only a caller
    # already authorized to install into that database may establish one.
    if (-not $Lease.BackLink -and -not [string]::Equals($gitDir, (Join-Path $root '.git'), [StringComparison]::OrdinalIgnoreCase)) {
      [CrgTransport.NativeV2]::AuthorizeDatabase($Pipe, $Lease, $gitDir, $true)
    }
    $requiresWrite = -not $privateDir.StartsWith(($common.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)
    if ($requiresWrite -and $null -ne $pendingBytes) {
      $refKey = [CrgTransport.NativeV2]::Digest([Text.UTF8Encoding]::new($false).GetBytes($attachment.PrivateRef))
      $reciprocal = $Lease.Read((Join-Path $privateDir ('crg-association-' + $refKey)), 65536, $false)
      $key = [CrgTransport.NativeV2]::Digest($pendingBytes)
      $expected = "crg-private-association v1`npublic-git-dir $gitDir`nattachment-sha256 $key`n"
      if ($null -ne $reciprocal -and [string]::Equals([CrgTransport.NativeV2]::Decode($reciprocal), $expected, [StringComparison]::Ordinal)) { $requiresWrite = $false }
    }
    [CrgTransport.NativeV2]::AuthorizeDatabase($Pipe, $Lease, $privateDir, $requiresWrite)
    return New-CrgHostBinding -Lease $Lease -Root $root -PrivateGitDir $privateDir -Attachment $attachmentBytes -Pending $pendingBytes -Handoff $handoffBytes -Pair $pointerBytes
  }
  if ($null -eq $attachment) { throw 'host admission receipt lacks an active or pending association' }
  [CrgTransport.NativeV2]::AuthorizeDatabase($Pipe, $Lease, $privateDir, $false)
  $capture = @(Get-Command Read-CrgCentralBlobBytes -Module central-context -CommandType Function -ListImported)[0].Module
  $retention = @(Get-Command Read-CrgCompletedPairRetention -Module paired-retention -CommandType Function -ListImported)[0].Module
  $readLine = & $capture { Get-Command Get-CrgStatusGitLine -CommandType Function }
  $gitExe = & $capture { Get-CrgCentralGitExecutable }
  $executableModule = (Get-Command Open-CrgPairedExecutableRead -Module paired-operation -CommandType Function).Module
  $gitOwner = $null; $retainExecutable = $false
  try {
    $gitOwner = & $executableModule { param($Path) Open-CrgPairedExecutableRead -Path $Path } $gitExe
    # The namespace owner also retains actual executable handles if a metadata
    # child cannot be proved quiescent. A later runspace import cannot drop custody.
    $Lease.ExecutableCustody = & $executableModule { param($Owner) Get-CrgExecutableReadState -Owner $Owner } $gitOwner
    $domains = [ordered]@{}
    foreach ($domain in @('public', 'private')) {
      $directory = if ([string]::Equals($domain, 'public', [StringComparison]::Ordinal)) { $gitDir } else { $privateDir }
      $database = if ([string]::Equals($domain, 'public', [StringComparison]::Ordinal)) { $common } else { $privateDir }
      $indirection = $Lease.Read((Join-Path $directory 'commondir'), 16384, $true)
      $prefix = @("--git-dir=$directory", "--work-tree=$root")
      $actualCommon = (& $readLine -Arguments ($prefix + @('rev-parse', '--path-format=absolute', '--git-common-dir')) -GitExe $gitExe).Replace('/', '\')
      $objects = (& $readLine -Arguments ($prefix + @('rev-parse', '--path-format=absolute', '--git-path', 'objects')) -GitExe $gitExe).Replace('/', '\')
      if (-not [string]::Equals($actualCommon, $database, [StringComparison]::OrdinalIgnoreCase) -or -not [string]::Equals($objects, (Join-Path $database 'objects'), [StringComparison]::OrdinalIgnoreCase)) { throw 'host admission Git namespace differs from the retained association' }
      [CrgTransport.NativeV2]::AuthorizeDatabase($Pipe, $Lease, $objects, $false)
      foreach ($leaf in @('alternates', 'http-alternates')) {
        if ($null -ne $Lease.Read((Join-Path $objects ('info\' + $leaf)), 65536, $true)) { throw 'host admission refuses object alternates' }
      }
      $format = & $readLine -Arguments ($prefix + @('rev-parse', '--show-object-format')) -GitExe $gitExe
      if (-not [Linq.Enumerable]::Contains([string[]]@('sha1', 'sha256'), $format, [StringComparer]::Ordinal)) { throw 'host admission object format is unsupported' }
      $domains[$domain] = [pscustomobject]@{ GitDir = $directory; CommonDir = $database; ObjectDir = $objects; ObjectFormat = $format }
    }
    $receiptKey = ''; $originName = ''
    if ($null -ne $handoffBytes) {
      $handoff = & (Get-Command Read-CrgPairHandoffBytes -Module paired-governance).Module {
        param($Bytes)
        $lines = Read-CrgPairRecords -Bytes $Bytes -Maximum 16384
        $origin = if ([string]::Equals($lines[0], 'crg-first-attachment-handoff v1', [StringComparison]::Ordinal)) { 'first-attachment-v1' } elseif ([string]::Equals($lines[0], 'crg-handoff v1', [StringComparison]::Ordinal)) { 'paired-v1' } else { throw 'invalid host admission handoff origin' }
        $names = @(Get-CrgHandoffNames -Origin $origin)
        if ($lines.Count -ne $names.Count + 1) { throw 'invalid host admission handoff fields' }
        $fields = @{}
        for ($i = 0; $i -lt $names.Count; $i++) { $fields[$names[$i]] = Read-CrgPairField -Line $lines[$i + 1] -Name $names[$i] }
        return [pscustomobject]@{ Origin = $origin; ReceiptSha256 = $fields['receipt-sha256'] }
      } $handoffBytes
      $receiptKey = $handoff.ReceiptSha256; $originName = $handoff.Origin
    } else {
      $pointer = Read-CrgCompletedPairPointerBytes -Bytes $pointerBytes
      $receiptKey = $pointer.ReceiptSha256; $originName = $pointer.Origin
    }
    $project = [pscustomobject]@{ Schema = 1; Root = $root; GitExe = $gitExe; Domains = $domains }
    $record = & $retention { param($Project, $Key, $OriginName) Read-CrgRetentionRecord -ProjectContext $Project -ReceiptSha256 $Key -ExpectedOrigin $OriginName } $project $receiptKey $originName
    $expected = @{ 'project-id' = $attachment.ProjectId; 'public-git-dir' = $gitDir; 'public-common-dir' = $common; 'private-git-dir' = $privateDir; 'public-ref' = $attachment.PublicRef; 'private-ref' = $attachment.PrivateRef }
    if (-not $Lease.BackLink) { $expected['public-worktree'] = $root }
    $expected['attachment-sha256'] = [CrgTransport.NativeV2]::Digest($associationBytes)
    foreach ($name in $expected.Keys) {
      if (-not [string]::Equals($record.Receipt.Fields[$name], $expected[$name], [StringComparison]::Ordinal)) { throw "host admission receipt association differs at '$name'" }
    }
    if ($null -ne $handoffBytes) {
      $reader = if ([string]::Equals($originName, 'first-attachment-v1', [StringComparison]::Ordinal)) { 'Read-CrgFirstAttachmentHandoffBytes' } else { 'Read-CrgPairHandoffBytes' }
      $null = & (Get-Command $reader -Module paired-governance) -Bytes $handoffBytes -ReceiptBytes $record.ReceiptBytes -PublicObjectFormat $domains.public.ObjectFormat -PrivateObjectFormat $domains.private.ObjectFormat
    }
    return New-CrgHostBinding -Lease $Lease -Root $root -PrivateGitDir $privateDir -Attachment $attachmentBytes -Pending $pendingBytes -Handoff $handoffBytes -Pair $pointerBytes
  } catch {
    $cause = $_.Exception
    while ($null -ne $cause) {
      if ($cause.Data.Contains('CrgUncertainGitChild')) { $retainExecutable = $true; break }
      $cause = $cause.InnerException
    }
    throw
  } finally {
    if ($null -ne $gitOwner -and -not $retainExecutable) {
      try {
        & $executableModule { param($Owner) Close-CrgPairedExecutableRead -Owner $Owner } $gitOwner
        $Lease.ExecutableCustody = $null
      } catch {
        [CrgTransport.NativeV2]::RetainAdmission($Lease, $_.Exception)
        $_.Exception.Data['CrgHostRetained'] = $true
        throw
      }
    }
  }
}

function Invoke-CrgHostConnection {
  param([IO.Pipes.NamedPipeServerStream]$Pipe, [string]$LauncherPath, [object]$Origin)
  $lease = $null; $retained = $false; $executionAttempted = $false
  try {
    $frame = [CrgTransport.NativeV2]::ReadFrame($Pipe, 10000)
    if ($frame.Kind -eq 6 -and $frame.Bytes.Length -eq 0) { [CrgTransport.NativeV2]::WriteFrame($Pipe, 6, [byte[]]@()); return }
    if ($frame.Kind -ne 1) { throw 'invalid local gate request frame' }
    $text = [CrgTransport.NativeV2]::Decode($frame.Bytes)
    $request = Read-CrgHostRequest -Text $text
    $lease = [CrgTransport.NativeV2]::Authorize($Pipe, $request.TargetRepo)
    $binding = Assert-CrgHostAssociation -Pipe $Pipe -Lease $lease -Request $request -Origin $Origin
    $text = ConvertTo-Json -InputObject ([pscustomobject]@{ Request = $request; Admission = $binding }) -Depth 12 -Compress
    if ([CrgTransport.NativeV2]::Encode($text).Length -gt [CrgTransport.NativeV2]::MaximumFrame) { throw 'owned gate request exceeds the protocol bound' }
    [CrgTransport.NativeV2]::WriteFrame($Pipe, 7, [byte[]]@())
    $executionAttempted = $true
    $null = [CrgTransport.NativeV2]::Execute($Pipe, $LauncherPath, $request.TargetRepo, $text, $lease)
  } catch {
    $failure = $_.Exception; $started = $executionAttempted
    while ($null -ne $failure) {
      if ($failure.Data.Contains('CrgHostRetained')) { $retained = $true }
      if ($failure.Data.Contains('CrgHostChildStarted')) { $started = $true }
      if ($failure.Data.Contains('CrgUncertainGitChild') -and $null -ne $lease -and -not $retained) { [CrgTransport.NativeV2]::RetainAdmission($lease, $_.Exception); $retained = $true }
      $failure = $failure.InnerException
    }
    $kind = if ($started) { 8 } else { 5 }
    try { [CrgTransport.NativeV2]::WriteFrame($Pipe, $kind, [CrgTransport.NativeV2]::Encode($_.Exception.Message)) } catch { }
  } finally {
    if ($null -ne $lease -and -not $retained) { $lease.Dispose() }
    $Pipe.Dispose()
  }
}

function Test-CrgHostAvailable {
  param([string]$Store)
  $pipe = $null
  try {
    $pipe = [CrgTransport.NativeV2]::Connect([CrgTransport.NativeV2]::PipeName($Store), 500)
    [CrgTransport.NativeV2]::WriteFrame($pipe, 6, [byte[]]@())
    $frame = [CrgTransport.NativeV2]::ReadFrame($pipe, 2000)
    if ($frame.Kind -eq 6 -and $frame.Bytes.Length -eq 0) { return $true }
    return ($frame.Kind -eq 5 -and [string]::Equals([CrgTransport.NativeV2]::Decode($frame.Bytes), 'Local gate worker capacity exhausted; operation not started', [StringComparison]::Ordinal))
  } catch { return $false }
  finally { if ($null -ne $pipe) { $pipe.Dispose() } }
}

function Complete-CrgHostWorker {
  param([object]$Job)
  if ($null -eq $Job.Result) {
    $state = $Job.PowerShell.InvocationStateInfo.State
    if ($state -notin @('NotStarted', 'Completed', 'Failed', 'Stopped')) { return $false }
  } elseif (-not $Job.Result.IsCompleted) { return $false }
  try {
    if ($null -ne $Job.Result) { $null = $Job.PowerShell.EndInvoke($Job.Result) }
    if ($Job.PowerShell.HadErrors) { Write-Warning -Message 'Local gate worker reported an error; connection outcome remains authoritative' -WarningAction Continue }
  } catch { Write-Warning -Message ('Local gate worker failed: ' + $_.Exception.Message) -WarningAction Continue }
  finally {
    try { $Job.Pipe.Dispose() } catch { Write-Warning -Message ('Local gate connection cleanup failed: ' + $_.Exception.Message) -WarningAction Continue }
    try { $Job.PowerShell.Dispose() } catch { Write-Warning -Message ('Local gate worker cleanup failed: ' + $_.Exception.Message) -WarningAction Continue }
  }
  return $true
}

function Start-CrgLocalHost {
  param([string]$Store, [string]$LauncherPath, [string]$ModulePath, [object]$Origin)
  $listener = $null; $pool = $null; $inputPinned = $false; $priorInput = $null
  $jobs = [Collections.Generic.List[object]]::new()
  try {
    $priorInput = [CrgTransport.NativeV2]::PinHostInput(); $inputPinned = $true
    $capture = Import-Module -Name $Origin.Payloads['scripts/central-context.psm1'].Path -PassThru -ErrorAction Stop
    # Native types are process-wide while worker module scopes are separate.
    # Compile the shared bounded reader before concurrent admissions can race.
    & $capture { Initialize-CrgBoundedSinkNative }
    $native = Import-Module -Name $Origin.Payloads['scripts/paired-diff.psm1'].Path -PassThru -ErrorAction Stop
    & $native { Initialize-CrgAttributeNeutralNative }
    $name = [CrgTransport.NativeV2]::PipeName($Store)
    $listener = [CrgTransport.NativeV2]::Listen($name, $true)
    $pool = [runspacefactory]::CreateRunspacePool(1, 8); $pool.Open()
    while ($true) {
      try { $listener.WaitForConnection() }
      catch [IO.IOException] {
        $next = [CrgTransport.NativeV2]::Listen($name, $false)
        $listener.Dispose(); $listener = $next
        continue
      }
      for ($i = $jobs.Count - 1; $i -ge 0; $i--) {
        if (Complete-CrgHostWorker -Job $jobs[$i]) { $jobs.RemoveAt($i) }
      }
      $connected = $listener
      $listener = [CrgTransport.NativeV2]::Listen($name, $false)
      if (($jobs.Count + [CrgTransport.NativeV2]::RetainedChildren()) -ge 8) {
        try { [CrgTransport.NativeV2]::WriteFrame($connected, 5, [CrgTransport.NativeV2]::Encode('Local gate worker capacity exhausted; operation not started')) }
        catch { Write-Warning -Message ('Local gate capacity refusal could not be delivered: ' + $_.Exception.Message) -WarningAction Continue }
        finally { try { $connected.Dispose() } catch { Write-Warning -Message ('Local gate connection cleanup failed: ' + $_.Exception.Message) -WarningAction Continue } }
        continue
      }
      $worker = $null; $job = $null
      try {
        $worker = [powershell]::Create(); $worker.RunspacePool = $pool
        $null = $worker.AddScript('param($ModulePath,$Pipe,$LauncherPath,$Origin) try { Import-Module -Name $ModulePath -ErrorAction Stop; Invoke-CrgHostConnection -Pipe $Pipe -LauncherPath $LauncherPath -Origin $Origin } catch { try { [CrgTransport.NativeV2]::WriteFrame($Pipe,8,[CrgTransport.NativeV2]::Encode($_.Exception.Message)) } catch { } finally { try { $Pipe.Dispose() } catch { } } }').AddArgument($ModulePath).AddArgument($connected).AddArgument($LauncherPath).AddArgument($Origin)
        # Record ownership before starting. A start failure with an uncertain
        # invocation state keeps the worker rather than cancelling a mutation.
        $job = [pscustomobject]@{ PowerShell = $worker; Result = $null; Pipe = $connected }
        $jobs.Add($job)
        $job.Result = $worker.BeginInvoke()
      } catch {
        Write-Warning -Message ('Local gate worker launch failed: ' + $_.Exception.Message) -WarningAction Continue
        if ($null -ne $job) {
          if (Complete-CrgHostWorker -Job $job) { $null = $jobs.Remove($job) }
        } else {
          try { [CrgTransport.NativeV2]::WriteFrame($connected, 5, [CrgTransport.NativeV2]::Encode('Local gate worker could not be created; operation not started')) } catch { }
          finally {
            try { $connected.Dispose() } catch { }
            if ($null -ne $worker) { try { $worker.Dispose() } catch { } }
          }
        }
      }
    }
  } finally {
    if ($null -ne $listener) { try { $listener.Dispose() } catch { Write-Warning -Message $_.Exception.Message -WarningAction Continue } }
    # Connection failures cannot skip later owners. Unconfirmed readers retain
    # the host and namespace; explicit process termination remains external.
    while ($jobs.Count -gt 0 -or [CrgTransport.NativeV2]::RetainedChildren() -gt 0) {
      for ($i = $jobs.Count - 1; $i -ge 0; $i--) {
        try { if (Complete-CrgHostWorker -Job $jobs[$i]) { $jobs.RemoveAt($i) } }
        catch { Write-Warning -Message ('Local gate worker completion remains unconfirmed: ' + $_.Exception.Message) -WarningAction Continue }
      }
      if ($jobs.Count -gt 0 -or [CrgTransport.NativeV2]::RetainedChildren() -gt 0) { [Threading.Thread]::Sleep(1000) }
    }
    try { if ($null -ne $pool) { $pool.Dispose() } }
    finally { if ($inputPinned) { [CrgTransport.NativeV2]::RestoreHostInput($priorInput) } }
  }
}

Export-ModuleMember -Function Read-CrgHostRequest, Read-CrgHostExecutionRequest, New-CrgHostChildAdmission, Close-CrgHostChildAdmission, Invoke-CrgHostClient, Invoke-CrgHostConnection, Test-CrgHostAvailable, Start-CrgLocalHost
