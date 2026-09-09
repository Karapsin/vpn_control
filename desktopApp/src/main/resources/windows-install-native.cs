// Captured into the fixed OS PowerShell bootstrap before elevation; never loaded by elevated -File.
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using System.Text;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;

public static class VpnInstallNative {
    const uint ReadControl = 0x20000, ReadAttributes = 0x80;
    [StructLayout(LayoutKind.Sequential)] public struct SecurityAttributes {
        public int Length; public IntPtr Descriptor; public int Inherit;
    }
    [StructLayout(LayoutKind.Sequential)] struct Overlapped {
        public IntPtr Internal, InternalHigh; public uint Offset, OffsetHigh; public IntPtr Event;
    }
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool LockFileEx(SafeFileHandle file, uint flags,
        uint reserved, uint length, uint lengthHigh, ref Overlapped overlapped);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UnlockFileEx(SafeFileHandle file,
        uint reserved, uint length, uint lengthHigh, ref Overlapped overlapped);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateDirectoryW(string path, ref SecurityAttributes security);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, byte[] data, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint GetFileType(SafeFileHandle file);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool GetVolumeInformationByHandleW(SafeFileHandle file, IntPtr volume, uint volumeSize,
        IntPtr serial, IntPtr componentLength, out uint flags, IntPtr systemName, uint systemNameSize);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern int LCMapStringEx(string locale, uint flags, string input, int length, IntPtr output,
        int capacity, IntPtr version, IntPtr reserved, IntPtr parameter);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle file, int kind, uint information,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder name, ref uint length);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("shell32.dll")] static extern int SHGetKnownFolderPath(ref Guid id, uint flags, IntPtr token, out IntPtr result);
    [DllImport("ole32.dll")] static extern void CoTaskMemFree(IntPtr memory);
    [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { public IntPtr Status; public UIntPtr Information; }
    [DllImport("ntdll.dll")] static extern int NtSetInformationFile(SafeFileHandle file,
        out IoStatusBlock status, IntPtr information, uint length, int informationClass);
    [DllImport("ntdll.dll")] static extern uint RtlNtStatusToDosError(int status);

    // Same-assembly disposal seam. Production always supplies the fixed closer;
    // no request or environment can replace it.
    internal interface IProcessPinCloseNative { bool Close(IntPtr handle); }
    sealed class FixedProcessPinCloseNative : IProcessPinCloseNative {
        public bool Close(IntPtr handle) { return CloseHandle(handle); }
    }
    public sealed class ProcessPin : IDisposable {
        IntPtr handle;
        readonly IProcessPinCloseNative closer;
        public readonly uint Pid;
        public readonly string Image;
        public readonly string Principal;
        public readonly long StartedAtEpochMillis;
        public ProcessPin(uint pid) : this(pid,new FixedProcessPinCloseNative(),null) { }
        internal ProcessPin(uint pid,IProcessPinCloseNative closeNative) : this(pid,closeNative,null) { }
        // Same-assembly test seam after the real process handle is opened. Production has no callback.
        internal ProcessPin(uint pid,IProcessPinCloseNative closeNative,Action afterOpen) {
            if (closeNative==null) throw new ArgumentException("Process close native unavailable");
            closer=closeNative;
            handle=OpenProcess(0x00101000, false, pid); // synchronize + query limited information
            if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                long created, exited, kernel, user;
                if (!GetProcessTimes(handle, out created, out exited, out kernel, out user)) throw new Win32Exception();
                StartedAtEpochMillis=(created-116444736000000000L)/10000;
                StringBuilder image=new StringBuilder(32768); uint length=32768;
                if (!QueryFullProcessImageNameW(handle, 0, image, ref length)) throw new Win32Exception();
                Image=image.ToString(); Pid=pid;
                IntPtr token;
                if (!OpenProcessToken(handle, 8, out token)) throw new Win32Exception();
                try { using (WindowsIdentity identity=new WindowsIdentity(token)) { Principal=identity.User.Value; } }
                finally { CloseHandle(token); }
                if (afterOpen!=null) afterOpen();
            } catch (Exception admissionFailure) {
                // Construction cannot return a retry owner. Preserve the admission cause;
                // a helper-process exit reclaims an unclosed handle and the marker records it.
                if (handle!=IntPtr.Zero) {
                    try {
                        if (closer.Close(handle)) handle=IntPtr.Zero;
                        else admissionFailure.Data["vpn.install.processPin.constructionCleanupUncertain"]=true;
                    } catch (Exception closeFailure) {
                        admissionFailure.Data["vpn.install.processPin.constructionCleanupUncertain"]=closeFailure.GetType().FullName;
                    }
                }
                throw;
            }
        }
        public bool Exited { get {
            if (handle == IntPtr.Zero) throw new ObjectDisposedException("ProcessPin");
            uint result=WaitForSingleObject(handle, 0);
            if (result == 0) return true;
            if (result == 258) return false;
            throw new IOException("Installer process identity unavailable");
        } }
        public string LocalAppData() {
            if (handle == IntPtr.Zero) throw new ObjectDisposedException("ProcessPin");
            IntPtr token;
            if (!OpenProcessToken(handle, 12, out token)) throw new Win32Exception();
            try { return KnownFolder("F1B32785-6FBA-4FCF-9D55-7B8E7F157091", token); }
            finally { CloseHandle(token); }
        }
        public void Dispose() {
            if (handle==IntPtr.Zero) return;
            // A failed close leaves this exact handle retained for an explicit retry.
            if (!closer.Close(handle)) throw new IOException("Process pin close unavailable");
            handle=IntPtr.Zero;
        }
    }
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint GetProcessId(IntPtr process);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int information,
        IntPtr buffer, uint length, out uint returned);

    // The public inventory path accepts only a PID. The internal native reader is a
    // same-assembly regression seam, never selected by a worker argument or request.
    internal interface IProcessImageNative {
        IntPtr Open(uint pid);
        ProcessImageStamp Stamp(IntPtr handle);
        string Image(IntPtr handle);
        byte[] Snapshot();
        void Close(IntPtr handle);
    }
    internal sealed class ProcessImageStamp {
        internal readonly uint Pid;
        internal readonly long Created, Exited;
        internal ProcessImageStamp(uint pid, long created, long exited) {
            Pid=pid; Created=created; Exited=exited;
        }
    }
    public sealed class ProcessImageObservation {
        public readonly uint Pid;
        public readonly long CreationFileTime;
        public readonly string Image;
        public readonly bool KernelOnly;
        internal ProcessImageObservation(uint pid, long created, string image, bool kernelOnly) {
            Pid=pid; CreationFileTime=created; Image=image; KernelOnly=kernelOnly;
        }
        public override string ToString() { return "ProcessImageObservation(redacted)"; }
    }
    public sealed class ProcessImagePin : IDisposable {
        readonly uint pid;
        readonly IProcessImageNative native;
        IntPtr handle;
        public ProcessImagePin(uint processId) : this(processId,new FixedProcessImageNative()) { }
        internal ProcessImagePin(uint processId, IProcessImageNative reader) {
            if (processId==0 || reader==null) throw new ArgumentException("Invalid process identity");
            pid=processId; native=reader;
            // No fallible inspection occurs in construction after ownership is acquired.
            // The caller retains this object before observing the process.
            handle=native.Open(pid);
            if (handle==IntPtr.Zero) throw new IOException("Process handle unavailable");
        }
        public ProcessImageObservation Observe() {
            if (handle==IntPtr.Zero) throw new ObjectDisposedException("ProcessImagePin");
            ProcessImageStamp before=native.Stamp(handle);
            RequireStamp(before,pid,0);
            string image=native.Image(handle);
            bool kernelOnly=false;
            if (image==null) {
                byte[] snapshot=native.Snapshot();
                try { kernelOnly=MatchKernelProcess(snapshot,pid,before.Created); }
                finally { if (snapshot!=null) Array.Clear(snapshot,0,snapshot.Length); }
                if (!kernelOnly) throw new IOException("Process executable identity unavailable");
            } else if (image.Length==0) throw new IOException("Empty process executable identity");
            // Snapshot and executable path must refer to this same retained generation.
            // A late query failure or exit cannot turn an unknown process into absence.
            RequireStamp(native.Stamp(handle),pid,before.Created);
            return new ProcessImageObservation(pid,before.Created,image,kernelOnly);
        }
        public void Dispose() {
            if (handle==IntPtr.Zero) return;
            native.Close(handle); // A failed close retains the exact handle for retry.
            handle=IntPtr.Zero;
        }
        public override string ToString() { return "ProcessImagePin(redacted)"; }
        static void RequireStamp(ProcessImageStamp stamp, uint expectedPid, long expectedCreation) {
            if (stamp==null || stamp.Pid!=expectedPid || stamp.Created<=0 || stamp.Exited!=0 ||
                expectedCreation!=0 && stamp.Created!=expectedCreation)
                throw new IOException("Retained process identity changed or exited");
        }
    }
    const int MaxProcessSnapshot=64*1024*1024;
    sealed class FixedProcessImageNative : IProcessImageNative {
        public IntPtr Open(uint pid) {
            IntPtr result=OpenProcess(0x1000,false,pid);
            if (result==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            return result;
        }
        public ProcessImageStamp Stamp(IntPtr handle) {
            uint pid=GetProcessId(handle);
            if (pid==0) throw new Win32Exception(Marshal.GetLastWin32Error());
            long created,exited,kernel,user;
            if (!GetProcessTimes(handle,out created,out exited,out kernel,out user))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return new ProcessImageStamp(pid,created,exited);
        }
        public string Image(IntPtr handle) {
            StringBuilder image=new StringBuilder(32768); uint length=32768;
            // The failure code carries no classification authority. Any failed image
            // lookup requires independent kernel evidence and the retained tuple.
            return QueryFullProcessImageNameW(handle,0,image,ref length) ? image.ToString() : null;
        }
        public byte[] Snapshot() {
            if (IntPtr.Size!=8) throw new IOException("Process classification layout unavailable");
            int size=65536;
            for (int attempt=0;attempt<12;attempt++) {
                IntPtr buffer=Marshal.AllocHGlobal(size);
                try {
                    uint returned;
                    int status=NtQuerySystemInformation(148,buffer,(uint)size,out returned);
                    if (status==0) {
                        if (returned<308 || returned>size) throw new IOException("Invalid process snapshot length");
                        byte[] bytes=new byte[returned];
                        Marshal.Copy(buffer,bytes,0,(int)returned); return bytes;
                    }
                    if (status!=unchecked((int)0xC0000004)) throw new IOException("Process classification unavailable");
                    long needed=Math.Max((long)size*2,(long)returned+65536);
                    if (needed>MaxProcessSnapshot) throw new IOException("Process snapshot resource limit");
                    size=(int)needed;
                } finally { Marshal.FreeHGlobal(buffer); }
            }
            throw new IOException("Process snapshot changed during bounded capture");
        }
        public void Close(IntPtr handle) {
            if (!CloseHandle(handle)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
    // SystemFullProcessInformation (148), x64 SYSTEM_PROCESS_INFORMATION (256)
    // plus SYSTEM_EXTENDED_THREAD_INFORMATION (136 each), then extension Flags+48.
    // These private NT layouts are deliberately fail-closed on unknown bounds/flags;
    // they grant no authority from process names, PIDs, or image-query error codes.
    // Reference: winsiderss/phnt ntexapi.h, SYSTEM_PROCESS_INFORMATION_EXTENSION.
    static bool MatchKernelProcess(byte[] bytes, uint processId, long created) {
        if (IntPtr.Size!=8 || bytes==null || bytes.Length<308 || bytes.Length>MaxProcessSnapshot)
            throw new IOException("Process classification layout unavailable");
        HashSet<uint> ids=new HashSet<uint>();
        bool found=false, kernelOnly=false;
        long offset=0;
        while (true) {
            if (offset>bytes.Length-308) throw new IOException("Truncated process record");
            int start=(int)offset;
            uint next=BitConverter.ToUInt32(bytes,start);
            long end=next==0 ? bytes.Length : offset+next;
            if (next!=0 && next<308 || end>bytes.Length || end<=offset)
                throw new IOException("Invalid process record bounds");
            ulong id=BitConverter.ToUInt64(bytes,start+80);
            long generation=BitConverter.ToInt64(bytes,start+32);
            if (id>uint.MaxValue || !ids.Add((uint)id)) throw new IOException("Invalid process snapshot identity");
            long extension=offset+256L+136L*BitConverter.ToUInt32(bytes,start+4);
            if (extension>end-52) throw new IOException("Invalid process extension bounds");
            uint flags=BitConverter.ToUInt32(bytes,(int)extension+48);
            int classification=(int)((flags>>1)&15);
            if ((flags&~63U)!=0 || classification>=5) throw new IOException("Unknown process classification");
            if (id==processId) {
                if (generation!=created) throw new IOException("Process snapshot generation mismatch");
                found=true; kernelOnly=classification==3 || classification==4;
            }
            // Native variable-length records need not be padded to eight bytes.
            if (next==0) break;
            offset=end;
        }
        if (!found) throw new IOException("Process snapshot identity missing");
        return kernelOnly;
    }

    public static string ProgramData() { return KnownFolder("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97", IntPtr.Zero); }
    public static string ProcessImage(uint pid) {
        IntPtr process=OpenProcess(0x1000,false,pid);
        if (process==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            StringBuilder image=new StringBuilder(32768); uint length=32768;
            if (!QueryFullProcessImageNameW(process,0,image,ref length)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return image.ToString();
        } finally { CloseHandle(process); }
    }
    public static string InstallationId(SafeFileHandle directory) {
        StringBuilder path=new StringBuilder(32768);
        uint count=GetFinalPathNameByHandleW(directory,path,32768,0);
        if (count==0 || count>=32768) throw new IOException("Installer path identity unavailable");
        string actual=path.ToString();
        int size=LCMapStringEx("",0x200,actual,actual.Length,IntPtr.Zero,0,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);
        if (size<=0 || size>65536) throw new IOException("Installer path normalization unavailable");
        // A positive source length produces NO terminating NUL. StringBuilder marshaling
        // otherwise reads beyond the mapped characters and makes the gate identity unstable.
        string upper;
        IntPtr output=Marshal.AllocHGlobal(checked(size*2));
        try {
            if (LCMapStringEx("",0x200,actual,actual.Length,output,size,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero)!=size)
                throw new IOException("Installer path normalization unavailable");
            upper=Marshal.PtrToStringUni(output,size);
        } finally { Marshal.FreeHGlobal(output); }
        byte[] hash;
        using (SHA256 digest=SHA256.Create()) { hash=digest.ComputeHash(new UTF8Encoding(false,true).GetBytes(upper)); }
        string hex=BitConverter.ToString(hash,0,16).Replace("-","").ToLowerInvariant();
        return hex.Substring(0,8)+"-"+hex.Substring(8,4)+"-"+hex.Substring(12,4)+"-"+hex.Substring(16,4)+"-"+hex.Substring(20,12);
    }
    static string KnownFolder(string id, IntPtr token) {
        Guid identifier=new Guid(id); IntPtr result;
        int error=SHGetKnownFolderPath(ref identifier, 0, token, out result);
        if (error != 0) throw new IOException("Installer known folder unavailable");
        try { return Marshal.PtrToStringUni(result); } finally { CoTaskMemFree(result); }
    }

    public static SafeFileHandle OpenDirectory(string path) {
        // Metadata-only handles do NOT prevent deletion despite a missing FILE_SHARE_DELETE.
        // FILE_LIST_DIRECTORY/FILE_READ_DATA activates the sharing guarantees used by pins.
        SafeFileHandle file = CreateFileW(path, 1 | ReadControl | ReadAttributes, 1, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (file.IsInvalid) { file.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        return file;
    }
    public static SafeFileHandle OpenRead(string path, bool cancellation) {
        SafeFileHandle file = CreateFileW(path, 0x80000000 | ReadControl | ReadAttributes,
            cancellation ? 3u : 1u, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        if (file.IsInvalid) { file.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        return file;
    }
    // The coordinator borrows a strictly admitted directory. Metadata handles retain
    // exact sibling identities but share writes/deletion so they do not obstruct MSI.
    public sealed class ExecutableReplacementSet : IDisposable {
        readonly SafeFileHandle directory;
        readonly string directoryPath, directoryIdentity, principal;
        readonly string[] paths = new string[2], identities = new string[2];
        readonly List<SafeFileHandle> captured = new List<SafeFileHandle>();
        readonly List<SafeFileHandle> readiness = new List<SafeFileHandle>();
        bool disposed;
        public ExecutableReplacementSet(SafeFileHandle installation, string inputPrincipal) {
            directory=installation; principal=inputPrincipal;
            Inspect(directory,true,false,principal);
            directoryPath=FinalPath(directory).TrimEnd('\\');
            directoryIdentity=ObjectIdentity(directory,true);
            try {
                string[] names={"vpn-control.exe","vpn-control-cli.exe"};
                for (int index=0;index<names.Length;index++) {
                    paths[index]=directoryPath+"\\"+names[index];
                    SafeFileHandle file=OpenImageMetadata(paths[index]); captured.Add(file);
                    Inspect(file,false,false,principal);
                    if (!String.Equals(Path.GetDirectoryName(FinalPath(file)),directoryPath,StringComparison.OrdinalIgnoreCase))
                        throw new IOException("CONFLICT");
                    identities[index]=ObjectIdentity(file,false);
                }
            } catch { try { Dispose(); } catch { } throw; }
        }
        public bool ContainsImage(string path) {
            if (disposed) throw new ObjectDisposedException("ExecutableReplacementSet");
            // Compare native object IDs, including aliases whose basename is an 8.3 name.
            // An unavailable image is unknown to the caller, never evidence of absence.
            using (SafeFileHandle image=OpenImageMetadata(path)) {
                string identity=ObjectIdentity(image,false);
                return String.Equals(identity,identities[0],StringComparison.Ordinal) ||
                    String.Equals(identity,identities[1],StringComparison.Ordinal);
            }
        }
        // Caller holds the protected gate's exclusive byte 0 throughout this call
        // and subsequent replacement. Both probes close before MSI, because a
        // retained WRITE handle would itself prevent normal publication/replacement.
        public bool TryReady() {
            if (disposed) throw new ObjectDisposedException("ExecutableReplacementSet");
            CloseExact(readiness);
            if (ObjectIdentity(directory,true)!=directoryIdentity || FinalPath(directory).TrimEnd('\\')!=directoryPath)
                throw new IOException("CONFLICT");
            try {
                for (int index=0;index<paths.Length;index++) {
                    SafeFileHandle file=CreateFileW(paths[index],0x40020080,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
                    if (file.IsInvalid) {
                        int code=Marshal.GetLastWin32Error(); file.Dispose();
                        // Mapped executable sections can report ACCESS_DENIED; neither
                        // it nor sharing/lock contention establishes replacement readiness.
                        if (code==5 || code==32 || code==33) return false;
                        throw new Win32Exception(code);
                    }
                    readiness.Add(file);
                    Inspect(file,false,false,principal);
                    if (ObjectIdentity(file,false)!=identities[index] ||
                        !String.Equals(Path.GetDirectoryName(FinalPath(file)),directoryPath,StringComparison.OrdinalIgnoreCase))
                        throw new IOException("CONFLICT");
                }
                return true;
            } finally { CloseExact(readiness); }
        }
        public void Dispose() {
            Exception failure=null;
            try { CloseExact(readiness); } catch (Exception error) { failure=error; }
            try { CloseExact(captured); } catch (Exception error) { if (failure==null) failure=error; }
            disposed=readiness.Count==0 && captured.Count==0;
            if (failure!=null) throw failure;
        }
        static void CloseExact(List<SafeFileHandle> handles) {
            Exception failure=null;
            for (int index=handles.Count-1;index>=0;index--) {
                SafeFileHandle handle=handles[index];
                if (!CloseHandle(handle.DangerousGetHandle())) {
                    if (failure==null) failure=new Win32Exception(Marshal.GetLastWin32Error());
                    continue; // Keep failed native ownership available for explicit retry.
                }
                handle.SetHandleAsInvalid(); handle.Dispose(); handles.RemoveAt(index);
            }
            if (failure!=null) throw failure;
        }
    }
    static SafeFileHandle OpenImageMetadata(string path) {
        SafeFileHandle file=CreateFileW(path,ReadControl|ReadAttributes,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
        if (file.IsInvalid) { int code=Marshal.GetLastWin32Error(); file.Dispose(); throw new Win32Exception(code); }
        return file;
    }
    static string ObjectIdentity(SafeFileHandle file,bool directory) {
        byte[] attributes=new byte[8], identity=new byte[24];
        if (GetFileType(file)!=1 || !GetFileInformationByHandleEx(file,9,attributes,8) ||
            !GetFileInformationByHandleEx(file,18,identity,24)) throw new IOException("Native image identity unavailable");
        uint flags=BitConverter.ToUInt32(attributes,0);
        if ((flags&0x400)!=0 || BitConverter.ToUInt32(attributes,4)!=0 || ((flags&0x10)!=0)!=directory)
            throw new IOException("Native image identity rejected");
        return BitConverter.ToString(identity);
    }
    public static SafeFileHandle OpenReceipt(string path) {
        // Protected status is atomically replaced; a retained reader keeps its old
        // object. Private input/package reads above must continue denying deletion.
        SafeFileHandle file=CreateFileW(path,0x80000000 | ReadControl | ReadAttributes,
            5,IntPtr.Zero,3,0x00200000,IntPtr.Zero); // FILE_SHARE_READ | FILE_SHARE_DELETE
        if (file.IsInvalid) { file.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        return file;
    }
    public static FileStream CreateFile(string path, string sddl, byte[] initial) {
        if (initial == null || initial.Length > 65536) throw new ArgumentException("Installer file size rejected");
        IntPtr descriptor; uint size;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, out size)) throw new Win32Exception();
        IntPtr pointer=IntPtr.Zero;
        try {
            SecurityAttributes attributes=new SecurityAttributes { Length=Marshal.SizeOf<SecurityAttributes>(), Descriptor=descriptor };
            pointer=Marshal.AllocHGlobal(attributes.Length); Marshal.StructureToPtr(attributes, pointer, false);
            SafeFileHandle file=CreateFileW(path, 0xC0020080, 3, pointer, 1, 0x80200000, IntPtr.Zero);
            if (file.IsInvalid) { file.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
            FileStream stream=null;
            try {
                stream=new FileStream(file, FileAccess.ReadWrite, 1, false);
                stream.Write(initial, 0, initial.Length); stream.Flush(true); stream.Position=0;
                return stream;
            } catch { if (stream != null) stream.Dispose(); else file.Dispose(); throw; }
        } finally { if (pointer != IntPtr.Zero) Marshal.FreeHGlobal(pointer); LocalFree(descriptor); }
    }
    public static FileStream OpenGate(string path, bool write) {
        SafeFileHandle file=CreateFileW(path, (write ? 0xC0000000u : 0x80000000u) | ReadControl | ReadAttributes,
            3, IntPtr.Zero, 3, 0x80200000, IntPtr.Zero);
        if (file.IsInvalid) { file.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        try { return new FileStream(file, write ? FileAccess.ReadWrite : FileAccess.Read, 1, false); }
        catch { file.Dispose(); throw; }
    }
    // Original-user records become visible only after their bytes are flushed and their writer is closed.
    // A leaf-only rename retains the strict parent pins and never replaces an existing acknowledgment.
    public static void PublishPrivateRecord(string path, string principal, byte[] bytes) {
        string leaf=Path.GetFileName(path);
        if (leaf != "worker-ready.json" && leaf != "worker-result.json") throw new ArgumentException("Private record name rejected");
        if (new SecurityIdentifier(principal).Value != principal) throw new ArgumentException("Private record principal rejected");
        string temporary=Path.Combine(Path.GetDirectoryName(path),"record-"+Guid.NewGuid().ToString()+".tmp");
        string acl="O:"+principal+"G:"+principal+"D:P(A;;FA;;;"+principal+")(A;;GR;;;BA)(A;;GR;;;SY)";
        using (FileStream stream=CreateFile(temporary,acl,bytes)) { }
        using (SafeFileHandle file=CreateFileW(temporary,0x00010000 | ReadControl | ReadAttributes,
            1,IntPtr.Zero,3,0x00200000,IntPtr.Zero)) {
            if (file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            Inspect(file,false,false,principal);
            byte[] name=Encoding.Unicode.GetBytes(leaf);
            int rootOffset=IntPtr.Size == 8 ? 8 : 4;
            int nameLengthOffset=rootOffset+IntPtr.Size;
            int nameOffset=nameLengthOffset+4;
            byte[] packet=new byte[nameOffset+name.Length];
            // ReplaceIfExists=false and RootDirectory=null: resolve this leaf in the source's retained parent.
            Array.Copy(BitConverter.GetBytes(name.Length),0,packet,nameLengthOffset,4);
            Array.Copy(name,0,packet,nameOffset,name.Length);
            IntPtr information=Marshal.AllocHGlobal(packet.Length);
            try {
                Marshal.Copy(packet,0,information,packet.Length);
                IoStatusBlock status;
                int result=NtSetInformationFile(file,out status,information,(uint)packet.Length,10);
                if (result < 0) throw new Win32Exception((int)RtlNtStatusToDosError(result));
            } finally { Marshal.FreeHGlobal(information); }
        }
    }
    public static bool TryLock(SafeFileHandle file, int offset, bool exclusive) {
        if (offset != 0 && offset != 16) throw new ArgumentException("Installer lock range rejected");
        Overlapped overlapped=new Overlapped { Offset=(uint)offset };
        if (LockFileEx(file, exclusive ? 3u : 1u, 0, 1, 0, ref overlapped)) return true;
        int error=Marshal.GetLastWin32Error();
        if (error == 33) return false;
        throw new Win32Exception(error);
    }
    public static void Unlock(SafeFileHandle file, int offset) {
        if (offset != 0 && offset != 16) throw new ArgumentException("Installer lock range rejected");
        Overlapped overlapped=new Overlapped { Offset=(uint)offset };
        if (!UnlockFileEx(file, 0, 1, 0, ref overlapped)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public static void ReplaceReceipt(SafeFileHandle directory, string temporaryName) {
        Guid id;
        if (temporaryName == null || !temporaryName.StartsWith("status-") || !temporaryName.EndsWith(".tmp") ||
            !Guid.TryParseExact(temporaryName.Substring(7,temporaryName.Length-11),"D",out id))
            throw new ArgumentException("Installer receipt name rejected");
        Inspect(directory,true,false,null);
        string parent=ReceiptObjectPath(directory).TrimEnd('\\');
        // Validate an existing destination while the strict parent excludes substitution.
        try {
            using (SafeFileHandle target=OpenRead(Path.Combine(parent,"status.json"),false)) {
                Inspect(target,false,false,null);
            }
        } catch (Win32Exception error) { if (error.NativeErrorCode!=2) throw; }
        using (SafeFileHandle source=CreateFileW(Path.Combine(parent,temporaryName),0x00010000 | ReadControl | ReadAttributes,
            7,IntPtr.Zero,3,0x00200000,IntPtr.Zero)) {
            if (source.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            Inspect(source,false,false,null);
            if (!String.Equals(Path.GetDirectoryName(ReceiptObjectPath(source)),parent,StringComparison.Ordinal))
                throw new IOException("Unlinked installer receipt");
            // Same-directory NT rename does not reopen our pinned parent for writes.
            // POSIX replacement retains existing read handles on their original receipt.
            // Unsupported Windows/filesystem behavior fails closed; never weaken the pins.
            byte[] name=Encoding.Unicode.GetBytes("status.json");
            int rootOffset=IntPtr.Size==8 ? 8 : 4;
            int nameLengthOffset=rootOffset+IntPtr.Size;
            int nameOffset=nameLengthOffset+4;
            byte[] packet=new byte[nameOffset+name.Length];
            Array.Copy(BitConverter.GetBytes(3u),0,packet,0,4); // REPLACE_IF_EXISTS | POSIX_SEMANTICS
            Array.Copy(BitConverter.GetBytes(name.Length),0,packet,nameLengthOffset,4);
            Array.Copy(name,0,packet,nameOffset,name.Length);
            IntPtr information=Marshal.AllocHGlobal(packet.Length);
            try {
                Marshal.Copy(packet,0,information,packet.Length);
                IoStatusBlock status;
                int result=NtSetInformationFile(source,out status,information,(uint)packet.Length,65);
                if (result<0) throw new Win32Exception((int)RtlNtStatusToDosError(result));
            } finally { Marshal.FreeHGlobal(information); }
        }
    }
    static string ReceiptObjectPath(SafeFileHandle file) {
        StringBuilder path=new StringBuilder(32768);
        uint length=GetFinalPathNameByHandleW(file,path,32768,0);
        if (length==0 || length>=32768) throw new IOException("Installer receipt path unavailable");
        return path.ToString();
    }
    public static void CreateDirectory(string path, string sddl) {
        IntPtr descriptor; uint size;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, out size)) throw new Win32Exception();
        try {
            SecurityAttributes attributes = new SecurityAttributes { Length=Marshal.SizeOf<SecurityAttributes>(), Descriptor=descriptor };
            if (!CreateDirectoryW(path, ref attributes)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { LocalFree(descriptor); }
    }

    // Protected output and system ancestry match WindowsInstallTrust's bounded ACL policy.
    // An optional input principal authorizes only that user's private input tree, never output storage.
    // Read-only proof over caller-retained non-delete-sharing objects. This method
    // opens/closes nothing, so a rejected witness remains owned by its coordinator.
    public static void InspectLinkedAncestor(SafeFileHandle parent, SafeFileHandle child, string inputPrincipal) {
        byte[] attributes=new byte[8], standard=new byte[24];
        if (GetFileType(child)!=1 || !GetFileInformationByHandleEx(child,9,attributes,8) ||
            !GetFileInformationByHandleEx(child,1,standard,24)) throw new IOException("Installer witness unavailable");
        uint flags=BitConverter.ToUInt32(attributes,0);
        if ((flags&0x400)!=0 || BitConverter.ToUInt32(attributes,4)!=0 ||
            ((flags&0x10)==0 && BitConverter.ToUInt32(standard,16)!=1)) throw new IOException("Installer witness rejected");
        string actual=FinalPath(parent).TrimEnd('\\');
        if (!String.Equals(Path.GetDirectoryName(FinalPath(child)).TrimEnd('\\'),actual,StringComparison.Ordinal))
            throw new IOException("Unlinked installer witness");
        InspectCore(parent,true,true,inputPrincipal,true);
        if (!String.Equals(FinalPath(parent).TrimEnd('\\'),actual,StringComparison.Ordinal))
            throw new IOException("Changed installer witness parent");
    }
    public static void Inspect(SafeFileHandle file, bool directory, bool ancestor, string inputPrincipal) {
        InspectCore(file,directory,ancestor,inputPrincipal,false);
    }
    static void InspectCore(SafeFileHandle file, bool directory, bool ancestor, string inputPrincipal, bool pinnedNonEmpty) {
        byte[] attributes = new byte[8]; byte[] standard = new byte[24];
        uint volumeFlags;
        if (!GetVolumeInformationByHandleW(file, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, out volumeFlags, IntPtr.Zero, 0) ||
            (volumeFlags & 8) == 0) throw new IOException("Installer volume does not enforce ACLs");
        if (GetFileType(file) != 1 || !GetFileInformationByHandleEx(file, 9, attributes, 8) ||
            !GetFileInformationByHandleEx(file, 1, standard, 24)) throw new IOException("Installer object unavailable");
        uint flags = BitConverter.ToUInt32(attributes, 0);
        if ((flags & 0x400) != 0 || BitConverter.ToUInt32(attributes, 4) != 0 ||
            ((flags & 0x10) != 0) != directory || (!directory && BitConverter.ToUInt32(standard, 16) != 1))
            throw new IOException("Installer link or object type rejected");
        IntPtr owner, group, dacl, sacl, descriptor;
        uint error = GetSecurityInfo(file, 1, 5, out owner, out group, out dacl, out sacl, out descriptor);
        if (error != 0) throw new Win32Exception((int)error);
        try {
            int size = checked((int)GetSecurityDescriptorLength(descriptor));
            if (size <= 0 || size > 1048576) throw new IOException("Installer ACL rejected");
            byte[] bytes = new byte[size]; Marshal.Copy(descriptor, bytes, 0, size);
            RawSecurityDescriptor security = new RawSecurityDescriptor(bytes, 0);
            ValidateSecurityDescriptor(security, ancestor, inputPrincipal,pinnedNonEmpty);
        } finally { LocalFree(descriptor); }
    }
    public static void ValidateSecurity(string sddl, bool ancestor, string inputPrincipal) {
        ValidateSecurityDescriptor(new RawSecurityDescriptor(sddl), ancestor, inputPrincipal);
    }
    static void ValidateSecurityDescriptor(RawSecurityDescriptor security, bool ancestor, string inputPrincipal, bool pinnedNonEmpty=false) {
            string sid = security.Owner.Value;
            bool trustedOwner = Trusted(sid) || (inputPrincipal != null && sid == inputPrincipal) ||
                (ancestor && sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
            if (!trustedOwner || security.DiscretionaryAcl == null || security.DiscretionaryAcl.Count > 4096)
                throw new IOException("Installer owner or ACL rejected");
            foreach (GenericAce generic in security.DiscretionaryAcl) {
                if (generic.AceType != AceType.AccessAllowed && generic.AceType != AceType.AccessDenied)
                    throw new IOException("Installer ACE type rejected");
                CommonAce ace = generic as CommonAce;
                if (ace == null) throw new IOException("Installer ACE rejected");
                if ((ace.AceFlags & AceFlags.InheritOnly) != 0 || ace.AceType == AceType.AccessDenied ||
                    Trusted(ace.SecurityIdentifier.Value) || (inputPrincipal != null && ace.SecurityIdentifier.Value == inputPrincipal)) continue;
                uint ancestorRights=ancestor ? (pinnedNonEmpty ? 0x116u : 6u) : 0u;
                uint mask = unchecked((uint)ace.AccessMask), allowed = 0xA01200A9u | ancestorRights;
                if ((mask & ~allowed) != 0 || (mask & 0x500D0156u & ~ancestorRights) != 0)
                    throw new IOException("Installer mutation rights rejected");
            }
    }
    static bool Trusted(string sid) { return sid == "S-1-5-18" || sid == "S-1-5-32-544"; }

    static string FinalPath(SafeFileHandle file) {
        StringBuilder path=new StringBuilder(32768);
        uint size=GetFinalPathNameByHandleW(file,path,32768,0);
        if (size==0 || size>=32768) throw new IOException("Installer canonical path unavailable");
        return path.ToString();
    }
    // Caller retains this parent and all its ancestors before invoking this method, and retains
    // the returned child until that ancestry is no longer used. Never relax final job/file ACLs.
    public static SafeFileHandle PinNonEmptyAncestor(SafeFileHandle parent,string inputPrincipal) {
        InspectCore(parent,true,true,inputPrincipal,true); // Eligibility only; no trust returned yet.
        string expected=FinalPath(parent);
        int count=0;
        foreach (string candidate in Directory.EnumerateFileSystemEntries(expected)) {
            if (++count>4096) break;
            SafeFileHandle child=null;
            try {
                child=OpenDirectory(candidate); // No FILE_SHARE_DELETE; an existing DELETE opener conflicts.
                byte[] attributes=new byte[8];
                if (GetFileType(child)!=1 || !GetFileInformationByHandleEx(child,9,attributes,8) ||
                    (BitConverter.ToUInt32(attributes,0)&0x400)!=0 || BitConverter.ToUInt32(attributes,4)!=0) continue;
                // Exact native paths, not case-folding: distinct case-sensitive directories must not alias.
                if (!String.Equals(Path.GetDirectoryName(FinalPath(child)),expected,StringComparison.Ordinal)) continue;
                if (!String.Equals(FinalPath(parent),expected,StringComparison.Ordinal)) throw new IOException("Installer parent moved");
                InspectCore(parent,true,true,inputPrincipal,true);
                SafeFileHandle result=child; child=null; return result;
            } catch (Win32Exception) { /* Inaccessible/concurrently removed candidates are not witnesses. */ }
            finally { if (child!=null) child.Dispose(); }
        }
        throw new IOException("Installer ancestor has no retained nonempty witness");
    }

    // The private request is a flat, bounded schema: strings and nonnegative Int64 values only.
    // Unlike ConvertFrom-Json this rejects duplicate keys instead of silently overwriting them.
    public static Dictionary<string,object> ParseFlatRecord(string input) {
        if (input == null || new UTF8Encoding(false,true).GetByteCount(input) > 65536) throw new IOException("Installer input too large");
        return new FlatParser(input).Read();
    }
    sealed class FlatParser {
        readonly string input; int at;
        public FlatParser(string value) { input=value; }
        void Space() { while (at < input.Length && (input[at]==' ' || input[at]=='\t' || input[at]=='\r' || input[at]=='\n')) at++; }
        void Expect(char value) { Space(); if (at == input.Length || input[at++] != value) throw new IOException("Installer input malformed"); }
        string Text() {
            Expect('"'); StringBuilder value=new StringBuilder(); bool ended=false;
            while (at < input.Length) {
                char ch=input[at++];
                if (ch=='"') { ended=true; break; }
                if (ch < 32) throw new IOException("Installer input string malformed");
                if (ch=='\\') {
                    if (at == input.Length) throw new IOException("Installer input escape malformed");
                    ch=input[at++];
                    switch (ch) {
                        case '"': case '\\': case '/': break;
                        case 'b': ch='\b'; break; case 'f': ch='\f'; break;
                        case 'n': ch='\n'; break; case 'r': ch='\r'; break; case 't': ch='\t'; break;
                        case 'u':
                            if (at+4 > input.Length) throw new IOException("Installer input escape malformed");
                            ushort code;
                            if (!ushort.TryParse(input.Substring(at,4), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out code))
                                throw new IOException("Installer input escape malformed");
                            ch=(char)code; at+=4; break;
                        default: throw new IOException("Installer input escape malformed");
                    }
                }
                value.Append(ch);
            }
            if (!ended) throw new IOException("Installer input string incomplete");
            string text=value.ToString();
            for (int index=0; index < text.Length; index++) {
                if (char.IsHighSurrogate(text[index])) {
                    if (++index == text.Length || !char.IsLowSurrogate(text[index])) throw new IOException("Installer input surrogate malformed");
                } else if (char.IsLowSurrogate(text[index])) throw new IOException("Installer input surrogate malformed");
            }
            return text;
        }
        object Value() {
            Space(); if (at < input.Length && input[at]=='"') return Text();
            int start=at;
            while (at < input.Length && input[at]>='0' && input[at]<='9') at++;
            if (start==at || (at-start>1 && input[start]=='0')) throw new IOException("Installer input number malformed");
            long value;
            if (!long.TryParse(input.Substring(start,at-start), NumberStyles.None, CultureInfo.InvariantCulture,out value))
                throw new IOException("Installer input number out of range");
            return value;
        }
        public Dictionary<string,object> Read() {
            Dictionary<string,object> result=new Dictionary<string,object>(StringComparer.Ordinal);
            Expect('{'); Space();
            if (at < input.Length && input[at]!='}') {
                while (true) {
                    string key=Text(); Expect(':'); object value=Value();
                    if (result.ContainsKey(key) || result.Count>=32) throw new IOException("Installer input fields rejected");
                    result.Add(key,value); Space();
                    if (at==input.Length || input[at]!=',') break;
                    at++;
                }
            }
            Expect('}'); Space(); if (at!=input.Length) throw new IOException("Installer input trailing data");
            return result;
        }
    }
}
