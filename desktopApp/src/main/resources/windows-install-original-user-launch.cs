// Fixed NativeAOT original-interactive-user launcher. It never accepts an image,
// credential, SID, token, or shell PID from argv: the shell handle is the OS source
// of original-user authority and this helper always re-launches its own image.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal sealed class VpnInstallOriginalUserLaunch : IDisposable {
    const uint PROCESS_QUERY_LIMITED_INFORMATION=0x1000;
    const uint TOKEN_ASSIGN_PRIMARY=1, TOKEN_DUPLICATE=2, TOKEN_QUERY=8;
    const uint TOKEN_ADJUST_DEFAULT=0x80, TOKEN_ADJUST_SESSIONID=0x100;
    const uint LOGON_WITH_PROFILE=1, CREATE_SUSPENDED=4;
    const int ERROR_PRIVILEGE_NOT_HELD=1314;
    const int TokenSessionId=12, TokenElevation=20;
    IntPtr token;
    internal readonly uint ShellPid, ShellSession;
    internal readonly long ShellCreationFileTime;
    internal readonly string PrincipalSid;

    VpnInstallOriginalUserLaunch(IntPtr retained,uint pid,long creation,uint session,string sid) {
        token=retained; ShellPid=pid; ShellCreationFileTime=creation; ShellSession=session; PrincipalSid=sid;
    }

    // GetShellWindow is an OS-owned exact interactive-shell handle. Do not replace this
    // with explorer-name enumeration or an alternate-user process fallback.
    internal static VpnInstallOriginalUserLaunch Capture() {
        IntPtr window=GetShellWindow(); if (window==IntPtr.Zero) throw new IOException("UNAVAILABLE");
        uint thread=GetWindowThreadProcessId(window,out uint pid); if (thread==0 || pid==0) throw new IOException("UNAVAILABLE");
        IntPtr process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,false,pid);
        if (process==IntPtr.Zero) throw Error("PERMISSION_DENIED");
        IntPtr source=IntPtr.Zero, primary=IntPtr.Zero;
        try {
            if (!ProcessIdToSessionId(pid,out uint session)) throw Error("UNAVAILABLE");
            uint current=GetCurrentProcessId();
            if (!ProcessIdToSessionId(current,out uint currentSession) || currentSession!=session) throw new IOException("CONFLICT");
            long creation=ProcessCreation(process);
            if (!OpenProcessToken(process,TOKEN_QUERY|TOKEN_DUPLICATE,out source)) throw Error("PERMISSION_DENIED");
            string sid=TokenSid(source);
            if (TokenScalar(source,TokenElevation)!=0 || (uint)TokenScalar(source,TokenSessionId)!=session)
                throw new IOException("CONFLICT");
            if (!DuplicateTokenEx(source,TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ADJUST_DEFAULT|TOKEN_ADJUST_SESSIONID,
                IntPtr.Zero,2,1,out primary)) throw Error("PERMISSION_DENIED");
            // Re-observe the exact shell process after duplication; PID reuse or a session
            // transition invalidates the retained primary token before it can launch anything.
            if (ProcessCreation(process)!=creation || !ProcessIdToSessionId(pid,out uint confirmed) || confirmed!=session)
                throw new IOException("CONFLICT");
            IntPtr retained=primary; primary=IntPtr.Zero;
            return new VpnInstallOriginalUserLaunch(retained,pid,creation,session,sid);
        } finally { if (primary!=IntPtr.Zero) CloseHandle(primary); if (source!=IntPtr.Zero) CloseHandle(source); CloseHandle(process); }
    }

    // `arguments` is a fixed helper invocation, not general command-line input. The
    // executable is always this NativeAOT image, so neither coordinator nor JVM can
    // select a script, JAR, MSI, shell, or alternate helper.
    internal StartedHelper StartSameHelper(string[] arguments) {
        return StartSameHelperCore(arguments,null);
    }
    // Same-assembly fixture seam. It can reproduce only the observed privileged
    // launch failure; the fallback itself still creates and verifies a real child.
    internal StartedHelper StartSameHelperForPrivilegeFailureFixture(string[] arguments,int capturedLaunchError) {
        return StartSameHelperCore(arguments,capturedLaunchError);
    }
    StartedHelper StartSameHelperCore(string[] arguments,int? capturedLaunchErrorForFixture) {
        if (token==IntPtr.Zero) throw new ObjectDisposedException("VpnInstallOriginalUserLaunch");
        ValidateInvocation(arguments);
        if (arguments[0]!="install-user") throw new IOException("INVALID_ARGUMENT");
        using (VpnInstallNative.ImageObjectPin selfImage=VpnInstallNative.ImageObjectPin.CaptureSelf(PrincipalSid)) {
        string image=SelfImage();
        STARTUPINFO startup=new STARTUPINFO(); startup.cb=Marshal.SizeOf<STARTUPINFO>();
        // The fixture may inject the first launch failure. Keep its process record
        // zeroed until either native launch supplies owned handles, so exception
        // cleanup can never act on uninitialized data.
        PROCESS_INFORMATION child=default(PROCESS_INFORMATION);
        System.Text.StringBuilder command=new System.Text.StringBuilder(Quote(image)+" "+String.Join(" ",Array.ConvertAll(arguments,Quote)));
        bool capturedStarted;
        int launchError;
        if (capturedLaunchErrorForFixture.HasValue) {
            capturedStarted=false; launchError=capturedLaunchErrorForFixture.Value;
        } else {
            capturedStarted=CreateProcessWithTokenW(token,LOGON_WITH_PROFILE,image,command,CREATE_SUSPENDED,IntPtr.Zero,null,ref startup,out child);
            launchError=capturedStarted ? 0 : Marshal.GetLastWin32Error();
        }
        if (!capturedStarted) {
            // A normal interactive process can lack SeImpersonatePrivilege even when
            // its primary token has the captured shell's non-elevated SID and session.
            // In that one case CreateProcessW preserves the same identity without
            // needing a token-assignment privilege.  Never use this path for an
            // elevated caller, another approving account, or another session.
            if (!CurrentProcessCanUseOriginalUserFallback(launchError)) throw Error("PERMISSION_DENIED",launchError);
            // Native process creation receives a mutable command buffer. Rebuild the
            // fixed invocation after the failed call instead of reusing its output.
            command=new System.Text.StringBuilder(Quote(image)+" "+String.Join(" ",Array.ConvertAll(arguments,Quote)));
            if (!CreateProcessW(image,command,IntPtr.Zero,IntPtr.Zero,false,CREATE_SUSPENDED,IntPtr.Zero,null,ref startup,out child))
                throw Error("PERMISSION_DENIED");
        }
        try {
            VerifyChild(child.hProcess,selfImage);
            if (ResumeThread(child.hThread)==UInt32.MaxValue) throw Error("OUTCOME_UNKNOWN");
            IntPtr process=child.hProcess; child.hProcess=IntPtr.Zero;
            return new StartedHelper(process,child.dwProcessId);
        } catch (Exception failure) {
            if (child.hProcess!=IntPtr.Zero) {
                // A failed verification/resume must not leave an unowned suspended
                // original-user helper behind. Do not claim cancellation merely
                // because TerminateProcess was requested: retain the process
                // handle until its exit is observed.
                if (WaitForSingleObject(child.hProcess,0)!=0 &&
                    (!TerminateProcess(child.hProcess,1) || WaitForSingleObject(child.hProcess,15000)!=0)) {
                    IntPtr retained=child.hProcess; child.hProcess=IntPtr.Zero;
                    throw new UncertainChild(new StartedHelper(retained,child.dwProcessId),failure);
                }
            }
            throw;
        }
        finally { if (child.hThread!=IntPtr.Zero) CloseHandle(child.hThread); if (child.hProcess!=IntPtr.Zero) CloseHandle(child.hProcess); }
        }
    }

    void VerifyChild(IntPtr child,VpnInstallNative.ImageObjectPin selfImage) {
        if (child==IntPtr.Zero || !ProcessIdToSessionId(GetProcessId(child),out uint session) || session!=ShellSession) throw new IOException("CONFLICT");
        IntPtr childToken=IntPtr.Zero;
        try {
            if (!OpenProcessToken(child,TOKEN_QUERY,out childToken) || TokenScalar(childToken,TokenElevation)!=0)
                throw new IOException("CONFLICT");
            // Do not use an ambient identity: inspect the exact retained child token.
            string childSid=TokenSid(childToken);
            bool sameImage=selfImage.MatchesProcessImage(child);
            if (!String.Equals(childSid,PrincipalSid,StringComparison.Ordinal) ||
                !sameImage) throw new IOException("CONFLICT");
        } finally { if (childToken!=IntPtr.Zero) CloseHandle(childToken); }
    }

    internal sealed class StartedHelper : IDisposable {
        IntPtr process;
        internal readonly uint ProcessId;
        internal StartedHelper(IntPtr retained,uint pid) { process=retained; ProcessId=pid; }
        internal ChildIdentity Observe() {
            if (process==IntPtr.Zero) throw new ObjectDisposedException("StartedHelper");
            IntPtr current=IntPtr.Zero;
            try {
                if (!OpenProcessToken(process,TOKEN_QUERY,out current)) throw Error("OUTCOME_UNKNOWN");
                if (!ProcessIdToSessionId(ProcessId,out uint session)) throw Error("OUTCOME_UNKNOWN");
                return new ChildIdentity(ProcessId,ProcessCreation(process),session,TokenSid(current),TokenScalar(current,TokenElevation)!=0);
            } finally { if (current!=IntPtr.Zero) CloseHandle(current); }
        }
        internal bool Wait(uint milliseconds) { return WaitForSingleObject(process,milliseconds)==0; }
        // This is used only before the coordinator has admitted the child or
        // created any protected installation state.  Once admission succeeds,
        // the worker may own an MSI attempt and must be reconciled by receipt,
        // never terminated by its parent.
        internal void StopBeforeCoordinatorAdmission() {
            if (process==IntPtr.Zero) throw new ObjectDisposedException("StartedHelper");
            if (!Wait(0) && !TerminateProcess(process,1) && !Wait(0)) {
                // A failed terminate request has no completed outcome. Retain
                // this exact child until it exits instead of returning through
                // a finally block that would abandon its only process witness.
            }
            WaitForExactExit();
        }
        internal void ReconcileAfterCoordinatorAdmission() {
            if (process==IntPtr.Zero) throw new ObjectDisposedException("StartedHelper");
            // Retain the exact process/generation handle until this child has
            // exited.  Closing a live handle here would let Main abandon a
            // worker whose protected receipt is still the only outcome record.
            WaitForExactExit();
        }
        void WaitForExactExit() { while (!Wait(UInt32.MaxValue)) System.Threading.Thread.Sleep(50); }
        public void Dispose() { if (process!=IntPtr.Zero) { CloseHandle(process); process=IntPtr.Zero; } }
    }
    // The caller owns this retained identity and must reconcile/close it; an
    // uncertain stop is never silently converted into a completed cancellation.
    internal sealed class UncertainChild : IOException, IDisposable {
        internal readonly StartedHelper Child;
        internal UncertainChild(StartedHelper child,Exception cause) : base("OUTCOME_UNKNOWN",cause) { Child=child; }
        // Reconciliation observes the exact retained process generation; disposal
        // is explicit so an accepted unknown result cannot leak an OS handle.
        internal ChildIdentity Observe() { return Child.Observe(); }
        internal bool Wait(uint milliseconds) { return Child.Wait(milliseconds); }
        public void Dispose() { Child.Dispose(); }
    }
    internal sealed class ChildIdentity {
        internal readonly uint ProcessId, Session; internal readonly long CreationFileTime; internal readonly string Sid; internal readonly bool Elevated;
        internal ChildIdentity(uint pid,long created,uint session,string sid,bool elevated) { ProcessId=pid; CreationFileTime=created; Session=session; Sid=sid; Elevated=elevated; }
    }

    internal static void ValidateInvocation(string[] values) {
        if (values==null || values.Length!=4 || (values[0]!="install-user" && values[0]!="install-coordinator")) throw new IOException("INVALID_ARGUMENT");
        Guid job; if (!Guid.TryParseExact(values[1],"D",out job) || job.ToString("D")!=values[1]) throw new IOException("INVALID_ARGUMENT");
        uint pid; long creation;
        if (!UInt32.TryParse(values[2],NumberStyles.None,CultureInfo.InvariantCulture,out pid) || pid==0 || pid.ToString(CultureInfo.InvariantCulture)!=values[2] ||
            !Int64.TryParse(values[3],NumberStyles.None,CultureInfo.InvariantCulture,out creation) || creation<=0 || creation.ToString(CultureInfo.InvariantCulture)!=values[3]) throw new IOException("INVALID_ARGUMENT");
    }
    internal static bool CurrentTokenElevated() {
        IntPtr current=IntPtr.Zero;
        try { if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,out current)) throw Error("UNAVAILABLE"); return TokenScalar(current,TokenElevation)!=0; }
        finally { if (current!=IntPtr.Zero) CloseHandle(current); }
    }
    // Kept separate so the routine fixture covers each boundary of the fallback
    // admission decision without needing an interactive shell or a privilege fault.
    internal static bool CurrentTokenFallbackPermitted(int launchError,uint currentSession,string currentSid,bool currentElevated,uint shellSession,string shellSid) {
        return launchError==ERROR_PRIVILEGE_NOT_HELD && !currentElevated && currentSession==shellSession &&
            !String.IsNullOrEmpty(currentSid) && !String.IsNullOrEmpty(shellSid) && String.Equals(currentSid,shellSid,StringComparison.Ordinal);
    }
    bool CurrentProcessCanUseOriginalUserFallback(int launchError) {
        IntPtr current=IntPtr.Zero;
        try {
            if (!ProcessIdToSessionId(GetCurrentProcessId(),out uint session) ||
                !OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,out current)) return false;
            return CurrentTokenFallbackPermitted(launchError,session,TokenSid(current),TokenScalar(current,TokenElevation)!=0,ShellSession,PrincipalSid);
        } catch { return false; }
        finally { if (current!=IntPtr.Zero) CloseHandle(current); }
    }
    static string SelfImage() {
        string image=Process.GetCurrentProcess().MainModule.FileName;
        if (String.IsNullOrEmpty(image) || !String.Equals(System.IO.Path.GetFileName(image),"vpn-control-install-helper.exe",StringComparison.OrdinalIgnoreCase)) throw new IOException("CONFLICT");
        return image;
    }
    static long ProcessCreation(IntPtr process) { FILETIME creation,exit,kernel,user; if (!GetProcessTimes(process,out creation,out exit,out kernel,out user)) throw Error("UNAVAILABLE"); return ((long)creation.high<<32)|creation.low; }
    static int TokenScalar(IntPtr source,int kind) { IntPtr value=Marshal.AllocHGlobal(4); try { int size; if (!GetTokenInformation(source,kind,value,4,out size) || size!=4) throw Error("UNAVAILABLE"); return Marshal.ReadInt32(value); } finally { Marshal.FreeHGlobal(value); } }
    static string TokenSid(IntPtr source) { using (WindowsIdentity identity=new WindowsIdentity(source)) { if (identity.User==null) throw new IOException("UNAVAILABLE"); return identity.User.Value; } }
    static string ProcessImage(IntPtr process) { var text=new System.Text.StringBuilder(32768); int length=text.Capacity; if (!QueryFullProcessImageNameW(process,0,text,ref length) || length<1 || length>=text.Capacity) throw Error("UNAVAILABLE"); return text.ToString(); }
    static string Quote(string value) { if (String.IsNullOrEmpty(value)) return "\"\""; string result="\""; int slashes=0; foreach(char c in value) { if(c=='\\') { slashes++; continue; } if(c=='\"') result+=new String('\\',slashes*2+1); else result+=new String('\\',slashes); result+=c; slashes=0; } return result+new String('\\',slashes*2)+"\""; }
    static IOException Error(string code) { return Error(code,Marshal.GetLastWin32Error()); }
    static IOException Error(string code,int nativeError) { return new IOException(code,new Win32Exception(nativeError)); }
    public void Dispose() { if (token!=IntPtr.Zero) { CloseHandle(token); token=IntPtr.Zero; } }
    [StructLayout(LayoutKind.Sequential)] struct FILETIME { internal uint low,high; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct STARTUPINFO {
        internal int cb; internal string reserved,desktop,title;
        internal int x,y,xs,ys,xc,yc,fill,flags; internal short show,reserved2;
        internal IntPtr reserved3,stdin,stdout,stderr;
    }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { internal IntPtr hProcess,hThread; internal uint dwProcessId,dwThreadId; }
    [DllImport("user32.dll",SetLastError=true)] static extern IntPtr GetShellWindow();
    [DllImport("user32.dll",SetLastError=true)] static extern uint GetWindowThreadProcessId(IntPtr window,out uint process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool ProcessIdToSessionId(uint process,out uint session);
    [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out FILETIME creation,out FILETIME exit,out FILETIME kernel,out FILETIME user);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,System.Text.StringBuilder text,ref int length);
    [DllImport("kernel32.dll")] static extern uint GetProcessId(IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr source,uint access,IntPtr attributes,int level,int type,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr value,int capacity,out int returned);
    [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool CreateProcessWithTokenW(IntPtr token,uint flags,string application,System.Text.StringBuilder command,uint creation,IntPtr environment,string directory,ref STARTUPINFO startup,out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool CreateProcessW(string application,System.Text.StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inheritHandles,uint creation,IntPtr environment,string directory,ref STARTUPINFO startup,out PROCESS_INFORMATION process);
}
