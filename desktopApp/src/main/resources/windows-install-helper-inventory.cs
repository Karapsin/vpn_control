// Fixed coordinator-only inventory of retained installation images.  It never
// starts, stops, restarts, or asks Restart Manager to modify any process.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

internal static class VpnInstallHelperProcessInventory {
    const uint ErrorMoreData=234;
    const int MaxCandidates=4096, Attempts=3;

    [StructLayout(LayoutKind.Sequential)] struct RmUniqueProcess {
        internal uint Pid;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Started;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct RmProcessInfo {
        internal RmUniqueProcess Process;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] internal string AppName;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=64)] internal string ServiceName;
        internal uint ApplicationType, Status, TerminalSession;
        [MarshalAs(UnmanagedType.Bool)] internal bool Restartable;
    }
    struct Identity {
        internal readonly uint Pid; internal readonly long Created;
        internal Identity(uint pid,long created) { Pid=pid; Created=created; }
        internal bool Matches(uint pid,long created) { return Pid==pid && Created==created; }
    }

    [DllImport("rstrtmgr.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern int RmStartSession(out uint session,uint flags,StringBuilder key);
    [DllImport("rstrtmgr.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern int RmRegisterResources(uint session,uint files,
        [MarshalAs(UnmanagedType.LPArray,ArraySubType=UnmanagedType.LPWStr)] string[] paths,
        uint applications,IntPtr process,uint services,IntPtr service);
    [DllImport("rstrtmgr.dll",SetLastError=true)]
    static extern int RmGetList(uint session,out uint needed,ref uint count,
        [In,Out] RmProcessInfo[] processes,out uint rebootReasons);
    [DllImport("rstrtmgr.dll",SetLastError=true)] static extern int RmEndSession(uint session);

    // Returns false for every unknown/racy candidate.  The two authorized
    // processes are pinned and stamped before the resource inventory, so a PID
    // alone never grants an exclusion during a later scan.
    internal static bool TryNoAdmittedInstallationCopies(VpnInstallNative.ExecutableReplacementSet installation,
        uint coordinatorPid,uint workerPid) {
        if (installation==null || coordinatorPid==0 || workerPid==0) return false;
        string[] paths;
        try { paths=installation.RetainedImagePaths(); }
        catch (Exception) { return false; }
        if (paths==null || paths.Length!=2 || String.IsNullOrEmpty(paths[0]) || String.IsNullOrEmpty(paths[1])) return false;
        try {
            using (VpnInstallNative.ProcessImagePin coordinator=new VpnInstallNative.ProcessImagePin(coordinatorPid))
            using (VpnInstallNative.ProcessImagePin worker=new VpnInstallNative.ProcessImagePin(workerPid)) {
                VpnInstallNative.ProcessImageObservation c=coordinator.Observe(), w=worker.Observe();
                if (c.KernelOnly || w.KernelOnly) return false;
                Identity coordinatorIdentity=new Identity(c.Pid,c.CreationFileTime);
                Identity workerIdentity=new Identity(w.Pid,w.CreationFileTime);
                for (int attempt=0;attempt<Attempts;attempt++) {
                    RmProcessInfo[] candidates;
                    if (!TryResourceSnapshot(paths,out candidates)) return false;
                    bool retry=false;
                    foreach (RmProcessInfo candidate in candidates) {
                        long created=FileTime(candidate.Process.Started);
                        if (candidate.Process.Pid==0 || created<=0) { retry=true; break; }
                        try {
                            using (VpnInstallNative.ProcessImagePin process=new VpnInstallNative.ProcessImagePin(candidate.Process.Pid)) {
                                VpnInstallNative.ProcessImageObservation seen=process.Observe();
                                // Restart Manager and the retained handle must identify one
                                // generation. A PID reuse or exit gets a new bounded snapshot.
                                if (seen.CreationFileTime!=created) { retry=true; break; }
                                if (coordinatorIdentity.Matches(seen.Pid,seen.CreationFileTime) ||
                                    workerIdentity.Matches(seen.Pid,seen.CreationFileTime)) continue;
                                // Object identity is checked through the retained installation
                                // handles; a textual alias or reparse result cannot be admitted.
                                if (seen.KernelOnly || String.IsNullOrEmpty(seen.Image) || installation.ContainsImage(seen.Image))
                                    return false;
                            }
                        } catch (Exception) {
                            // This candidate was reported as holding an installed image.
                            // It may have exited, so refresh; never silently skip it.
                            retry=true; break;
                        }
                    }
                    if (!retry) return true;
                }
            }
        } catch (Exception) { return false; }
        return false;
    }

    static bool TryResourceSnapshot(string[] paths,out RmProcessInfo[] result) {
        result=null; uint session=0; bool started=false;
        try {
            StringBuilder key=new StringBuilder(33);
            if (RmStartSession(out session,0,key)!=0) return false;
            started=true;
            if (RmRegisterResources(session,(uint)paths.Length,paths,0,IntPtr.Zero,0,IntPtr.Zero)!=0) return false;
            for (int attempt=0;attempt<Attempts;attempt++) {
                uint needed=0,count=0,reasons;
                int status=RmGetList(session,out needed,ref count,null,out reasons);
                if (status!=0 && status!=ErrorMoreData) return false;
                if (needed>MaxCandidates) return false;
                if (needed==0) { result=new RmProcessInfo[0]; return true; }
                RmProcessInfo[] values=new RmProcessInfo[needed]; count=needed;
                status=RmGetList(session,out needed,ref count,values,out reasons);
                if (status==0 && count<=values.Length) {
                    if (count!=values.Length) Array.Resize(ref values,(int)count);
                    result=values; return true;
                }
                if (status!=ErrorMoreData || needed>MaxCandidates) return false;
            }
            return false;
        } finally { if (started) RmEndSession(session); }
    }
    static long FileTime(System.Runtime.InteropServices.ComTypes.FILETIME value) {
        return ((long)(uint)value.dwHighDateTime<<32) | (uint)value.dwLowDateTime;
    }
}
