// Fixed native installer session admission. Requests are data only until this
// class retains the invoking owner generation, its token identity, and every
// private input ancestor. No argv path selects any of these objects.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal interface VpnInstallHelperSessionFactory {
    int Run(VpnInstallHelperProtocol.Invocation invocation);
}

internal sealed class VpnInstallHelperNativeSessions : VpnInstallHelperSessionFactory {
    public int Run(VpnInstallHelperProtocol.Invocation invocation) {
        if (invocation==null) throw new ArgumentException("INVALID_ARGUMENT");
        bool originalUser=invocation.Operation==VpnInstallHelperProtocol.Role.OriginalUser;
        OwnerInputAdmission admission=OwnerInputAdmission.Open(invocation,originalUser);
        OriginalUserSessionAdapter session=null;
        try {
            if (!originalUser) throw new IOException("RUNTIME_FAILED");
            session=new OriginalUserSessionAdapter(admission);
            int result=VpnInstallHelperRoles.RunOriginalUser(session);
            return result;
        } catch (VpnInstallHelperRoles.WorkerFailure failure) {
            // Main would otherwise immediately end the process and release every
            // local pin.  An attempted MSI call therefore remains live while this
            // bounded reconciliation reads the protected terminal receipt.  A later
            // invocation cannot reuse this adapter, and InstallVerifiedPackage also
            // rejects a second attempt in this process.
            if (failure.InstallerStarted && session!=null) {
                try { session.ReconcileUncertainOutcome(); }
                catch (Exception error) when (error is IOException || error is Win32Exception ||
                    error is UnauthorizedAccessException || error is InvalidOperationException) {
                    // The original WorkerFailure remains the explicit accepted/unknown outcome.
                }
            }
            throw;
        } finally {
            // A failed retained close keeps the whole admitted chain alive for
            // its explicit retry; do not discard the owner witness underneath it.
            if (session!=null) session.Dispose();
            admission.Dispose();
        }
    }
}

// Production implementation of the retained original-user role.  All paths are
// derived from an admitted request and fixed roots; argv selects neither a package
// nor a receipt.  The admission remains owned by the caller on an uncertain result.
internal sealed class OriginalUserSessionAdapter : VpnInstallHelperRoles.OriginalUserSession, IDisposable {
    const int PollMilliseconds=100;
    readonly OwnerInputAdmission admission;
    readonly string inputDirectory, receiptPath;
    readonly DateTime authorizationDeadline, returnDeadline;
    readonly PackageInput package;
    readonly VpnInstallHelperMsi.Prepared prepared;
    readonly OriginalUserSessionAdapterFacilities fixture;
    VpnInstallHelperRoles.Receipt lastObservedReceipt;
    bool installAttempted;
    bool disposed;

    // Same-assembly fixture seam. Production construction always uses admitted
    // process/file authority; no request, environment value, or external argument
    // can select these facilities.
    internal OriginalUserSessionAdapter(OriginalUserSessionAdapterFacilities facilities) {
        if (facilities==null) throw new ArgumentNullException("facilities");
        fixture=facilities;
        authorizationDeadline=DateTime.UtcNow.AddMinutes(10);
        returnDeadline=authorizationDeadline.AddMinutes(20);
    }

    internal OriginalUserSessionAdapter(OwnerInputAdmission retainedAdmission) {
        if (retainedAdmission==null || retainedAdmission.Request==null) throw new IOException("CONFLICT");
        admission=retainedAdmission;
        inputDirectory=Path.Combine(admission.Owner.LocalAppData(),"vpn-control-install-inputs",admission.Request.JobId);
        receiptPath=Path.Combine(VpnInstallNative.ProgramData(),"vpn-control-install-jobs",admission.Request.JobId,"status.json");
        VpnInstallHelperProtocol.LocalPath(inputDirectory);
        VpnInstallHelperProtocol.LocalPath(receiptPath);
        authorizationDeadline=DateTime.UtcNow.AddMinutes(10);
        returnDeadline=authorizationDeadline.AddMinutes(20);
        package=new PackageInput(admission);
        try { prepared=VpnInstallHelperMsi.Prepared.Prepare(package); }
        catch { package.Dispose(); throw; }
    }

    public string JobId { get { return fixture==null ? admission.Request.JobId : fixture.JobId; } }
    public bool AuthorizationDeadlineReached { get { return fixture==null ? DateTime.UtcNow>=authorizationDeadline : fixture.AuthorizationDeadlineReached; } }
    public bool ReturnDeadlineReached { get { return fixture==null ? DateTime.UtcNow>=returnDeadline : fixture.ReturnDeadlineReached; } }
    public void Pause() { if (fixture==null) Thread.Sleep(PollMilliseconds); else fixture.Pause(); }

    public void PublishReady() {
        if (fixture!=null) { fixture.PublishReady(); return; }
        using (VpnInstallNative.ProcessImagePin self=new VpnInstallNative.ProcessImagePin((uint)Process.GetCurrentProcess().Id)) {
            VpnInstallNative.ProcessImageObservation identity=self.Observe();
            if (identity.Pid==0 || identity.CreationFileTime<=0 || identity.KernelOnly) throw new IOException("RUNTIME_FAILED");
            string executable=Process.GetCurrentProcess().MainModule.FileName;
            string digest=PackageInput.Sha256(executable);
            byte[] record=VpnInstallHelperProtocol.EncodeWorkerReady(JobId,identity.Pid,identity.CreationFileTime,
                admission.Caller.User.Value,digest);
            VpnInstallNative.PublishPrivateRecord(Path.Combine(inputDirectory,"worker-ready.json"),admission.Owner.Principal,record);
        }
    }

    public VpnInstallHelperRoles.Receipt ReadProtectedReceipt() {
        VpnInstallHelperRoles.Receipt receipt=ReadReceipt();
        if (receipt!=null) lastObservedReceipt=receipt;
        return receipt;
    }

    VpnInstallHelperRoles.Receipt ReadReceipt() {
        if (fixture!=null) return fixture.ReadProtectedReceipt();
        try {
            using (SafeFileHandle handle=VpnInstallNative.OpenReceipt(receiptPath)) {
                VpnInstallNative.Inspect(handle,false,false,null);
                using (FileStream stream=new FileStream(handle,FileAccess.Read,1,false))
                    return VpnInstallHelperProtocol.ParseReceipt(ReadBounded(stream,4096));
            }
        } catch (Win32Exception error) {
            if (error.NativeErrorCode==2 || error.NativeErrorCode==3) return null;
            throw;
        }
    }

    public uint InstallVerifiedPackage() {
        // The role marks this before calling us, but retain the guard at the real
        // resource boundary too: recovery is observation only, never MSI replay.
        if (installAttempted) throw new IOException("OUTCOME_UNKNOWN");
        installAttempted=true;
        return fixture==null ? prepared.Install() : fixture.InstallVerifiedPackage();
    }
    public void PublishNativeResult(uint exitCode) {
        if (fixture!=null) { fixture.PublishNativeResult(exitCode); return; }
        VpnInstallNative.PublishPrivateRecord(Path.Combine(inputDirectory,"worker-result.json"),admission.Owner.Principal,
            VpnInstallHelperProtocol.EncodeWorkerResult(JobId,exitCode));
    }

    public void RelaunchOriginalOwner() {
        if (fixture!=null) { fixture.RelaunchOriginalOwner(); return; }
        // The admitted owner process is intentionally gone before INSTALLING; the
        // retained caller token is the original-user authority for this relaunch.
        if (admission.Caller.User==null || !String.Equals(admission.Caller.User.Value,admission.Owner.Principal,StringComparison.Ordinal))
            throw new IOException("CONFLICT");
        ProcessStartInfo launch=new ProcessStartInfo(admission.Request.Launcher);
        launch.UseShellExecute=false;
        launch.Arguments="--state-dir \""+admission.Request.StateDirectory+"\""+
            (admission.Request.FrontendPid.HasValue ? "" : " serve");
        using (Process process=Process.Start(launch)) { if (process==null) throw new IOException("RUNTIME_FAILED"); }
    }

    public void Dispose() {
        if (disposed) return;
        if (fixture==null) prepared.Dispose(); else fixture.Dispose();
        disposed=true;
    }

    // Unknown worker failure is reconciled only by reading the fixed protected
    // receipt. It does not publish, install, or relaunch. The finite role deadline
    // bounds retained process/file handles when no coordinator terminal state exists.
    internal void ReconcileUncertainOutcome() {
        VpnInstallHelperRoles.ReceiptCursor cursor=new VpnInstallHelperRoles.ReceiptCursor(JobId);
        long minimumSequence=lastObservedReceipt==null ? -1 : lastObservedReceipt.Sequence;
        for (;;) {
            VpnInstallHelperRoles.Receipt receipt=ReadReceipt();
            if (receipt!=null) {
                VpnInstallHelperRoles.Receipt accepted=cursor.Accept(receipt);
                if (accepted.Terminal) {
                    if (accepted.Sequence<=minimumSequence) throw new IOException("CONFLICT");
                    return;
                }
                // ReceiptCursor permits later nonterminal progress, including an
                // advanced INSTALLING receipt. It remains observation-only until a
                // correlated terminal receipt arrives.
                if (accepted.Sequence<minimumSequence) throw new IOException("CONFLICT");
            }
            if (ReturnDeadlineReached) throw new IOException("OUTCOME_UNKNOWN");
            Pause();
        }
    }

    static byte[] ReadBounded(FileStream stream,int limit) {
        if (stream==null || !stream.CanRead || stream.Length<1 || stream.Length>limit) throw new IOException("INVALID_ARGUMENT");
        byte[] bytes=new byte[checked((int)stream.Length)]; int offset=0;
        while (offset<bytes.Length) { int count=stream.Read(bytes,offset,bytes.Length-offset); if (count<=0) throw new IOException("UNAVAILABLE"); offset+=count; }
        if (stream.ReadByte()!=-1) throw new IOException("INVALID_ARGUMENT");
        return bytes;
    }

    sealed class PackageInput : VpnInstallHelperMsi.AdmittedInput {
        readonly OwnerInputAdmission admission;
        readonly string path, digest;
        readonly long size;
        FileStream stream;
        internal PackageInput(OwnerInputAdmission retainedAdmission) {
            admission=retainedAdmission; path=admission.Request.PackageFile; size=admission.Request.PackageSize;
            SafeFileHandle handle=admission.OpenAdmittedPackage(path);
            try {
                stream=new FileStream(handle,FileAccess.Read,1,false); handle=null;
                if (stream.Length!=size) throw new IOException("INVALID_ARGUMENT");
                digest=Sha256(stream); if (!String.Equals(digest,admission.Request.PackageSha256,StringComparison.Ordinal)) throw new IOException("INVALID_ARGUMENT");
                stream.Position=0;
            } catch {
                if (stream!=null) { stream.Dispose(); stream=null; }
                throw;
            } finally { if (handle!=null) handle.Dispose(); }
        }
        public string PackagePath { get { return path; } }
        public void Recheck() {
            if (stream==null) throw new ObjectDisposedException("package");
            // Coordinator admission deliberately waits for the old owner to exit;
            // package identity is held by this stream, not re-derived from that PID.
            if (stream.Length!=size ||
                !String.Equals(Sha256(stream),digest,StringComparison.Ordinal)) throw new IOException("CONFLICT");
            stream.Position=0;
        }
        internal static string Sha256(string file) { using (FileStream source=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read)) return Sha256(source); }
        internal static string Sha256(FileStream source) {
            source.Position=0; using (SHA256 hash=SHA256.Create()) {
                byte[] value=hash.ComputeHash(source); return BitConverter.ToString(value).Replace("-","").ToLowerInvariant();
            }
        }
        public void Dispose() { if (stream!=null) { stream.Dispose(); stream=null; } }
    }
}

// Internal test-only facilities for constructing the actual adapter with inert
// effects. This type is not reachable from protocol parsing or the native entrypoint.
internal interface OriginalUserSessionAdapterFacilities : IDisposable {
    string JobId { get; }
    bool AuthorizationDeadlineReached { get; }
    bool ReturnDeadlineReached { get; }
    void Pause();
    void PublishReady();
    VpnInstallHelperRoles.Receipt ReadProtectedReceipt();
    uint InstallVerifiedPackage();
    void PublishNativeResult(uint exitCode);
    void RelaunchOriginalOwner();
}

// Retains the exact source of all later role authority. Close failures retain
// ownership in this object for an explicit retry; they never turn a possibly
// live owner/input into permission to adopt a replacement.
internal sealed class OwnerInputAdmission : IDisposable {
    readonly List<IDisposable> retained=new List<IDisposable>();
    bool closed;
    internal readonly VpnInstallNative.ProcessPin Owner;
    internal readonly VpnInstallNative.ProcessImagePin OwnerGeneration;
    internal readonly WindowsIdentity Caller;
    internal VpnInstallHelperProtocol.Request Request { get; private set; }

    OwnerInputAdmission(VpnInstallNative.ProcessPin owner,VpnInstallNative.ProcessImagePin generation,
        WindowsIdentity caller) {
        Owner=owner; OwnerGeneration=generation; Caller=caller;
        retained.Add(owner); retained.Add(generation); retained.Add(caller);
    }

    internal static OwnerInputAdmission Open(VpnInstallHelperProtocol.Invocation invocation,bool originalUser) {
        return Open(invocation,originalUser,null);
    }

    // Same-assembly test seam for an owned local root; production always reads the
    // retained owner's known LocalAppData path.
    internal static OwnerInputAdmission Open(VpnInstallHelperProtocol.Invocation invocation,bool originalUser,
        Func<string> localRootForTest) {
        if (invocation==null) throw new ArgumentException("INVALID_ARGUMENT");
        VpnInstallNative.ProcessPin owner=null;
        VpnInstallNative.ProcessImagePin generation=null;
        WindowsIdentity caller=null;
        OwnerInputAdmission result=null;
        try {
            owner=new VpnInstallNative.ProcessPin(invocation.OwnerPid);
            generation=new VpnInstallNative.ProcessImagePin(invocation.OwnerPid);
            VpnInstallNative.ProcessImageObservation observed=generation.Observe();
            if (observed.Pid!=invocation.OwnerPid || observed.CreationFileTime!=invocation.OwnerCreationFileTime ||
                observed.KernelOnly || owner.Exited) throw new IOException("CONFLICT");
            caller=WindowsIdentity.GetCurrent();
            if (caller==null || caller.User==null || String.IsNullOrEmpty(caller.User.Value))
                throw new IOException("Installer caller token unavailable");
            bool administrator=new WindowsPrincipal(caller).IsInRole(WindowsBuiltInRole.Administrator);
            if (originalUser) {
                if (administrator || !String.Equals(caller.User.Value,owner.Principal,StringComparison.Ordinal))
                    throw new IOException("CONFLICT");
            } else if (!administrator) throw new IOException("PRIVILEGE_REQUIRED");
            result=new OwnerInputAdmission(owner,generation,caller);
            owner=null; generation=null; caller=null;
            result.ReadRequest(invocation,localRootForTest==null ? result.Owner.LocalAppData() : localRootForTest());
            result.ValidateRequest(invocation);
            return result;
        } catch {
            if (result!=null) { try { result.Dispose(); } catch { } }
            else {
                if (caller!=null) caller.Dispose();
                if (generation!=null) generation.Dispose();
                if (owner!=null) owner.Dispose();
            }
            throw;
        }
    }

    void ReadRequest(VpnInstallHelperProtocol.Invocation invocation,string local) {
        VpnInstallHelperProtocol.LocalPath(local);
        int retainedAtStart=retained.Count;
        SafeFileHandle requestHandle=null;
        try {
            SafeFileHandle localDirectory=PinDirectoryPath(local,Owner.Principal);
            SafeFileHandle inputRoot=OpenPinnedDirectory(localDirectory,
                Path.Combine(local,"vpn-control-install-inputs"),Owner.Principal,true);
            retained.Add(inputRoot);
            SafeFileHandle input=OpenPinnedDirectory(inputRoot,
                Path.Combine(local,"vpn-control-install-inputs",invocation.JobId),Owner.Principal,false);
            retained.Add(input);
            requestHandle=VpnInstallNative.OpenRead(Path.Combine(local,"vpn-control-install-inputs",invocation.JobId,"request.json"),false);
            VpnInstallNative.InspectLinkedAncestor(input,requestHandle,Owner.Principal);
            VpnInstallNative.Inspect(requestHandle,false,false,Owner.Principal);
            FileStream requestStream=new FileStream(requestHandle,FileAccess.Read,1,false);
            requestHandle=null;
            retained.Add(requestStream);
            Request=VpnInstallHelperProtocol.ParseRequest(ReadBounded(requestStream,65536));
            // The stream remains retained after parsing. A later leaf replacement cannot
            // alter the already admitted request or free its no-delete input witness.
        } catch (Exception readFailure) {
            if (requestHandle!=null) {
                try { requestHandle.Dispose(); }
                catch (Exception cleanupFailure) {
                    readFailure.Data["vpn.install.inputAdmission.cleanupUncertain"]=cleanupFailure.GetType().FullName;
                }
            }
            try { ReleaseRetainedFrom(retainedAtStart); }
            catch (Exception cleanupFailure) {
                readFailure.Data["vpn.install.inputAdmission.cleanupUncertain"]=cleanupFailure.GetType().FullName;
            }
            throw;
        }
    }

    // Package bytes are admitted through their pinned parent and that parent is
    // retained with the original input chain. A leaf-only pin cannot establish that
    // the request's package remained inside the admitted private input directory.
    internal SafeFileHandle OpenAdmittedPackage(string path) {
        VpnInstallHelperProtocol.LocalPath(path);
        string parentPath=Path.GetDirectoryName(path);
        if (String.IsNullOrEmpty(parentPath)) throw new IOException("INVALID_ARGUMENT");
        SafeFileHandle parent=PinDirectoryPath(parentPath,Owner.Principal);
        SafeFileHandle package=VpnInstallNative.OpenRead(path,false);
        try {
            VpnInstallNative.InspectLinkedAncestor(parent,package,Owner.Principal);
            VpnInstallNative.Inspect(package,false,false,Owner.Principal);
            return package;
        } catch { package.Dispose(); throw; }
    }

    SafeFileHandle PinDirectoryPath(string path,string principal) {
        string root=Path.GetPathRoot(path);
        if (String.IsNullOrEmpty(root) || !String.Equals(root,path.Substring(0,root.Length),StringComparison.Ordinal))
            throw new IOException("INVALID_ARGUMENT");
        string remaining=path.Substring(root.Length);
        string[] parts=remaining.Split(new char[] {'\\'},StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length==0) throw new IOException("INVALID_ARGUMENT");
        SafeFileHandle parent=VpnInstallNative.OpenDirectory(root);
        try {
            VpnInstallNative.Inspect(parent,true,true,principal);
            retained.Add(parent);
            string current=root.TrimEnd('\\');
            for (int index=0;index<parts.Length;index++) {
                string part=parts[index];
                if (part=="." || part=="..") throw new IOException("INVALID_ARGUMENT");
                current=current+"\\"+part;
                SafeFileHandle child=OpenPinnedDirectory(parent,current,principal,index!=parts.Length-1);
                retained.Add(child); parent=child;
            }
            return parent;
        } catch { if (!retained.Contains(parent)) parent.Dispose(); throw; }
    }

    static SafeFileHandle OpenPinnedDirectory(SafeFileHandle parent,string path,string principal,bool ancestor) {
        SafeFileHandle result=VpnInstallNative.OpenDirectory(path);
        try {
            if (parent==null) VpnInstallNative.Inspect(result,true,ancestor,principal);
            else VpnInstallNative.InspectLinkedAncestor(parent,result,principal);
            if (!ancestor) VpnInstallNative.Inspect(result,true,false,principal);
            return result;
        } catch { result.Dispose(); throw; }
    }

    static byte[] ReadBounded(FileStream stream,int limit) {
        if (stream==null || !stream.CanRead || stream.Length<1 || stream.Length>limit) throw new IOException("INVALID_ARGUMENT");
        int length=checked((int)stream.Length); byte[] bytes=new byte[length]; int offset=0;
        while (offset<bytes.Length) {
            int count=stream.Read(bytes,offset,bytes.Length-offset);
            if (count<=0) throw new IOException("UNAVAILABLE");
            offset+=count;
        }
        if (stream.ReadByte()!=-1) throw new IOException("INVALID_ARGUMENT");
        return bytes;
    }

    void ValidateRequest(VpnInstallHelperProtocol.Invocation invocation) {
        VpnInstallNative.ProcessImageObservation current=OwnerGeneration.Observe();
        if (current.Pid!=invocation.OwnerPid || current.CreationFileTime!=invocation.OwnerCreationFileTime || current.KernelOnly)
            throw new IOException("CONFLICT");
        if (Request==null || Request.JobId!=invocation.JobId || Request.OwnerPid!=invocation.OwnerPid ||
            Request.OwnerStartedAtEpochMillis!=Owner.StartedAtEpochMillis ||
            !String.Equals(Request.PrincipalSid,Owner.Principal,StringComparison.Ordinal)) throw new IOException("CONFLICT");
        string imageLeaf=Path.GetFileName(Owner.Image);
        if ((!String.Equals(imageLeaf,"vpn-control.exe",StringComparison.OrdinalIgnoreCase) &&
             !String.Equals(imageLeaf,"vpn-control-cli.exe",StringComparison.OrdinalIgnoreCase)) ||
            !String.Equals(Path.GetDirectoryName(Owner.Image),Path.GetDirectoryName(Request.Launcher),StringComparison.OrdinalIgnoreCase))
            throw new IOException("CONFLICT");
        if (Owner.Exited) throw new IOException("CONFLICT");
    }

    void ReleaseRetainedFrom(int start) {
        Exception failure=null;
        for (int index=retained.Count-1;index>=start;index--) {
            try { retained[index].Dispose(); retained.RemoveAt(index); }
            catch (Exception error) { if (failure==null) failure=error; }
        }
        if (failure!=null) throw new IOException("PERSISTENCE_FAILED",failure);
    }

    public void Dispose() {
        if (closed) return;
        Exception failure=null;
        for (int index=retained.Count-1;index>=0;index--) {
            try { retained[index].Dispose(); retained.RemoveAt(index); }
            catch (Exception error) { if (failure==null) failure=error; }
        }
        closed=retained.Count==0;
        if (failure!=null) throw new IOException("PERSISTENCE_FAILED",failure);
    }
}
