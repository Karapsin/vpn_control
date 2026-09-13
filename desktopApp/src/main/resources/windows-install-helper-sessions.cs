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
        CoordinatorSessionAdapter coordinator=null;
        try {
            if (originalUser) {
                session=new OriginalUserSessionAdapter(admission);
                return VpnInstallHelperRoles.RunOriginalUser(session);
            }
            coordinator=new CoordinatorSessionAdapter(admission);
            VpnInstallHelperRoles.RunCoordinator(coordinator);
            return 0;
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
            if (coordinator!=null) coordinator.Dispose();
            if (session!=null) session.Dispose();
            admission.Dispose();
        }
    }
}

// Coordinator state is intentionally separated from OriginalUserSessionAdapter:
// it owns only protected state and retained identity witnesses, never an MSI
// adapter, package handle, command line, or relaunch authority.
internal sealed class CoordinatorSessionAdapter : VpnInstallHelperRoles.CoordinatorSession, IDisposable {
    readonly CoordinatorSessionAdapterFacilities fixture;
    readonly OwnerInputAdmission admission;
    readonly DateTime precommitDeadline, exitDeadline;
    readonly CoordinatorReceiptWriter fixtureReceiptWriter;
    CoordinatorReceiptWriter receiptWriter;
    VpnInstallNative.ProcessPin worker, frontend;
    VpnInstallNative.ProcessImagePin workerGeneration, coordinatorGeneration;
    VpnInstallNative.ExecutableReplacementSet installation;
    FileStream workerImage, coordinatorImage, gate, cancel;
    SafeFileHandle programDataDirectory, programDataWitness, machineDirectory, jobDirectory;
    bool reserved, exclusive;
    bool disposed;

    internal CoordinatorSessionAdapter(CoordinatorSessionAdapterFacilities facilities) {
        if (facilities==null) throw new ArgumentNullException("facilities");
        fixture=facilities;
    }
    internal CoordinatorSessionAdapter(CoordinatorSessionAdapterFacilities facilities,CoordinatorReceiptWriter writer) {
        if (facilities==null || writer==null || facilities.JobId!=writer.JobId) throw new ArgumentException("Coordinator fixture rejected");
        fixture=facilities; fixtureReceiptWriter=writer;
    }

    internal CoordinatorSessionAdapter(OwnerInputAdmission retainedAdmission) {
        if (retainedAdmission==null || retainedAdmission.Request==null) throw new IOException("CONFLICT");
        admission=retainedAdmission;
        precommitDeadline=DateTime.UtcNow.AddMinutes(3);
        exitDeadline=precommitDeadline;
        try { AdmitWorker(); }
        catch { Dispose(); throw; }
    }

    public string JobId { get { return fixture==null ? admission.Request.JobId : fixture.JobId; } }
    public void ReserveInstallation() {
        if (fixture!=null) { fixture.ReserveInstallation(); return; }
        string launcherDirectory=Path.GetDirectoryName(admission.Request.Launcher);
        if (String.IsNullOrEmpty(launcherDirectory)) throw new IOException("CONFLICT");
        SafeFileHandle directory=VpnInstallNative.OpenDirectory(launcherDirectory);
        string installationId;
        try {
            VpnInstallNative.Inspect(directory,true,false,admission.Owner.Principal);
            installationId=VpnInstallNative.InstallationId(directory);
            installation=new VpnInstallNative.ExecutableReplacementSet(directory,admission.Owner.Principal);
            directory=null;
        } finally { if (directory!=null) directory.Dispose(); }
        string machine=OpenProtectedMachineDirectory();
        string gatePath=Path.Combine(machine,"gate-"+installationId);
        const string gateAcl="O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;BU)";
        try { gate=VpnInstallNative.CreateFile(gatePath,gateAcl,new byte[17]); }
        catch (Win32Exception error) { if (error.NativeErrorCode!=80) throw; gate=VpnInstallNative.OpenGate(gatePath,true); }
        VpnInstallNative.InspectLinkedAncestor(machineDirectory,gate.SafeFileHandle,null);
        VpnInstallNative.Inspect(gate.SafeFileHandle,false,false,null);
        if (gate.Length!=17 || !VpnInstallNative.TryLock(gate.SafeFileHandle,16,true)) throw new IOException("BUSY");
        reserved=true; gate.Position=0;
        for (int index=0;index<17;index++) if (gate.ReadByte()!=0) throw new IOException("BUSY");
    }
    public void CreateProtectedJob() {
        if (fixture!=null) { fixture.CreateProtectedJob(); return; }
        string machine=OpenProtectedMachineDirectory();
        string jobPath=Path.Combine(machine,JobId);
        const string jobAcl="O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)";
        VpnInstallNative.CreateDirectory(jobPath,jobAcl);
        jobDirectory=VpnInstallNative.OpenDirectory(jobPath);
        VpnInstallNative.InspectLinkedAncestor(machineDirectory,jobDirectory,null);
        VpnInstallNative.Inspect(jobDirectory,true,false,null);
        string cancelAcl="O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x00120083;;;";
        cancel=VpnInstallNative.CreateProtectedChild(jobDirectory,"cancel",cancelAcl+admission.Owner.Principal+")",new byte[] { 0 });
        receiptWriter=new CoordinatorReceiptWriter(JobId,jobDirectory,new NativeCoordinatorReceiptPublisher());
    }
    public void Publish(VpnInstallHelperRoles.Phase phase,string code) {
        if (fixture!=null) { if (fixtureReceiptWriter!=null) fixtureReceiptWriter.Publish(phase,code); else fixture.Publish(phase,code); return; }
        if (jobDirectory==null) throw new IOException("CONFLICT");
        if (receiptWriter==null) receiptWriter=new CoordinatorReceiptWriter(JobId,jobDirectory,new NativeCoordinatorReceiptPublisher());
        receiptWriter.Publish(phase,code);
    }
    public void SetPending(bool value) {
        if (fixture!=null) { fixture.SetPending(value); return; }
        if (gate==null) throw new IOException("CONFLICT");
        gate.Position=8; gate.WriteByte(value ? (byte)1 : (byte)0); gate.Flush(true);
    }
    public bool CancellationRequested { get {
        if (fixture!=null) return fixture.CancellationRequested;
        if (cancel==null) throw new IOException("CONFLICT");
        cancel.Position=0; int value=cancel.ReadByte();
        if (value!=0 && value!=1) throw new IOException("CONFLICT"); return value==1;
    } }
    public bool OwnerExited { get { return fixture==null ? admission.Owner.Exited : fixture.OwnerExited; } }
    public bool FrontendExited { get { return fixture==null ? frontend==null || frontend.Exited : fixture.FrontendExited; } }
    public bool WorkerExited { get { return fixture==null ? worker.Exited : fixture.WorkerExited; } }
    public bool PrecommitDeadlineReached { get { return fixture==null ? DateTime.UtcNow>=precommitDeadline : fixture.PrecommitDeadlineReached; } }
    public bool ExitDeadlineReached { get { return fixture==null ? DateTime.UtcNow>=exitDeadline : fixture.ExitDeadlineReached; } }
    public bool CommitExists() {
        if (fixture!=null) return fixture.CommitExists();
        byte[] record=admission.ReadPrivateLeaf("commit.json",true);
        return record!=null && VpnInstallHelperProtocol.IsCommit(record,JobId);
    }
    public bool TryExclusiveAdmission() {
        if (fixture!=null) return fixture.TryExclusiveAdmission();
        if (gate==null || !admission.Owner.Exited || (frontend!=null && !frontend.Exited)) return false;
        if (!exclusive) exclusive=VpnInstallNative.TryLock(gate.SafeFileHandle,0,true);
        return exclusive;
    }
    public bool TryInstallationReady() {
        if (fixture!=null) return fixture.TryInstallationReady();
        if (!exclusive || installation==null) throw new IOException("CONFLICT");
        return VpnInstallHelperProcessInventory.TryNoAdmittedInstallationCopies(installation,
            (uint)Process.GetCurrentProcess().Id,worker.Pid) && installation.TryReady();
    }
    public uint? ReadNativeResult() {
        if (fixture!=null) return fixture.ReadNativeResult();
        byte[] record=admission.ReadPrivateLeaf("worker-result.json",true);
        return record==null ? (uint?)null : VpnInstallHelperProtocol.ParseWorkerResult(record,JobId);
    }
    public void Pause() { if (fixture==null) Thread.Sleep(100); else fixture.Pause(); }
    string OpenProtectedMachineDirectory() {
        if (machineDirectory!=null) return Path.Combine(VpnInstallNative.ProgramData(),"vpn-control-install-jobs");
        string programData=VpnInstallNative.ProgramData();
        programDataDirectory=VpnInstallNative.OpenDirectory(programData);
        try { VpnInstallNative.Inspect(programDataDirectory,true,true,null); }
        catch {
            // ProgramData can legitimately carry inheritable metadata rights; retain
            // a nonempty exact child witness rather than trusting a path lookup.
            programDataWitness=VpnInstallNative.PinNonEmptyAncestor(programDataDirectory,null);
        }
        string machine=Path.Combine(programData,"vpn-control-install-jobs");
        const string machineAcl="O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)";
        try { VpnInstallNative.CreateDirectory(machine,machineAcl); }
        catch (Win32Exception error) { if (error.NativeErrorCode!=183) throw; }
        machineDirectory=VpnInstallNative.OpenDirectory(machine);
        VpnInstallNative.InspectLinkedAncestor(programDataDirectory,machineDirectory,null);
        VpnInstallNative.Inspect(machineDirectory,true,false,null);
        return machine;
    }
    void AdmitWorker() {
        VpnInstallHelperProtocol.WorkerReady ready=VpnInstallHelperProtocol.ParseWorkerReady(admission.ReadPrivateLeaf("worker-ready.json",false));
        if (ready.JobId!=JobId || ready.PrincipalSid!=admission.Owner.Principal) throw new IOException("CONFLICT");
        worker=new VpnInstallNative.ProcessPin(ready.Pid);
        workerGeneration=new VpnInstallNative.ProcessImagePin(ready.Pid);
        VpnInstallNative.ProcessImageObservation observed=workerGeneration.Observe();
        if (worker.Exited || worker.Principal!=admission.Owner.Principal || observed.KernelOnly ||
            observed.CreationFileTime!=ready.CreationFileTime) throw new IOException("CONFLICT");
        SafeFileHandle image=VpnInstallNative.OpenRead(observed.Image,false);
        try {
            VpnInstallNative.Inspect(image,false,false,null);
            workerImage=new FileStream(image,FileAccess.Read,1,false); image=null;
            if (!String.Equals(VpnInstallNative.Sha256(workerImage),ready.HelperSha256,StringComparison.Ordinal)) throw new IOException("CONFLICT");
        } finally { if (image!=null) image.Dispose(); }
        coordinatorGeneration=new VpnInstallNative.ProcessImagePin((uint)Process.GetCurrentProcess().Id);
        VpnInstallNative.ProcessImageObservation coordinator=coordinatorGeneration.Observe();
        if (coordinator.KernelOnly) throw new IOException("CONFLICT");
        SafeFileHandle coordinatorHandle=VpnInstallNative.OpenRead(coordinator.Image,false);
        try {
            VpnInstallNative.Inspect(coordinatorHandle,false,false,null);
            coordinatorImage=new FileStream(coordinatorHandle,FileAccess.Read,1,false); coordinatorHandle=null;
            if (!VpnInstallNative.SameFileObject(workerImage.SafeFileHandle,coordinatorImage.SafeFileHandle) ||
                !String.Equals(VpnInstallNative.Sha256(coordinatorImage),ready.HelperSha256,StringComparison.Ordinal))
                throw new IOException("CONFLICT");
        } finally { if (coordinatorHandle!=null) coordinatorHandle.Dispose(); }
        if (admission.Request.FrontendPid.HasValue) {
            frontend=new VpnInstallNative.ProcessPin(admission.Request.FrontendPid.Value);
            if (frontend.Exited || frontend.Principal!=admission.Owner.Principal ||
                frontend.StartedAtEpochMillis!=admission.Request.FrontendStartedAtEpochMillis.Value ||
                !String.Equals(frontend.Image,admission.Request.Launcher,StringComparison.OrdinalIgnoreCase)) throw new IOException("CONFLICT");
        }
    }
    public void Dispose() {
        if (disposed) return;
        if (fixture!=null) { fixture.Dispose(); disposed=true; return; }
        Exception failure=null;
        try { if (exclusive) { VpnInstallNative.Unlock(gate.SafeFileHandle,0); exclusive=false; } } catch (Exception error) { failure=error; }
        try { if (reserved) { VpnInstallNative.Unlock(gate.SafeFileHandle,16); reserved=false; } } catch (Exception error) { if (failure==null) failure=error; }
        IDisposable[] resources={ cancel,jobDirectory,machineDirectory,programDataWitness,programDataDirectory,gate,workerImage,coordinatorImage,
            workerGeneration,coordinatorGeneration,worker,frontend,installation };
        for (int index=0;index<resources.Length;index++) try { if (resources[index]!=null) resources[index].Dispose(); }
            catch (Exception error) { if (failure==null) failure=error; }
        if (failure!=null) throw new IOException("PERSISTENCE_FAILED",failure);
        disposed=true;
    }
}

// Same-assembly only. It intentionally has no MSI, command, path, token or
// process-launch member, making it impossible for a coordinator regression to
// acquire original-user installation authority through this seam.
internal interface CoordinatorSessionAdapterFacilities : IDisposable {
    string JobId { get; }
    void ReserveInstallation();
    void CreateProtectedJob();
    void Publish(VpnInstallHelperRoles.Phase phase,string code);
    void SetPending(bool value);
    bool CancellationRequested { get; }
    bool OwnerExited { get; }
    bool FrontendExited { get; }
    bool WorkerExited { get; }
    bool PrecommitDeadlineReached { get; }
    bool ExitDeadlineReached { get; }
    bool CommitExists();
    bool TryExclusiveAdmission();
    bool TryInstallationReady();
    uint? ReadNativeResult();
    void Pause();
}

// The writer is the sole receipt publication boundary used by the production
// adapter. A test may replace only its atomic publisher; it cannot supply a
// coordinator role, installer, token, path, or process-launch authority.
internal interface CoordinatorReceiptPublisher {
    void Replace(SafeFileHandle directory,string temporaryName,byte[] record);
}

internal sealed class NativeCoordinatorReceiptPublisher : CoordinatorReceiptPublisher {
    const string ReceiptAcl="O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;BU)";
    public void Replace(SafeFileHandle directory,string temporaryName,byte[] record) {
        using (FileStream output=VpnInstallNative.CreateProtectedChild(directory,temporaryName,ReceiptAcl,record)) { }
        VpnInstallNative.ReplaceReceipt(directory,temporaryName);
    }
}

internal sealed class CoordinatorReceiptWriter {
    readonly string jobId;
    readonly SafeFileHandle directory;
    readonly CoordinatorReceiptPublisher publisher;
    readonly VpnInstallHelperRoles.ReceiptCursor cursor;
    long sequence=-1;
    internal string JobId { get { return jobId; } }
    internal CoordinatorReceiptWriter(string job,SafeFileHandle retainedDirectory,CoordinatorReceiptPublisher receiptPublisher) {
        VpnInstallHelperProtocol.Job(job);
        if (receiptPublisher==null) throw new ArgumentNullException("receiptPublisher");
        jobId=job; directory=retainedDirectory; publisher=receiptPublisher;
        cursor=new VpnInstallHelperRoles.ReceiptCursor(job);
    }
    internal void Publish(VpnInstallHelperRoles.Phase phase,string code) {
        VpnInstallHelperRoles.Receipt receipt=new VpnInstallHelperRoles.Receipt(jobId,checked(sequence+1),phase,code);
        try {
            publisher.Replace(directory,"status-"+Guid.NewGuid().ToString("D")+".tmp",VpnInstallHelperProtocol.EncodeReceipt(receipt));
        } catch (VpnInstallHelperRoles.PublicationUncertainException) { throw; }
        catch (Exception error) { throw new VpnInstallHelperRoles.PublicationUncertainException(error); }
        cursor.Accept(receipt);
        sequence=receipt.Sequence;
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
    internal SafeFileHandle InputDirectory { get; private set; }

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
            InputDirectory=input;
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

    // Only known protocol leaves are read through the retained private input
    // directory. A caller cannot choose a path or replace an admitted leaf.
    internal byte[] ReadPrivateLeaf(string leaf,bool initialMissing) {
        if (InputDirectory==null || InputDirectory.IsInvalid) throw new IOException("CONFLICT");
        if (leaf!="worker-ready.json" && leaf!="commit.json" && leaf!="worker-result.json")
            throw new IOException("INVALID_ARGUMENT");
        string local=Owner.LocalAppData();
        string path=Path.Combine(local,"vpn-control-install-inputs",Request.JobId,leaf);
        try {
            using (SafeFileHandle file=VpnInstallNative.OpenRead(path,false)) {
                VpnInstallNative.InspectLinkedAncestor(InputDirectory,file,Owner.Principal);
                VpnInstallNative.Inspect(file,false,false,Owner.Principal);
                using (FileStream stream=new FileStream(file,FileAccess.Read,1,false))
                    return ReadBounded(stream,65536);
            }
        } catch (Win32Exception error) {
            if (initialMissing && (error.NativeErrorCode==2 || error.NativeErrorCode==3)) return null;
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
