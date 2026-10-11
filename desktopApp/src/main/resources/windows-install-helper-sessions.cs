// Fixed native installer session admission. Requests are data only until this
// class retains the invoking owner generation, its token identity, and every
// private input ancestor. No argv path selects any of these objects.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal interface VpnInstallHelperSessionFactory {
    int Run(VpnInstallHelperProtocol.Invocation invocation);
}

// The coordinator alone owns the elevated-to-original-user handoff.  The child
// exposes only its retained OS identity; no test or caller can supply an image,
// token, command, package, or arbitrary worker implementation.
internal interface CoordinatorOriginalUserChild : IDisposable {
    uint ProcessId { get; }
    long CreationFileTime { get; }
    string PrincipalSid { get; }
    bool Exited { get; }
    void ReconcileBeforeAdmission();
    void ReconcileAfterAdmission();
    // Releases only the launch-time image/ancestry witness after the coordinator
    // has retained and compared its own exact image handles.
    void ReleaseLaunchImagePinAfterAdmission();
}

internal static class CoordinatorOriginalUserBootstrap {
    sealed class NativeChild : CoordinatorOriginalUserChild {
        readonly VpnInstallOriginalUserLaunch.StartedHelper child;
        readonly VpnInstallOriginalUserLaunch.ChildIdentity identity;
        internal NativeChild(VpnInstallOriginalUserLaunch.StartedHelper started) {
            if (started==null) throw new ArgumentNullException("started");
            child=started; identity=child.Observe();
            if (identity.ProcessId==0 || identity.CreationFileTime<=0 || identity.Elevated ||
                String.IsNullOrEmpty(identity.Sid)) throw new IOException("CONFLICT");
        }
        public uint ProcessId { get { return identity.ProcessId; } }
        public long CreationFileTime { get { return identity.CreationFileTime; } }
        public string PrincipalSid { get { return identity.Sid; } }
        public bool Exited { get { return child.Wait(0); } }
        public void ReconcileBeforeAdmission() { child.StopBeforeCoordinatorAdmission(); }
        public void ReconcileAfterAdmission() { child.ReconcileAfterCoordinatorAdmission(); }
        public void ReleaseLaunchImagePinAfterAdmission() { child.ReleaseLaunchImagePinAfterAdmission(); }
        public void Dispose() { child.Dispose(); }
    }

    internal static CoordinatorOriginalUserChild Start(VpnInstallHelperProtocol.Invocation invocation,string ownerPrincipal) {
        if (invocation==null || String.IsNullOrEmpty(ownerPrincipal)) throw new IOException("CONFLICT");
        using (VpnInstallOriginalUserLaunch original=VpnInstallOriginalUserLaunch.Capture()) {
            if (!String.Equals(original.PrincipalSid,ownerPrincipal,StringComparison.Ordinal)) throw new IOException("CONFLICT");
            VpnInstallOriginalUserLaunch.StartedHelper started=null;
            try {
                try {
                    started=original.StartSameHelper(new string[] { "install-user",invocation.JobId,
                        invocation.OwnerPid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        invocation.OwnerCreationFileTime.ToString(System.Globalization.CultureInfo.InvariantCulture) });
                } catch (VpnInstallOriginalUserLaunch.UncertainChild uncertain) {
                    // StartSameHelper retained this exact pre-admission child;
                    // it cannot escape through the exception path.
                    try { uncertain.Child.StopBeforeCoordinatorAdmission(); }
                    finally { uncertain.Dispose(); }
                    throw;
                }
                NativeChild child=null;
                try { child=new NativeChild(started); }
                catch { started.StopBeforeCoordinatorAdmission(); throw; }
                started=null;
                if (!String.Equals(child.PrincipalSid,ownerPrincipal,StringComparison.Ordinal)) {
                    child.ReconcileBeforeAdmission(); child.Dispose(); throw new IOException("CONFLICT");
                }
                return child;
            } finally { if (started!=null) { started.StopBeforeCoordinatorAdmission(); started.Dispose(); } }
        }
    }
}

// This lease is the sole coordinator bootstrap ordering.  It retains the exact
// original-user process from launch through parser admission and later role
// cleanup.  A failed parser is still before any gate/job/receipt/MSI phase, so
// the owned child is stopped and observed; after admission it is only observed.
internal sealed class CoordinatorOriginalUserBootstrapLease : IDisposable {
    readonly CoordinatorOriginalUserChild child;
    readonly CoordinatorSessionAdapter coordinator;
    readonly OwnerInputAdmission admission;
    bool disposed;
    internal CoordinatorSessionAdapter Coordinator { get { return coordinator; } }
    internal CoordinatorOriginalUserBootstrapLease(VpnInstallHelperProtocol.Invocation invocation,OwnerInputAdmission retainedAdmission) :
        this(invocation,retainedAdmission,null,null,null) { }
    // Same-assembly regression seam. It may inject only the already-started OS
    // child observations and monotonic wait source; parser/admission stays real.
    internal CoordinatorOriginalUserBootstrapLease(VpnInstallHelperProtocol.Invocation invocation,OwnerInputAdmission retainedAdmission,
        Func<VpnInstallHelperProtocol.Invocation,string,CoordinatorOriginalUserChild> startForTest,
        CoordinatorWorkerReadyWait waitForTest,Func<string> machineDirectoryForTest) {
        if (invocation==null || retainedAdmission==null) throw new IOException("CONFLICT");
        admission=retainedAdmission;
        try {
            child=startForTest==null ? CoordinatorOriginalUserBootstrap.Start(invocation,admission.Owner.Principal) :
                startForTest(invocation,admission.Owner.Principal);
            if (child==null) throw new IOException("RUNTIME_FAILED");
            coordinator=new CoordinatorSessionAdapter(admission,child,waitForTest,machineDirectoryForTest);
        } catch {
            if (child!=null) {
                // No protected job can exist before the adapter constructor
                // returns. This includes a launch-pin release failure at the
                // final admission step, so it is still bounded pre-admission.
                child.ReconcileBeforeAdmission();
                child.Dispose();
            }
            throw;
        }
    }
    public void Dispose() {
        if (disposed) return;
        Exception failure=ReconcileAndDispose(child,coordinator);
        disposed=true;
        if (failure!=null) throw new IOException("OUTCOME_UNKNOWN",failure);
    }
    // Shared disposal boundary; same-assembly tests may supply only retained
    // child observations and an adapter with no MSI/launch/token authority.
    internal static Exception ReconcileAndDispose(CoordinatorOriginalUserChild child,CoordinatorSessionAdapter coordinator) {
        Exception failure=null;
        // Release only terminal-cleared gate ranges before waiting for return.
        // The exact child and all coordinator/input witnesses remain retained.
        try { coordinator.ReleaseTerminalReturnGate(); } catch (Exception error) { failure=error; }
        try { child.ReconcileAfterAdmission(); } catch (Exception error) { if (failure==null) failure=error; }
        try { child.Dispose(); } catch (Exception error) { if (failure==null) failure=error; }
        try { coordinator.Dispose(); } catch (Exception error) { if (failure==null) failure=error; }
        return failure;
    }
}

internal interface CoordinatorWorkerReadyWait {
    bool DeadlineReached { get; }
    bool CancellationRequested { get; }
    void Pause();
}

internal sealed class NativeCoordinatorWorkerReadyWait : CoordinatorWorkerReadyWait {
    readonly Stopwatch stopwatch=Stopwatch.StartNew();
    readonly OwnerInputAdmission admission;
    internal NativeCoordinatorWorkerReadyWait(OwnerInputAdmission retainedAdmission) { admission=retainedAdmission; }
    public bool DeadlineReached { get { return stopwatch.ElapsedMilliseconds>=30000; } }
    // The retained owner process is the only admitted pre-job cancellation
    // authority until a protected job/cancel leaf exists.
    public bool CancellationRequested { get { return admission.Owner.Exited; } }
    public void Pause() { Thread.Sleep(50); }
}

internal sealed class VpnInstallHelperNativeSessions : VpnInstallHelperSessionFactory {
    public int Run(VpnInstallHelperProtocol.Invocation invocation) {
        if (invocation==null) throw new ArgumentException("INVALID_ARGUMENT");
        bool originalUser=invocation.Operation==VpnInstallHelperProtocol.Role.OriginalUser;
        OwnerInputAdmission admission=OwnerInputAdmission.Open(invocation,originalUser);
        OriginalUserSessionAdapter session=null;
        CoordinatorOriginalUserBootstrapLease bootstrap=null;
        try {
            if (originalUser) {
                session=new OriginalUserSessionAdapter(admission);
                return VpnInstallHelperRoles.RunOriginalUser(session);
            }
            bootstrap=new CoordinatorOriginalUserBootstrapLease(invocation,admission);
            VpnInstallHelperRoles.RunCoordinator(bootstrap.Coordinator);
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
            Exception cleanup=null;
            try { if (session!=null) session.Dispose(); } catch (Exception error) { cleanup=error; }
            // Bootstrap reconciliation runs while admission still retains the
            // owner/input witnesses. Cleanup failures cannot skip this step.
            try { if (bootstrap!=null) bootstrap.Dispose(); } catch (Exception error) { if (cleanup==null) cleanup=error; }
            try { admission.Dispose(); } catch (Exception error) { if (cleanup==null) cleanup=error; }
            if (cleanup!=null) throw new IOException("PERSISTENCE_FAILED",cleanup);
        }
    }
}

// Coordinator state is intentionally separated from OriginalUserSessionAdapter:
// it owns only protected state and retained identity witnesses, never an MSI
// adapter, package handle, command line, or relaunch authority.
internal sealed class CoordinatorSessionAdapter : VpnInstallHelperRoles.CoordinatorSession, VpnInstallHelperRoles.CoordinatorCompletedInputSession, IDisposable {
    readonly CoordinatorSessionAdapterFacilities fixture;
    readonly OwnerInputAdmission admission;
    // Same-assembly test seam for a unique, direct child of the real ProgramData
    // directory. Production never supplies this and remains bound to its fixed
    // vpn-control-install-jobs path.
    readonly Func<string> testMachineDirectory;
    readonly DateTime precommitDeadline, exitDeadline;
    readonly CoordinatorReceiptWriter fixtureReceiptWriter;
    CoordinatorReceiptWriter receiptWriter;
    VpnInstallNative.ProcessPin worker, frontend;
    VpnInstallNative.ProcessImagePin workerGeneration, coordinatorGeneration;
    VpnInstallNative.ExecutableReplacementSet installation;
    FileStream gate, cancel;
    SafeFileHandle programDataDirectory, programDataWitness, machineDirectory, jobDirectory;
    bool reserved, exclusive;
    bool terminalPublished, terminalGateReleaseReady;
    VpnInstallHelperProtocol.WorkerReady admittedReady;
    uint? observedNativeResult;
    NativeInputCustodySource inputCustodySource;
    bool inputCustodyFailed { get; set; }
    VpnInstallHelperRoles.PreinstallStage preinstallStage=VpnInstallHelperRoles.PreinstallStage.None;
    bool preinstallIdentityFailure;
    bool disposed;

    internal CoordinatorSessionAdapter(CoordinatorSessionAdapterFacilities facilities) {
        if (facilities==null) throw new ArgumentNullException("facilities");
        fixture=facilities;
    }
    internal CoordinatorSessionAdapter(CoordinatorSessionAdapterFacilities facilities,CoordinatorReceiptWriter writer) {
        if (facilities==null || writer==null || facilities.JobId!=writer.JobId) throw new ArgumentException("Coordinator fixture rejected");
        fixture=facilities; fixtureReceiptWriter=writer;
    }

    internal CoordinatorSessionAdapter(OwnerInputAdmission retainedAdmission) : this(retainedAdmission,null,null) { }

    internal CoordinatorSessionAdapter(OwnerInputAdmission retainedAdmission,CoordinatorOriginalUserChild originalUserChild) :
        this(retainedAdmission,originalUserChild,null,null) { }

    internal CoordinatorSessionAdapter(OwnerInputAdmission retainedAdmission,Func<string> machineDirectoryForTest) :
        this(retainedAdmission,null,null,machineDirectoryForTest) { }

    internal CoordinatorSessionAdapter(OwnerInputAdmission retainedAdmission,CoordinatorOriginalUserChild originalUserChild,
        Func<string> machineDirectoryForTest) : this(retainedAdmission,originalUserChild,null,machineDirectoryForTest) { }

    internal CoordinatorSessionAdapter(OwnerInputAdmission retainedAdmission,CoordinatorOriginalUserChild originalUserChild,
        CoordinatorWorkerReadyWait waitForTest,Func<string> machineDirectoryForTest) {
        if (retainedAdmission==null || retainedAdmission.Request==null) throw new IOException("CONFLICT");
        admission=retainedAdmission;
        testMachineDirectory=machineDirectoryForTest;
        precommitDeadline=DateTime.UtcNow.AddMinutes(3);
        exitDeadline=precommitDeadline;
        try {
            AdmitWorker(originalUserChild,waitForTest);
            if (originalUserChild!=null) originalUserChild.ReleaseLaunchImagePinAfterAdmission();
        }
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
        if (fixture!=null) { if (fixtureReceiptWriter!=null) fixtureReceiptWriter.Publish(phase,code); else fixture.Publish(phase,code); }
        else {
            if (jobDirectory==null) throw new IOException("CONFLICT");
            if (receiptWriter==null) receiptWriter=new CoordinatorReceiptWriter(JobId,jobDirectory,new NativeCoordinatorReceiptPublisher());
            receiptWriter.Publish(phase,code);
        }
        // An uncertain publication must not release a live installation gate.
        if (phase==VpnInstallHelperRoles.Phase.Succeeded || phase==VpnInstallHelperRoles.Phase.Failed ||
            phase==VpnInstallHelperRoles.Phase.Cancelled) terminalPublished=true;
    }
    public void SetPending(bool value) {
        if (value) terminalGateReleaseReady=false;
        if (fixture!=null) fixture.SetPending(value);
        else {
            if (gate==null) throw new IOException("CONFLICT");
            gate.Position=8; gate.WriteByte(value ? (byte)1 : (byte)0); gate.Flush(true);
        }
        // Set this only after both terminal acknowledgement and pending flush.
        terminalGateReleaseReady=!value && terminalPublished;
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
        preinstallStage=VpnInstallHelperRoles.PreinstallStage.ExclusiveAdmission;
        if (gate==null || !admission.Owner.Exited || (frontend!=null && !frontend.Exited)) return false;
        if (!exclusive) exclusive=VpnInstallNative.TryLock(gate.SafeFileHandle,0,true);
        return exclusive;
    }
    public bool TryInstallationReady() {
        if (fixture!=null) return fixture.TryInstallationReady();
        preinstallStage=VpnInstallHelperRoles.PreinstallStage.Inventory;
        preinstallIdentityFailure=false;
        if (!exclusive || installation==null) throw new IOException("CONFLICT");
        if (!VpnInstallHelperProcessInventory.TryNoAdmittedInstallationCopies(installation,
            (uint)Process.GetCurrentProcess().Id,worker.Pid)) return false;
        preinstallStage=VpnInstallHelperRoles.PreinstallStage.Readiness;
        try { return installation.TryReady(); }
        catch (IOException) { preinstallIdentityFailure=true; throw; }
    }
    public void PublishPreinstallDiagnostic(int attemptedStage,bool win32Failure) {
        if (fixture!=null) return;
        if (jobDirectory==null || attemptedStage<1 || attemptedStage>2) return;
        VpnInstallHelperRoles.PreinstallStage stage=attemptedStage==1 ?
            VpnInstallHelperRoles.PreinstallStage.ExclusiveAdmission : preinstallStage;
        if (stage!=VpnInstallHelperRoles.PreinstallStage.ExclusiveAdmission &&
            stage!=VpnInstallHelperRoles.PreinstallStage.Inventory &&
            stage!=VpnInstallHelperRoles.PreinstallStage.Readiness) return;
        VpnInstallHelperRoles.PreinstallKind kind=preinstallIdentityFailure ? VpnInstallHelperRoles.PreinstallKind.Identity :
            win32Failure ? VpnInstallHelperRoles.PreinstallKind.Win32Api : VpnInstallHelperRoles.PreinstallKind.Other;
        VpnInstallHelperRoles.PublishProtectedPreinstallDiagnostic(jobDirectory,stage,kind);
    }
    public uint? ReadNativeResult() {
        if (fixture!=null) return fixture.ReadNativeResult();
        byte[] record=admission.ReadPrivateLeaf("worker-result.json",true);
        observedNativeResult=record==null ? (uint?)null : VpnInstallHelperProtocol.ParseWorkerResult(record,JobId);
        return observedNativeResult;
    }
    public void PrepareInputCustody(uint result) {
        if(fixture!=null) { var f=fixture as VpnInstallHelperRoles.CoordinatorCompletedInputSession;if(f!=null)f.PrepareInputCustody(result);return; }
        if(!observedNativeResult.HasValue || observedNativeResult.Value!=result || (result!=0 && result!=3010) || inputCustodySource!=null)throw new IOException("CONFLICT");
        inputCustodySource=new NativeInputCustodySource(admission,machineDirectory,jobDirectory,workerGeneration,coordinatorGeneration,admittedReady,result);
        InputCustodyWriter.CaptureAndPublish(inputCustodySource);
    }
    public void RetainInputCustodyFailure() { inputCustodyFailed=true; }
    public void Pause() { if (fixture==null) Thread.Sleep(100); else fixture.Pause(); }
    string OpenProtectedMachineDirectory() {
        if (machineDirectory!=null) return testMachineDirectory==null ?
            Path.Combine(VpnInstallNative.ProgramData(),"vpn-control-install-jobs") : testMachineDirectory();
        string programData=VpnInstallNative.ProgramData();
        programDataDirectory=VpnInstallNative.OpenDirectory(programData);
        try { VpnInstallNative.Inspect(programDataDirectory,true,true,null); }
        catch {
            // ProgramData can legitimately carry inheritable metadata rights; retain
            // a nonempty exact child witness rather than trusting a path lookup.
            programDataWitness=VpnInstallNative.PinNonEmptyAncestor(programDataDirectory,null);
        }
        string machine=testMachineDirectory==null ? Path.Combine(programData,"vpn-control-install-jobs") : testMachineDirectory();
        if (!String.Equals(Path.GetDirectoryName(machine),programData,StringComparison.OrdinalIgnoreCase))
            throw new IOException("CONFLICT");
        const string machineAcl="O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)";
        try { VpnInstallNative.CreateDirectory(machine,machineAcl); }
        catch (Win32Exception error) { if (error.NativeErrorCode!=183) throw; }
        machineDirectory=VpnInstallNative.OpenDirectory(machine);
        VpnInstallNative.InspectLinkedAncestor(programDataDirectory,machineDirectory,null);
        VpnInstallNative.Inspect(machineDirectory,true,false,null);
        return machine;
    }
    void AdmitWorker(CoordinatorOriginalUserChild originalUserChild,CoordinatorWorkerReadyWait waitForTest) {
        VpnInstallHelperProtocol.WorkerReady ready=ReadWorkerReady(originalUserChild,waitForTest);
        if (ready.JobId!=JobId || ready.PrincipalSid!=admission.Owner.Principal) throw new IOException("CONFLICT");
        if (originalUserChild!=null && (ready.Pid!=originalUserChild.ProcessId || ready.CreationFileTime!=originalUserChild.CreationFileTime ||
            !String.Equals(ready.PrincipalSid,originalUserChild.PrincipalSid,StringComparison.Ordinal))) throw new IOException("CONFLICT");
        admittedReady=ready;
        worker=new VpnInstallNative.ProcessPin(ready.Pid);
        workerGeneration=new VpnInstallNative.ProcessImagePin(ready.Pid);
        coordinatorGeneration=new VpnInstallNative.ProcessImagePin((uint)Process.GetCurrentProcess().Id);
        AdmitSameOriginalUserImages(worker,workerGeneration,coordinatorGeneration,ready,admission.Owner.Principal);
        if (admission.Request.FrontendPid.HasValue) {
            frontend=new VpnInstallNative.ProcessPin(admission.Request.FrontendPid.Value);
            if (frontend.Exited || frontend.Principal!=admission.Owner.Principal ||
                frontend.StartedAtEpochMillis!=admission.Request.FrontendStartedAtEpochMillis.Value ||
                !String.Equals(frontend.Image,admission.Request.Launcher,StringComparison.OrdinalIgnoreCase)) throw new IOException("CONFLICT");
        }
    }
    // The single worker-admission boundary retains both concrete process-image
    // handles only while it checks the original-user SID, generation, ACL,
    // file-object identity and hash. Its callers retain the process/generation
    // witnesses; releasing file handles here avoids blocking later replacement.
    internal static void AdmitSameOriginalUserImages(VpnInstallNative.ProcessPin worker,
        VpnInstallNative.ProcessImagePin workerGeneration,VpnInstallNative.ProcessImagePin coordinatorGeneration,
        VpnInstallHelperProtocol.WorkerReady ready,string originalPrincipal) {
        if (worker==null || workerGeneration==null || coordinatorGeneration==null || ready==null ||
            String.IsNullOrEmpty(originalPrincipal) || ready.PrincipalSid!=originalPrincipal) throw new IOException("CONFLICT");
        VpnInstallNative.ProcessImageObservation observed=workerGeneration.Observe();
        if (worker.Exited || worker.Principal!=originalPrincipal || observed.KernelOnly ||
            observed.CreationFileTime!=ready.CreationFileTime) throw new IOException("CONFLICT");
        VpnInstallNative.ProcessImageObservation coordinator=coordinatorGeneration.Observe();
        if (coordinator.KernelOnly) throw new IOException("CONFLICT");
        using (SafeFileHandle workerHandle=VpnInstallNative.OpenRead(observed.Image,false))
        using (SafeFileHandle coordinatorHandle=VpnInstallNative.OpenRead(coordinator.Image,false))
        using (FileStream workerImage=new FileStream(workerHandle,FileAccess.Read,1,false))
        using (FileStream coordinatorImage=new FileStream(coordinatorHandle,FileAccess.Read,1,false)) {
            VpnInstallNative.Inspect(workerImage.SafeFileHandle,false,false,originalPrincipal);
            VpnInstallNative.Inspect(coordinatorImage.SafeFileHandle,false,false,originalPrincipal);
            if (!VpnInstallNative.SameFileObject(workerImage.SafeFileHandle,coordinatorImage.SafeFileHandle) ||
                !String.Equals(VpnInstallNative.Sha256(workerImage),ready.HelperSha256,StringComparison.Ordinal) ||
                !String.Equals(VpnInstallNative.Sha256(coordinatorImage),ready.HelperSha256,StringComparison.Ordinal))
                throw new IOException("CONFLICT");
        }
    }
    VpnInstallHelperProtocol.WorkerReady ReadWorkerReady(CoordinatorOriginalUserChild originalUserChild,CoordinatorWorkerReadyWait waitForTest) {
        if (originalUserChild==null) return VpnInstallHelperProtocol.ParseWorkerReady(admission.ReadPrivateLeaf("worker-ready.json",false));
        CoordinatorWorkerReadyWait wait=waitForTest ?? new NativeCoordinatorWorkerReadyWait(admission);
        for (;;) {
            if (originalUserChild.Exited) throw new IOException("RUNTIME_FAILED");
            byte[] record=admission.ReadPrivateLeaf("worker-ready.json",true);
            if (record!=null) return VpnInstallHelperProtocol.ParseWorkerReady(record);
            // An exact committed handoff wins over owner exit, matching the
            // coordinator role's later commit-before-exit ordering. It is read
            // through the retained private input directory, never an argv path.
            byte[] commit=admission.ReadPrivateLeaf("commit.json",true);
            bool committed=commit!=null && VpnInstallHelperProtocol.IsCommit(commit,JobId);
            if (wait.CancellationRequested && !committed) throw new IOException("CANCELLED");
            if (wait.DeadlineReached) throw new IOException("TIMEOUT");
            wait.Pause();
        }
    }
    internal void ReleaseTerminalReturnGate() {
        if (disposed || !terminalGateReleaseReady) return;
        if (fixture!=null) {
            CoordinatorTerminalReturnGateFacilities returnGate=fixture as CoordinatorTerminalReturnGateFacilities;
            if (returnGate!=null) returnGate.ReleaseTerminalReturnGate();
            return;
        }
        Exception failure=null;
        // Only input pins are handed off after actual ready/result capture and terminal+pending acknowledgement.
        // A release failure stays owned; it cannot suppress known-success return gate release.
        if(observedNativeResult.HasValue && (observedNativeResult.Value==0 || observedNativeResult.Value==3010)) {
            try { if(inputCustodySource!=null)inputCustodySource.Dispose(); } catch(Exception error) { failure=error;inputCustodyFailed=true; }
            try { admission.ReleaseCompletedInputPins(); } catch(Exception error) { if(failure==null)failure=error;inputCustodyFailed=true; }
        }
        try { if (exclusive) { VpnInstallNative.Unlock(gate.SafeFileHandle,0); exclusive=false; } } catch (Exception error) { if(failure==null)failure=error; }
        try { if (reserved) { VpnInstallNative.Unlock(gate.SafeFileHandle,16); reserved=false; } } catch (Exception error) { if (failure==null) failure=error; }
        if (failure!=null) throw new IOException("PERSISTENCE_FAILED",failure);
    }
    public void Dispose() {
        if (disposed) return;
        if (fixture!=null) { fixture.Dispose(); disposed=true; return; }
        Exception failure=null;
        try { if (exclusive) { VpnInstallNative.Unlock(gate.SafeFileHandle,0); exclusive=false; } } catch (Exception error) { failure=error; }
        try { if (reserved) { VpnInstallNative.Unlock(gate.SafeFileHandle,16); reserved=false; } } catch (Exception error) { if (failure==null) failure=error; }
        IDisposable[] resources={ cancel,jobDirectory,machineDirectory,programDataWitness,programDataDirectory,gate,
            workerGeneration,coordinatorGeneration,worker,frontend,installation,inputCustodySource };
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

// Same-assembly inert gate seam. It carries no request, token, path, installer
// or launch authority; native production always releases its own exact ranges.
internal interface CoordinatorTerminalReturnGateFacilities {
    void ReleaseTerminalReturnGate();
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
internal sealed class OriginalUserSessionAdapter : VpnInstallHelperRoles.OriginalUserSession, VpnInstallHelperRoles.OriginalUserCompletedInputSession, IDisposable {
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
    bool preparedDisposed;
    uint? completedNativeExit;
    Exception completedInputFailure;
    bool completedInputCleanupFailed { get; set; }
    readonly VpnInstallCompletedInputCleanup.Debt completedInputDebt=new VpnInstallCompletedInputCleanup.Debt();
    readonly List<IDisposable> returnPins=new List<IDisposable>();
    SafeFileHandle returnMachineDirectory;
    FileStream returnGate;
    bool returnGateLocked;
    bool returnReservationLocked;

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
        completedNativeExit=fixture==null ? prepared.Install() : fixture.InstallVerifiedPackage();
        return completedNativeExit.Value;
    }
    public void PublishNativeResult(uint exitCode) {
        if (fixture!=null) { fixture.PublishNativeResult(exitCode); return; }
        VpnInstallNative.PublishPrivateRecord(Path.Combine(inputDirectory,"worker-result.json"),admission.Owner.Principal,
            VpnInstallHelperProtocol.EncodeWorkerResult(JobId,exitCode));
    }

    public void CompleteInputCleanup() {
        try {
            if(!completedNativeExit.HasValue || (completedNativeExit.Value!=0 && completedNativeExit.Value!=3010) ||
                lastObservedReceipt==null || lastObservedReceipt.State!=VpnInstallHelperRoles.Phase.Succeeded)throw new IOException("OUTCOME_UNKNOWN");
            // Wait for the unchanged exact shared return gate before releasing any input capability.
            while(!TryAcquireReturnAdmission()){if(ReturnDeadlineReached)throw new IOException("OUTCOME_UNKNOWN");Pause();}
            if(fixture!=null) { var f=fixture as VpnInstallHelperRoles.OriginalUserCompletedInputSession;if(f!=null)f.CompleteInputCleanup();return; }
            VerifyReturnGate();if(!ReturnGateIsClear(ReadReturnGate()))throw new IOException("CONFLICT");
            SafeFileHandle protectedJob=VpnInstallNative.OpenDirectory(Path.Combine(VpnInstallNative.ProgramData(),"vpn-control-install-jobs",JobId));
            returnPins.Add(protectedJob);VpnInstallNative.InspectLinkedAncestor(returnMachineDirectory,protectedJob,null);VpnInstallNative.Inspect(protectedJob,true,false,null);
            // Validate the protected capability against original admitted handles before handing them off.
            InputCustodyRecord captured=InputCustodyContract.Parse(NativeCompletedInputFacilities.ReadProtectedLeaf(protectedJob,InputCustodyContract.ProtectedLeaf,InputCustodyContract.MaximumBytes));
            if(captured.Provenance.JobId!=JobId || captured.Provenance.PrincipalSid!=admission.Request.PrincipalSid ||
                captured.InputRootNativeId!=admission.OriginalInputRootId || captured.InputJobNativeId!=admission.OriginalInputJobId ||
                captured.Leaf(InputCustodyLeaf.Request).NativeId!=admission.OriginalRequestId ||
                captured.Leaf(InputCustodyLeaf.Request).Sha256!=NativeInputCustodySource.Digest(admission.OriginalRequestStream))throw new IOException("CONFLICT");
            if(!preparedDisposed){prepared.Dispose();preparedDisposed=true;}
            admission.ReleaseCompletedInputPins();
            using(NativeCompletedInputFacilities inputs=new NativeCompletedInputFacilities(admission,returnMachineDirectory,protectedJob,lastObservedReceipt,ReadReceipt,
                ()=>{VerifyReturnGate();if(!returnGateLocked || !returnReservationLocked || !ReturnGateIsClear(ReadReturnGate()))throw new IOException("CONFLICT");})) {
                InputCustodyRecord c=inputs.Custody;InputCustodyContract.RequireSame(captured,c);
                VpnInstallCompletedInputCleanup.Leaf[] leaves=new VpnInstallCompletedInputCleanup.Leaf[5];
                InputCustodyLeaf[] slots={InputCustodyLeaf.Package,InputCustodyLeaf.Request,InputCustodyLeaf.Commit,InputCustodyLeaf.WorkerReady,InputCustodyLeaf.WorkerResult};
                for(int i=0;i<leaves.Length;i++) {
                    InputCustodyFile f=c.Leaf(slots[i]);if(f.Name!=VpnInstallCompletedInputCleanup.Leaves[i])throw new IOException("CONFLICT");
                    leaves[i]=new VpnInstallCompletedInputCleanup.Leaf(f.Name,f.NativeId,f.Size,f.Sha256);
                }
                VpnInstallCompletedInputCleanup.Release(inputs,c.InputRootNativeId,c.InputJobNativeId,leaves,completedInputDebt);
            }
        } catch(Exception error) { completedInputFailure=completedInputFailure ?? error;throw; }
    }
    public void RetainInputCleanupFailure(){completedInputCleanupFailed=true;}

    public void RelaunchOriginalOwner() {
        // SUCCEEDED can be observed before the coordinator clears pending and releases
        // its exclusive installation lock. Receipt completion alone cannot admit the
        // returned process. Wait using the existing finite return deadline, retaining
        // the authenticated shared gate lease through the single launch.
        while (!TryAcquireReturnAdmission()) {
            if (ReturnDeadlineReached) throw new IOException("OUTCOME_UNKNOWN");
            Pause();
        }
        if (fixture!=null) { fixture.RelaunchOriginalOwner(); return; }
        VerifyReturnGate();
        if (!ReturnGateIsClear(ReadReturnGate())) throw new IOException("CONFLICT");
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

    bool TryAcquireReturnAdmission() {
        if (disposed) throw new ObjectDisposedException("original-user return");
        if (fixture!=null) return fixture.TryAcquireReturnAdmission();
        if (returnGate==null) OpenReturnGate();
        VerifyReturnGate();
        // The coordinator releases byte 0 and byte 16 separately. Retain both
        // shared ranges before reading all 17 bytes, and exclude a new installer
        // reservation while the returned process is being launched.
        if (!returnReservationLocked) {
            if (!VpnInstallNative.TryLock(returnGate.SafeFileHandle,16,false)) return false;
            returnReservationLocked=true;
        }
        if (!returnGateLocked) {
            if (!VpnInstallNative.TryLock(returnGate.SafeFileHandle,0,false)) {
                ReleaseReturnGateLock(); return false;
            }
            returnGateLocked=true;
        }
        bool clear;
        try { clear=ReturnGateIsClear(ReadReturnGate()); }
        catch { ReleaseReturnGateLock(); throw; }
        if (!clear) ReleaseReturnGateLock();
        return clear;
    }

    void OpenReturnGate() {
        // Derive the exact installation gate from the already admitted launcher;
        // neither a caller nor a receipt supplies a new path or storage authority.
        string launcherDirectory=Path.GetDirectoryName(admission.Request.Launcher);
        if (String.IsNullOrEmpty(launcherDirectory)) throw new IOException("CONFLICT");
        SafeFileHandle installation=VpnInstallNative.OpenDirectory(launcherDirectory);
        returnPins.Add(installation);
        VpnInstallNative.Inspect(installation,true,false,admission.Owner.Principal);
        string id=VpnInstallNative.InstallationId(installation);
        string programData=VpnInstallNative.ProgramData();
        SafeFileHandle root=VpnInstallNative.OpenDirectory(programData);
        returnPins.Add(root);
        try { VpnInstallNative.Inspect(root,true,true,null); }
        catch { returnPins.Add(VpnInstallNative.PinNonEmptyAncestor(root,null)); }
        string machine=Path.Combine(programData,"vpn-control-install-jobs");
        returnMachineDirectory=VpnInstallNative.OpenDirectory(machine);
        returnPins.Add(returnMachineDirectory);
        VpnInstallNative.InspectLinkedAncestor(root,returnMachineDirectory,null);
        VpnInstallNative.Inspect(returnMachineDirectory,true,false,null);
        returnGate=VpnInstallNative.OpenGate(Path.Combine(machine,"gate-"+id),false);
        returnPins.Add(returnGate);
        VerifyReturnGate();
    }

    void VerifyReturnGate() {
        VpnInstallNative.InspectLinkedAncestor(returnMachineDirectory,returnGate.SafeFileHandle,null);
        VpnInstallNative.Inspect(returnGate.SafeFileHandle,false,false,null);
    }
    byte[] ReadReturnGate() {
        returnGate.Position=0;
        return ReadBounded(returnGate,17);
    }
    internal static bool ReturnGateIsClear(byte[] bytes) {
        if (bytes==null || bytes.Length!=17) throw new IOException("CONFLICT");
        for (int index=0;index<bytes.Length;index++) {
            if (index==8) { if (bytes[index]>1) throw new IOException("CONFLICT"); }
            else if (bytes[index]!=0) throw new IOException("CONFLICT");
        }
        return bytes[8]==0;
    }
    void ReleaseReturnGateLock() {
        Exception failure=null;
        if (returnGateLocked) {
            try { VpnInstallNative.Unlock(returnGate.SafeFileHandle,0); returnGateLocked=false; }
            catch (Exception error) { failure=error; }
        }
        if (returnReservationLocked) {
            try { VpnInstallNative.Unlock(returnGate.SafeFileHandle,16); returnReservationLocked=false; }
            catch (Exception error) { if (failure==null) failure=error; }
        }
        if (failure!=null) throw new IOException("PERSISTENCE_FAILED",failure);
    }

    public void Dispose() {
        if (disposed) return;
        Exception failure=null;
        try { completedInputDebt.CloseAll(); } catch(Exception error) { failure=error; }
        try { ReleaseReturnGateLock(); } catch (Exception error) { if(failure==null)failure=error; }
        // Failed unlock retains the exact locked handle for cleanup retry. Close
        // every other independent resource even when another disposal fails.
        if (!returnGateLocked && !returnReservationLocked) {
            for (int index=returnPins.Count-1;index>=0;index--) {
                try { returnPins[index].Dispose(); returnPins.RemoveAt(index); }
                catch (Exception error) { if (failure==null) failure=error; }
            }
        }
        if (!preparedDisposed) {
            try { if (fixture==null) prepared.Dispose(); else fixture.Dispose(); preparedDisposed=true; }
            catch (Exception error) { if (failure==null) failure=error; }
        }
        if (failure!=null) throw new IOException("PERSISTENCE_FAILED",failure);
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
    bool TryAcquireReturnAdmission();
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
    internal SafeFileHandle InputRoot { get; private set; }
    internal FileStream OriginalRequestStream { get; private set; }
    internal string OriginalInputRootId,OriginalInputJobId,OriginalRequestId;
    // The exact local root whose ancestry was retained during request admission.
    // Production records Owner.LocalAppData(); the same-assembly fixture supplies
    // an owned equivalent. Later private leaves must never resolve a fresh path.
    string admittedLocalDirectory;

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
            retained.Add(inputRoot);InputRoot=inputRoot;OriginalInputRootId=VpnInstallNative.InputObjectIdentity(inputRoot,true);
            SafeFileHandle input=OpenPinnedDirectory(inputRoot,
                Path.Combine(local,"vpn-control-install-inputs",invocation.JobId),Owner.Principal,false);
            retained.Add(input);
            InputDirectory=input;OriginalInputJobId=VpnInstallNative.InputObjectIdentity(input,true);
            requestHandle=VpnInstallNative.OpenRead(Path.Combine(local,"vpn-control-install-inputs",invocation.JobId,"request.json"),false);
            VpnInstallNative.InspectLinkedAncestor(input,requestHandle,Owner.Principal);
            VpnInstallNative.Inspect(requestHandle,false,false,Owner.Principal);
            FileStream requestStream=new FileStream(requestHandle,FileAccess.Read,1,false);
            requestHandle=null;
            retained.Add(requestStream);OriginalRequestStream=requestStream;OriginalRequestId=VpnInstallNative.InputObjectIdentity(requestStream.SafeFileHandle,false);
            Request=VpnInstallHelperProtocol.ParseRequest(ReadBounded(requestStream,65536));
            admittedLocalDirectory=local;
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
        string local=admittedLocalDirectory;
        if (String.IsNullOrEmpty(local)) throw new IOException("CONFLICT");
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

    internal string FixedInputRootPath(){if(String.IsNullOrEmpty(admittedLocalDirectory))throw new IOException("CONFLICT");return Path.Combine(admittedLocalDirectory,"vpn-control-install-inputs");}
    internal string FixedInputPath(string leaf){if(leaf!="request.json" && leaf!="package.msi" && leaf!="commit.json" && leaf!="worker-ready.json" && leaf!="worker-result.json")throw new IOException("INVALID_ARGUMENT");return Path.Combine(FixedInputRootPath(),Request.JobId,leaf);}
    internal SafeFileHandle PinCleanupLocalAncestor(){return PinDirectoryPath(admittedLocalDirectory,Request.PrincipalSid);}
    internal void ReleaseCompletedInputPins(){ReleaseRetainedFrom(3);InputRoot=null;InputDirectory=null;OriginalRequestStream=null;}

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
// Isolated candidate core. Native adapters supply only authenticated fixed-job facilities.
// Tests model Windows identity/ACL/DeleteDisposition syscalls, with real files and streams.

internal static class VpnInstallCompletedInputCleanup {
    internal static readonly string[] Leaves={"package.msi","request.json","commit.json","worker-ready.json","worker-result.json"};
    internal sealed class Leaf {
        internal readonly string Name,Identity,Digest;
        internal readonly long Size;
        internal Leaf(string name,string identity,long size,string digest) {
            if (Array.IndexOf(Leaves,name)<0 || identity==null || identity.Length!=48 || size<1 || digest==null || digest.Length!=64)
                throw new IOException("INVALID_ARGUMENT");
            foreach (char c in identity+digest) if (!((c>='0' && c<='9') || (c>='a' && c<='f'))) throw new IOException("INVALID_ARGUMENT");
            Name=name; Identity=identity; Size=size; Digest=digest;
        }
    }
    internal interface Handle : IDisposable { }
    // The fixed native implementation derives roots from the original admission/current owner,
    // and reads custody only from the retained protected job. No path/command is an input here.
    internal interface Facilities {
        void RevalidateTerminalCustodyAndActors();
        Handle OpenRoot(); // null only precise native missing child under held admitted ancestry.
        Handle OpenJob(Handle root);
        Handle OpenLeaf(Handle job,string fixedLeaf);
        void Verify(Handle handle,Handle parent,string expectedIdentity,bool directory);
        string[] Children(Handle job); // at most 5+1; no recursive enumeration.
        void VerifyFullBytes(Handle file,Leaf expected);
        void Delete(Handle handle); // actual retained FILE_DISPOSITION_INFO capability.
    }
    internal sealed class Debt {
        internal readonly List<Handle> Handles=new List<Handle>();
        internal void CloseAll() {
            Exception first=null;
            for (int i=Handles.Count-1;i>=0;i--) try { Handles[i].Dispose(); Handles.RemoveAt(i); }
                catch (Exception e) { if(first==null)first=e; }
            if(first!=null)throw new IOException("PERSISTENCE_FAILED",first);
        }
    }
    internal static void Release(Facilities native,string rootIdentity,string jobIdentity,Leaf[] leaves,Debt debt) {
        if(native==null || debt==null || leaves==null || leaves.Length!=Leaves.Length)throw new IOException("INVALID_ARGUMENT");
        for(int i=0;i<leaves.Length;i++)if(leaves[i]==null || leaves[i].Name!=Leaves[i])throw new IOException("CONFLICT");
        // Retry only owned closing debt first; failure cannot authorize another deletion attempt.
        debt.CloseAll();
        Exception primary=null;
        try { ReleaseHeld(native,rootIdentity,jobIdentity,leaves,debt); }
        catch(Exception e) { primary=e; }
        finally {
            try { debt.CloseAll(); }
            catch(Exception e) { if(primary==null)primary=e; }
        }
        if(primary!=null)throw new IOException("PERSISTENCE_FAILED",primary);
    }
    static void ReleaseHeld(Facilities native,string rootIdentity,string jobIdentity,Leaf[] leaves,Debt debt) {
            native.RevalidateTerminalCustodyAndActors();
            Handle root=native.OpenRoot();
            if(root==null)return;
            debt.Handles.Add(root); native.Verify(root,null,rootIdentity,true);
            Handle job=native.OpenJob(root);
            if(job==null)return;
            debt.Handles.Add(job); native.Verify(job,root,jobIdentity,true);
            string[] names=native.Children(job);
            if(names==null || names.Length>Leaves.Length)throw new IOException("CONFLICT");
            HashSet<string> unique=new HashSet<string>(StringComparer.Ordinal);
            foreach(string name in names)if(Array.IndexOf(Leaves,name)<0 || !unique.Add(name))throw new IOException("CONFLICT");
            Handle[] held=new Handle[Leaves.Length];
            for(int i=0;i<Leaves.Length;i++) {
                Handle h=native.OpenLeaf(job,Leaves[i]);
                // Immutable native object IDs make precise missing slots safe on cold/partial retry;
                // a same-digest replacement is still refused when it is present.
                if(h==null)continue;
                held[i]=h; debt.Handles.Add(h);
                native.Verify(h,job,leaves[i].Identity,false);
                native.VerifyFullBytes(h,leaves[i]);
            }
            native.RevalidateTerminalCustodyAndActors();
            native.Verify(root,null,rootIdentity,true); native.Verify(job,root,jobIdentity,true);
            for(int i=0;i<held.Length;i++)if(held[i]!=null) {
                native.Verify(held[i],job,leaves[i].Identity,false);
                native.VerifyFullBytes(held[i],leaves[i]);
            }
            // Every fixed object is admitted before the first effect. No tree/path deletion.
            for(int i=0;i<held.Length;i++)if(held[i]!=null) {
                native.Delete(held[i]); held[i].Dispose(); debt.Handles.Remove(held[i]);
            }
            native.Delete(job); job.Dispose(); debt.Handles.Remove(job);
            // Closed delete handles must be followed by precise named absence. Replacement or
            // inaccessible path is failure, even if the preceding disposition returned success.
            Handle remains=native.OpenJob(root);
            if(remains!=null) { debt.Handles.Add(remains); throw new IOException("CONFLICT"); }
            native.RevalidateTerminalCustodyAndActors();
    }
}
// PROPOSAL: data-only custody schema plus a same-assembly admitted-handle writer seam.
// Parsing this record does not admit cleanup, native actor closure, a terminal receipt,
// or installation replay. Production must bind the source to fixed native adapters.

internal enum InputCustodyLeaf { Request, Package, Commit, WorkerReady, WorkerResult }
internal enum InputCustodyActor { Worker, Coordinator }

internal sealed class InputCustodyProvenance {
    internal readonly string JobId, PrincipalSid, WorkspaceSha256;
    internal InputCustodyProvenance(string job,string sid,string workspace) {
        VpnInstallHelperProtocol.Job(job); VpnInstallHelperProtocol.Sid(sid); VpnInstallHelperProtocol.Digest(workspace);
        JobId=job; PrincipalSid=sid; WorkspaceSha256=workspace;
    }
    public override string ToString() { return "Install custody provenance (private identity)"; }
}
internal sealed class InputCustodyProcess {
    internal readonly uint Pid;
    internal readonly long CreationFileTime;
    internal readonly string HelperSha256;
    internal InputCustodyProcess(uint pid,long birth,string helper) {
        if (pid==0 || birth<=0) throw InputCustodyContract.Invalid();
        VpnInstallHelperProtocol.Digest(helper);
        Pid=pid; CreationFileTime=birth; HelperSha256=helper;
    }
    public override string ToString() { return "Install custody process (private identity)"; }
}
internal sealed class InputCustodyFile {
    internal readonly InputCustodyLeaf Slot;
    internal readonly string NativeId, Sha256;
    internal readonly long Size;
    internal string Name { get { return InputCustodyContract.LeafName(Slot); } }
    internal InputCustodyFile(InputCustodyLeaf slot,string identity,long size,string digest) {
        InputCustodyContract.LeafName(slot); InputCustodyContract.NativeId(identity);
        VpnInstallHelperProtocol.Digest(digest);
        if (size<=0) throw InputCustodyContract.Invalid();
        Slot=slot; NativeId=identity; Size=size; Sha256=digest;
    }
    public override string ToString() { return "Install custody file (private identity)"; }
}
internal sealed class InputCustodyRecord {
    internal readonly InputCustodyProvenance Provenance;
    internal readonly string InputRootNativeId, InputJobNativeId, ProtectedMachineNativeId, ProtectedJobNativeId;
    internal readonly InputCustodyProcess Worker, Coordinator;
    readonly InputCustodyFile[] leaves;
    internal InputCustodyRecord(InputCustodyProvenance provenance,string inputRoot,string inputJob,
        string machine,string protectedJob,InputCustodyProcess worker,InputCustodyProcess coordinator,
        InputCustodyFile[] originals) {
        if (provenance==null || worker==null || coordinator==null || originals==null || originals.Length!=5)
            throw InputCustodyContract.Invalid();
        if (worker.Pid==coordinator.Pid || worker.HelperSha256!=coordinator.HelperSha256) throw InputCustodyContract.Invalid();
        HashSet<string> identities=new HashSet<string>(StringComparer.Ordinal);
        foreach (string id in new string[] { inputRoot,inputJob,machine,protectedJob }) {
            InputCustodyContract.NativeId(id); if (!identities.Add(id)) throw InputCustodyContract.Invalid();
        }
        leaves=(InputCustodyFile[])originals.Clone();
        for (int index=0;index<5;index++) {
            if (leaves[index]==null || leaves[index].Slot!=(InputCustodyLeaf)index ||
                !identities.Add(leaves[index].NativeId)) throw InputCustodyContract.Invalid();
        }
        Provenance=provenance; InputRootNativeId=inputRoot; InputJobNativeId=inputJob;
        ProtectedMachineNativeId=machine; ProtectedJobNativeId=protectedJob; Worker=worker; Coordinator=coordinator;
    }
    internal InputCustodyFile Leaf(InputCustodyLeaf slot) {
        InputCustodyContract.LeafName(slot); return leaves[(int)slot];
    }
    public override string ToString() { return "Install input custody (data only)"; }
}

internal static class InputCustodyContract {
    internal const int MaximumBytes=4096;
    internal const string ProtectedLeaf="input-custody.json";
    internal const string ProtectedAcl="O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;BU)";
    static readonly string[] Names={"request.json","package.msi","commit.json","worker-ready.json","worker-result.json"};
    static readonly string[] BaseFields={"version","jobId","principalSid","workspaceSha256","inputRootNativeId",
        "inputJobNativeId","protectedMachineNativeId","protectedJobNativeId","workerPid","workerCreationFileTime",
        "workerHelperSha256","coordinatorPid","coordinatorCreationFileTime","coordinatorHelperSha256"};
    internal static IOException Invalid() { return new IOException("INVALID_INPUT_CUSTODY"); }
    internal static string LeafName(InputCustodyLeaf slot) {
        int index=(int)slot; if (index<0 || index>=5) throw Invalid(); return Names[index];
    }
    internal static void NativeId(string value) {
        if (value==null || value.Length!=48) throw Invalid();
        bool nonzero=false;
        foreach (char item in value) {
            if (!((item>='0' && item<='9') || (item>='a' && item<='f'))) throw Invalid();
            if (item!='0') nonzero=true;
        }
        if (!nonzero) throw Invalid();
    }
    static string[] Fields() {
        List<string> fields=new List<string>(BaseFields);
        foreach (string name in Names) { fields.Add(name+".nativeId"); fields.Add(name+".size"); fields.Add(name+".sha256"); }
        return fields.ToArray(); // Exactly 29; the authentic flat parser refuses >32.
    }
    internal static InputCustodyRecord Parse(byte[] bytes) {
        Dictionary<string,object> record=VpnInstallHelperProtocol.Record(bytes,MaximumBytes);
        VpnInstallHelperProtocol.Fields(record,Fields());
        if (VpnInstallHelperProtocol.Integer(record,"version")!=1) throw Invalid();
        InputCustodyProvenance provenance=new InputCustodyProvenance(Text(record,"jobId"),Text(record,"principalSid"),Text(record,"workspaceSha256"));
        InputCustodyProcess worker=Process(record,"worker"), coordinator=Process(record,"coordinator");
        InputCustodyFile[] leaves=new InputCustodyFile[5];
        for (int index=0;index<5;index++) {
            string name=Names[index];
            leaves[index]=new InputCustodyFile((InputCustodyLeaf)index,Text(record,name+".nativeId"),
                VpnInstallHelperProtocol.Integer(record,name+".size"),Text(record,name+".sha256"));
        }
        return new InputCustodyRecord(provenance,Text(record,"inputRootNativeId"),Text(record,"inputJobNativeId"),
            Text(record,"protectedMachineNativeId"),Text(record,"protectedJobNativeId"),worker,coordinator,leaves);
    }
    static string Text(Dictionary<string,object> record,string key) { return VpnInstallHelperProtocol.Text(record,key); }
    static InputCustodyProcess Process(Dictionary<string,object> record,string prefix) {
        long pid=VpnInstallHelperProtocol.Integer(record,prefix+"Pid");
        if (pid<=0 || pid>UInt32.MaxValue) throw Invalid();
        return new InputCustodyProcess((uint)pid,VpnInstallHelperProtocol.Integer(record,prefix+"CreationFileTime"),
            Text(record,prefix+"HelperSha256"));
    }
    internal static byte[] Encode(InputCustodyRecord record) {
        if (record==null) throw Invalid();
        StringBuilder json=new StringBuilder("{\"version\":1");
        Add(json,"jobId",record.Provenance.JobId); Add(json,"principalSid",record.Provenance.PrincipalSid);
        Add(json,"workspaceSha256",record.Provenance.WorkspaceSha256); Add(json,"inputRootNativeId",record.InputRootNativeId);
        Add(json,"inputJobNativeId",record.InputJobNativeId); Add(json,"protectedMachineNativeId",record.ProtectedMachineNativeId);
        Add(json,"protectedJobNativeId",record.ProtectedJobNativeId); AddProcess(json,"worker",record.Worker); AddProcess(json,"coordinator",record.Coordinator);
        for (int index=0;index<5;index++) {
            InputCustodyFile leaf=record.Leaf((InputCustodyLeaf)index);
            Add(json,leaf.Name+".nativeId",leaf.NativeId); Add(json,leaf.Name+".size",leaf.Size); Add(json,leaf.Name+".sha256",leaf.Sha256);
        }
        byte[] bytes=new UTF8Encoding(false,true).GetBytes(json.Append('}').ToString());
        Parse(bytes); // Fixed canonical fields/ASCII grammars; still data-only.
        return bytes;
    }
    static void Add(StringBuilder json,string key,string value) { json.Append(",\"").Append(key).Append("\":\"").Append(value).Append('"'); }
    static void Add(StringBuilder json,string key,long value) { json.Append(",\"").Append(key).Append("\":").Append(value.ToString(CultureInfo.InvariantCulture)); }
    static void AddProcess(StringBuilder json,string prefix,InputCustodyProcess process) {
        Add(json,prefix+"Pid",process.Pid); Add(json,prefix+"CreationFileTime",process.CreationFileTime); Add(json,prefix+"HelperSha256",process.HelperSha256);
    }
    internal static void RequireSame(InputCustodyRecord expected,InputCustodyRecord observed) {
        if (expected==null || observed==null) throw Invalid();
        byte[] first=Encode(expected),second=Encode(observed);
        if (first.Length!=second.Length) throw Invalid();
        for (int index=0;index<first.Length;index++) if (first[index]!=second[index]) throw Invalid();
    }
}

// Same-assembly only: production binds this interface to the admitted session and
// fixed native methods. No request/argv/parser object implements it. Tests model
// ACL/token/native IDs explicitly; the interface is NOT a native admission proof.
internal interface IAdmittedInputCustodyNativeSource {
    SafeFileHandle InputRoot { get; }
    SafeFileHandle InputJob { get; }
    SafeFileHandle ProtectedMachine { get; }
    SafeFileHandle ProtectedJob { get; }
    InputCustodyProvenance ReadOriginalProvenance();
    InputCustodyProcess ReadOriginalProcess(InputCustodyActor actor);
    FileStream RetainedOriginalLeaf(InputCustodyLeaf leaf);
    string DirectoryNativeId(SafeFileHandle retainedDirectory);
    string FileNativeId(SafeFileHandle retainedFile);
    void RequireOriginalAdmission(); // token, source, fixed path/ACL/ancestry/share and original actor generations
    void RequireOriginalLeaf(InputCustodyLeaf leaf,SafeFileHandle retainedFile); // actual original identity and admitted private ancestry
    uint ReadObservedSuccessfulNativeExit(); // actual native MSI outcome; not worker-result data alone
    void PublishCustodyNoReplace(SafeFileHandle protectedJob,string fixedLeaf,string fixedAcl,byte[] bytes);
    byte[] ReadPublishedCustodyRetained(SafeFileHandle protectedJob); // actual inspected protected object, bounded to 4096
}
internal sealed class InputCustodyPublicationUncertainException : IOException {
    internal InputCustodyPublicationUncertainException(Exception cause) : base("INPUT_CUSTODY_PUBLICATION_UNCERTAIN",cause) { }
}
internal static class InputCustodyWriter {
    static void Handle(SafeFileHandle file) {
        if (file==null || file.IsInvalid || file.IsClosed) throw InputCustodyContract.Invalid();
    }
    static string Digest(FileStream file) {
        file.Position=0;
        using (SHA256 digest=SHA256.Create()) {
            string result=BitConverter.ToString(digest.ComputeHash(file)).Replace("-","").ToLowerInvariant();
            file.Position=0; return result;
        }
    }
    static byte[] Small(FileStream file) {
        if (file.Length<=0 || file.Length>65536) throw InputCustodyContract.Invalid();
        byte[] bytes=new byte[checked((int)file.Length)]; file.Position=0;
        int at=0;
        while (at<bytes.Length) { int count=file.Read(bytes,at,bytes.Length-at); if (count==0) throw InputCustodyContract.Invalid(); at+=count; }
        if (file.ReadByte()!=-1) throw InputCustodyContract.Invalid(); file.Position=0; return bytes;
    }
    // Only admitted handles/native adapter enter this API. There is no Publish(record),
    // caller path, authority boolean, success flag, or deletion operation.
    internal static InputCustodyRecord CaptureAndPublish(IAdmittedInputCustodyNativeSource source) {
        if (source==null) throw InputCustodyContract.Invalid();
        source.RequireOriginalAdmission();
        SafeFileHandle[] directories={source.InputRoot,source.InputJob,source.ProtectedMachine,source.ProtectedJob};
        string[] ids=new string[4];
        for (int index=0;index<4;index++) { Handle(directories[index]); ids[index]=source.DirectoryNativeId(directories[index]); }
        InputCustodyProvenance provenance=source.ReadOriginalProvenance();
        InputCustodyProcess worker=source.ReadOriginalProcess(InputCustodyActor.Worker), coordinator=source.ReadOriginalProcess(InputCustodyActor.Coordinator);
        InputCustodyFile[] leaves=new InputCustodyFile[5]; FileStream[] streams=new FileStream[5]; byte[][] small=new byte[5][];
        for (int index=0;index<5;index++) {
            InputCustodyLeaf slot=(InputCustodyLeaf)index; FileStream file=source.RetainedOriginalLeaf(slot);
            if (file==null || !file.CanRead || !file.CanSeek) throw InputCustodyContract.Invalid();
            Handle(file.SafeFileHandle); source.RequireOriginalLeaf(slot,file.SafeFileHandle);
            string identity=source.FileNativeId(file.SafeFileHandle); long size=file.Length; string digest=Digest(file);
            if (slot!=InputCustodyLeaf.Package) small[index]=Small(file);
            if (file.Length!=size || source.FileNativeId(file.SafeFileHandle)!=identity) throw InputCustodyContract.Invalid();
            source.RequireOriginalLeaf(slot,file.SafeFileHandle);
            leaves[index]=new InputCustodyFile(slot,identity,size,digest); streams[index]=file;
        }
        InputCustodyRecord record=new InputCustodyRecord(provenance,ids[0],ids[1],ids[2],ids[3],worker,coordinator,leaves);
        VpnInstallHelperProtocol.Request request=VpnInstallHelperProtocol.ParseRequest(small[(int)InputCustodyLeaf.Request]);
        InputCustodyFile package=record.Leaf(InputCustodyLeaf.Package);
        if (request.JobId!=provenance.JobId || request.PrincipalSid!=provenance.PrincipalSid ||
            request.PackageSha256!=package.Sha256 || request.PackageSize!=package.Size) throw InputCustodyContract.Invalid();
        VpnInstallHelperProtocol.IsCommit(small[(int)InputCustodyLeaf.Commit],provenance.JobId);
        VpnInstallHelperProtocol.WorkerReady ready=VpnInstallHelperProtocol.ParseWorkerReady(small[(int)InputCustodyLeaf.WorkerReady]);
        if (ready.JobId!=provenance.JobId || ready.PrincipalSid!=provenance.PrincipalSid || ready.Pid!=worker.Pid ||
            ready.CreationFileTime!=worker.CreationFileTime || ready.HelperSha256!=worker.HelperSha256) throw InputCustodyContract.Invalid();
        uint exit=VpnInstallHelperProtocol.ParseWorkerResult(small[(int)InputCustodyLeaf.WorkerResult],provenance.JobId);
        if ((exit!=0 && exit!=3010) || source.ReadObservedSuccessfulNativeExit()!=exit) throw InputCustodyContract.Invalid();
        source.RequireOriginalAdmission();
        for (int index=0;index<4;index++) if (source.DirectoryNativeId(directories[index])!=ids[index]) throw InputCustodyContract.Invalid();
        InputCustodyProvenance closingProvenance=source.ReadOriginalProvenance();
        if (closingProvenance==null || closingProvenance.JobId!=provenance.JobId || closingProvenance.PrincipalSid!=provenance.PrincipalSid ||
            closingProvenance.WorkspaceSha256!=provenance.WorkspaceSha256) throw InputCustodyContract.Invalid();
        RequireProcess(worker,source.ReadOriginalProcess(InputCustodyActor.Worker)); RequireProcess(coordinator,source.ReadOriginalProcess(InputCustodyActor.Coordinator));
        for (int index=0;index<5;index++) {
            source.RequireOriginalLeaf((InputCustodyLeaf)index,streams[index].SafeFileHandle);
            if (source.FileNativeId(streams[index].SafeFileHandle)!=leaves[index].NativeId || streams[index].Length!=leaves[index].Size)
                throw InputCustodyContract.Invalid();
        }
        byte[] bytes=InputCustodyContract.Encode(record);
        try {
            source.PublishCustodyNoReplace(directories[3],InputCustodyContract.ProtectedLeaf,InputCustodyContract.ProtectedAcl,bytes);
            InputCustodyContract.RequireSame(record,InputCustodyContract.Parse(source.ReadPublishedCustodyRetained(directories[3])));
            source.RequireOriginalAdmission();
        } catch (Exception error) { throw new InputCustodyPublicationUncertainException(error); }
        return record; // No native cleanup/terminal/closure authority is returned.
    }
    static void RequireProcess(InputCustodyProcess first,InputCustodyProcess second) {
        if (second==null || first.Pid!=second.Pid || first.CreationFileTime!=second.CreationFileTime || first.HelperSha256!=second.HelperSha256)
            throw InputCustodyContract.Invalid();
    }
}
// Native-only same-assembly adapters. No new argv role, path, command or privilege request.

internal sealed class NativeInputCustodySource : IAdmittedInputCustodyNativeSource,IDisposable {
    readonly OwnerInputAdmission admission;
    readonly SafeFileHandle machine,job;
    readonly VpnInstallNative.ProcessImagePin worker,coordinator;
    readonly VpnInstallHelperProtocol.WorkerReady ready;
    readonly uint observedResult;
    readonly FileStream[] files=new FileStream[5];
    readonly List<FileStream> owned=new List<FileStream>();
    internal NativeInputCustodySource(OwnerInputAdmission admitted,SafeFileHandle retainedMachine,SafeFileHandle retainedJob,
        VpnInstallNative.ProcessImagePin retainedWorker,VpnInstallNative.ProcessImagePin retainedCoordinator,
        VpnInstallHelperProtocol.WorkerReady originalReady,uint acceptedResult) {
        admission=admitted;machine=retainedMachine;job=retainedJob;worker=retainedWorker;coordinator=retainedCoordinator;ready=originalReady;observedResult=acceptedResult;
        RequireOriginalAdmission();
        try {
            for(int i=0;i<files.Length;i++) {
                InputCustodyLeaf slot=(InputCustodyLeaf)i;
                if(slot==InputCustodyLeaf.Request)files[i]=admission.OriginalRequestStream;
                else {
                    SafeFileHandle h=VpnInstallNative.OpenRead(admission.FixedInputPath(InputCustodyContract.LeafName(slot)),false);
                    try { RequireOriginalLeaf(slot,h);files[i]=new FileStream(h,FileAccess.Read,8192,false);h=null;owned.Add(files[i]); }
                    finally { if(h!=null)h.Dispose(); }
                }
            }
        } catch { try{Dispose();}catch{} throw; }
    }
    public SafeFileHandle InputRoot{get{return admission.InputRoot;}}
    public SafeFileHandle InputJob{get{return admission.InputDirectory;}}
    public SafeFileHandle ProtectedMachine{get{return machine;}}
    public SafeFileHandle ProtectedJob{get{return job;}}
    public InputCustodyProvenance ReadOriginalProvenance(){return new InputCustodyProvenance(admission.Request.JobId,admission.Request.PrincipalSid,
        Digest(new UTF8Encoding(false,true).GetBytes(admission.Request.StateDirectory)));}
    public InputCustodyProcess ReadOriginalProcess(InputCustodyActor actor) {
        VpnInstallNative.ProcessImageObservation p=(actor==InputCustodyActor.Worker?worker:coordinator).Observe();
        if(p.KernelOnly || (actor==InputCustodyActor.Worker && (p.Pid!=ready.Pid || p.CreationFileTime!=ready.CreationFileTime)))throw new IOException("CONFLICT");
        using(SafeFileHandle h=VpnInstallNative.OpenRead(p.Image,false)) {
            VpnInstallNative.Inspect(h,false,false,admission.Request.PrincipalSid);
            using(FileStream s=new FileStream(h,FileAccess.Read,8192,false)) {
                string hash=Digest(s);if(hash!=ready.HelperSha256)throw new IOException("CONFLICT");
                return new InputCustodyProcess(p.Pid,p.CreationFileTime,hash);
            }
        }
    }
    public FileStream RetainedOriginalLeaf(InputCustodyLeaf slot){return files[(int)slot];}
    public string DirectoryNativeId(SafeFileHandle h){return VpnInstallNative.InputObjectIdentity(h,true);}
    public string FileNativeId(SafeFileHandle h){return VpnInstallNative.InputObjectIdentity(h,false);}
    public void RequireOriginalAdmission() {
        if(admission==null || ready==null || admission.Request==null || (observedResult!=0 && observedResult!=3010) ||
            ready.JobId!=admission.Request.JobId || ready.PrincipalSid!=admission.Request.PrincipalSid)throw new IOException("CONFLICT");
        VpnInstallNative.InspectPrivateInput(InputRoot,true,ready.PrincipalSid);
        VpnInstallNative.InspectPrivateInput(InputJob,true,ready.PrincipalSid);
        VpnInstallNative.InspectLinkedAncestor(InputRoot,InputJob,ready.PrincipalSid);
        if(DirectoryNativeId(InputRoot)!=admission.OriginalInputRootId || DirectoryNativeId(InputJob)!=admission.OriginalInputJobId)throw new IOException("CONFLICT");
        VpnInstallNative.Inspect(machine,true,false,null);VpnInstallNative.Inspect(job,true,false,null);
        VpnInstallNative.InspectLinkedAncestor(machine,job,null);
    }
    public void RequireOriginalLeaf(InputCustodyLeaf slot,SafeFileHandle h) {
        VpnInstallNative.InspectPrivateInput(h,false,ready.PrincipalSid);VpnInstallNative.InspectLinkedAncestor(InputJob,h,ready.PrincipalSid);
        if(VpnInstallNative.InputCanonicalPath(h)!=VpnInstallNative.InputCanonicalPath(InputJob).TrimEnd('\\')+"\\"+InputCustodyContract.LeafName(slot))throw new IOException("CONFLICT");
        if(slot==InputCustodyLeaf.Request && FileNativeId(h)!=admission.OriginalRequestId)throw new IOException("CONFLICT");
    }
    public uint ReadObservedSuccessfulNativeExit(){return observedResult;}
    public void PublishCustodyNoReplace(SafeFileHandle retained,string leaf,string acl,byte[] bytes) {
        if(!Object.ReferenceEquals(retained,job) || leaf!=InputCustodyContract.ProtectedLeaf || acl!=InputCustodyContract.ProtectedAcl)throw new IOException("CONFLICT");
        using(FileStream output=VpnInstallNative.CreateProtectedChild(job,leaf,acl,bytes)){}
    }
    public byte[] ReadPublishedCustodyRetained(SafeFileHandle retained) {
        if(!Object.ReferenceEquals(retained,job))throw new IOException("CONFLICT");
        return NativeCompletedInputFacilities.ReadProtectedLeaf(job,InputCustodyContract.ProtectedLeaf,InputCustodyContract.MaximumBytes);
    }
    public void Dispose() {
        Exception first=null;for(int i=owned.Count-1;i>=0;i--)try{owned[i].Dispose();owned.RemoveAt(i);}catch(Exception e){if(first==null)first=e;}
        if(first!=null)throw new IOException("PERSISTENCE_FAILED",first);
    }
    internal static string Digest(byte[] bytes){using(SHA256 h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
    internal static string Digest(FileStream s){s.Position=0;using(SHA256 h=SHA256.Create()){string d=BitConverter.ToString(h.ComputeHash(s)).Replace("-","").ToLowerInvariant();s.Position=0;return d;}}
}

internal sealed class NativeCompletedInputFacilities : VpnInstallCompletedInputCleanup.Facilities,IDisposable {
    readonly OwnerInputAdmission admission;
    readonly SafeFileHandle machine,job;
    readonly InputCustodyRecord custody;
    readonly byte[] encoded;
    readonly VpnInstallHelperRoles.Receipt terminal;
    readonly Func<VpnInstallHelperRoles.Receipt> readReceipt;
    readonly Action requireReturnAdmission;
    readonly SafeFileHandle ancestor;
    internal NativeCompletedInputFacilities(OwnerInputAdmission admitted,SafeFileHandle retainedMachine,SafeFileHandle retainedJob,
        VpnInstallHelperRoles.Receipt actualTerminal,Func<VpnInstallHelperRoles.Receipt> receipt,Action retainedReturnAdmission) {
        admission=admitted;machine=retainedMachine;job=retainedJob;terminal=actualTerminal;readReceipt=receipt;requireReturnAdmission=retainedReturnAdmission;
        encoded=ReadProtectedLeaf(job,InputCustodyContract.ProtectedLeaf,InputCustodyContract.MaximumBytes);
        custody=InputCustodyContract.Parse(encoded);
        if(custody.Provenance.JobId!=admission.Request.JobId || custody.Provenance.PrincipalSid!=admission.Request.PrincipalSid ||
            custody.Provenance.WorkspaceSha256!=NativeInputCustodySource.Digest(new UTF8Encoding(false,true).GetBytes(admission.Request.StateDirectory)))throw new IOException("CONFLICT");
        RevalidateTerminalCustodyAndActors();
        ancestor=admission.PinCleanupLocalAncestor();
    }
    internal InputCustodyRecord Custody{get{return custody;}}
    public void RevalidateTerminalCustodyAndActors() {
        if(terminal==null || terminal.State!=VpnInstallHelperRoles.Phase.Succeeded || terminal.JobId!=admission.Request.JobId || !terminal.Same(readReceipt()))throw new IOException("OUTCOME_UNKNOWN");
        if(admission.Caller.User==null || admission.Caller.User.Value!=custody.Provenance.PrincipalSid)throw new IOException("PERMISSION_DENIED");
        requireReturnAdmission();
        using(VpnInstallNative.ProcessImagePin self=new VpnInstallNative.ProcessImagePin((uint)System.Diagnostics.Process.GetCurrentProcess().Id)) {
            VpnInstallNative.ProcessImageObservation p=self.Observe();
            if(p.KernelOnly || p.Pid!=custody.Worker.Pid || p.CreationFileTime!=custody.Worker.CreationFileTime)throw new IOException("CONFLICT");
            using(SafeFileHandle h=VpnInstallNative.OpenRead(p.Image,false))using(FileStream s=new FileStream(h,FileAccess.Read,8192,false))
                if(NativeInputCustodySource.Digest(s)!=custody.Worker.HelperSha256)throw new IOException("CONFLICT");
        }
        VpnInstallNative.Inspect(machine,true,false,null);VpnInstallNative.Inspect(job,true,false,null);VpnInstallNative.InspectLinkedAncestor(machine,job,null);
        if(VpnInstallNative.InputObjectIdentity(machine,true)!=custody.ProtectedMachineNativeId || VpnInstallNative.InputObjectIdentity(job,true)!=custody.ProtectedJobNativeId)throw new IOException("CONFLICT");
        byte[] again=ReadProtectedLeaf(job,InputCustodyContract.ProtectedLeaf,InputCustodyContract.MaximumBytes);
        if(again.Length!=encoded.Length)throw new IOException("CONFLICT");for(int i=0;i<again.Length;i++)if(again[i]!=encoded[i])throw new IOException("CONFLICT");
    }
    sealed class Held : VpnInstallCompletedInputCleanup.Handle {
        internal readonly SafeFileHandle Native;
        internal Held(SafeFileHandle h){Native=h;}
        public void Dispose(){VpnInstallNative.CloseInputDeleteHandle(Native);}
    }
    Held Open(string fixedPath) {
        try{return new Held(VpnInstallNative.OpenInputDelete(fixedPath));}
        catch(Win32Exception e){if(e.NativeErrorCode==2 || e.NativeErrorCode==3)return null;throw;}
    }
    public VpnInstallCompletedInputCleanup.Handle OpenRoot() {
        Held h=Open(admission.FixedInputRootPath());
        if(h!=null)try{VpnInstallNative.InspectLinkedAncestor(ancestor,h.Native,admission.Request.PrincipalSid);}catch{h.Dispose();throw;}
        return h;
    }
    public VpnInstallCompletedInputCleanup.Handle OpenJob(VpnInstallCompletedInputCleanup.Handle root){return Open(VpnInstallNative.InputCanonicalPath(((Held)root).Native).TrimEnd('\\')+"\\"+custody.Provenance.JobId);}
    public VpnInstallCompletedInputCleanup.Handle OpenLeaf(VpnInstallCompletedInputCleanup.Handle input,string leaf) {
        if(Array.IndexOf(VpnInstallCompletedInputCleanup.Leaves,leaf)<0)throw new IOException("INVALID_ARGUMENT");
        return Open(VpnInstallNative.InputCanonicalPath(((Held)input).Native).TrimEnd('\\')+"\\"+leaf);
    }
    public void Verify(VpnInstallCompletedInputCleanup.Handle h,VpnInstallCompletedInputCleanup.Handle parent,string identity,bool directory) {
        SafeFileHandle f=((Held)h).Native;VpnInstallNative.InspectPrivateInput(f,directory,admission.Request.PrincipalSid);
        if(VpnInstallNative.InputObjectIdentity(f,directory)!=identity)throw new IOException("CONFLICT");
        if(parent!=null)VpnInstallNative.InspectLinkedAncestor(((Held)parent).Native,f,admission.Request.PrincipalSid);
        using(SafeFileHandle named=VpnInstallNative.OpenInputNamedMetadata(VpnInstallNative.InputCanonicalPath(f))) {
            if(VpnInstallNative.InputObjectIdentity(named,directory)!=identity)throw new IOException("CONFLICT");
        }
    }
    public string[] Children(VpnInstallCompletedInputCleanup.Handle input) {
        List<string> names=new List<string>();foreach(string path in Directory.EnumerateFileSystemEntries(VpnInstallNative.InputCanonicalPath(((Held)input).Native))) {
            names.Add(Path.GetFileName(path));if(names.Count>5)break;
        }return names.ToArray();
    }
    public void VerifyFullBytes(VpnInstallCompletedInputCleanup.Handle h,VpnInstallCompletedInputCleanup.Leaf expected) {
        SafeFileHandle f=((Held)h).Native;
        using(SafeFileHandle borrowed=new SafeFileHandle(f.DangerousGetHandle(),false))
        using(FileStream s=new FileStream(borrowed,FileAccess.Read,8192,false)) {
            if(s.Length!=expected.Size || NativeInputCustodySource.Digest(s)!=expected.Digest || s.Length!=expected.Size)throw new IOException("CONFLICT");
        }
    }
    public void Delete(VpnInstallCompletedInputCleanup.Handle h){VpnInstallNative.DeleteInputHandle(((Held)h).Native);}
    internal static byte[] ReadProtectedLeaf(SafeFileHandle directory,string fixedLeaf,int max) {
        if(fixedLeaf!=InputCustodyContract.ProtectedLeaf || max!=InputCustodyContract.MaximumBytes)throw new IOException("INVALID_ARGUMENT");
        VpnInstallNative.Inspect(directory,true,false,null);
        using(SafeFileHandle h=VpnInstallNative.OpenRead(VpnInstallNative.InputCanonicalPath(directory).TrimEnd('\\')+"\\"+fixedLeaf,false)) {
            VpnInstallNative.InspectLinkedAncestor(directory,h,null);VpnInstallNative.Inspect(h,false,false,null);
            using(FileStream s=new FileStream(h,FileAccess.Read,4096,false)) {
                if(s.Length<1 || s.Length>max)throw new IOException("INVALID_ARGUMENT");byte[] b=new byte[(int)s.Length];int offset=0;
                while(offset<b.Length){int n=s.Read(b,offset,b.Length-offset);if(n<=0)throw new IOException("UNAVAILABLE");offset+=n;}
                if(s.ReadByte()!=-1)throw new IOException("INVALID_ARGUMENT");return b;
            }
        }
    }
    public void Dispose(){} // Ancestry is owned by admission; protected job/machine by the session.
}
