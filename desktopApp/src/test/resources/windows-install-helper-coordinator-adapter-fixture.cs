// Never packaged. This causal fixture drives only the coordinator adapter's
// same-assembly facilities seam; it exposes no MSI, path, launch or token input.
using System;
using System.Collections.Generic;
using System.IO;

public static class CoordinatorAdapterFixtures {
    const string Job="00000000-0000-0000-0000-00000000000f";

    sealed class Session : CoordinatorSessionAdapterFacilities {
        internal readonly List<string> Calls=new List<string>();
        internal bool FailInstallingPublication, WorkerGone;
        internal uint? Result=0;
        internal bool Pending;
        bool installing;
        public string JobId { get { return Job; } }
        public void ReserveInstallation() { Calls.Add("reserve"); }
        public void CreateProtectedJob() { Calls.Add("job"); }
        public void Publish(VpnInstallHelperRoles.Phase phase,string code) {
            Calls.Add("publish:"+phase);
            if (phase==VpnInstallHelperRoles.Phase.Installing) installing=true;
            if (phase==VpnInstallHelperRoles.Phase.Installing && FailInstallingPublication)
                throw new IOException("lost INSTALLING acknowledgement");
        }
        public void SetPending(bool value) { Pending=value; Calls.Add(value ? "pending:1" : "pending:0"); }
        public bool CancellationRequested { get { return false; } }
        public bool OwnerExited { get { return true; } }
        public bool FrontendExited { get { return true; } }
        public bool WorkerExited { get { return installing && WorkerGone; } }
        public bool PrecommitDeadlineReached { get { return false; } }
        public bool ExitDeadlineReached { get { return false; } }
        public bool CommitExists() { Calls.Add("commit"); return true; }
        public bool TryExclusiveAdmission() { Calls.Add("exclusive"); return true; }
        public bool TryInstallationReady() { Calls.Add("ready"); return true; }
        public uint? ReadNativeResult() { Calls.Add("result"); return Result; }
        public void Pause() { Calls.Add("pause"); }
        public void Dispose() { Calls.Add("dispose"); }
    }

    // This is injected at CoordinatorSessionAdapter.Publish's real receipt
    // boundary. It records the byte payload that would have been atomically
    // replaced, then simulates a lost acknowledgement after INSTALLING became
    // visible. It is not a second coordinator state model.
    sealed class RecordingPublisher : CoordinatorReceiptPublisher {
        internal readonly List<VpnInstallHelperRoles.Receipt> Records=new List<VpnInstallHelperRoles.Receipt>();
        readonly VpnInstallHelperRoles.Phase? loseAcknowledgement;
        internal RecordingPublisher(VpnInstallHelperRoles.Phase? losePhase) { loseAcknowledgement=losePhase; }
        public void Replace(Microsoft.Win32.SafeHandles.SafeFileHandle directory,string name,byte[] bytes) {
            VpnInstallHelperRoles.Receipt receipt=VpnInstallHelperProtocol.ParseReceipt(bytes);
            Records.Add(receipt);
            if (loseAcknowledgement.HasValue && receipt.State==loseAcknowledgement.Value)
                throw new IOException("visible protected receipt acknowledgement lost");
        }
    }

    public static string KnownResultHasNoMsiAuthority() {
        Session session=new Session();
        using (CoordinatorSessionAdapter adapter=new CoordinatorSessionAdapter(session))
            VpnInstallHelperRoles.RunCoordinator(adapter);
        if (!session.Calls.Contains("publish:Installing") || !session.Calls.Contains("publish:Succeeded") ||
            !session.Calls.Contains("result") || session.Pending || session.Calls.Contains("install"))
            throw new Exception("Coordinator changed authority or terminal ordering");
        return "COORDINATOR_ADAPTER_NO_MSI";
    }

    public static string LostInstallingAcknowledgementRetainsPending() {
        Session session=new Session(); session.FailInstallingPublication=true;
        try {
            using (CoordinatorSessionAdapter adapter=new CoordinatorSessionAdapter(session))
                VpnInstallHelperRoles.RunCoordinator(adapter);
        } catch (IOException) { }
        if (!session.Pending || session.Calls.Contains("pending:0") || session.Calls.Contains("result") ||
            session.Calls.Contains("publish:Failed"))
            throw new Exception("Lost INSTALLING acknowledgement fabricated a terminal outcome");
        return "COORDINATOR_INSTALLING_ACK_RETAINED";
    }

    public static string WorkerExitBeforeResultRemainsUnknown() {
        Session session=new Session(); session.WorkerGone=true; session.Result=null;
        try {
            using (CoordinatorSessionAdapter adapter=new CoordinatorSessionAdapter(session))
                VpnInstallHelperRoles.RunCoordinator(adapter);
        } catch (IOException) { }
        if (!session.Pending || session.Calls.Contains("pending:0") || session.Calls.Contains("publish:Failed") ||
            session.Calls.Contains("publish:Succeeded"))
            throw new Exception("Worker exit before exact result was made terminal");
        return "COORDINATOR_WORKER_EXIT_UNKNOWN";
    }

    public static string VisibleInstallingAckLossRetainsPendingWithoutDuplicateTerminal() {
        Session session=new Session(); RecordingPublisher publisher=new RecordingPublisher(VpnInstallHelperRoles.Phase.Installing);
        CoordinatorReceiptWriter writer=new CoordinatorReceiptWriter(Job,null,publisher);
        try {
            using (CoordinatorSessionAdapter adapter=new CoordinatorSessionAdapter(session,writer))
                VpnInstallHelperRoles.RunCoordinator(adapter);
        } catch (VpnInstallHelperRoles.PublicationUncertainException) { }
        if (!session.Pending || session.Calls.Contains("pending:0") || publisher.Records.Count!=4 ||
            publisher.Records[3].State!=VpnInstallHelperRoles.Phase.Installing ||
            publisher.Records[3].Sequence!=3 || session.Calls.Contains("publish:Failed"))
            throw new Exception("Visible receipt loss fabricated a conflicting terminal outcome");
        return "COORDINATOR_VISIBLE_ACK_LOSS_RETAINED";
    }

    public static string ActualAdapterReceiptWriterKeepsMonotonicSequence() {
        Session session=new Session(); RecordingPublisher publisher=new RecordingPublisher(null);
        CoordinatorReceiptWriter writer=new CoordinatorReceiptWriter(Job,null,publisher);
        using (CoordinatorSessionAdapter adapter=new CoordinatorSessionAdapter(session,writer))
            VpnInstallHelperRoles.RunCoordinator(adapter);
        if (publisher.Records.Count!=5 || session.Pending || session.Calls.Contains("install"))
            throw new Exception("Actual coordinator receipt boundary was not exercised");
        for (int index=0;index<publisher.Records.Count;index++)
            if (publisher.Records[index].Sequence!=index) throw new Exception("Coordinator receipt sequence regressed");
        return "COORDINATOR_RECEIPT_SEQUENCE_MONOTONIC";
    }

    public static string VisibleAuthorizedAckLossRetainsPendingWithoutConflictingFailedReceipt() {
        Session session=new Session(); RecordingPublisher publisher=new RecordingPublisher(VpnInstallHelperRoles.Phase.Authorized);
        CoordinatorReceiptWriter writer=new CoordinatorReceiptWriter(Job,null,publisher);
        try {
            using (CoordinatorSessionAdapter adapter=new CoordinatorSessionAdapter(session,writer))
                VpnInstallHelperRoles.RunCoordinator(adapter);
        } catch (VpnInstallHelperRoles.PublicationUncertainException) { }
        if (!session.Pending || session.Calls.Contains("pending:0") || publisher.Records.Count!=2 ||
            publisher.Records[0].Sequence!=0 || publisher.Records[1].Sequence!=1 ||
            publisher.Records[1].State!=VpnInstallHelperRoles.Phase.Authorized ||
            session.Calls.Contains("publish:Failed"))
            throw new Exception("Visible AUTHORIZED loss fabricated FAILED at sequence one");
        return "COORDINATOR_AUTHORIZED_ACK_LOSS_RETAINED";
    }

    // Actual adapter/lease disposal controls. Only external gate/process/token
    // facilities are inert: two real semaphores and retained real FileStreams.
    sealed class ReturnState : IDisposable {
        internal readonly System.Threading.SemaphoreSlim Range0=new System.Threading.SemaphoreSlim(0,1);
        internal readonly System.Threading.SemaphoreSlim Range16=new System.Threading.SemaphoreSlim(0,1);
        internal readonly System.Threading.ManualResetEventSlim ReconcileEntered=new System.Threading.ManualResetEventSlim(false);
        internal readonly System.Threading.ManualResetEventSlim WorkerEntered=new System.Threading.ManualResetEventSlim(false);
        internal readonly System.Threading.ManualResetEventSlim ChildTerminal=new System.Threading.ManualResetEventSlim(false);
        internal readonly System.Threading.ManualResetEventSlim ExternalTerminal=new System.Threading.ManualResetEventSlim(false);
        internal readonly List<string> Calls=new List<string>();
        internal readonly string Root;
        internal readonly FileStream Gate, ChildWitness, CoordinatorWitness, OwnerWitness, InputWitness;
        internal bool Released0,Released16,ChildClosed,CoordinatorClosed,UnknownChild;
        internal bool FailPendingClear,FailCleanup,NativeResultReadRefused;
        internal int Launches,GateReleaseCalls,NativeCalls;
        internal readonly IOException ReleaseFailure=new IOException("RELEASE_REFUSAL");
        internal readonly IOException ReconcileFailure=new IOException("RECONCILE_REFUSAL");
        internal Exception WorkerFailure;
        internal ReturnState() {
            Root=Path.Combine(Path.GetTempPath(),"vpn-return-order-"+Guid.NewGuid().ToString("D"));
            Directory.CreateDirectory(Root);
            Gate=New("gate"); Gate.Write(new byte[17],0,17); Gate.Flush(true);
            ChildWitness=New("child"); CoordinatorWitness=New("coordinator");
            OwnerWitness=New("owner"); InputWitness=New("input");
        }
        FileStream New(string name) { return new FileStream(Path.Combine(Root,name),FileMode.CreateNew,FileAccess.ReadWrite,FileShare.Read); }
        internal void Record(string name) { lock(Calls) Calls.Add(name); }
        internal bool Has(string name) { lock(Calls) return Calls.Contains(name); }
        internal void Pending(bool value) {
            lock(Gate) { Gate.Position=8; Gate.WriteByte(value ? (byte)1 : (byte)0); Gate.Flush(true); }
            Record(value ? "pending:1" : "pending:0");
            // The write can be visible even when its acknowledgement is lost.
            if (!value && FailPendingClear) throw new IOException("PENDING_CLEAR_REFUSAL");
        }
        internal bool TryReturn() {
            if (!Range16.Wait(0)) return false;
            if (!Range0.Wait(0)) { Range16.Release(); return false; }
            try {
                byte[] bytes=new byte[17];
                lock(Gate) { Gate.Position=0; if (Gate.Read(bytes,0,17)!=17) throw new IOException("GATE_BOUND"); }
                return OriginalUserSessionAdapter.ReturnGateIsClear(bytes);
            } finally { Range0.Release(); Range16.Release(); }
        }
        internal void ReleaseRanges() {
            GateReleaseCalls++; Record("release-ranges");
            if (!Released0) { Released0=true; Range0.Release(); }
            if (!Released16) { Released16=true; Range16.Release(); }
            if (FailCleanup) throw ReleaseFailure;
        }
        internal void Rescue() {
            if (!Released0) { Released0=true; Range0.Release(); }
            if (!Released16) { Released16=true; Range16.Release(); }
            ExternalTerminal.Set();
        }
        public void Dispose() {
            Rescue(); ChildWitness.Dispose(); CoordinatorWitness.Dispose(); OwnerWitness.Dispose(); InputWitness.Dispose(); Gate.Dispose();
            ReconcileEntered.Dispose(); WorkerEntered.Dispose(); ChildTerminal.Dispose(); ExternalTerminal.Dispose(); Range0.Dispose(); Range16.Dispose();
            Directory.Delete(Root,true);
        }
    }
    sealed class ReturnCoordinator : CoordinatorSessionAdapterFacilities,CoordinatorTerminalReturnGateFacilities {
        readonly ReturnState state;
        internal ReturnCoordinator(ReturnState value) { state=value; }
        public string JobId { get { return Job; } }
        public void ReserveInstallation() { }
        public void CreateProtectedJob() { }
        public void Publish(VpnInstallHelperRoles.Phase phase,string code) { state.Record("publish:"+phase); }
        public void SetPending(bool value) { state.Pending(value); }
        public bool CancellationRequested { get { return false; } }
        public bool OwnerExited { get { return true; } }
        public bool FrontendExited { get { return true; } }
        public bool WorkerExited { get { return false; } }
        public bool PrecommitDeadlineReached { get { return false; } }
        public bool ExitDeadlineReached { get { return false; } }
        public bool CommitExists() { return true; }
        public bool TryExclusiveAdmission() { return true; }
        public bool TryInstallationReady() { return true; }
        public uint? ReadNativeResult() { if(state.NativeResultReadRefused) throw new IOException("OUTCOME_UNKNOWN"); return 0; }
        public void Pause() { System.Threading.Thread.Sleep(1); }
        public void ReleaseTerminalReturnGate() { state.ReleaseRanges(); }
        public void Dispose() {
            state.Record("coordinator-dispose");
            state.Rescue(); state.CoordinatorWitness.Dispose(); state.CoordinatorClosed=true;
            if (state.FailCleanup) throw new IOException("COORDINATOR_CLOSE_REFUSAL");
        }
    }
    sealed class ReturnUser : OriginalUserSessionAdapterFacilities {
        readonly ReturnState state;
        readonly System.Diagnostics.Stopwatch clock=System.Diagnostics.Stopwatch.StartNew();
        internal ReturnUser(ReturnState value) { state=value; }
        public string JobId { get { return Job; } }
        public void PublishReady() { throw new Exception("NO_NATIVE_AUTHORITY"); }
        public VpnInstallHelperRoles.Receipt ReadProtectedReceipt() { throw new Exception("NO_RECEIPT_AUTHORITY"); }
        public bool AuthorizationDeadlineReached { get { return false; } }
        public bool ReturnDeadlineReached { get { return clock.ElapsedMilliseconds>=5000; } }
        public void Pause() { System.Threading.Thread.Sleep(1); }
        public uint InstallVerifiedPackage() { state.NativeCalls++; throw new Exception("NO_MSI_AUTHORITY"); }
        public void PublishNativeResult(uint code) { throw new Exception("NO_NATIVE_RESULT_AUTHORITY"); }
        public bool TryAcquireReturnAdmission() { return state.TryReturn(); }
        public void RelaunchOriginalOwner() { state.Record("owner-return"); state.Launches++; }
        public void Dispose() { state.Record("return-lease-dispose"); }
    }
    sealed class ReturnChild : CoordinatorOriginalUserChild {
        readonly ReturnState state;
        internal ReturnChild(ReturnState value) { state=value; }
        public uint ProcessId { get { return 424242; } }
        public long CreationFileTime { get { return 134000000000000001; } }
        public string PrincipalSid { get { return "S-1-5-21-1-2-3-1001"; } }
        public bool Exited { get { return state.ChildTerminal.IsSet; } }
        public void ReleaseLaunchImagePinAfterAdmission() { }
        public void ReconcileBeforeAdmission() { throw new Exception("NO_POST_ADMISSION_TERMINATION"); }
        public void ReconcileAfterAdmission() {
            state.Record("child-reconcile"); state.ReconcileEntered.Set();
            state.ChildTerminal.Wait();
            if (state.ChildClosed || !state.ChildWitness.CanRead || !state.OwnerWitness.CanRead || !state.InputWitness.CanRead)
                throw new Exception("EXACT_WITNESS_LOST");
            if (state.FailCleanup) throw state.ReconcileFailure;
        }
        public void Dispose() {
            state.Record("child-dispose");
            if (!state.ChildTerminal.IsSet) throw new Exception("LIVE_CHILD_WITNESS_CLOSED");
            state.ChildWitness.Dispose(); state.ChildClosed=true;
            if (state.FailCleanup) throw new IOException("CHILD_CLOSE_REFUSAL");
        }
    }
    static Exception DisposeReturnLease(ReturnChild child,CoordinatorSessionAdapter coordinator) {
        return CoordinatorOriginalUserBootstrapLease.ReconcileAndDispose(child,coordinator);
    }
    static void ReturnCase(string name,bool unknown,VpnInstallHelperRoles.Phase? publicationLoss,bool clearLoss,bool malformedClear,bool cleanupFailure) {
        using (ReturnState state=new ReturnState()) {
            state.UnknownChild=unknown; state.FailPendingClear=clearLoss; state.FailCleanup=cleanupFailure;
            state.NativeResultReadRefused=name=="live-install-result-refusal";
            ReturnCoordinator facility=new ReturnCoordinator(state);
            RecordingPublisher publisher=new RecordingPublisher(publicationLoss);
            CoordinatorReceiptWriter writer=new CoordinatorReceiptWriter(Job,null,publisher);
            CoordinatorSessionAdapter coordinator=new CoordinatorSessionAdapter(facility,writer);
            if (malformedClear) { coordinator.Publish(VpnInstallHelperRoles.Phase.Preparing,"OK"); coordinator.SetPending(false); }
            else try { VpnInstallHelperRoles.RunCoordinator(coordinator); }
                catch (VpnInstallHelperRoles.PublicationUncertainException) { }
                catch (IOException error) {
                    if (!(clearLoss && error.Message=="PENDING_CLEAR_REFUSAL") &&
                        !(state.NativeResultReadRefused && error.Message=="OUTCOME_UNKNOWN")) throw;
                }
            ReturnChild child=new ReturnChild(state); Exception cleanup=null;
            System.Threading.Thread worker=new System.Threading.Thread(delegate() {
                try {
                    state.WorkerEntered.Set();
                    if (unknown) state.ExternalTerminal.Wait();
                    else using (OriginalUserSessionAdapter user=new OriginalUserSessionAdapter(new ReturnUser(state))) user.RelaunchOriginalOwner();
                } catch(Exception error) { state.WorkerFailure=error; }
                finally { state.Record("child-terminal"); state.ChildTerminal.Set(); }
            });
            System.Threading.Thread disposer=new System.Threading.Thread(delegate() { cleanup=DisposeReturnLease(child,coordinator); });
            worker.Start(); if(!state.WorkerEntered.Wait(1000)) throw new Exception("WORKER_DID_NOT_START");
            disposer.Start(); bool joined=false;
            try {
                if (!state.ReconcileEntered.Wait(1000)) throw new Exception("RECONCILE_DID_NOT_START");
                if (unknown) {
                    if (state.GateReleaseCalls!=0 || state.Released0 || state.Released16 || state.ChildClosed || state.CoordinatorClosed ||
                        !state.OwnerWitness.CanRead || !state.InputWitness.CanRead || !state.ChildWitness.CanRead || !state.CoordinatorWitness.CanRead || state.Launches!=0)
                        throw new Exception("UNKNOWN_WITNESSES_OR_GATE_RELEASED");
                    state.ExternalTerminal.Set();
                }
                joined=disposer.Join(1000);
                if (!joined) throw new Exception("RETURN_GATE_CIRCULAR_WAIT");
                if (!worker.Join(1000) || state.WorkerFailure!=null) throw new Exception("WORKER_RETURN_FAILED",state.WorkerFailure);
                if (!state.ChildClosed || !state.CoordinatorClosed || state.NativeCalls!=0) throw new Exception("CLEANUP_OR_NATIVE_AUTHORITY");
                if (unknown) { if(state.Launches!=0) throw new Exception("UNKNOWN_OWNER_LAUNCHED"); }
                else if (state.Launches!=1 || state.GateReleaseCalls!=1) throw new Exception("SUCCESS_RETURN_NOT_SINGLE");
                if (cleanupFailure) {
                    if(!Object.ReferenceEquals(cleanup,state.ReleaseFailure) || !state.Has("child-dispose") || !state.Has("coordinator-dispose"))
                        throw new Exception("FIRST_CLEANUP_FAILURE_MASKED_OR_RELEASE_SKIPPED");
                } else if (cleanup!=null) throw new Exception("UNEXPECTED_CLEANUP_FAILURE",cleanup);
                Console.WriteLine("CASE:"+name);
            } finally {
                state.Rescue();
                if(!worker.Join(6000) || !disposer.Join(6000)) throw new Exception("INERT_THREAD_CLEANUP_FAILED");
            }
        }
    }
    public static string TerminalReturnLeaseReleasesGateBeforeChildWait() {
        ReturnCase("terminal-success-gate-before-child",false,null,false,false,false);
        return "TERMINAL_RETURN_GATE_BEFORE_CHILD_OK";
    }
    public static string UnknownReturnLeaseRetainsGateAndExactWitnesses() {
        ReturnCase("visible-installing-ack-loss",true,VpnInstallHelperRoles.Phase.Installing,false,false,false);
        ReturnCase("visible-terminal-ack-loss",true,VpnInstallHelperRoles.Phase.Succeeded,false,false,false);
        ReturnCase("live-install-result-refusal",true,null,false,false,false);
        ReturnCase("pending-clear-ack-loss",true,null,true,false,false);
        ReturnCase("pending-clear-without-terminal",true,null,false,true,false);
        return "UNKNOWN_RETURN_GATE_WITNESSES_RETAINED_OK";
    }
    public static string ReturnLeaseCleanupAttemptsEveryStageAndKeepsFirstFailure() {
        ReturnCase("release-reconcile-and-close-refusals",false,null,false,false,true);
        return "RETURN_LEASE_INDEPENDENT_CLEANUP_OK";
    }
}
