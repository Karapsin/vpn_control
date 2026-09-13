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
}
