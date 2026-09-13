// Never packaged. This causal harness constructs the real original-user adapter
// through its same-assembly inert-facilities seam. No request/argv/environment
// selects an adapter or external facility.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Text;

public static class OriginalUserAdapterFixtures {
    const string Job="00000000-0000-0000-0000-00000000000d";
    const string Other="00000000-0000-0000-0000-00000000000e";

    sealed class Session : OriginalUserSessionAdapterFacilities {
        internal readonly Queue<VpnInstallHelperRoles.Receipt> receipts;
        VpnInstallHelperRoles.Receipt last;
        internal int NativeCalls, ResultCalls, Relaunches, Disposals, Pauses, PauseLimit=-1;
        internal long ClockMillis, ReturnDeadlineMillis=-1;
        internal bool ResultAckLost;
        internal Session(params VpnInstallHelperRoles.Receipt[] source) { receipts=new Queue<VpnInstallHelperRoles.Receipt>(source); }
        public string JobId { get { return Job; } }
        public void PublishReady() { }
        public VpnInstallHelperRoles.Receipt ReadProtectedReceipt() {
            if (receipts.Count!=0) last=receipts.Dequeue();
            return last;
        }
        public bool AuthorizationDeadlineReached { get { return last==null && receipts.Count==0; } }
        public bool ReturnDeadlineReached { get { return ReturnDeadlineMillis>=0 ? ClockMillis>=ReturnDeadlineMillis : receipts.Count==0; } }
        public void Pause() {
            Pauses++; ClockMillis+=100;
            if (PauseLimit>=0 && Pauses>PauseLimit) throw new IOException("PAUSE_CAP");
        }
        public uint InstallVerifiedPackage() {
            NativeCalls++;
            return 0;
        }
        public void PublishNativeResult(uint exit) {
            ResultCalls++;
            if (ResultAckLost) throw new IOException("Private result acknowledgement lost");
        }
        public void RelaunchOriginalOwner() { Relaunches++; }
        public void Dispose() { Disposals++; }
    }

    static VpnInstallHelperRoles.Receipt Receipt(string job,long sequence,VpnInstallHelperRoles.Phase phase) {
        return new VpnInstallHelperRoles.Receipt(job,sequence,phase,phase==VpnInstallHelperRoles.Phase.Cancelled ? "CANCELLED" : "OK");
    }
    static VpnInstallHelperRoles.WorkerFailure Failure(OriginalUserSessionAdapter session) {
        try { VpnInstallHelperRoles.RunOriginalUser(session); }
        catch (VpnInstallHelperRoles.WorkerFailure error) { return error; }
        throw new Exception("Expected retained original-user failure");
    }

    public static string AcknowledgementLossDoesNotReplayMsi() {
        Session session=new Session(Receipt(Job,3,VpnInstallHelperRoles.Phase.Installing));
        session.ResultAckLost=true;
        OriginalUserSessionAdapter adapter=new OriginalUserSessionAdapter(session);
        VpnInstallHelperRoles.WorkerFailure first;
        try { VpnInstallHelperRoles.RunOriginalUser(adapter); throw new Exception("Expected uncertain result"); }
        catch (VpnInstallHelperRoles.WorkerFailure error) { first=error; }
        if (!first.InstallerStarted || session.NativeCalls!=1 || session.ResultCalls!=1 || session.Relaunches!=0 || session.Disposals!=0)
            throw new Exception("Lost acknowledgement did not retain uncertain native attempt");
        // The terminal receipt is observation only. The exact adapter remains live
        // through it, then its resource owner is explicitly released once.
        session.receipts.Enqueue(Receipt(Job,4,VpnInstallHelperRoles.Phase.Succeeded));
        adapter.ReconcileUncertainOutcome();
        if (session.Disposals!=0) throw new Exception("Reconciliation released input before terminal disposal");
        try { adapter.InstallVerifiedPackage(); throw new Exception("Unknown result replayed MSI"); }
        catch (IOException) { }
        if (session.NativeCalls!=1) throw new Exception("Unknown result reached native MSI twice");
        adapter.Dispose();
        if (session.Disposals!=1) throw new Exception("Terminal adapter did not release retained input exactly once");
        return "ACK_LOSS_NO_REPLAY";
    }

    public static string WrongCorrelationIsRejectedBeforeMsi() {
        Session session=new Session(Receipt(Other,3,VpnInstallHelperRoles.Phase.Installing));
        OriginalUserSessionAdapter adapter=new OriginalUserSessionAdapter(session);
        VpnInstallHelperRoles.WorkerFailure failure=Failure(adapter);
        if (failure.InstallerStarted || session.NativeCalls!=0 || session.ResultCalls!=0 || session.Relaunches!=0)
            throw new Exception("Foreign receipt reached native installation");
        return "FOREIGN_RECEIPT_REJECTED";
    }

    public static string StalledInstallingReceiptReachesDeadline() {
        Session session=new Session(Receipt(Job,3,VpnInstallHelperRoles.Phase.Installing));
        session.ResultAckLost=true;
        session.ReturnDeadlineMillis=300;
        session.PauseLimit=3;
        OriginalUserSessionAdapter adapter=new OriginalUserSessionAdapter(session);
        try { VpnInstallHelperRoles.RunOriginalUser(adapter); throw new Exception("Expected uncertain result"); }
        catch (VpnInstallHelperRoles.WorkerFailure error) {
            if (!error.InstallerStarted || session.NativeCalls!=1 || session.ResultCalls!=1) throw new Exception("Fixture did not reach uncertain native result");
        }
        try { adapter.ReconcileUncertainOutcome(); throw new Exception("Stalled INSTALLING did not reach deadline"); }
        catch (IOException error) {
            if (error.Message!="OUTCOME_UNKNOWN") throw;
        }
        if (session.Pauses!=3 || session.ClockMillis!=300 || session.NativeCalls!=1 || session.Relaunches!=0) throw new Exception("Deadline reconciliation changed native outcome");
        return "INSTALLING_DEADLINE_REACHED";
    }

    public static string AdvancedInstallingReceiptWaitsForTerminal() {
        Session session=new Session(Receipt(Job,3,VpnInstallHelperRoles.Phase.Installing));
        session.ResultAckLost=true;
        OriginalUserSessionAdapter adapter=new OriginalUserSessionAdapter(session);
        try { VpnInstallHelperRoles.RunOriginalUser(adapter); throw new Exception("Expected uncertain result"); }
        catch (VpnInstallHelperRoles.WorkerFailure error) {
            if (!error.InstallerStarted || session.NativeCalls!=1 || session.ResultCalls!=1) throw new Exception("Fixture did not reach uncertain native result");
        }
        session.receipts.Enqueue(Receipt(Job,4,VpnInstallHelperRoles.Phase.Installing));
        session.receipts.Enqueue(Receipt(Job,5,VpnInstallHelperRoles.Phase.Succeeded));
        adapter.ReconcileUncertainOutcome();
        if (session.Pauses!=1 || session.NativeCalls!=1 || session.Relaunches!=0) throw new Exception("Advanced receipt replayed or relaunched");
        return "ADVANCED_INSTALLING_ACCEPTED";
    }
}
