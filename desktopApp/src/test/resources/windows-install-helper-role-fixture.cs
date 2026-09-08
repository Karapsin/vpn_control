// Never a product input. Compiles into the same regression assembly as the fixed role core.
using System;
using System.Collections.Generic;
using System.IO;

public static class InstallerRoleFixtures {
    const string Job="00000000-0000-0000-0000-00000000000a";
    static VpnInstallHelperRoles.Receipt Receipt(long sequence,VpnInstallHelperRoles.Phase phase) {
        return new VpnInstallHelperRoles.Receipt(Job,sequence,phase,
            phase==VpnInstallHelperRoles.Phase.Failed ? "RUNTIME_FAILED" :
            phase==VpnInstallHelperRoles.Phase.Cancelled ? "CANCELLED" : "OK");
    }
    static void Check(bool value,string message) { if (!value) throw new Exception(message); }
    sealed class User : VpnInstallHelperRoles.OriginalUserSession {
        readonly Queue<VpnInstallHelperRoles.Receipt> receipts;
        internal readonly List<string> Calls=new List<string>();
        internal uint ExitCode;
        internal bool FailInstall,FailPublication,AuthorizationExpired,ReturnExpired;
        public string JobId { get { return Job; } }
        internal User(params VpnInstallHelperRoles.Receipt[] values) { receipts=new Queue<VpnInstallHelperRoles.Receipt>(values); }
        public void PublishReady() { Calls.Add("ready"); }
        public VpnInstallHelperRoles.Receipt ReadProtectedReceipt() {
            Calls.Add("read");
            if (receipts.Count==0) throw new IOException("Fixture exhausted");
            return receipts.Dequeue();
        }
        public bool AuthorizationDeadlineReached { get { return AuthorizationExpired; } }
        public bool ReturnDeadlineReached { get { return ReturnExpired; } }
        public void Pause() { Calls.Add("pause"); }
        public uint InstallVerifiedPackage() {
            Calls.Add("install");
            if (FailInstall) throw new IOException("Native result unavailable");
            return ExitCode;
        }
        public void PublishNativeResult(uint result) {
            Check(result==ExitCode,"Exact native outcome was lost"); Calls.Add("result");
            if (FailPublication) throw new IOException("Private publication unavailable");
        }
        public void RelaunchOriginalOwner() { Calls.Add("relaunch"); }
    }
    sealed class Coordinator : VpnInstallHelperRoles.CoordinatorSession {
        internal readonly List<string> Calls=new List<string>();
        internal bool Cancel,Ready=true,Expired,ExitedUnexpectedly,FailInstallPublication,FailSuccessPublication,OwnerAlreadyExited;
        internal int CancelPublicationFailure;
        internal bool CancellationReplaced;
        bool waiting,installing;
        internal uint? Result=0;
        public string JobId { get { return Job; } }
        public void ReserveInstallation() { Calls.Add("reserve"); }
        public void CreateProtectedJob() { Calls.Add("job"); }
        public void Publish(VpnInstallHelperRoles.Phase phase,string code) {
            Calls.Add("publish:"+phase);
            if (phase==VpnInstallHelperRoles.Phase.Cancelled) {
                if (CancelPublicationFailure==1) throw new IOException("Cancellation failed before replacement");
                CancellationReplaced=true;
                if (CancelPublicationFailure==2) throw new IOException("Cancellation reply lost after replacement");
            }
            if (phase==VpnInstallHelperRoles.Phase.WaitingForExit) waiting=true;
            if (phase==VpnInstallHelperRoles.Phase.Installing) {
                installing=true;
                if (FailInstallPublication) throw new IOException("Publication acknowledgement lost");
            }
            if (phase==VpnInstallHelperRoles.Phase.Succeeded && FailSuccessPublication) throw new IOException("Terminal publication lost");
        }
        public void SetPending(bool value) { Calls.Add(value ? "pending:1" : "pending:0"); }
        public bool CancellationRequested { get { return Cancel; } }
        public bool OwnerExited { get { return waiting || OwnerAlreadyExited; } }
        public bool FrontendExited { get { return waiting; } }
        public bool WorkerExited { get { return installing && ExitedUnexpectedly; } }
        public bool PrecommitDeadlineReached { get { return Expired; } }
        public bool ExitDeadlineReached { get { return Expired; } }
        public bool CommitExists() { Calls.Add("commit"); return true; }
        public bool TryExclusiveAdmission() { Calls.Add("exclusive"); return true; }
        public bool TryInstallationReady() { Calls.Add("inventory"); return Ready; }
        public uint? ReadNativeResult() { Calls.Add("result"); return Result; }
        public void Pause() { Calls.Add("pause"); }
    }
    static VpnInstallHelperRoles.WorkerFailure UserFails(User session) {
        try { VpnInstallHelperRoles.RunOriginalUser(session); }
        catch(VpnInstallHelperRoles.WorkerFailure failure) { return failure; }
        throw new Exception("Expected fixed worker failure");
    }
    static void CoordinatorFails(Coordinator session) {
        bool failed=false;
        try { VpnInstallHelperRoles.RunCoordinator(session); } catch(IOException) { failed=true; }
        Check(failed,"Expected coordinator failure");
    }
    public static void CommittedOwnerExit() {
        Coordinator session=new Coordinator(); session.OwnerAlreadyExited=true;
        VpnInstallHelperRoles.RunCoordinator(session);
        Check(session.Calls.Contains("publish:Installing") && session.Calls.Contains("publish:Succeeded") &&
            !session.Calls.Contains("publish:Cancelled"),"Valid committed handoff was cancelled because its owner exited");
    }
    public static void UndefinedReceiptPhase() {
        bool rejected=false;
        try { Receipt(1,(VpnInstallHelperRoles.Phase)999); } catch(IOException) { rejected=true; }
        Check(rejected,"Undefined receipt phase was accepted");
    }
    public static void CancelFailureBeforeReplacement() { CancellationPublicationFailure(1); }
    public static void CancelFailureAfterReplacement() { CancellationPublicationFailure(2); }
    static void CancellationPublicationFailure(int scenario) {
        Coordinator session=new Coordinator(); session.Cancel=true; session.CancelPublicationFailure=scenario;
        CoordinatorFails(session);
        Check(session.CancellationReplaced==(scenario==2),"Fixture replacement boundary did not execute");
        Check(!session.Calls.Contains("publish:Failed") && !session.Calls.Contains("pending:0") &&
            !session.Calls.Contains("publish:Installing"),"Unconfirmed cancellation publication was rewritten or reopened admission");
    }
    public static string[] Run() {
        List<string> passed=new List<string>();
        foreach(uint result in new uint[]{0,3010}) {
            User user=new User(null,Receipt(0,VpnInstallHelperRoles.Phase.Preparing),Receipt(1,VpnInstallHelperRoles.Phase.Authorized),
                Receipt(2,VpnInstallHelperRoles.Phase.WaitingForExit),Receipt(3,VpnInstallHelperRoles.Phase.Installing),
                Receipt(4,VpnInstallHelperRoles.Phase.Succeeded)); user.ExitCode=result;
            Check(VpnInstallHelperRoles.RunOriginalUser(user)==0,"Known install did not return");
            Check(user.Calls[0]=="ready" && user.Calls.IndexOf("install")<user.Calls.IndexOf("result") &&
                user.Calls.IndexOf("result")<user.Calls.IndexOf("relaunch"),"Worker lifecycle ordering changed");
            passed.Add("original-known-"+result);
        }
        foreach(VpnInstallHelperRoles.Phase phase in new[]{VpnInstallHelperRoles.Phase.Failed,VpnInstallHelperRoles.Phase.Cancelled}) {
            User user=new User(Receipt(0,phase));
            Check(VpnInstallHelperRoles.RunOriginalUser(user)==(phase==VpnInstallHelperRoles.Phase.Cancelled ? 130 : 1),"Terminal pre-install result changed");
            Check(!user.Calls.Contains("install") && !user.Calls.Contains("relaunch"),"Unapproved installation ran");
            passed.Add("original-before-install-"+phase);
        }
        User premature=new User(Receipt(4,VpnInstallHelperRoles.Phase.Succeeded));
        Check(!UserFails(premature).InstallerStarted && !premature.Calls.Contains("install"),"Premature terminal receipt started installation");
        passed.Add("premature-success");
        User wrongSequence=new User(Receipt(1,VpnInstallHelperRoles.Phase.Authorized),Receipt(1,VpnInstallHelperRoles.Phase.Installing));
        Check(!UserFails(wrongSequence).InstallerStarted,"Changed same-sequence receipt started installation");
        passed.Add("same-sequence-change");
        User missingAfterObserved=new User(Receipt(1,VpnInstallHelperRoles.Phase.Authorized),null);
        Check(!UserFails(missingAfterObserved).InstallerStarted,"Receipt loss became startup permission");
        passed.Add("observed-receipt-loss");
        User lostReturn=new User(Receipt(3,VpnInstallHelperRoles.Phase.Installing)); lostReturn.FailInstall=true;
        VpnInstallHelperRoles.WorkerFailure lost=UserFails(lostReturn);
        Check(lost.InstallerStarted && !lost.NativeExitCode.HasValue && !lostReturn.Calls.Contains("result"),"Lost native return became proven no-start");
        passed.Add("native-return-unknown");
        User lostPublication=new User(Receipt(3,VpnInstallHelperRoles.Phase.Installing)); lostPublication.ExitCode=3010; lostPublication.FailPublication=true;
        VpnInstallHelperRoles.WorkerFailure publication=UserFails(lostPublication);
        Check(publication.InstallerStarted && publication.NativeExitCode==3010 && !lostPublication.Calls.Contains("relaunch"),"Known result was discarded or relaunched without protected receipt");
        passed.Add("publication-retains-known-exit");
        User impossibleSuccess=new User(Receipt(3,VpnInstallHelperRoles.Phase.Installing),Receipt(4,VpnInstallHelperRoles.Phase.Succeeded)); impossibleSuccess.ExitCode=1603;
        Check(UserFails(impossibleSuccess).NativeExitCode==1603 && !impossibleSuccess.Calls.Contains("relaunch"),"Failed MSI relaunched through inconsistent success");
        passed.Add("native-failure-vs-success");
        User expired=new User(new VpnInstallHelperRoles.Receipt[]{null}); expired.AuthorizationExpired=true;
        Check(!UserFails(expired).InstallerStarted && !expired.Calls.Contains("install"),"Authorization expiry started installation");
        passed.Add("authorization-deadline");
        User returnExpired=new User(Receipt(3,VpnInstallHelperRoles.Phase.Installing),Receipt(3,VpnInstallHelperRoles.Phase.Installing)); returnExpired.ReturnExpired=true;
        Check(UserFails(returnExpired).NativeExitCode==0 && !returnExpired.Calls.Contains("relaunch"),"Return deadline lost the native result or relaunched early");
        passed.Add("return-deadline-retains-result");
        Coordinator known=new Coordinator(); VpnInstallHelperRoles.RunCoordinator(known);
        Check(known.Calls.IndexOf("exclusive")<known.Calls.IndexOf("inventory") &&
            known.Calls.IndexOf("inventory")<known.Calls.IndexOf("publish:Installing") &&
            known.Calls.IndexOf("publish:Succeeded")<known.Calls.IndexOf("pending:0"),"Coordinator admission/publication ordering changed");
        passed.Add("coordinator-known-success");
        Coordinator denied=new Coordinator(); denied.Cancel=true; VpnInstallHelperRoles.RunCoordinator(denied);
        Check(denied.Calls.Contains("publish:Cancelled") && denied.Calls.Contains("pending:0") && !denied.Calls.Contains("publish:Installing"),"Precommit cancellation did not preserve no-start");
        passed.Add("coordinator-precommit-cancel");
        Coordinator unready=new Coordinator(); unready.Ready=false; unready.Expired=true; CoordinatorFails(unready);
        Check(unready.Calls.Contains("publish:Failed") && unready.Calls.Contains("pending:0") && !unready.Calls.Contains("publish:Installing"),"Unready physical installation started modification");
        passed.Add("coordinator-unready");
        Coordinator exited=new Coordinator(); exited.ExitedUnexpectedly=true; exited.Result=null; CoordinatorFails(exited);
        Check(exited.Calls.Contains("publish:Installing") && !exited.Calls.Contains("pending:0") && !exited.Calls.Contains("publish:Failed"),"Unexpected worker exit cleared uncertain installation");
        passed.Add("coordinator-unknown-child-exit");
        Coordinator lostInstalling=new Coordinator(); lostInstalling.FailInstallPublication=true; CoordinatorFails(lostInstalling);
        Check(!lostInstalling.Calls.Contains("pending:0") && !lostInstalling.Calls.Contains("publish:Failed"),"Lost INSTALLING publication created false failure");
        passed.Add("coordinator-installing-ack-loss");
        Coordinator lostSuccess=new Coordinator(); lostSuccess.FailSuccessPublication=true; CoordinatorFails(lostSuccess);
        Check(!lostSuccess.Calls.Contains("pending:0") && !lostSuccess.Calls.Contains("publish:Failed"),"Lost terminal publication reopened admission");
        passed.Add("coordinator-success-ack-loss");
        return passed.ToArray();
    }
}
