// Fixed installer role state machines. Native authority and storage implementations are separate.
using System;
using System.IO;

internal static class VpnInstallHelperRoles {
    internal enum Phase { Preparing, Authorized, WaitingForExit, Installing, Succeeded, Failed, Cancelled }

    internal sealed class Receipt {
        internal readonly string JobId, Code;
        internal readonly long Sequence;
        internal readonly Phase State;
        internal bool Terminal { get { return State==Phase.Succeeded || State==Phase.Failed || State==Phase.Cancelled; } }
        internal Receipt(string job,long sequence,Phase phase,string code) {
            VpnInstallHelperProtocol.Job(job);
            if ((int)phase<(int)Phase.Preparing || (int)phase>(int)Phase.Cancelled) throw new IOException("INVALID_ARGUMENT");
            if (sequence<0 || code==null || code.Length<1 || code.Length>40) throw new IOException("INVALID_ARGUMENT");
            foreach(char item in code) if (!((item>='A' && item<='Z') || item=='_')) throw new IOException("INVALID_ARGUMENT");
            if ((phase==Phase.Cancelled && code!="CANCELLED") ||
                (phase==Phase.Failed && (code=="OK" || code=="ACCEPTED" || code=="CANCELLED")) ||
                (phase!=Phase.Cancelled && phase!=Phase.Failed && code!="OK")) throw new IOException("INVALID_ARGUMENT");
            JobId=job; Sequence=sequence; State=phase; Code=code;
        }
        internal bool Same(Receipt other) { return other!=null && JobId==other.JobId && Sequence==other.Sequence && State==other.State && Code==other.Code; }
        public override string ToString() { return "Install receipt (private correlation)"; }
    }

    internal sealed class ReceiptCursor {
        readonly string job;
        Receipt previous;
        internal ReceiptCursor(string jobId) { VpnInstallHelperProtocol.Job(jobId); job=jobId; }
        internal Receipt Accept(Receipt receipt) {
            if (receipt==null || receipt.JobId!=job) throw new IOException("CONFLICT");
            if (previous!=null && !previous.Same(receipt)) {
                if (previous.Terminal || receipt.Sequence<=previous.Sequence ||
                    (!receipt.Terminal && (int)receipt.State<=(int)previous.State)) throw new IOException("CONFLICT");
            }
            previous=receipt;
            return receipt;
        }
    }

    // This is a same-assembly regression seam. The fixed entrypoint supplies native implementations;
    // no command, path, delegate, reader, token decision or role implementation comes from argv.
    internal interface OriginalUserSession {
        string JobId { get; }
        void PublishReady();
        Receipt ReadProtectedReceipt(); // Null is allowed only for native initial ERROR_FILE_NOT_FOUND.
        bool AuthorizationDeadlineReached { get; }
        bool ReturnDeadlineReached { get; }
        void Pause();
        uint InstallVerifiedPackage(); // Fixed msi.dll operation under the admitted original restricted token.
        void PublishNativeResult(uint exitCode);
        void RelaunchOriginalOwner(); // Fixed admitted launcher, original workspace argument, original token.
    }

    internal sealed class WorkerFailure : IOException {
        internal readonly bool InstallerStarted;
        internal readonly uint? NativeExitCode;
        internal WorkerFailure(string code,bool started,uint? nativeExit,Exception cause) : base(code,cause) {
            InstallerStarted=started; NativeExitCode=nativeExit;
        }
    }

    internal static int RunOriginalUser(OriginalUserSession session) {
        bool started=false;
        uint? nativeExit=null;
        ReceiptCursor cursor=new ReceiptCursor(session.JobId);
        bool observedReceipt=false;
        try {
            session.PublishReady();
            for (;;) {
                Receipt receipt=session.ReadProtectedReceipt();
                if (receipt==null) {
                    if (observedReceipt) throw new IOException("CONFLICT");
                } else {
                    observedReceipt=true; cursor.Accept(receipt);
                    if (receipt.State==Phase.Failed) return 1;
                    if (receipt.State==Phase.Cancelled) return 130;
                    if (receipt.State==Phase.Succeeded) throw new IOException("CONFLICT");
                    if (receipt.State==Phase.Installing) break;
                }
                if (session.AuthorizationDeadlineReached) throw new IOException("TIMEOUT");
                session.Pause();
            }
            // Mark before the call: a lost native return is unknown, never authority to repeat installation.
            started=true;
            nativeExit=session.InstallVerifiedPackage();
            session.PublishNativeResult(nativeExit.Value);
            for (;;) {
                Receipt receipt=cursor.Accept(session.ReadProtectedReceipt());
                if (receipt.State==Phase.Failed) return 1;
                if (receipt.State==Phase.Cancelled) throw new IOException("CONFLICT");
                if (receipt.State==Phase.Succeeded) {
                    if (nativeExit!=0 && nativeExit!=3010) throw new IOException("CONFLICT");
                    session.RelaunchOriginalOwner();
                    return 0;
                }
                if (session.ReturnDeadlineReached) throw new IOException("OUTCOME_UNKNOWN");
                session.Pause();
            }
        } catch (Exception error) {
            if (error is OutOfMemoryException || error is IOException || error is System.ComponentModel.Win32Exception ||
                error is UnauthorizedAccessException || error is InvalidOperationException)
                throw new WorkerFailure(started ? "OUTCOME_UNKNOWN" : "RUNTIME_FAILED",started,nativeExit,error);
            throw;
        }
    }

    internal interface CoordinatorSession {
        string JobId { get; }
        void ReserveInstallation(); // Retained physical installation/worker identities and reserved protected byte16.
        void CreateProtectedJob();
        // Returning confirms the durable exact receipt. An exception supplies no proof that
        // replacement did not occur; callers must not overwrite an attempted terminal state.
        void Publish(Phase phase,string code);
        void SetPending(bool value);
        bool CancellationRequested { get; }
        bool OwnerExited { get; }
        bool FrontendExited { get; }
        bool WorkerExited { get; }
        bool PrecommitDeadlineReached { get; }
        bool ExitDeadlineReached { get; }
        bool CommitExists(); // Admitted, exact immutable v1 commit record; no caller flag.
        bool TryExclusiveAdmission();
        bool TryInstallationReady(); // Same-handle native inventory plus both physical sibling write probes.
        uint? ReadNativeResult(); // Exact worker-result record, never inferred from process exit or timeout.
        void Pause();
    }

    internal static void RunCoordinator(CoordinatorSession session) {
        bool created=false, preparingPublished=false, pending=false, installing=false, terminal=false;
        bool terminalPublicationAttempted=false;
        try {
            session.ReserveInstallation();
            session.CreateProtectedJob(); created=true;
            session.Publish(Phase.Preparing,"OK"); preparingPublished=true;
            pending=true; // A failed flush can still have exposed pending=1.
            session.SetPending(true);
            session.Publish(Phase.Authorized,"OK");
            for (;;) {
                if (session.CancellationRequested || session.WorkerExited) {
                    terminalPublicationAttempted=true;
                    session.Publish(Phase.Cancelled,"CANCELLED"); terminal=true; return;
                }
                if (session.CommitExists()) break;
                // The owner may exit immediately after publishing a valid commit. Check the
                // admitted record before treating owner exit as an abandoned preparation.
                if (session.OwnerExited) {
                    terminalPublicationAttempted=true;
                    session.Publish(Phase.Cancelled,"CANCELLED"); terminal=true; return;
                }
                if (session.PrecommitDeadlineReached) throw new IOException("TIMEOUT");
                session.Pause();
            }
            session.Publish(Phase.WaitingForExit,"OK");
            for (;;) {
                if (session.CancellationRequested || session.WorkerExited) {
                    terminalPublicationAttempted=true;
                    session.Publish(Phase.Cancelled,"CANCELLED"); terminal=true; return;
                }
                if (session.OwnerExited && session.FrontendExited && session.TryExclusiveAdmission()) break;
                if (session.ExitDeadlineReached) throw new IOException("BUSY");
                session.Pause();
            }
            for (;;) {
                if (session.CancellationRequested || session.WorkerExited) {
                    terminalPublicationAttempted=true;
                    session.Publish(Phase.Cancelled,"CANCELLED"); terminal=true; return;
                }
                if (session.TryInstallationReady()) break;
                if (session.ExitDeadlineReached) throw new IOException("BUSY");
                session.Pause();
            }
            // The original-user helper can observe INSTALLING as soon as publication starts.
            installing=true;
            session.Publish(Phase.Installing,"OK");
            for (;;) {
                uint? result=session.ReadNativeResult();
                if (result.HasValue) {
                    terminalPublicationAttempted=true;
                    session.Publish(result==0 || result==3010 ? Phase.Succeeded : Phase.Failed,
                        result==0 || result==3010 ? "OK" : "RUNTIME_FAILED");
                    terminal=true; return;
                }
                if (session.WorkerExited) throw new IOException("OUTCOME_UNKNOWN");
                // A live modifying installer is never killed or classified failed on a timer.
                session.Pause();
            }
        } catch {
            if (created && !installing && !terminalPublicationAttempted) {
                if (!preparingPublished) session.Publish(Phase.Preparing,"OK");
                terminalPublicationAttempted=true;
                session.Publish(Phase.Failed,"RUNTIME_FAILED"); terminal=true;
            }
            throw;
        } finally {
            if (pending && terminal) session.SetPending(false);
            // The owning native session releases exact handles only after this disposition.
            // Unknown installation retains pending=1 and INSTALLING for later reconciliation.
        }
    }
}
