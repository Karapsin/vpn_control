using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;

public static class CompletedInputCleanupFixtures {
    static readonly string Job="10000000-0000-4000-8000-000000000001";
    static void Require(bool value,string message) { if(!value)throw new IOException(message); }
    static string Hash(byte[] bytes) { using(SHA256 sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant(); }
    static byte[] Content(string name) { return Encoding.UTF8.GetBytes("harmless-source-only:"+name); }
    sealed class Node {
        internal readonly string Path;
        internal string Id;
        internal bool Directory,Reparse,Private=true;
        internal int Links=1;
        internal Node(string p,bool d,int id) { Path=p;Directory=d;Id=id.ToString("x48"); }
    }
    sealed class Held : VpnInstallCompletedInputCleanup.Handle {
        internal readonly Fixture F;internal readonly Node N;internal readonly FileStream Stream;
        internal bool Closed,DeletePending;
        internal Held(Fixture f,Node n) { F=f;N=n;if(!n.Directory)Stream=new FileStream(n.Path,FileMode.Open,FileAccess.Read,FileShare.Read);F.OpenCount++; }
        public void Dispose() {
            if(Closed)return;
            F.Events.Add("close:"+System.IO.Path.GetFileName(N.Path));
            if(F.CloseFailure==System.IO.Path.GetFileName(N.Path) && F.CloseFailures-->0)throw new IOException("modeled-native-close-refusal");
            if(Stream!=null)Stream.Dispose();
            if(DeletePending) {
                if(N.Directory)System.IO.Directory.Delete(N.Path,false);else File.Delete(N.Path);
                F.Nodes.Remove(N.Path);
            }
            Closed=true;F.OpenCount--;
        }
    }
    sealed class Fixture : VpnInstallCompletedInputCleanup.Facilities,IDisposable {
        internal readonly string Base,Root,Input;
        internal readonly Dictionary<string,Node> Nodes=new Dictionary<string,Node>(StringComparer.Ordinal);
        internal readonly List<string> Events=new List<string>();
        internal readonly VpnInstallCompletedInputCleanup.Debt Debt=new VpnInstallCompletedInputCleanup.Debt();
        internal readonly VpnInstallCompletedInputCleanup.Leaf[] Leaves=new VpnInstallCompletedInputCleanup.Leaf[5];
        internal int OpenCount,Deletes,Next=3,CloseFailures,Revalidations;
        internal string DeleteFailure,CloseFailure,OpenFailure;
        internal bool Terminal=true,Custody=true,ActorsClosed=true,GateClear=true;
        internal Action<int> OnRevalidate;internal Action<string> BeforeDelete;
        internal readonly string RootId,InputId;
        internal Fixture(string ownParent) {
            Base=System.IO.Path.Combine(ownParent,Guid.NewGuid().ToString("D"));Root=System.IO.Path.Combine(Base,"input-root");Input=System.IO.Path.Combine(Root,Job);
            System.IO.Directory.CreateDirectory(Input);Nodes.Add(Root,new Node(Root,true,1));Nodes.Add(Input,new Node(Input,true,2));
            RootId=Nodes[Root].Id;InputId=Nodes[Input].Id;
            for(int i=0;i<Leaves.Length;i++) { string n=VpnInstallCompletedInputCleanup.Leaves[i];Add(n,Content(n));Node node=Nodes[System.IO.Path.Combine(Input,n)];Leaves[i]=new VpnInstallCompletedInputCleanup.Leaf(n,node.Id,Content(n).Length,Hash(Content(n))); }
        }
        internal void Add(string name,byte[] bytes) { string path=System.IO.Path.Combine(Input,name);File.WriteAllBytes(path,bytes);Nodes[path]=new Node(path,false,Next++); }
        internal void Release() { VpnInstallCompletedInputCleanup.Release(this,RootId,InputId,Leaves,Debt); }
        public void RevalidateTerminalCustodyAndActors() {
            Revalidations++;if(OnRevalidate!=null)OnRevalidate(Revalidations);
            if(!Terminal || !Custody || !ActorsClosed || !GateClear)throw new IOException("OUTCOME_UNKNOWN");
        }
        Held Open(string path) {
            if(OpenFailure==System.IO.Path.GetFileName(path))throw new IOException("modeled-native-access-denied");
            Node n;return Nodes.TryGetValue(path,out n)?new Held(this,n):null;
        }
        public VpnInstallCompletedInputCleanup.Handle OpenRoot() { return Open(Root); }
        public VpnInstallCompletedInputCleanup.Handle OpenJob(VpnInstallCompletedInputCleanup.Handle root) { Require(((Held)root).N.Path==Root,"fixed-root");return Open(Input); }
        public VpnInstallCompletedInputCleanup.Handle OpenLeaf(VpnInstallCompletedInputCleanup.Handle job,string leaf) { Require(((Held)job).N.Path==Input && Array.IndexOf(VpnInstallCompletedInputCleanup.Leaves,leaf)>=0,"fixed-leaf");return Open(System.IO.Path.Combine(Input,leaf)); }
        public void Verify(VpnInstallCompletedInputCleanup.Handle handle,VpnInstallCompletedInputCleanup.Handle parent,string id,bool directory) {
            Held h=(Held)handle;Require(!h.Closed && h.N.Id==id && h.N.Directory==directory && !h.N.Reparse && h.N.Private && (directory || h.N.Links==1),"native-object-policy");
            Node named;Require(Nodes.TryGetValue(h.N.Path,out named) && Object.ReferenceEquals(named,h.N),"named-object-replaced");
            Require(directory?System.IO.Directory.Exists(h.N.Path):File.Exists(h.N.Path),"named-object-missing");
            if(parent!=null)Require(System.IO.Path.GetDirectoryName(h.N.Path)==((Held)parent).N.Path,"linked-parent");
        }
        public string[] Children(VpnInstallCompletedInputCleanup.Handle job) { string[] p=System.IO.Directory.GetFileSystemEntries(((Held)job).N.Path);for(int i=0;i<p.Length;i++)p[i]=System.IO.Path.GetFileName(p[i]);return p; }
        public void VerifyFullBytes(VpnInstallCompletedInputCleanup.Handle file,VpnInstallCompletedInputCleanup.Leaf leaf) {
            Held h=(Held)file;h.Stream.Position=0;using(MemoryStream m=new MemoryStream()) { h.Stream.CopyTo(m);byte[] bytes=m.ToArray();Require(bytes.LongLength==leaf.Size && Hash(bytes)==leaf.Digest,"full-byte-binding"); }
        }
        public void Delete(VpnInstallCompletedInputCleanup.Handle handle) {
            Held h=(Held)handle;string name=System.IO.Path.GetFileName(h.N.Path);if(BeforeDelete!=null)BeforeDelete(name);
            if(DeleteFailure==name)throw new IOException("modeled-native-delete-refusal");
            if(h.N.Directory)Require(System.IO.Directory.GetFileSystemEntries(h.N.Path).Length==0,"foreign-child-retained");
            Deletes++;h.DeletePending=true;Events.Add("delete:"+name);
        }
        public void Dispose() { Debt.CloseAll();Require(OpenCount==0,"owned-handle-leak");if(System.IO.Directory.Exists(Base))System.IO.Directory.Delete(Base,true); }
    }
    sealed class Worker : VpnInstallHelperRoles.OriginalUserSession,VpnInstallHelperRoles.OriginalUserCompletedInputSession {
        internal readonly Fixture F;internal int Reads,InstallCalls,Relauches;internal bool CleanupFailed;
        internal uint Exit=0;
        internal Worker(Fixture f) { F=f; }
        public string JobId { get { return Job; } }
        public bool AuthorizationDeadlineReached { get { return true; } }
        public bool ReturnDeadlineReached { get { return true; } }
        public void Pause() { throw new IOException("unexpected-poll"); }
        public void PublishReady() { F.Events.Add("worker-ready"); }
        public VpnInstallHelperRoles.Receipt ReadProtectedReceipt() { Reads++;return new VpnInstallHelperRoles.Receipt(Job,Reads,Reads==1?VpnInstallHelperRoles.Phase.Installing:VpnInstallHelperRoles.Phase.Succeeded,"OK"); }
        public uint InstallVerifiedPackage() { InstallCalls++;return Exit; }
        public void PublishNativeResult(uint value) { Require(value==Exit,"native-result");F.Events.Add("native-result-captured"); }
        public void CompleteInputCleanup() { F.Release(); }
        public void RetainInputCleanupFailure() { CleanupFailed=true;F.Events.Add("cleanup-failed"); }
        public void RelaunchOriginalOwner() { Relauches++;F.Events.Add("original-user-return"); }
    }
    public static string SuccessfulReturnRemovesExactInputs(string parent) { using(Fixture f=new Fixture(parent)) { Worker w=new Worker(f);Require(VpnInstallHelperRoles.RunOriginalUser(w)==0,"known-success");Require(!System.IO.Directory.Exists(f.Input),"SUCCESS_INPUTS_REMAIN");Require(w.Relauches==1 && w.InstallCalls==1,"one-install-one-return");return "SUCCESS_INPUTS_ABSENT_AND_RETURNED"; } }
    public static string CleanupFailurePreservesSuccessAndReturn(string parent) { using(Fixture f=new Fixture(parent)) { f.DeleteFailure="request.json";Worker w=new Worker(f);w.Exit=3010;Require(VpnInstallHelperRoles.RunOriginalUser(w)==0,"msi3010-return");Require(w.CleanupFailed && w.Relauches==1 && w.InstallCalls==1,"cleanup-failure-masked-or-return-suppressed");Require(File.Exists(System.IO.Path.Combine(f.Input,"request.json")),"failed-leaf-retained");f.DeleteFailure=null;f.Release();Require(!System.IO.Directory.Exists(f.Input),"partial-retry-not-complete");return "MSI3010_SUCCESS_RETURN_WITH_SEPARATE_CLEANUP_FAILURE_AND_RETRY"; } }
    public static string ColdRetryMissingSlotAndReplacementRefusal(string parent) { using(Fixture f=new Fixture(parent)) { f.DeleteFailure="request.json";try { f.Release();throw new IOException("expected-delete-failure"); }catch(IOException e){Require(e.Message=="PERSISTENCE_FAILED","finite-failure");}f.Add("package.msi",Content("package.msi"));f.DeleteFailure=null;int deleted=f.Deletes;try { f.Release();throw new IOException("replacement-admitted"); }catch(IOException e){Require(e.Message=="PERSISTENCE_FAILED","replacement-refusal");}Require(f.Deletes==deleted,"effects-before-identity-admission");return "COLD_REPLACEMENT_REFUSED"; } }
    public static string ForeignReparseAclHashAndLiveGuardsRefuse(string parent) {
        Action<Fixture>[] changes={f=>f.Terminal=false,f=>f.Custody=false,f=>f.ActorsClosed=false,f=>f.GateClear=false,f=>f.Nodes[f.Input].Id="f".PadLeft(48,'f'),f=>f.Nodes[System.IO.Path.Combine(f.Input,"request.json")].Reparse=true,f=>f.Nodes[System.IO.Path.Combine(f.Input,"request.json")].Private=false,f=>f.Nodes[System.IO.Path.Combine(f.Input,"request.json")].Links=2,f=>File.WriteAllBytes(System.IO.Path.Combine(f.Input,"request.json"),new byte[]{0}),f=>f.Add("foreign",new byte[]{1}),f=>f.OpenFailure="request.json",f=>f.OnRevalidate=i=>{if(i==2)f.Terminal=false;}};
        foreach(Action<Fixture> change in changes)using(Fixture f=new Fixture(parent)){change(f);try{f.Release();throw new IOException("guard-admitted");}catch(IOException e){Require(e.Message=="PERSISTENCE_FAILED","guard-failure");}Require(f.Deletes==0,"guard-deleted-before-admission");}
        return "TWELVE_GUARDS_REFUSED_ZERO_EFFECTS";
    }
    public static string LateForeignChildAndCloseFailureStayOwned(string parent) {
        using(Fixture f=new Fixture(parent)) { f.BeforeDelete=name=>{if(name=="package.msi")f.Add("foreign",new byte[]{7});};try{f.Release();throw new IOException("foreign-race-admitted");}catch(IOException e){Require(e.Message=="PERSISTENCE_FAILED","foreign-race");}Require(File.Exists(System.IO.Path.Combine(f.Input,"foreign")),"foreign-deleted"); }
        using(Fixture f=new Fixture(parent)) { f.CloseFailure="request.json";f.CloseFailures=3;try{f.Release();throw new IOException("close-admitted");}catch(IOException e){Require(e.Message=="PERSISTENCE_FAILED","close-failure");}Require(f.Debt.Handles.Count>0 && f.OpenCount>0,"failed-close-debt-lost");f.CloseFailures=0;f.Release();Require(f.OpenCount==0 && !System.IO.Directory.Exists(f.Input),"close-retry-incomplete"); }
        return "FOREIGN_RETAINED_AND_FAILED_CLOSE_RETRIED";
    }
    public static string MissingJobCloseRefusalIsNotSuccess(string parent) { using(Fixture f=new Fixture(parent)) { f.Release();f.CloseFailure="input-root";f.CloseFailures=2;try{f.Release();throw new IOException("absent-close-masked");}catch(IOException e){Require(e.Message=="PERSISTENCE_FAILED","absence-close-error");}Require(f.Debt.Handles.Count>0,"absent-close-debt-lost");f.CloseFailures=0;f.Release();return "PRECISE_ABSENCE_STILL_REQUIRES_ALL_CLOSES"; } }
}

public static class RetentionFixtures {
    const string Job="10000000-0000-4000-8000-000000000001";
    static void Require(bool x,string m){if(!x)throw new IOException(m);}
    sealed class Worker : VpnInstallHelperRoles.OriginalUserSession,VpnInstallHelperRoles.OriginalUserCompletedInputSession {
        internal readonly IOException Primary=new IOException("actual-cleanup-refusal");
        internal int Read,Return,Install;
        public string JobId{get{return Job;}}
        public bool AuthorizationDeadlineReached{get{return true;}}
        public bool ReturnDeadlineReached{get{return true;}}
        public void Pause(){throw new IOException("unexpected-poll");}
        public void PublishReady(){}
        public VpnInstallHelperRoles.Receipt ReadProtectedReceipt(){Read++;return new VpnInstallHelperRoles.Receipt(Job,Read,Read==1?VpnInstallHelperRoles.Phase.Installing:VpnInstallHelperRoles.Phase.Succeeded,"OK");}
        public uint InstallVerifiedPackage(){Install++;return 0;}
        public void PublishNativeResult(uint x){Require(x==0,"native-return");}
        public void CompleteInputCleanup(){throw Primary;}
        public void RetainInputCleanupFailure(){throw new IOException("actual-retention-refusal");}
        public void RelaunchOriginalOwner(){Return++;}
    }
    sealed class Coordinator : VpnInstallHelperRoles.CoordinatorSession,VpnInstallHelperRoles.CoordinatorCompletedInputSession {
        internal readonly IOException Primary=new IOException("actual-custody-refusal");
        internal bool Pending,Cleared;internal VpnInstallHelperRoles.Phase Published;
        public string JobId{get{return Job;}}
        public void ReserveInstallation(){}
        public void CreateProtectedJob(){}
        public void Publish(VpnInstallHelperRoles.Phase p,string c){Published=p;Require(c=="OK","known-native-success");}
        public void SetPending(bool x){Pending=x;if(!x)Cleared=true;}
        public bool CancellationRequested{get{return false;}}
        public bool OwnerExited{get{return true;}}
        public bool FrontendExited{get{return true;}}
        public bool WorkerExited{get{return false;}}
        public bool PrecommitDeadlineReached{get{return true;}}
        public bool ExitDeadlineReached{get{return true;}}
        public bool CommitExists(){return true;}
        public bool TryExclusiveAdmission(){return true;}
        public bool TryInstallationReady(){return true;}
        public void PublishPreinstallDiagnostic(int x,bool y){}
        public uint? ReadNativeResult(){return 0;}
        public void Pause(){throw new IOException("unexpected-poll");}
        public void PrepareInputCustody(uint x){Require(x==0,"observed-result");throw Primary;}
        public void RetainInputCustodyFailure(){throw new IOException("actual-retention-refusal");}
    }
    public static string WorkerRetentionFailureCannotSuppressReturn(){Worker w=new Worker();Exception thrown=null;try{VpnInstallHelperRoles.RunOriginalUser(w);}catch(Exception e){thrown=e;}Require(thrown==null && w.Return==1 && w.Install==1,"RETENTION_SUPPRESSED_KNOWN_SUCCESS_RETURN");Require((bool)w.Primary.Data["vpn.install.cleanupRetentionUncertain"],"secondary-marker-lost");return "KNOWN_SUCCESS_RETURN_PRIMARY_AND_SECONDARY_RETAINED";}
    public static string CoordinatorRetentionFailureCannotSuppressKnownOutcome(){Coordinator c=new Coordinator();Exception thrown=null;try{VpnInstallHelperRoles.RunCoordinator(c);}catch(Exception e){thrown=e;}Require(thrown==null && c.Published==VpnInstallHelperRoles.Phase.Succeeded && c.Cleared && !c.Pending,"RETENTION_SUPPRESSED_KNOWN_SUCCESS_PUBLICATION");Require((bool)c.Primary.Data["vpn.install.custodyRetentionUncertain"],"secondary-marker-lost");return "KNOWN_SUCCESS_PUBLISHED_AND_PENDING_CLEARED";}
}

// Managed causal regression only. Native IDs, ACLs, token and actor states are modeled;
// file bytes, streams, hashing, partial deletion and owned cleanup are real.
public static class CompletedInputCleanupRoutineFixtures {
    public static string Run() {
        string parent=Path.Combine(Path.GetTempPath(),"vpn-completed-input-fixture-"+Guid.NewGuid().ToString("D"));
        Directory.CreateDirectory(parent);
        try {
            string[] cases={
                CompletedInputCleanupFixtures.SuccessfulReturnRemovesExactInputs(parent),
                CompletedInputCleanupFixtures.CleanupFailurePreservesSuccessAndReturn(parent),
                CompletedInputCleanupFixtures.ColdRetryMissingSlotAndReplacementRefusal(parent),
                CompletedInputCleanupFixtures.ForeignReparseAclHashAndLiveGuardsRefuse(parent),
                CompletedInputCleanupFixtures.LateForeignChildAndCloseFailureStayOwned(parent),
                CompletedInputCleanupFixtures.MissingJobCloseRefusalIsNotSuccess(parent),
                RetentionFixtures.WorkerRetentionFailureCannotSuppressReturn(),
                RetentionFixtures.CoordinatorRetentionFailureCannotSuppressKnownOutcome()
            };
            for(int i=0;i<cases.Length;i++)cases[i]="CASE:"+cases[i];
            return String.Join("\n",cases)+"\nCOMPLETED_INPUT_CLEANUP_AND_RETENTION_OK";
        } finally {
            if(Directory.GetFileSystemEntries(parent).Length!=0)throw new IOException("OWNED_FIXTURE_CLEANUP_INCOMPLETE");
            Directory.Delete(parent,false);
        }
    }
}
