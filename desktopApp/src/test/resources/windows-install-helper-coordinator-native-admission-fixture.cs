// Never packaged. Exercises the actual CoordinatorSessionAdapter constructor
// with a real same-image helper and an owned, unique direct ProgramData child.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;

public static class CoordinatorNativeAdmissionFixtures {
    const string MachineAcl="O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)";
    const string UnsafeMachineAcl="O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;BU)";

    public static int Main(string[] arguments) {
        if (arguments!=null && arguments.Length==1 && arguments[0]=="worker") { Thread.Sleep(15000); return 0; }
        string token=arguments!=null && arguments.Length==2 && arguments[0]=="--completion-token" ? arguments[1] : Guid.NewGuid().ToString("N");
        Run(token); return 0;
    }

    static void Run(string token) {
        if (!String.Equals(Path.GetFileName(Environment.ProcessPath),"vpn-control.exe",StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Probe must execute the emitted vpn-control.exe apphost");
        string job=Guid.NewGuid().ToString("D");
        string machine=Path.Combine(VpnInstallNative.ProgramData(),"VpnCoordinatorGate36-"+Guid.NewGuid().ToString("N"));
        string completion=Path.Combine(Path.GetTempPath(),"vpn-coordinator-native-"+token+".json");
        // The real ProgramData ancestor is already admitted by the native policy;
        // this unique child is task-owned and avoids any user profile workspace.
        string local=Path.Combine(VpnInstallNative.ProgramData(),"VpnCoordinatorInput36-"+Guid.NewGuid().ToString("N"));
        string inputRoot=Path.Combine(local,"vpn-control-install-inputs");
        string input=Path.Combine(inputRoot,job);
        Process worker=null;
        try {
            if (File.Exists(completion)) throw new IOException("Completion token already exists");
            using (WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
                if (identity.User==null) throw new IOException("Fixture caller identity unavailable");
                string sid=identity.User.Value;
                uint pid=(uint)Process.GetCurrentProcess().Id;
                long created=Creation(pid);
                VpnInstallNative.CreateDirectory(local,PrivateAcl(sid));
                CreatePrivateInputs(inputRoot,input,job,pid,created,sid);
                worker=StartWorker();
                long workerCreated=Creation((uint)worker.Id);
                string digest=Hash(Environment.ProcessPath);

                VpnInstallHelperProtocol.Invocation invocation=new VpnInstallHelperProtocol.Invocation(
                    VpnInstallHelperProtocol.Role.Coordinator,job,pid,created);

                CreateMachine(machine,MachineAcl);
                string foreignSid=sid=="S-1-5-18" ? "S-1-5-19" : "S-1-5-18";
                RejectsBeforeOutput(invocation,local,input,job,(uint)worker.Id,workerCreated,foreignSid,digest,machine,"SID");
                RejectsBeforeOutput(invocation,local,input,job,(uint)worker.Id,checked(workerCreated+1),sid,digest,machine,"GENERATION");
                RejectsBeforeOutput(invocation,local,input,job,(uint)worker.Id,workerCreated,sid,new string('0',64),machine,"DIGEST");

                DeleteDirectory(machine); CreateMachine(machine,UnsafeMachineAcl);
                WriteReady(input,job,(uint)worker.Id,workerCreated,sid,digest);
                RejectsReserve(invocation,local,machine,"UNSAFE_ACL");

                DeleteDirectory(machine);
                string target=Path.Combine(Path.GetTempPath(),"VpnCoordinatorGate36-target-"+Guid.NewGuid().ToString("N"));
                CreateMachine(target,MachineAcl);
                try {
                    Directory.CreateSymbolicLink(machine,target);
                    RejectsReserve(invocation,local,machine,"REPARSE");
                } finally { DeleteDirectory(machine); DeleteDirectory(target); }

                CreateMachine(machine,MachineAcl);
                using (OwnerInputAdmission admission=OwnerInputAdmission.Open(invocation,false,delegate { return local; }))
                using (CoordinatorSessionAdapter adapter=new CoordinatorSessionAdapter(admission,delegate { return machine; })) {
                    adapter.ReserveInstallation();
                    adapter.CreateProtectedJob();
                    if (!Directory.EnumerateFiles(machine,"gate-*").GetEnumerator().MoveNext() ||
                        !Directory.Exists(Path.Combine(machine,job))) throw new IOException("Positive constructor did not create protected output");
                }
                File.WriteAllText(completion,"{\"token\":\""+token+"\",\"result\":\"COORDINATOR_NATIVE_ADMISSION_OK\"}");
                Console.WriteLine("COORDINATOR_NATIVE_ADMISSION_OK token="+token+" completion="+completion);
            }
        } finally {
            if (worker!=null) { worker.WaitForExit(); worker.Dispose(); }
            DeleteDirectory(machine);
            DeleteDirectory(input);
            TryDeleteInputRoot(inputRoot);
            DeleteDirectory(local);
        }
    }

    static void RejectsBeforeOutput(VpnInstallHelperProtocol.Invocation invocation,string local,string input,string job,uint pid,long created,string sid,string digest,string machine,string name) {
        WriteReady(input,job,pid,created,sid,digest);
        try {
            using (OwnerInputAdmission admission=OwnerInputAdmission.Open(invocation,false,delegate { return local; }))
            using (CoordinatorSessionAdapter adapter=new CoordinatorSessionAdapter(admission,delegate { return machine; })) { }
        } catch (IOException) {
            if (Directory.EnumerateFileSystemEntries(machine).GetEnumerator().MoveNext()) throw new IOException(name+" reached gate or job output");
            return;
        }
        throw new IOException(name+" readiness was admitted");
    }

    static void RejectsReserve(VpnInstallHelperProtocol.Invocation invocation,string local,string machine,string name) {
        try {
            using (OwnerInputAdmission admission=OwnerInputAdmission.Open(invocation,false,delegate { return local; }))
            using (CoordinatorSessionAdapter adapter=new CoordinatorSessionAdapter(admission,delegate { return machine; })) adapter.ReserveInstallation();
        } catch (IOException) {
            if (Directory.Exists(machine) && Directory.EnumerateFileSystemEntries(machine).GetEnumerator().MoveNext())
                throw new IOException(name+" wrote a gate or job before rejecting its machine root");
            return;
        }
        throw new IOException(name+" machine root was admitted");
    }

    static Process StartWorker() {
        Process worker=Process.Start(new ProcessStartInfo { FileName=Environment.ProcessPath, Arguments="worker", UseShellExecute=false, CreateNoWindow=true });
        if (worker==null) throw new IOException("Same-image worker did not start");
        return worker;
    }
    static long Creation(uint pid) { using (VpnInstallNative.ProcessImagePin pin=new VpnInstallNative.ProcessImagePin(pid)) return pin.Observe().CreationFileTime; }
    static string Hash(string path) { using (FileStream file=File.OpenRead(path)) return VpnInstallNative.Sha256(file); }
    static void WriteReady(string input,string job,uint pid,long created,string sid,string digest) {
        string path=Path.Combine(input,"worker-ready.json"); if (File.Exists(path)) File.Delete(path);
        using (WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
            if (identity.User==null) throw new IOException("Fixture caller identity unavailable");
            using (FileStream file=VpnInstallNative.CreateFile(path,PrivateAcl(identity.User.Value),
                VpnInstallHelperProtocol.EncodeWorkerReady(job,pid,created,sid,digest))) { }
        }
    }
    static void CreatePrivateInputs(string inputRoot,string input,string job,uint pid,long created,string sid) {
        if (!Directory.Exists(inputRoot)) VpnInstallNative.CreateDirectory(inputRoot,PrivateAcl(sid));
        VpnInstallNative.CreateDirectory(input,PrivateAcl(sid));
        string launcher=Environment.ProcessPath, state=Path.Combine(Path.GetTempPath(),"VpnCoordinatorGate36-state-"+job);
        string request="{\"version\":1,\"jobId\":\""+job+"\",\"principalSid\":\""+sid+"\",\"ownerPid\":"+pid+
            ",\"ownerStartedAtEpochMillis\":"+Started(pid)+",\"launcher\":\""+Json(launcher)+"\",\"packageFile\":\""+Json(Path.Combine(Path.GetTempPath(),"VpnCoordinatorGate36-"+job+".msi"))+"\",\"packageSha256\":\""+new string('0',64)+"\",\"packageSize\":1,\"stateDirectory\":\""+Json(state)+"\"}";
        using (FileStream file=VpnInstallNative.CreateFile(Path.Combine(input,"request.json"),PrivateAcl(sid),System.Text.Encoding.UTF8.GetBytes(request))) { }
    }
    static long Started(uint pid) { using (VpnInstallNative.ProcessPin pin=new VpnInstallNative.ProcessPin(pid)) return pin.StartedAtEpochMillis; }
    static string Json(string text) { return text.Replace("\\","\\\\").Replace("\"","\\\""); }
    static string PrivateAcl(string sid) { return "O:"+sid+"G:"+sid+"D:P(A;OICI;FA;;;"+sid+")(A;OICI;GR;;;BA)(A;OICI;GR;;;SY)"; }
    static void CreateMachine(string path,string acl) { VpnInstallNative.CreateDirectory(path,acl); }
    static void DeleteDirectory(string path) { try { if (Directory.Exists(path)) Directory.Delete(path,true); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
    static void TryDeleteInputRoot(string root) { try { if (Directory.Exists(root) && !Directory.EnumerateFileSystemEntries(root).GetEnumerator().MoveNext()) Directory.Delete(root); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
}
