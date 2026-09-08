// Never packaged. Native tests only create/read/delete inert Property-table databases.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class InstallerMsiFixtures {
    sealed class Input : VpnInstallHelperMsi.AdmittedInput {
        internal string Path="C:\\private job\\package.msi";
        internal int Checks,RejectAt,CloseFailures,Closes;
        internal bool Closed;
        public string PackagePath { get { return Path; } }
        public void Recheck() {
            if (Closed) throw new ObjectDisposedException("fixture");
            if (++Checks==RejectAt) throw new UnauthorizedAccessException("fixture admission failure");
        }
        public void Dispose() {
            Closes++;
            if (CloseFailures-- > 0) throw new IOException("fixture close failure");
            Closed=true;
        }
    }

    sealed class Native : VpnInstallHelperMsi.Native {
        internal readonly List<string> Calls=new List<string>();
        internal readonly HashSet<uint> Open=new HashSet<uint>();
        internal string Product="vpn-control",Upgrade="{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}";
        internal uint Result,UiResult=5,OpenError,Fields=1;
        internal bool Missing,Duplicate,ThrowInstall;
        internal int CloseFailures,Installs,Fetches;
        uint next=1;
        VpnInstallHelperMsi.Property property;
        VpnInstallHelperMsi.OpenResult Handle(uint error) {
            uint handle=next++; Open.Add(handle);
            return new VpnInstallHelperMsi.OpenResult(error,handle);
        }
        public VpnInstallHelperMsi.OpenResult OpenReadOnly(string path) { Calls.Add("read-only:"+path); return Handle(OpenError); }
        public VpnInstallHelperMsi.OpenResult OpenProperty(uint database,VpnInstallHelperMsi.Property selected) {
            Calls.Add("property:"+selected); property=selected; Fetches=0; return Handle(0);
        }
        public uint Execute(uint view) { Calls.Add("execute"); return 0; }
        public VpnInstallHelperMsi.OpenResult Fetch(uint view) {
            Fetches++;
            if (Missing) return new VpnInstallHelperMsi.OpenResult(259,0);
            if (Fetches>1 && !Duplicate) return new VpnInstallHelperMsi.OpenResult(259,0);
            return Handle(0);
        }
        public uint FieldCount(uint record) { return Fields; }
        public uint ReadString(uint record,StringBuilder value,ref uint capacity) {
            string text=property==VpnInstallHelperMsi.Property.ProductName ? Product : Upgrade;
            uint original=capacity; capacity=(uint)text.Length;
            if (text.Length>=original) return 234;
            value.Append(text); return 0;
        }
        public uint Close(uint handle) {
            Calls.Add("close:"+handle);
            if (CloseFailures-- > 0) return 6;
            Require(Open.Remove(handle),"Unknown or duplicate native close"); return 0;
        }
        public uint SetSilentUi() { Calls.Add("silent-ui"); return UiResult; }
        public uint InstallPerUser(string path) {
            Calls.Add("per-user:"+path); Installs++;
            Require(Open.Count==0,"MSI database still open at modifying call");
            if (ThrowInstall) throw new IOException("fixture lost native return");
            return Result;
        }
    }

    static void Require(bool value,string message) { if (!value) throw new Exception(message); }
    static void Reject(Action action) {
        try { action(); } catch (Exception error) {
            if (error is IOException || error is UnauthorizedAccessException || error is Win32Exception || error is InvalidOperationException) return;
            throw;
        }
        throw new Exception("Expected fixed MSI admission failure");
    }
    static VpnInstallHelperMsi.Prepared Prepare(Input input,Native native) { return VpnInstallHelperMsi.Prepared.Prepare(input,native); }
    static void RejectedPackage(Native native) {
        Input input=new Input(); Reject(delegate { Prepare(input,native); });
        Require(native.Installs==0 && native.Open.Count==0 && input.Closed,"Rejected package leaked authority/resources or installed");
    }

    public static string[] Run() {
        List<string> passed=new List<string>();
        foreach (uint exit in new uint[] {0,3010,1603}) {
            Input input=new Input(); Native native=new Native { Result=exit };
            using (VpnInstallHelperMsi.Prepared prepared=Prepare(input,native)) {
                Require(native.Installs==0 && native.Open.Count==0,"Preparation modified MSI or retained database handles");
                Require(prepared.Install()==exit && prepared.NativeExitCode==exit,"Native result changed");
                Require(prepared.InstallAttempted && native.Installs==1,"Native attempt not retained");
                Reject(delegate { prepared.Install(); });
                Require(native.Installs==1,"Repeated installation executed");
            }
            Require(input.Closed,"Successful input was not released");
            passed.Add("exact-native-exit-"+exit);
        }
        RejectedPackage(new Native { Product="different product" }); passed.Add("reject-product");
        RejectedPackage(new Native { Upgrade="{00000000-0000-0000-0000-000000000000}" }); passed.Add("reject-upgrade");
        RejectedPackage(new Native { Upgrade="{{7a5e0a8e-2a7a-4baf-9f2a-5fb2c3529af2}}" }); passed.Add("reject-malformed-upgrade");
        RejectedPackage(new Native { Missing=true }); passed.Add("reject-missing-property");
        RejectedPackage(new Native { Duplicate=true }); passed.Add("reject-duplicate-property");
        RejectedPackage(new Native { Product=new String('x',200) }); passed.Add("bound-property-bytes");
        RejectedPackage(new Native { Fields=2 }); passed.Add("reject-extra-field");
        RejectedPackage(new Native { OpenError=1620 }); passed.Add("close-handle-returned-with-error");
        {
            Input input=new Input { RejectAt=1 }; Native native=new Native();
            Reject(delegate { Prepare(input,native); });
            Require(native.Calls.Count==0 && input.Closed,"Denied input reached native MSI"); passed.Add("initial-admission-before-msi");
        }
        {
            Input input=new Input(); Native native=new Native();
            using (VpnInstallHelperMsi.Prepared prepared=Prepare(input,native)) {
                input.RejectAt=input.Checks+1;
                Reject(delegate { prepared.Install(); }); Reject(delegate { prepared.Install(); });
                Require(native.Installs==0 && !prepared.InstallAttempted,"Failed recheck started MSI");
            }
            passed.Add("recheck-failure-consumes-readiness");
        }
        {
            Input input=new Input(); Native native=new Native();
            using (VpnInstallHelperMsi.Prepared prepared=Prepare(input,native)) {
                input.Path="C:\\other\\package.msi";
                Reject(delegate { prepared.Install(); });
                Require(native.Installs==0,"Changed package path reached MSI");
            }
            passed.Add("no-input-retarget");
        }
        {
            Input input=new Input(); Native native=new Native { UiResult=0 };
            using (VpnInstallHelperMsi.Prepared prepared=Prepare(input,native)) {
                Reject(delegate { prepared.Install(); });
                Require(native.Installs==0 && !prepared.InstallAttempted,"Invalid UI state reached MSI");
            }
            passed.Add("ui-configuration-before-attempt");
        }
        {
            Input input=new Input(); Native native=new Native { ThrowInstall=true };
            using (VpnInstallHelperMsi.Prepared prepared=Prepare(input,native)) {
                Reject(delegate { prepared.Install(); }); Reject(delegate { prepared.Install(); });
                Require(prepared.InstallAttempted && !prepared.NativeExitCode.HasValue && native.Installs==1,"Lost native return was replayed or terminalized");
            }
            passed.Add("lost-native-return-no-replay");
        }
        {
            Input input=new Input(); Native native=new Native { CloseFailures=2 };
            VpnInstallHelperMsi.RetainedFailure pending=null;
            try { Prepare(input,native); } catch (VpnInstallHelperMsi.RetainedFailure error) { pending=error; }
            Require(pending!=null && native.Open.Count>0 && !input.Closed,"Unclosed MSI ownership was discarded");
            Reject(delegate { pending.Pending.Install(); });
            pending.Pending.Dispose();
            Require(native.Open.Count==0 && input.Closed && native.Installs==0,"Exact MSI close retry failed");
            passed.Add("failed-native-close-retains-all-inputs");
        }
        {
            Input input=new Input { CloseFailures=1 }; Native native=new Native { Result=3010 };
            VpnInstallHelperMsi.Prepared prepared=Prepare(input,native);
            Require(prepared.Install()==3010,"Native reboot-success lost");
            VpnInstallHelperMsi.RetainedFailure pending=null;
            try { prepared.Dispose(); } catch (VpnInstallHelperMsi.RetainedFailure error) { pending=error; }
            Require(pending!=null && pending.Pending==prepared && pending.InstallAttempted && pending.NativeExitCode==3010,
                "Cleanup failure erased known native result or ownership");
            pending.Pending.Dispose();
            Require(input.Closed && prepared.NativeExitCode==3010 && native.Installs==1,"Cleanup retry changed native outcome");
            passed.Add("known-exit-survives-input-close-failure");
        }
        {
            Input input=new Input(); Native native=new Native();
            using (VpnInstallHelperMsi.Prepared prepared=Prepare(input,native)) {
                Require(prepared.ToString().IndexOf(input.Path,StringComparison.Ordinal)<0,"Private package path exposed");
            }
            passed.Add("redacted-package-context");
        }
        return passed.ToArray();
    }

    sealed class PinnedFixture : VpnInstallHelperMsi.AdmittedInput {
        readonly string path;
        readonly FileStream stream;
        readonly byte[] digest;
        internal PinnedFixture(string file) {
            path=file; stream=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read);
            digest=Hash();
        }
        byte[] Hash() { stream.Position=0; using (SHA256 hash=SHA256.Create()) { return hash.ComputeHash(stream); } }
        public string PackagePath { get { return path; } }
        public void Recheck() { Require(Convert.ToBase64String(Hash())==Convert.ToBase64String(digest),"Pinned fixture bytes changed"); }
        public void Dispose() { stream.Dispose(); }
    }

    // Real System32 MSI read-only calls; no Install(), token admission, UAC or product effects.
    public static string[] NativeReadOnly(string directory) {
        List<string> passed=new List<string>();
        foreach (bool valid in new bool[] {true,false}) {
            string path=Path.Combine(directory,valid ? "valid.msi" : "other.msi");
            Require(!File.Exists(path),"Fixture destination exists");
            CreateDatabase(path,valid ? "vpn-control" : "other product");
            byte[] before=File.ReadAllBytes(path);
            long modified=File.GetLastWriteTimeUtc(path).Ticks;
            try {
                if (valid) {
                    using (VpnInstallHelperMsi.Prepared prepared=VpnInstallHelperMsi.Prepared.Prepare(new PinnedFixture(path))) {
                        Require(!prepared.InstallAttempted && !prepared.NativeExitCode.HasValue,"Read-only validation started MSI");
                    }
                } else Reject(delegate { VpnInstallHelperMsi.Prepared.Prepare(new PinnedFixture(path)); });
                Require(Convert.ToBase64String(File.ReadAllBytes(path))==Convert.ToBase64String(before) &&
                    File.GetLastWriteTimeUtc(path).Ticks==modified,"Native read-only validation changed the database");
                using (new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None)) { }
                passed.Add(valid ? "native-read-only-identity" : "native-read-only-rejection");
            } finally { File.Delete(path); }
        }
        return passed.ToArray();
    }

    static void Check(uint value) { if (value!=0) throw new Win32Exception((int)value); }
    static void CreateDatabase(string path,string product) {
        uint database;
        Check(MsiOpenDatabaseW(path,new IntPtr(3),out database)); // CREATE, inert test fixture only.
        try {
            Query(database,"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(255) LOCALIZABLE PRIMARY KEY `Property`)");
            Query(database,"INSERT INTO `Property` (`Property`,`Value`) VALUES ('ProductName','"+product+"')");
            Query(database,"INSERT INTO `Property` (`Property`,`Value`) VALUES ('UpgradeCode','{7a5e0a8e-2a7a-4baf-9f2a-5fb2c3529af2}')");
            Check(MsiDatabaseCommit(database));
        } finally { Check(MsiCloseHandle(database)); }
    }
    static void Query(uint database,string sql) {
        uint view; Check(MsiDatabaseOpenViewW(database,sql,out view));
        try { Check(MsiViewExecute(view,0)); } finally { Check(MsiCloseHandle(view)); }
    }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)] static extern uint MsiOpenDatabaseW(string path,IntPtr mode,out uint database);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)] static extern uint MsiDatabaseOpenViewW(uint database,string query,out uint view);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiViewExecute(uint view,uint record);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiDatabaseCommit(uint database);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiCloseHandle(uint handle);
}
