// Fixed Windows Installer adapter. The enabled helper entrypoint does not call this yet.
// A native original-user session must supply the retained token, package and ancestry
// proof before this adapter can be bound to install-user. Parsing a request is not proof.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

internal static class VpnInstallHelperMsi {
    internal enum Property { ProductName, UpgradeCode }

    // Consumed by Prepare, including on failure. This same-assembly seam is not an
    // argv/record authority surface; its production implementation must recheck the
    // exact original-user process token and retained no-write/no-delete package pins.
    internal interface AdmittedInput : IDisposable {
        string PackagePath { get; }
        void Recheck();
    }

    internal struct OpenResult {
        internal readonly uint Code, Handle;
        internal OpenResult(uint code,uint handle) { Code=code; Handle=handle; }
    }

    // Fixed operations only. Neither the SQL, properties, UI mode nor a native
    // executable can be provided by an external caller or request record.
    internal interface Native {
        OpenResult OpenReadOnly(string package);
        OpenResult OpenProperty(uint database,Property property);
        uint Execute(uint view);
        OpenResult Fetch(uint view);
        uint FieldCount(uint record);
        uint ReadString(uint record,StringBuilder value,ref uint capacity);
        uint Close(uint handle);
        uint SetSilentUi();
        uint InstallPerUser(string package);
    }

    internal sealed class RetainedFailure : IOException {
        internal readonly Prepared Pending;
        internal bool InstallAttempted { get { return Pending.InstallAttempted; } }
        internal uint? NativeExitCode { get { return Pending.NativeExitCode; } }
        internal RetainedFailure(Prepared pending,Exception cause) : base("Installer resource cleanup pending",cause) {
            Pending=pending;
        }
        public override string ToString() { return "Installer resource cleanup pending (private context)"; }
    }

    internal sealed class Prepared : IDisposable {
        AdmittedInput input;
        readonly Native native;
        // A database, a view and at most two fetched records. Preallocate before
        // acquiring any native handle, including a handle returned alongside error.
        readonly uint[] handles=new uint[4];
        int count;
        string package;
        bool ready, attempted, closed;
        uint? nativeExit;
        internal bool InstallAttempted { get { return attempted; } }
        internal uint? NativeExitCode { get { return nativeExit; } }

        Prepared(AdmittedInput admitted,Native adapter) { input=admitted; native=adapter; }

        internal static Prepared Prepare(AdmittedInput admitted) { return Prepare(admitted,new SystemMsi()); }

        internal static Prepared Prepare(AdmittedInput admitted,Native adapter) {
            if (admitted==null || adapter==null) throw new ArgumentNullException();
            Prepared result=new Prepared(admitted,adapter);
            try { result.Validate(); return result; }
            catch (Exception validation) {
                try { result.Dispose(); }
                catch (RetainedFailure cleanup) {
                    throw new RetainedFailure(result,new AggregateException(validation,cleanup.InnerException));
                }
                throw;
            }
        }

        void Recheck() {
            if (input==null) throw new ObjectDisposedException("Installer package");
            input.Recheck();
            if (!String.Equals(package,input.PackagePath,StringComparison.Ordinal)) throw new IOException("CONFLICT");
        }

        void Validate() {
            input.Recheck();
            package=input.PackagePath;
            VpnInstallHelperProtocol.LocalPath(package);
            if (!package.EndsWith(".msi",StringComparison.OrdinalIgnoreCase)) throw new IOException("INVALID_ARGUMENT");
            uint database=Acquire(native.OpenReadOnly(package));
            if (ReadProperty(database,Property.ProductName)!="vpn-control") throw new IOException("INVALID_ARGUMENT");
            string upgrade=ReadProperty(database,Property.UpgradeCode);
            Guid parsed;
            if ((!Guid.TryParseExact(upgrade,"B",out parsed) && !Guid.TryParseExact(upgrade,"D",out parsed)) ||
                parsed!=new Guid("7a5e0a8e-2a7a-4baf-9f2a-5fb2c3529af2")) throw new IOException("INVALID_ARGUMENT");
            // No MSI database/view/record is kept open across the modifying API.
            CloseTo(0);
            Recheck();
            ready=true;
        }

        uint Acquire(OpenResult result) {
            if (result.Handle!=0) {
                if (count==handles.Length) throw new InvalidOperationException("MSI handle bound exceeded");
                handles[count++]=result.Handle;
            }
            Check(result.Code);
            if (result.Handle==0) throw new IOException("Installer handle unavailable");
            return result.Handle;
        }

        string ReadProperty(uint database,Property property) {
            int retained=count;
            uint view=Acquire(native.OpenProperty(database,property));
            Check(native.Execute(view));
            uint record=Acquire(native.Fetch(view));
            if (native.FieldCount(record)!=1) throw new IOException("INVALID_ARGUMENT");
            StringBuilder value=new StringBuilder(128);
            uint length=128;
            uint code=native.ReadString(record,value,ref length);
            if (code==234 || length==0 || length>=128) throw new IOException("INVALID_ARGUMENT");
            Check(code);
            string result=value.ToString();
            if (result.Length!=length || result.IndexOf('\0')>=0) throw new IOException("INVALID_ARGUMENT");
            OpenResult extra=native.Fetch(view);
            // Even a malformed/error return cannot discard a native handle.
            if (extra.Handle!=0) {
                if (count==handles.Length) throw new InvalidOperationException("MSI handle bound exceeded");
                handles[count++]=extra.Handle;
            }
            if (extra.Code!=259 || extra.Handle!=0) throw new IOException("INVALID_ARGUMENT");
            CloseTo(retained);
            return result;
        }

        internal uint Install() {
            if (!ready || attempted || closed || count!=0) throw new InvalidOperationException("Installer package is not ready");
            // Any failed recheck consumes readiness; callers cannot silently retry
            // the prepared object after changed token/package admission.
            ready=false;
            Recheck();
            if (native.SetSilentUi()==0) throw new IOException("Installer UI configuration failed");
            Recheck();
            attempted=true;
            uint result=native.InstallPerUser(package);
            nativeExit=result;
            // This is the final native operation. No finally/cleanup can obscure
            // the established 0, 3010, 1603, or other Windows Installer result.
            return result;
        }

        void CloseTo(int remaining) {
            while (count>remaining) {
                Check(native.Close(handles[count-1]));
                handles[--count]=0;
            }
        }

        public void Dispose() {
            if (closed) return;
            ready=false;
            try {
                CloseTo(0);
                if (input!=null) { input.Dispose(); input=null; }
                closed=true;
            } catch (Exception error) {
                // Keep this object, every unclosed native handle and the original
                // input lease available for an explicit close retry.
                throw new RetainedFailure(this,error);
            }
        }

        public override string ToString() { return "Prepared installer package (private identity)"; }
    }

    static void Check(uint error) { if (error!=0) throw new Win32Exception(unchecked((int)error)); }

    sealed class SystemMsi : Native {
        const string InstallProperties="REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable ALLUSERS=2 MSIINSTALLPERUSER=1";
        public OpenResult OpenReadOnly(string package) {
            uint handle;
            uint result=MsiOpenDatabaseW(package,IntPtr.Zero,out handle); // MSIDBOPEN_READONLY
            return new OpenResult(result,handle);
        }
        public OpenResult OpenProperty(uint database,Property property) {
            string query;
            if (property==Property.ProductName) query="SELECT `Value` FROM `Property` WHERE `Property`='ProductName'";
            else if (property==Property.UpgradeCode) query="SELECT `Value` FROM `Property` WHERE `Property`='UpgradeCode'";
            else throw new ArgumentOutOfRangeException("property");
            uint handle;
            uint result=MsiDatabaseOpenViewW(database,query,out handle);
            return new OpenResult(result,handle);
        }
        public uint Execute(uint view) { return MsiViewExecute(view,0); }
        public OpenResult Fetch(uint view) {
            uint handle;
            uint result=MsiViewFetch(view,out handle);
            return new OpenResult(result,handle);
        }
        public uint FieldCount(uint record) { return MsiRecordGetFieldCount(record); }
        public uint ReadString(uint record,StringBuilder value,ref uint capacity) { return MsiRecordGetStringW(record,1,value,ref capacity); }
        public uint Close(uint handle) { return MsiCloseHandle(handle); }
        public uint SetSilentUi() { return MsiSetInternalUI(2,IntPtr.Zero); } // NONE: no second UAC prompt.
        public uint InstallPerUser(string package) { return MsiInstallProductW(package,InstallProperties); }
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
    static extern uint MsiOpenDatabaseW(string path,IntPtr persistence,out uint handle);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
    static extern uint MsiDatabaseOpenViewW(uint database,string query,out uint view);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiViewExecute(uint view,uint record);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiViewFetch(uint view,out uint record);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiRecordGetFieldCount(uint record);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
    static extern uint MsiRecordGetStringW(uint record,uint field,StringBuilder value,ref uint capacity);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiCloseHandle(uint handle);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiSetInternalUI(uint level,IntPtr parent);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("msi.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
    static extern uint MsiInstallProductW(string package,string properties);
}
