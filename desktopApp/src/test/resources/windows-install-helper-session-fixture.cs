using System;
using System.Diagnostics;
using System.IO;
using System.ComponentModel;
using System.Security.Principal;
using System.Security.AccessControl;

public static class InstallerSessionAdmissionFixtures {
    sealed class CloseOnce : VpnInstallNative.IProcessPinCloseNative {
        internal int Calls;
        public bool Close(IntPtr handle) { Calls++; return Calls!=1; }
    }

    public static string FailedOwnerCloseRetainsExactHandleForRetry() {
        CloseOnce closer=new CloseOnce();
        VpnInstallNative.ProcessPin pin=new VpnInstallNative.ProcessPin((uint)Process.GetCurrentProcess().Id,closer);
        bool closeFailed=false;
        try { pin.Dispose(); } catch (IOException) { closeFailed=true; }
        bool retained=false;
        try { retained=!pin.Exited; } catch (ObjectDisposedException) { retained=false; }
        if (!closeFailed || !retained || closer.Calls!=1) throw new InvalidOperationException("Failed close discarded owner handle");
        pin.Dispose();
        if (closer.Calls!=2) throw new InvalidOperationException("Owner close was not retried");
        return "OWNER_CLOSE_RETRIED";
    }

    sealed class AlwaysFailClose : VpnInstallNative.IProcessPinCloseNative {
        internal int Calls;
        public bool Close(IntPtr handle) { Calls++; return false; }
    }

    public static string ConstructionFailureKeepsOriginalFailureAndRecordsUncertainCleanup() {
        AlwaysFailClose closer=new AlwaysFailClose();
        try {
            new VpnInstallNative.ProcessPin((uint)Process.GetCurrentProcess().Id,closer,
                delegate { throw new InvalidOperationException("admission failure"); });
        } catch (Exception error) {
            if (!(error is InvalidOperationException) || error.Message!="admission failure" || closer.Calls!=1)
                throw new InvalidOperationException("Construction failure was masked");
            if (!error.Data.Contains("vpn.install.processPin.constructionCleanupUncertain"))
                throw new InvalidOperationException("Construction cleanup uncertainty was discarded");
            return "CONSTRUCTION_FAILURE_RETAINED";
        }
        throw new InvalidOperationException("Construction failure unexpectedly completed");
    }

    public static string MissingJobInputReleasesPinnedAncestor() {
        uint pid=(uint)Process.GetCurrentProcess().Id;
        long creation;
        using (VpnInstallNative.ProcessImagePin pin=new VpnInstallNative.ProcessImagePin(pid)) {
            creation=pin.Observe().CreationFileTime;
        }
        bool originalUser;
        SecurityIdentifier principal;
        using (WindowsIdentity caller=WindowsIdentity.GetCurrent()) {
            originalUser=!new WindowsPrincipal(caller).IsInRole(WindowsBuiltInRole.Administrator);
            principal=caller.User;
        }
        // SYSTEM has no interactive user profile: its LocalAppData is below Windows,
        // whose TrustedInstaller mutation grants are outside owner-input policy.
        // The test seam can use a private ProgramData subtree for that test identity.
        string profileLocal=Environment.GetFolderPath(principal.IsWellKnown(WellKnownSidType.LocalSystemSid)
            ? Environment.SpecialFolder.CommonApplicationData : Environment.SpecialFolder.LocalApplicationData);
        if (String.IsNullOrEmpty(profileLocal)) throw new InvalidOperationException("Fixture requires the caller LocalAppData");
        string local=Path.Combine(profileLocal,"VpnInstallerInputLeak-"+Guid.NewGuid().ToString("N"));
        string inputRoot=Path.Combine(local,"vpn-control-install-inputs");
        string moved=inputRoot+"-moved";
        Directory.CreateDirectory(local);
        // Admission validates every ancestor, so a private leaf below shared SYSTEM
        // temp is insufficient. Keep our own subtree private under admitted ancestry.
        DirectorySecurity security=new DirectorySecurity();
        security.SetAccessRuleProtection(true,false);
        security.SetOwner(principal);
        foreach (SecurityIdentifier allowed in new[] {principal,new SecurityIdentifier("S-1-5-18"),new SecurityIdentifier("S-1-5-32-544")})
            security.AddAccessRule(new FileSystemAccessRule(allowed,FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        new DirectoryInfo(local).SetAccessControl(security);
        Directory.CreateDirectory(inputRoot);
        try {
            VpnInstallHelperProtocol.Invocation invocation=new VpnInstallHelperProtocol.Invocation(
                originalUser?VpnInstallHelperProtocol.Role.OriginalUser:VpnInstallHelperProtocol.Role.Coordinator,
                "00000000-0000-0000-0000-00000000000c",pid,creation);
            Exception failure=null;
            bool lookupReached=false;
            try {
                OwnerInputAdmission.Open(invocation,originalUser,delegate { lookupReached=true; return local; });
            } catch (Exception error) { failure=error; }
            if (!lookupReached) throw new InvalidOperationException("Fixture never reached input admission");
            Win32Exception missing=failure as Win32Exception;
            if (missing==null || (missing.NativeErrorCode!=2 && missing.NativeErrorCode!=3))
                throw new InvalidOperationException("Fixture did not reach the missing job child",failure);
            Directory.Move(inputRoot,moved);
            Directory.Delete(moved);
            return "MISSING_INPUT_ANCESTOR_RELEASED";
        } finally {
            if (Directory.Exists(moved)) Directory.Delete(moved,true);
            if (Directory.Exists(inputRoot)) Directory.Delete(inputRoot,true);
            if (Directory.Exists(local)) Directory.Delete(local,true);
        }
    }

    public static string WrongOwnerGenerationIsRejectedBeforeAnyInputLookup() {
        uint pid=(uint)Process.GetCurrentProcess().Id;
        long creation;
        using (VpnInstallNative.ProcessImagePin pin=new VpnInstallNative.ProcessImagePin(pid)) {
            creation=pin.Observe().CreationFileTime;
        }
        VpnInstallHelperProtocol.Invocation invocation=new VpnInstallHelperProtocol.Invocation(
            VpnInstallHelperProtocol.Role.OriginalUser,
            "00000000-0000-0000-0000-00000000000b",pid,checked(creation+1));
        try {
            new VpnInstallHelperNativeSessions().Run(invocation);
        } catch (IOException error) {
            if (error.Message=="CONFLICT") return "OWNER_GENERATION_REJECTED";
            throw;
        }
        throw new InvalidOperationException("Wrong owner generation reached a native session");
    }
}
