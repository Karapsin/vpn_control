using System;
using System.Security.Principal;

public static class InstallerOriginalUserLaunchFixtures {
    static readonly string Job="00000000-0000-0000-0000-00000000000a";
    // This has no shell, process-launch, privilege, or filesystem side effect.
    // Run it before the opt-in interactive fixture so TokenElevation's exact
    // GetTokenInformation buffer contract is routine Windows CI coverage.
    public static string ProbeCurrentTokenScalars() {
        VpnInstallOriginalUserLaunch.CurrentTokenElevated();
        // The ordinary compiler runner has no interactive shell. Exercise the
        // bounded policy separately from the OS-only token launch: only a 1314
        // failure for the exact non-elevated shell SID/session may use the
        // current-token path.
        if (!VpnInstallOriginalUserLaunch.CurrentTokenFallbackPermitted(1314,7,"S-1-5-21-1",false,7,"S-1-5-21-1") ||
            VpnInstallOriginalUserLaunch.CurrentTokenFallbackPermitted(5,7,"S-1-5-21-1",false,7,"S-1-5-21-1") ||
            VpnInstallOriginalUserLaunch.CurrentTokenFallbackPermitted(1314,8,"S-1-5-21-1",false,7,"S-1-5-21-1") ||
            VpnInstallOriginalUserLaunch.CurrentTokenFallbackPermitted(1314,7,"S-1-5-21-2",false,7,"S-1-5-21-1") ||
            VpnInstallOriginalUserLaunch.CurrentTokenFallbackPermitted(1314,7,"S-1-5-21-1",true,7,"S-1-5-21-1"))
            throw new Exception("Original-user current-token fallback was not bounded");
        return "ORIGINAL_USER_CURRENT_TOKEN_SCALARS_OK";
    }
    public static string Run() {
        foreach(string[] invalid in new string[][] {
            new string[] { "-Command",Job,"1","1" }, new string[] { "install-user",Job,"01","1" },
            new string[] { "install-user",Job,"1","0" }, new string[] { "install-user",Job,"1","1","x" },
        }) ExpectReject(invalid);
        using (VpnInstallOriginalUserLaunch original=VpnInstallOriginalUserLaunch.Capture()) {
            string expected=Environment.GetEnvironmentVariable("VPN_CONTROL_TEST_ORIGINAL_INTERACTIVE_SID");
            if (!String.IsNullOrEmpty(expected) && original.PrincipalSid!=expected) throw new Exception("Unexpected interactive SID");
            if (Environment.GetEnvironmentVariable("VPN_CONTROL_TEST_EXPECT_ELEVATED_OWNER")=="1" && !VpnInstallOriginalUserLaunch.CurrentTokenElevated())
                throw new Exception("Fixture did not run as an elevated owner");
            bool different=Environment.GetEnvironmentVariable("VPN_CONTROL_TEST_EXPECT_DIFFERENT_APPROVER")=="1";
            using (WindowsIdentity current=WindowsIdentity.GetCurrent()) {
                if (different && (current.User==null || current.User.Value==original.PrincipalSid))
                    throw new Exception("Fixture did not run as a distinct approving account");
            }
            ExpectOriginalUserOnly(original);
            using (VpnInstallOriginalUserLaunch.StartedHelper child=original.StartSameHelper(new string[] { "install-user",Job,"1","1" })) {
                VpnInstallOriginalUserLaunch.ChildIdentity identity=child.Observe();
                if (identity.ProcessId==0 || identity.CreationFileTime<=0 || identity.Elevated ||
                    identity.Session!=original.ShellSession || identity.Sid!=original.PrincipalSid || !child.Wait(15000))
                    throw new Exception("Original interactive helper identity mismatch");
            }
            // Force the observed 1314 result through the production orchestration
            // branch. This must still launch the pinned helper under the verified
            // current token; it is not a mock child or a source-only assertion.
            bool fallbackAllowed;
            using (WindowsIdentity current=WindowsIdentity.GetCurrent()) {
                fallbackAllowed=VpnInstallOriginalUserLaunch.CurrentTokenFallbackPermitted(1314,
                    (uint)System.Diagnostics.Process.GetCurrentProcess().SessionId,current.User?.Value,
                    VpnInstallOriginalUserLaunch.CurrentTokenElevated(),original.ShellSession,original.PrincipalSid);
            }
            if (!fallbackAllowed) ExpectPrivilegeFailureFallbackReject(original,1314);
            else using (VpnInstallOriginalUserLaunch.StartedHelper child=original.StartSameHelperForPrivilegeFailureFixture(new string[] { "install-user",Job,"1","1" },1314)) {
                VpnInstallOriginalUserLaunch.ChildIdentity identity=child.Observe();
                if (identity.ProcessId==0 || identity.CreationFileTime<=0 || identity.Elevated ||
                    identity.Session!=original.ShellSession || identity.Sid!=original.PrincipalSid || !child.Wait(15000))
                    throw new Exception("Original interactive fallback helper identity mismatch");
            }
            ExpectPrivilegeFailureFallbackReject(original);

        }
        return "ORIGINAL_INTERACTIVE_USER_LAUNCH_OK";
    }
    static void ExpectReject(string[] arguments) {
        try { VpnInstallOriginalUserLaunch.ValidateInvocation(arguments); }
        catch (Exception) { return; }
        throw new Exception("Invalid helper invocation accepted");
    }
    static void ExpectOriginalUserOnly(VpnInstallOriginalUserLaunch original) {
        try { original.StartSameHelper(new string[] { "install-coordinator",Job,"1","1" }); }
        catch (Exception) { return; }
        throw new Exception("Original-user token launcher accepted coordinator role");
    }
    static void ExpectPrivilegeFailureFallbackReject(VpnInstallOriginalUserLaunch original,int nativeError=5) {
        try { original.StartSameHelperForPrivilegeFailureFixture(new string[] { "install-user",Job,"1","1" },nativeError); }
        catch (Exception) { return; }
        throw new Exception("Original-user fallback accepted a non-privilege launch failure");
    }
}
