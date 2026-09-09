// Fixed NativeAOT entrypoint. This executable deliberately exposes no script,
// assembly, command, package, or arbitrary path execution surface.
using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;

// Applies to the linked application P/Invokes, including the lazily resolved shell32 call.
// The native linker separately restricts imports that run before managed Main.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

public static class VpnInstallHelper {
    const string ValidateOnly = "validate-only";

    public static int Main(string[] arguments) {
        try {
            return Run(arguments,new VpnInstallHelperNativeSessions());
        } catch (Exception error) when (error is ArgumentException || error is InvalidOperationException ||
            error is IOException || error is Win32Exception || error is UnauthorizedAccessException) {
            Console.Error.WriteLine("VPN_INSTALL_HELPER_VALIDATE_ONLY_FAILED");
            return 2;
        }
    }

    // Same-assembly seam: Main supplies only the fixed native factory. Tests compile an
    // inert factory into this assembly; argv and environment never select a factory.
    internal static int Run(string[] arguments,VpnInstallHelperSessionFactory factory) {
        if (arguments != null && arguments.Length == 1 && String.Equals(arguments[0],ValidateOnly,StringComparison.Ordinal)) {
            ValidateNativeBoundary();
            Console.WriteLine("VPN_INSTALL_HELPER_VALIDATE_ONLY_OK");
            return 0;
        }
        if (factory==null) throw new ArgumentNullException("factory");
        // The protocol accepts only a fixed role and canonical private identity tuple.
        // The factory is fixed by Main; tests can supply an inert same-assembly factory.
        return factory.Run(VpnInstallHelperProtocol.ParseInvocation(arguments));
    }

    // This is the only currently enabled role. It gives the native build a
    // deterministic, non-mutating probe while installer role wiring is under
    // security review. A future user/coordinator implementation must retain
    // the request, receipt, gate, and original-token contracts; it must not
    // turn unreviewed arguments into paths or commands.
    static void ValidateNativeBoundary() {
        string programData = VpnInstallNative.ProgramData();
        if (String.IsNullOrEmpty(programData) || !programData.EndsWith("ProgramData", StringComparison.OrdinalIgnoreCase))
            throw new IOException("ProgramData identity unavailable");
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) {
            if (identity.User == null || String.IsNullOrEmpty(identity.User.Value))
                throw new InvalidOperationException("Current principal unavailable");
        }
    }
}
