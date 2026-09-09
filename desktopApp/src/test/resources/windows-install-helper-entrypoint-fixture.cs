using System;
using System.IO;

public static class InstallerEntrypointFixtures {
    sealed class Factory : VpnInstallHelperSessionFactory {
        internal int Calls;
        internal VpnInstallHelperProtocol.Invocation Invocation;
        public int Run(VpnInstallHelperProtocol.Invocation invocation) {
            Calls++;
            Invocation=invocation;
            return 0;
        }
    }

    public static string Run() {
        const string Job="00000000-0000-0000-0000-00000000000a";
        Factory factory=new Factory();
        if (VpnInstallHelper.Run(new string[] { "install-user",Job,"912","134332558909139351" },factory)!=0 ||
            factory.Calls!=1 || factory.Invocation==null || factory.Invocation.Operation!=VpnInstallHelperProtocol.Role.OriginalUser ||
            factory.Invocation.JobId!=Job || factory.Invocation.OwnerPid!=912 || factory.Invocation.OwnerCreationFileTime!=134332558909139351)
            throw new InvalidOperationException("Canonical role was not dispatched through the supplied factory");
        foreach(string[] invalid in new string[][] {
            new string[] { "install-user",Job,"0","134332558909139351" },
            new string[] { "install-user",Job,"912","01" },
            new string[] { "-Command",Job,"912","134332558909139351" },
            new string[] { "install-user",Job,"912","134332558909139351","C:\\x" },
        }) {
            bool rejected=false;
            try { VpnInstallHelper.Run(invalid,factory); } catch (IOException) { rejected=true; }
            if (!rejected || factory.Calls!=1) throw new InvalidOperationException("Invalid invocation reached factory");
        }
        return "FIXED_INSTALL_ENTRYPOINT_OK";
    }
}
