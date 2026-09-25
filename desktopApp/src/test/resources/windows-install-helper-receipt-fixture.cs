using System;

public static class VpnInstallHelperReceiptFixture {
    public static string[] EncodeAll(string jobId) {
        Array phases=Enum.GetValues(typeof(VpnInstallHelperRoles.Phase));
        string[] encoded=new string[phases.Length];
        for (int index=0;index<phases.Length;index++) {
            VpnInstallHelperRoles.Phase phase=(VpnInstallHelperRoles.Phase)phases.GetValue(index);
            string code=phase==VpnInstallHelperRoles.Phase.Cancelled ? "CANCELLED" :
                phase==VpnInstallHelperRoles.Phase.Failed ? "RUNTIME_FAILED" : "OK";
            byte[] bytes=VpnInstallHelperProtocol.EncodeReceipt(
                new VpnInstallHelperRoles.Receipt(jobId,index,phase,code));
            encoded[index]=Convert.ToBase64String(bytes);
        }
        return encoded;
    }
}
