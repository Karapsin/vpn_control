// Data-only fixed helper protocol. Parsing a record never establishes native process or file authority.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

public static class VpnInstallHelperProtocol {
    public enum Role { OriginalUser, Coordinator }

    public sealed class Invocation {
        public readonly Role Operation;
        public readonly string JobId;
        public readonly uint OwnerPid;
        public readonly long OwnerCreationFileTime;
        internal Invocation(Role role,string job,uint pid,long created) {
            Operation=role; JobId=job; OwnerPid=pid; OwnerCreationFileTime=created;
        }
        public override string ToString() { return "Install helper invocation (private identity)"; }
    }

    public static Invocation ParseInvocation(string[] arguments) {
        if (arguments==null || arguments.Length!=4) throw Invalid();
        Role role;
        if (arguments[0]=="install-user") role=Role.OriginalUser;
        else if (arguments[0]=="install-coordinator") role=Role.Coordinator;
        else throw Invalid();
        Job(arguments[1]);
        long pid=Number(arguments[2]), created=Number(arguments[3]);
        if (pid<=0 || pid>UInt32.MaxValue || created<=0) throw Invalid();
        return new Invocation(role,arguments[1],(uint)pid,created);
    }

    public sealed class WorkerReady {
        public readonly string JobId, PrincipalSid, HelperSha256;
        public readonly uint Pid;
        public readonly long CreationFileTime;
        internal WorkerReady(string job,uint pid,long created,string principal,string digest) {
            JobId=job; Pid=pid; CreationFileTime=created; PrincipalSid=principal; HelperSha256=digest;
        }
        public override string ToString() { return "Install worker readiness (private identity)"; }
    }

    public static WorkerReady ParseWorkerReady(byte[] bytes) {
        Dictionary<string,object> record=Record(bytes,4096);
        Fields(record,"version","jobId","pid","creationFileTime","principalSid","helperSha256");
        if (Integer(record,"version")!=2) throw Invalid();
        string job=Text(record,"jobId"), principal=Text(record,"principalSid"), digest=Text(record,"helperSha256");
        long pid=Integer(record,"pid"), created=Integer(record,"creationFileTime");
        Job(job); Sid(principal); Digest(digest);
        if (pid<=0 || pid>UInt32.MaxValue || created<=0) throw Invalid();
        return new WorkerReady(job,(uint)pid,created,principal,digest);
    }

    public static byte[] EncodeWorkerReady(string job,uint pid,long created,string principal,string digest) {
        Job(job); Sid(principal); Digest(digest);
        if (pid==0 || created<=0) throw Invalid();
        // Every text field has a canonical ASCII grammar. Arbitrary paths or JSON cannot enter this record.
        string json="{\"version\":2,\"jobId\":\""+job+"\",\"pid\":"+pid.ToString(CultureInfo.InvariantCulture)+
            ",\"creationFileTime\":"+created.ToString(CultureInfo.InvariantCulture)+",\"principalSid\":\""+principal+
            "\",\"helperSha256\":\""+digest+"\"}";
        return new UTF8Encoding(false,true).GetBytes(json);
    }

    public sealed class Request {
        public readonly string JobId, PrincipalSid, Launcher, PackageFile, PackageSha256, StateDirectory;
        public readonly uint OwnerPid;
        public readonly long OwnerStartedAtEpochMillis, PackageSize;
        public readonly uint? FrontendPid;
        public readonly long? FrontendStartedAtEpochMillis;
        internal Request(Dictionary<string,object> record) {
            JobId=Text(record,"jobId"); PrincipalSid=Text(record,"principalSid");
            Launcher=Text(record,"launcher"); PackageFile=Text(record,"packageFile");
            PackageSha256=Text(record,"packageSha256"); StateDirectory=Text(record,"stateDirectory");
            long pid=Integer(record,"ownerPid");
            OwnerStartedAtEpochMillis=Integer(record,"ownerStartedAtEpochMillis"); PackageSize=Integer(record,"packageSize");
            if (pid<=0 || pid>UInt32.MaxValue || OwnerStartedAtEpochMillis<=0 || PackageSize<=0) throw Invalid();
            OwnerPid=(uint)pid;
            Job(JobId); Sid(PrincipalSid); Digest(PackageSha256);
            LocalPath(Launcher); LocalPath(PackageFile); LocalPath(StateDirectory);
            if (!String.Equals(Leaf(Launcher),"vpn-control.exe",StringComparison.OrdinalIgnoreCase) ||
                !PackageFile.EndsWith(".msi",StringComparison.OrdinalIgnoreCase)) throw Invalid();
            if (record.ContainsKey("frontendPid")) {
                long frontend=Integer(record,"frontendPid"), started=Integer(record,"frontendStartedAtEpochMillis");
                if (frontend<=0 || frontend>UInt32.MaxValue || started<=0) throw Invalid();
                FrontendPid=(uint)frontend; FrontendStartedAtEpochMillis=started;
            }
        }
        public override string ToString() { return "Install request (private metadata)"; }
    }

    public static Request ParseRequest(byte[] bytes) {
        Dictionary<string,object> record=Record(bytes,65536);
        string[] required={"version","jobId","principalSid","ownerPid","ownerStartedAtEpochMillis","launcher",
            "packageFile","packageSha256","packageSize","stateDirectory"};
        if (record.Count==required.Length) Fields(record,required);
        else Fields(record,"version","jobId","principalSid","ownerPid","ownerStartedAtEpochMillis","launcher",
            "packageFile","packageSha256","packageSize","stateDirectory","frontendPid","frontendStartedAtEpochMillis");
        if (Integer(record,"version")!=1) throw Invalid();
        return new Request(record);
    }

    internal static Dictionary<string,object> Record(byte[] bytes,int limit) {
        if (bytes==null || bytes.Length>limit) throw Invalid();
        return VpnInstallNative.ParseFlatRecord(new UTF8Encoding(false,true).GetString(bytes));
    }
    internal static void Fields(Dictionary<string,object> record,params string[] names) {
        if (record.Count!=names.Length) throw Invalid();
        foreach(string name in names) if (!record.ContainsKey(name)) throw Invalid();
    }
    internal static string Text(Dictionary<string,object> record,string name) {
        object value;
        if (!record.TryGetValue(name,out value) || !(value is string)) throw Invalid();
        return (string)value;
    }
    internal static long Integer(Dictionary<string,object> record,string name) {
        object value;
        if (!record.TryGetValue(name,out value) || !(value is long)) throw Invalid();
        return (long)value;
    }
    internal static void Job(string value) {
        Guid id;
        if (value==null || !Guid.TryParseExact(value,"D",out id) || id.ToString("D")!=value) throw Invalid();
    }
    internal static void Digest(string value) {
        if (value==null || value.Length!=64) throw Invalid();
        foreach(char item in value) if (!((item>='0' && item<='9') || (item>='a' && item<='f'))) throw Invalid();
    }
    internal static void Sid(string value) {
        if (value==null) throw Invalid();
        string[] parts=value.Split('-');
        if (parts.Length<4 || parts.Length>18 || parts[0]!="S" || parts[1]!="1") throw Invalid();
        for (int index=2;index<parts.Length;index++) {
            long number=Number(parts[index]);
            if (number>(index==2 ? 0xffffffffffffL : UInt32.MaxValue)) throw Invalid();
        }
    }
    static long Number(string text) {
        if (String.IsNullOrEmpty(text)) throw Invalid();
        foreach(char item in text) if (item<'0' || item>'9') throw Invalid();
        long value;
        if (!Int64.TryParse(text,NumberStyles.None,CultureInfo.InvariantCulture,out value) ||
            value.ToString(CultureInfo.InvariantCulture)!=text) throw Invalid();
        return value;
    }
    internal static string Leaf(string path) { return path.Substring(path.LastIndexOf('\\')+1); }
    internal static void LocalPath(string path) {
        if (path==null || path.Length<4 || path.Length>32760 ||
            !((path[0]>='A' && path[0]<='Z') || (path[0]>='a' && path[0]<='z')) || path[1]!=':' || path[2]!='\\') throw Invalid();
        for (int index=2;index<path.Length;index++) {
            char item=path[index];
            if (item<32 || ":/\"<>|?*".IndexOf(item)>=0) throw Invalid();
        }
        foreach(string part in path.Substring(3).Split('\\')) {
            if (part.Length==0 || part=="." || part==".." || part.EndsWith(".",StringComparison.Ordinal) ||
                part.EndsWith(" ",StringComparison.Ordinal)) throw Invalid();
        }
    }
    static IOException Invalid() { return new IOException("INVALID_ARGUMENT"); }
}
