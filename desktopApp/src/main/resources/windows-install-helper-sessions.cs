// Fixed native installer session admission. Requests are data only until this
// class retains the invoking owner generation, its token identity, and every
// private input ancestor. No argv path selects any of these objects.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

internal interface VpnInstallHelperSessionFactory {
    int Run(VpnInstallHelperProtocol.Invocation invocation);
}

internal sealed class VpnInstallHelperNativeSessions : VpnInstallHelperSessionFactory {
    public int Run(VpnInstallHelperProtocol.Invocation invocation) {
        if (invocation==null) throw new ArgumentException("INVALID_ARGUMENT");
        bool originalUser=invocation.Operation==VpnInstallHelperProtocol.Role.OriginalUser;
        using (OwnerInputAdmission admission=OwnerInputAdmission.Open(invocation,originalUser)) {
            // Admission is deliberately separate from role execution. Neither role may
            // start MSI, publish a receipt, or relaunch until its retained session is
            // complete; a parsed record cannot substitute for those missing bindings.
            throw new IOException("RUNTIME_FAILED");
        }
    }
}

// Retains the exact source of all later role authority. Close failures retain
// ownership in this object for an explicit retry; they never turn a possibly
// live owner/input into permission to adopt a replacement.
internal sealed class OwnerInputAdmission : IDisposable {
    readonly List<IDisposable> retained=new List<IDisposable>();
    bool closed;
    internal readonly VpnInstallNative.ProcessPin Owner;
    internal readonly VpnInstallNative.ProcessImagePin OwnerGeneration;
    internal readonly WindowsIdentity Caller;
    internal VpnInstallHelperProtocol.Request Request { get; private set; }

    OwnerInputAdmission(VpnInstallNative.ProcessPin owner,VpnInstallNative.ProcessImagePin generation,
        WindowsIdentity caller) {
        Owner=owner; OwnerGeneration=generation; Caller=caller;
        retained.Add(owner); retained.Add(generation); retained.Add(caller);
    }

    internal static OwnerInputAdmission Open(VpnInstallHelperProtocol.Invocation invocation,bool originalUser) {
        return Open(invocation,originalUser,null);
    }

    // Same-assembly test seam for an owned local root; production always reads the
    // retained owner's known LocalAppData path.
    internal static OwnerInputAdmission Open(VpnInstallHelperProtocol.Invocation invocation,bool originalUser,
        Func<string> localRootForTest) {
        if (invocation==null) throw new ArgumentException("INVALID_ARGUMENT");
        VpnInstallNative.ProcessPin owner=null;
        VpnInstallNative.ProcessImagePin generation=null;
        WindowsIdentity caller=null;
        OwnerInputAdmission result=null;
        try {
            owner=new VpnInstallNative.ProcessPin(invocation.OwnerPid);
            generation=new VpnInstallNative.ProcessImagePin(invocation.OwnerPid);
            VpnInstallNative.ProcessImageObservation observed=generation.Observe();
            if (observed.Pid!=invocation.OwnerPid || observed.CreationFileTime!=invocation.OwnerCreationFileTime ||
                observed.KernelOnly || owner.Exited) throw new IOException("CONFLICT");
            caller=WindowsIdentity.GetCurrent();
            if (caller==null || caller.User==null || String.IsNullOrEmpty(caller.User.Value))
                throw new IOException("Installer caller token unavailable");
            bool administrator=new WindowsPrincipal(caller).IsInRole(WindowsBuiltInRole.Administrator);
            if (originalUser) {
                if (administrator || !String.Equals(caller.User.Value,owner.Principal,StringComparison.Ordinal))
                    throw new IOException("CONFLICT");
            } else if (!administrator) throw new IOException("PRIVILEGE_REQUIRED");
            result=new OwnerInputAdmission(owner,generation,caller);
            owner=null; generation=null; caller=null;
            result.ReadRequest(invocation,localRootForTest==null ? result.Owner.LocalAppData() : localRootForTest());
            result.ValidateRequest(invocation);
            return result;
        } catch {
            if (result!=null) { try { result.Dispose(); } catch { } }
            else {
                if (caller!=null) caller.Dispose();
                if (generation!=null) generation.Dispose();
                if (owner!=null) owner.Dispose();
            }
            throw;
        }
    }

    void ReadRequest(VpnInstallHelperProtocol.Invocation invocation,string local) {
        VpnInstallHelperProtocol.LocalPath(local);
        int retainedAtStart=retained.Count;
        SafeFileHandle requestHandle=null;
        try {
            SafeFileHandle localDirectory=PinDirectoryPath(local,Owner.Principal);
            SafeFileHandle inputRoot=OpenPinnedDirectory(localDirectory,
                Path.Combine(local,"vpn-control-install-inputs"),Owner.Principal,true);
            retained.Add(inputRoot);
            SafeFileHandle input=OpenPinnedDirectory(inputRoot,
                Path.Combine(local,"vpn-control-install-inputs",invocation.JobId),Owner.Principal,false);
            retained.Add(input);
            requestHandle=VpnInstallNative.OpenRead(Path.Combine(local,"vpn-control-install-inputs",invocation.JobId,"request.json"),false);
            VpnInstallNative.InspectLinkedAncestor(input,requestHandle,Owner.Principal);
            VpnInstallNative.Inspect(requestHandle,false,false,Owner.Principal);
            FileStream requestStream=new FileStream(requestHandle,FileAccess.Read,1,false);
            requestHandle=null;
            retained.Add(requestStream);
            Request=VpnInstallHelperProtocol.ParseRequest(ReadBounded(requestStream,65536));
            // The stream remains retained after parsing. A later leaf replacement cannot
            // alter the already admitted request or free its no-delete input witness.
        } catch (Exception readFailure) {
            if (requestHandle!=null) {
                try { requestHandle.Dispose(); }
                catch (Exception cleanupFailure) {
                    readFailure.Data["vpn.install.inputAdmission.cleanupUncertain"]=cleanupFailure.GetType().FullName;
                }
            }
            try { ReleaseRetainedFrom(retainedAtStart); }
            catch (Exception cleanupFailure) {
                readFailure.Data["vpn.install.inputAdmission.cleanupUncertain"]=cleanupFailure.GetType().FullName;
            }
            throw;
        }
    }

    SafeFileHandle PinDirectoryPath(string path,string principal) {
        string root=Path.GetPathRoot(path);
        if (String.IsNullOrEmpty(root) || !String.Equals(root,path.Substring(0,root.Length),StringComparison.Ordinal))
            throw new IOException("INVALID_ARGUMENT");
        string remaining=path.Substring(root.Length);
        string[] parts=remaining.Split(new char[] {'\\'},StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length==0) throw new IOException("INVALID_ARGUMENT");
        SafeFileHandle parent=VpnInstallNative.OpenDirectory(root);
        try {
            VpnInstallNative.Inspect(parent,true,true,principal);
            retained.Add(parent);
            string current=root.TrimEnd('\\');
            for (int index=0;index<parts.Length;index++) {
                string part=parts[index];
                if (part=="." || part=="..") throw new IOException("INVALID_ARGUMENT");
                current=current+"\\"+part;
                SafeFileHandle child=OpenPinnedDirectory(parent,current,principal,index!=parts.Length-1);
                retained.Add(child); parent=child;
            }
            return parent;
        } catch { if (!retained.Contains(parent)) parent.Dispose(); throw; }
    }

    static SafeFileHandle OpenPinnedDirectory(SafeFileHandle parent,string path,string principal,bool ancestor) {
        SafeFileHandle result=VpnInstallNative.OpenDirectory(path);
        try {
            if (parent==null) VpnInstallNative.Inspect(result,true,ancestor,principal);
            else VpnInstallNative.InspectLinkedAncestor(parent,result,principal);
            if (!ancestor) VpnInstallNative.Inspect(result,true,false,principal);
            return result;
        } catch { result.Dispose(); throw; }
    }

    static byte[] ReadBounded(FileStream stream,int limit) {
        if (stream==null || !stream.CanRead || stream.Length<1 || stream.Length>limit) throw new IOException("INVALID_ARGUMENT");
        int length=checked((int)stream.Length); byte[] bytes=new byte[length]; int offset=0;
        while (offset<bytes.Length) {
            int count=stream.Read(bytes,offset,bytes.Length-offset);
            if (count<=0) throw new IOException("UNAVAILABLE");
            offset+=count;
        }
        if (stream.ReadByte()!=-1) throw new IOException("INVALID_ARGUMENT");
        return bytes;
    }

    void ValidateRequest(VpnInstallHelperProtocol.Invocation invocation) {
        VpnInstallNative.ProcessImageObservation current=OwnerGeneration.Observe();
        if (current.Pid!=invocation.OwnerPid || current.CreationFileTime!=invocation.OwnerCreationFileTime || current.KernelOnly)
            throw new IOException("CONFLICT");
        if (Request==null || Request.JobId!=invocation.JobId || Request.OwnerPid!=invocation.OwnerPid ||
            Request.OwnerStartedAtEpochMillis!=Owner.StartedAtEpochMillis ||
            !String.Equals(Request.PrincipalSid,Owner.Principal,StringComparison.Ordinal)) throw new IOException("CONFLICT");
        string imageLeaf=Path.GetFileName(Owner.Image);
        if ((!String.Equals(imageLeaf,"vpn-control.exe",StringComparison.OrdinalIgnoreCase) &&
             !String.Equals(imageLeaf,"vpn-control-cli.exe",StringComparison.OrdinalIgnoreCase)) ||
            !String.Equals(Path.GetDirectoryName(Owner.Image),Path.GetDirectoryName(Request.Launcher),StringComparison.OrdinalIgnoreCase))
            throw new IOException("CONFLICT");
        if (Owner.Exited) throw new IOException("CONFLICT");
    }

    void ReleaseRetainedFrom(int start) {
        Exception failure=null;
        for (int index=retained.Count-1;index>=start;index--) {
            try { retained[index].Dispose(); retained.RemoveAt(index); }
            catch (Exception error) { if (failure==null) failure=error; }
        }
        if (failure!=null) throw new IOException("PERSISTENCE_FAILED",failure);
    }

    public void Dispose() {
        if (closed) return;
        Exception failure=null;
        for (int index=retained.Count-1;index>=0;index--) {
            try { retained[index].Dispose(); retained.RemoveAt(index); }
            catch (Exception error) { if (failure==null) failure=error; }
        }
        closed=retained.Count==0;
        if (failure!=null) throw new IOException("PERSISTENCE_FAILED",failure);
    }
}
