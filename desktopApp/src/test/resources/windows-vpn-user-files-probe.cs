namespace VpnScopedStorage {
 public static class UserFilesProbe {
  public static string AdmittedParent(string root) {
   using(var owner=System.Diagnostics.Process.GetCurrentProcess())
   using(var files=new OriginalUser(owner.Handle,System.Security.Principal.WindowsIdentity.GetCurrent().User.Value))
    return files.AdmitDestination(System.IO.Path.Combine(root,"cache.db")).ParentIdentity;
  }
  static void Need(bool value) { if(!value) throw new System.Exception("RESOURCE_PROBE_ASSERTION"); }
  static System.IO.MemoryStream Bytes(string value) { return new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(value)); }
  static void Fails(string code,System.Action action) {
   try { action(); } catch(System.IO.IOException error) { Need(error.Message==code); return; }
   throw new System.Exception("RESOURCE_PROBE_MISSING_FAILURE");
  }
  public static string Run(string root) {
   using(var owner=System.Diagnostics.Process.GetCurrentProcess())
   using(var files=new OriginalUser(owner.Handle,System.Security.Principal.WindowsIdentity.GetCurrent().User.Value)) {
    return RunWith(root,files);
   }
  }
  public static string RunWith(string root,OriginalUser files) {
   Need(System.IO.Directory.Exists(root)&&System.IO.Directory.GetFileSystemEntries(root).Length==0);
   {
    string path=System.IO.Path.Combine(root,"cache.db"); System.IO.File.WriteAllText(path,"before");
    var target=files.Capture(path); var phases=new System.Collections.Generic.List<string>();
    var result=files.Publish(target,Bytes("after"),phase=>phases.Add(phase.Phase));
    Need(System.IO.File.ReadAllText(path)=="after"&&result.FileIdentity!=target.FileIdentity);
    Need(System.String.Join(",",phases)=="PREPARED,ORIGINAL_MOVING,ORIGINAL_MOVED,PUBLISHING,PUBLISHED");
    Need(System.IO.Directory.GetFileSystemEntries(root).Length==1);

    // B's authorization binds the destination parent while A keeps changing its cache. At commit
    // a legitimate A publication can replace the file; B must copy the newest bytes from that parent.
    var destination=files.AdmitDestination(path);
    target=files.Capture(path); files.Publish(target,Bytes("latest-A-cache"),phase=>{});
    var current=files.CaptureCurrent(destination);
    using(var copied=new System.IO.MemoryStream()) {
     Need(current.FileIdentity!=target.FileIdentity&&files.CopyInput(current,copied)&&
      System.Text.Encoding.UTF8.GetString(copied.ToArray())=="latest-A-cache");
    }
    System.IO.File.WriteAllText(path,"after");

    target=files.Capture(path); System.IO.File.WriteAllText(path,"external-content-change");
    Fails("CONFLICT",()=>files.Publish(target,Bytes("unwanted"),phase=>{}));
    Need(System.IO.File.ReadAllText(path)=="external-content-change");
    System.IO.File.WriteAllText(path,"after");

    target=files.Capture(path); System.IO.File.Move(path,path+"-old"); System.IO.File.WriteAllText(path,"replaced");
    Fails("CONFLICT",()=>files.Publish(target,Bytes("unwanted"),phase=>{}));
    Need(System.IO.File.ReadAllText(path)=="replaced"&&System.IO.File.ReadAllText(path+"-old")=="after");
    System.IO.File.Delete(path); System.IO.File.Delete(path+"-old");

    string parent=System.IO.Path.Combine(root,"parent"),child=System.IO.Path.Combine(parent,"value");
    System.IO.Directory.CreateDirectory(parent); System.IO.File.WriteAllText(child,"original-parent");
    target=files.Capture(child); destination=files.AdmitDestination(child); System.IO.Directory.Move(parent,parent+"-old");
    System.IO.Directory.CreateDirectory(parent); System.IO.File.WriteAllText(child,"replacement-parent");
    Fails("CONFLICT",()=>files.Publish(target,Bytes("unwanted"),phase=>{}));
    Fails("CONFLICT",()=>files.CaptureCurrent(destination));
    Need(System.IO.File.ReadAllText(child)=="replacement-parent");
    System.IO.File.Delete(child); System.IO.Directory.Delete(parent);
    System.IO.File.Delete(System.IO.Path.Combine(parent+"-old","value")); System.IO.Directory.Delete(parent+"-old");

    target=files.Capture(path); Publication last=null;
    Fails("PERSISTENCE_FAILED",()=>files.Publish(target,Bytes("preserved-source"),phase=>{
     last=phase; if(phase.Phase=="PUBLISHING") System.IO.File.WriteAllText(path,"racing-destination");
    }));
    Need(last!=null&&last.Phase=="PUBLISHING"&&System.IO.File.ReadAllText(path)=="racing-destination");
    string temporary=System.IO.Path.Combine(root,last.TemporaryName);
    Need(System.IO.File.ReadAllText(temporary)=="preserved-source");
    System.IO.File.Delete(temporary); System.IO.File.Delete(path);

    System.IO.File.WriteAllText(path,"prior-cache"); target=files.Capture(path); last=null; Publication beforeRename=null;
    Fails("PERSISTENCE_FAILED",()=>files.Publish(target,Bytes("committed-cache"),phase=>{
     last=phase; if(phase.Phase=="PUBLISHING") beforeRename=phase;
     if(phase.Phase=="PUBLISHED") throw new System.IO.IOException("PERSISTENCE_FAILED");
    }));
    Need(last!=null&&last.Phase=="PUBLISHED"&&System.IO.File.ReadAllText(path)=="committed-cache");
    string backup=System.IO.Path.Combine(root,last.BackupName);
    Need(System.IO.File.ReadAllText(backup)=="prior-cache");
    Need(beforeRename!=null&&files.PublicationCommitted(target,beforeRename));
    Need(System.IO.Directory.GetFileSystemEntries(root).Length==2);
    System.IO.File.WriteAllText(path,"later-user-change");
    Need(files.PublicationCommitted(target,last)&&System.IO.File.ReadAllText(path)=="later-user-change");
    Fails("OUTCOME_UNKNOWN",()=>files.PublicationCommitted(target,beforeRename));
    System.IO.File.Move(backup,backup+"-owned"); System.IO.File.WriteAllText(backup,"foreign-evidence");
    Fails("CONFLICT",()=>files.CleanupCommitted(target,last));
    Need(System.IO.File.ReadAllText(path)=="later-user-change"&&System.IO.File.ReadAllText(backup)=="foreign-evidence");
    System.IO.File.Delete(backup); System.IO.File.Move(backup+"-owned",backup);
    files.CleanupCommitted(target,last);
    Need(!System.IO.File.Exists(backup)&&System.IO.File.ReadAllText(path)=="later-user-change");
    files.CleanupCommitted(target,last); // Exact cleanup remains safe after an acknowledged retry.
    System.IO.File.Delete(path);
    Need(System.IO.Directory.GetFileSystemEntries(root).Length==0);
    return "USER_FILES_OK:13";
   }
  }
 }
 public static class PublicationJournalProbe {
  static void Need(bool value) { if(!value) throw new System.Exception("JOURNAL_PROBE_ASSERTION"); }
  static void Fails(string code,System.Action action) {
   try { action(); } catch(System.IO.IOException error) { Need(error.Message==code); return; }
   throw new System.Exception("JOURNAL_PROBE_MISSING_FAILURE");
  }
  static System.IO.MemoryStream Bytes(string value) { return new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(value)); }
  static System.IO.FileStream Create(string path) {
   return new System.IO.FileStream(path,System.IO.FileMode.CreateNew,System.IO.FileAccess.ReadWrite,
    System.IO.FileShare.Read,65536,System.IO.FileOptions.WriteThrough);
  }
  static System.IO.FileStream Read(string path) {
   return new System.IO.FileStream(path,System.IO.FileMode.Open,System.IO.FileAccess.Read,System.IO.FileShare.Read);
  }
  public static string Run(string root) {
   Need(System.IO.Directory.Exists(root)&&System.IO.Directory.GetFileSystemEntries(root).Length==0);
   string job=System.Guid.NewGuid().ToString("D"),resource=System.Guid.NewGuid().ToString("D");
   string scope=System.Guid.NewGuid().ToString("D"),controller=System.Guid.NewGuid().ToString("D");
   string sid=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
   string path=System.IO.Path.Combine(root,"cache.db"),record=System.IO.Path.Combine(root,"publication.journal");
   using(var owner=System.Diagnostics.Process.GetCurrentProcess()) using(var files=new OriginalUser(owner.Handle,sid)) {
    string scopePath=System.IO.Path.Combine(root,"scope.json");
    System.IO.File.WriteAllText(scopePath,"{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}");
    ScopeRecordProbe.Protect(scopePath,sid); var proof=files.Capture(scopePath); files.ValidateScope(proof,scope);
    System.IO.File.WriteAllText(path,"prior-cache"); Target target=files.Capture(path); Publication last=null;
    using(var storage=Create(record)) {
     var journal=PublicationJournal.Create(storage,job,resource,files.Owner,scope,controller,proof,target);
     // The rename commits, but the post-rename callback loses its reply before recording success.
     Fails("PERSISTENCE_FAILED",()=>files.Publish(target,Bytes("committed-cache"),phase=>{
      if(phase.Phase=="PUBLISHED") throw new System.IO.IOException("PERSISTENCE_FAILED");
      journal.Record(phase); last=phase;
     }));
     Need(journal.Last.Phase=="PUBLISHING");
    }
    using(var storage=Read(record)) {
     var cold=PublicationJournal.Open(storage,job,resource,files.Owner,scope,controller,proof);
     Need(cold.Last.Phase=="PUBLISHING"&&!cold.IncompleteTail&&files.PublicationCommitted(cold.Target,cold.Last));
     Need(cold.ToString().IndexOf(root,System.StringComparison.Ordinal)<0);
     long before=storage.Length; Fails("CONFLICT",()=>cold.Record(new Publication("PUBLISHED",last.TemporaryName,
      last.TemporaryIdentity,last.BackupName,last.OriginalIdentity,last.ByteCount,last.Sha256)));
     Need(before==storage.Length);
    }
    using(var storage=Read(record)) Fails("CONFLICT",()=>PublicationJournal.Open(storage,System.Guid.NewGuid().ToString("D"),resource,files.Owner,scope,controller,proof));
    using(var storage=Read(record)) Fails("CONFLICT",()=>PublicationJournal.Open(storage,job,System.Guid.NewGuid().ToString("D"),files.Owner,scope,controller,proof));
    using(var storage=Read(record)) Fails("PERMISSION_DENIED",()=>PublicationJournal.Open(storage,job,resource,new OwnerIdentity(files.Owner.ProcessId,files.Owner.CreationFileTime,sid=="S-1-5-18"?"S-1-5-19":"S-1-5-18"),scope,controller,proof));
    using(var storage=Read(record)) Fails("CONFLICT",()=>PublicationJournal.Open(storage,job,resource,files.Owner,System.Guid.NewGuid().ToString("D"),controller,proof));
    using(var storage=Read(record)) Fails("CONFLICT",()=>PublicationJournal.Open(storage,job,resource,files.Owner,scope,System.Guid.NewGuid().ToString("D"),proof));
    using(var storage=Read(record)) Fails("CONFLICT",()=>PublicationJournal.Open(storage,job,resource,
     new OwnerIdentity(files.Owner.ProcessId+1,files.Owner.CreationFileTime,sid),scope,controller,proof));
    using(var storage=Read(record)) Fails("CONFLICT",()=>PublicationJournal.Open(storage,job,resource,
     new OwnerIdentity(files.Owner.ProcessId,files.Owner.CreationFileTime+1,sid),scope,controller,proof));
    System.IO.File.Copy(scopePath,scopePath+".copy"); ScopeRecordProbe.Protect(scopePath+".copy",sid);
    var copiedProof=files.Capture(scopePath+".copy"); files.ValidateScope(copiedProof,scope);
    using(var storage=Read(record)) Fails("CONFLICT",()=>PublicationJournal.Open(storage,job,resource,files.Owner,scope,controller,copiedProof));
    System.IO.File.Delete(scopePath+".copy");
    System.IO.File.Delete(path); System.IO.File.Delete(System.IO.Path.Combine(root,last.BackupName)); System.IO.File.Delete(record);

    target=files.Capture(path);
    using(var storage=Create(record)) {
     var journal=PublicationJournal.Create(storage,job,resource,files.Owner,scope,controller,proof,target);
     files.Publish(target,Bytes("confirmed-cache"),journal.Record);
     Need(journal.Last.Phase=="PUBLISHED");
     long before=storage.Length; Fails("CONFLICT",()=>journal.Record(journal.Last)); Need(before==storage.Length);
    }
    // A partial subsequent record does not erase an earlier established success or authorize writes.
    using(var storage=new System.IO.FileStream(record,System.IO.FileMode.Append,System.IO.FileAccess.Write)) {
     storage.Write(new byte[]{1,2,3},0,3); storage.Flush(true);
    }
    System.IO.File.WriteAllText(path,"later-user-write");
    using(var storage=Read(record)) {
     var cold=PublicationJournal.Open(storage,job,resource,files.Owner,scope,controller,proof);
     Need(cold.IncompleteTail&&cold.Last.Phase=="PUBLISHED"&&files.PublicationCommitted(cold.Target,cold.Last));
    }
    // A corrupted complete record is not treated as an empty journal or repaired in place.
    byte[] corrupt=System.IO.File.ReadAllBytes(record); corrupt[8]^=1; System.IO.File.WriteAllBytes(record,corrupt);
    using(var storage=Read(record)) Fails("OUTCOME_UNKNOWN",()=>PublicationJournal.Open(storage,job,resource,files.Owner,scope,controller,proof));
    Need(System.Convert.ToBase64String(System.IO.File.ReadAllBytes(record))==System.Convert.ToBase64String(corrupt));
    System.IO.File.Delete(path); System.IO.File.Delete(record);
    System.IO.File.Delete(scopePath);
    Need(System.IO.Directory.GetFileSystemEntries(root).Length==0);
    return "JOURNAL_OK:13";
   }
  }
 }
 public static class ScopeRecordProbe {
  static void Need(bool value) { if(!value) throw new System.Exception("SCOPE_PROBE_ASSERTION"); }
  static void Fails(string code,System.Action action) {
   try { action(); } catch(System.IO.IOException error) { Need(error.Message==code); return; }
   throw new System.Exception("SCOPE_PROBE_MISSING_FAILURE");
  }
  internal static void Protect(string path,string sid,bool publicRead=false) {
   var acl=new System.Security.AccessControl.FileSecurity(); acl.SetAccessRuleProtection(true,false);
   acl.SetOwner(new System.Security.Principal.SecurityIdentifier(sid));
   acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid),
    System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
   if(publicRead) acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"),
    System.Security.AccessControl.FileSystemRights.Read,System.Security.AccessControl.AccessControlType.Allow));
   System.IO.File.SetAccessControl(path,acl);
  }
  public static string Run(string root) {
   Need(System.IO.Directory.Exists(root)&&System.IO.Directory.GetFileSystemEntries(root).Length==0);
   string scope=System.Guid.NewGuid().ToString("D"),sid=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
   string path=System.IO.Path.Combine(root,"scope.json"),content="{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}";
   using(var owner=System.Diagnostics.Process.GetCurrentProcess()) using(var files=new OriginalUser(owner.Handle,sid)) {
    System.IO.File.WriteAllText(path,content,new System.Text.UTF8Encoding(false,true)); Protect(path,sid);
    var proof=files.Capture(path); files.ValidateScope(proof,scope);
    Fails("CONFLICT",()=>files.ValidateScope(proof,System.Guid.NewGuid().ToString("D")));
    Protect(path,sid,true); Fails("PERMISSION_DENIED",()=>files.ValidateScope(proof,scope)); Protect(path,sid);
    System.IO.File.WriteAllText(path,content+" "); Fails("CONFLICT",()=>files.ValidateScope(proof,scope));
    System.IO.File.WriteAllText(path,content); files.ValidateScope(proof,scope);
    System.IO.File.Move(path,path+".owned"); System.IO.File.WriteAllText(path,content); Protect(path,sid);
    Fails("CONFLICT",()=>files.ValidateScope(proof,scope));
    System.IO.File.Delete(path); System.IO.File.Delete(path+".owned");
    Need(System.IO.Directory.GetFileSystemEntries(root).Length==0);
    return "SCOPE_OK:5";
   }
  }
 }
 public static class CacheLeaseProbe {
  static void Need(bool value) { if(!value) throw new System.Exception("CACHE_LEASE_ASSERTION"); }
  static System.IO.FileStream Create(string path) { return new System.IO.FileStream(path,System.IO.FileMode.CreateNew,
   System.IO.FileAccess.ReadWrite,System.IO.FileShare.Read,65536,System.IO.FileOptions.WriteThrough); }
 static void Write(System.IO.FileStream file,string text) {
   byte[] bytes=System.Text.Encoding.UTF8.GetBytes(text); file.Position=0; file.SetLength(0); file.Write(bytes,0,bytes.Length); file.Flush(true);
  }
  static string Read(System.IO.FileStream file) {
   file.Position=0;
   using(var reader=new System.IO.StreamReader(file,System.Text.Encoding.UTF8,true,1024,true)) return reader.ReadToEnd();
  }
  sealed class FailingJournal : System.IO.FileStream {
   int flushes;
   public FailingJournal(string path) : base(path,System.IO.FileMode.CreateNew,System.IO.FileAccess.ReadWrite,
    System.IO.FileShare.Read,65536,System.IO.FileOptions.WriteThrough) { }
   public override void Flush(bool toDisk) {
    if(toDisk&&++flushes==6) throw new System.IO.IOException("PERSISTENCE_FAILED");
    base.Flush(toDisk);
   }
  }
  public static string Run(string root) {
   Need(System.IO.Directory.Exists(root)&&System.IO.Directory.GetFileSystemEntries(root).Length==0);
   string sid=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value,scope=System.Guid.NewGuid().ToString("D"),controller=System.Guid.NewGuid().ToString("D");
   string scopePath=System.IO.Path.Combine(root,"scope.json"),path=System.IO.Path.Combine(root,"user-cache.db");
   string privateCache=System.IO.Path.Combine(root,"retained-cache.db"),record=System.IO.Path.Combine(root,"cache.journal");
   System.IO.File.WriteAllText(scopePath,"{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}"); ScopeRecordProbe.Protect(scopePath,sid);
   using(var owner=System.Diagnostics.Process.GetCurrentProcess()) using(var files=new OriginalUser(owner.Handle,sid)) {
    var proof=files.Capture(scopePath); System.IO.File.WriteAllText(path,"initial-A"); var destination=files.AdmitDestination(path);
    System.IO.File.WriteAllText(path,"latest-A");
    using(var cache=Create(privateCache)) using(var journal=Create(record)) {
     var lease=new CacheLease(files,destination,System.Guid.NewGuid().ToString("D"),System.Guid.NewGuid().ToString("D"),scope,controller,proof);
     lease.CaptureAtCommit(cache,journal); Need(Read(cache)=="latest-A"); Write(cache,"latest-B");
     bool busy=false; try { lease.PublishAfterExit(cache,()=>false); } catch(System.IO.IOException error) { busy=error.Message=="BUSY"; }
     Need(busy&&System.IO.File.ReadAllText(path)=="latest-A");
     var result=lease.PublishAfterExit(cache,()=>true); Need(result.Disposition=="PUBLISHED"&&result.Code==null&&System.IO.File.ReadAllText(path)=="latest-B");
     Write(cache,"do-not-replay"); Need(System.Object.ReferenceEquals(result,lease.PublishAfterExit(cache,()=>true))&&System.IO.File.ReadAllText(path)=="latest-B");
    }
    System.IO.File.Delete(privateCache); System.IO.File.Delete(record);
    using(var cache=Create(privateCache)) using(var journal=Create(record)) {
     var lease=new CacheLease(files,destination,System.Guid.NewGuid().ToString("D"),System.Guid.NewGuid().ToString("D"),scope,controller,proof);
     lease.CaptureAtCommit(cache,journal); Write(cache,"retained-latest-owned"); System.IO.File.WriteAllText(path,"external-writer");
     var result=lease.PublishAfterExit(cache,()=>true);
     Need(result.Disposition=="PENDING_PUBLICATION"&&result.Code=="CONFLICT"&&System.IO.File.ReadAllText(path)=="external-writer"&&
      Read(cache)=="retained-latest-owned");
    }
    System.IO.File.Delete(privateCache); System.IO.File.Delete(record);
    using(var cache=Create(privateCache)) using(var journal=new FailingJournal(record)) {
     var lease=new CacheLease(files,destination,System.Guid.NewGuid().ToString("D"),System.Guid.NewGuid().ToString("D"),scope,controller,proof);
     lease.CaptureAtCommit(cache,journal); Write(cache,"known-commit");
     var result=lease.PublishAfterExit(cache,()=>true);
     Need(result.Disposition=="COMMITTED_CLEANUP_PENDING"&&result.Code=="PERSISTENCE_FAILED"&&System.IO.File.ReadAllText(path)=="known-commit");
     var backups=System.IO.Directory.GetFiles(root,".vpn-control-resource-*.backup"); Need(backups.Length==1&&System.IO.File.ReadAllText(backups[0])=="external-writer");
     System.IO.File.Delete(backups[0]);
    }
    System.IO.File.Delete(privateCache); System.IO.File.Delete(record); System.IO.File.Delete(path); System.IO.File.Delete(scopePath);
    Need(System.IO.Directory.GetFileSystemEntries(root).Length==0); return "CACHE_LEASE_OK:3";
   }
  }
 }
 public static class ResourceGateProbe {
  static void Need(bool value) { if(!value) throw new System.Exception("RESOURCE_GATE_ASSERTION"); }
  static void Fails(string code,System.Action action) {
   try { action(); } catch(System.IO.IOException error) { Need(error.Message==code); return; }
   throw new System.Exception("RESOURCE_GATE_MISSING_FAILURE");
  }
  static System.IO.FileStream Open(string path,System.IO.FileMode mode) {
   return new System.IO.FileStream(path,mode,System.IO.FileAccess.ReadWrite,System.IO.FileShare.None,65536,System.IO.FileOptions.WriteThrough);
  }
  public static string Run(string root) {
   Need(System.IO.Directory.Exists(root)&&System.IO.Directory.GetFileSystemEntries(root).Length==0);
   string sid=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value,scope=System.Guid.NewGuid().ToString("D"),controller=System.Guid.NewGuid().ToString("D");
   string scopePath=System.IO.Path.Combine(root,"scope.json"),path=System.IO.Path.Combine(root,"admission.gate");
   System.IO.File.WriteAllText(scopePath,"{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}"); ScopeRecordProbe.Protect(scopePath,sid);
   var start=new System.Diagnostics.ProcessStartInfo("powershell.exe","-NoProfile -NonInteractive -Command \"$null=[Console]::In.ReadLine()\"");
   start.UseShellExecute=false; start.CreateNoWindow=true; start.RedirectStandardInput=true;
   using(var fixture=System.Diagnostics.Process.Start(start)) {
    try {
     using(var files=new OriginalUser(fixture.Handle,sid)) {
      var proof=files.Capture(scopePath); files.ValidateScope(proof,scope);
      string job=System.Guid.NewGuid().ToString("D"),resource=System.Guid.NewGuid().ToString("D");
      var entries=new[]{new ResourceIdentity(resource,"CACHE")};
      var binding=new RuntimeResourceBinding(job,scope,controller,files.Owner,proof,entries);
      using(var storage=Open(path,System.IO.FileMode.CreateNew)) {
       var gate=ResourceAdmissionGate.CreateForOriginal(storage,binding,()=>!fixture.HasExited);
       Need(gate.HadOriginalAdmission&&!gate.AdmissionClosed);
       long bytes=storage.Length; Fails("BUSY",()=>ResourceAdmissionGate.CloseForRecovery(storage,binding,()=>fixture.HasExited));
       Need(storage.Length==bytes&&!gate.AdmissionClosed);
       bool blocked=false; try { using(var competing=Open(path,System.IO.FileMode.Open)) {} }
       catch(System.IO.IOException error) { blocked=(error.HResult&0xffff)==32; } Need(blocked);
      }
      fixture.StandardInput.Close(); Need(fixture.WaitForExit(10000));
      using(var storage=Open(path,System.IO.FileMode.Open)) {
       var cold=ResourceAdmissionGate.CloseForRecovery(storage,binding,()=>fixture.HasExited);
       Need(cold.HadOriginalAdmission&&cold.AdmissionClosed);
       long bytes=storage.Length; Need(ResourceAdmissionGate.CloseForRecovery(storage,binding,()=>fixture.HasExited).AdmissionClosed);
       Need(storage.Length==bytes); Fails("CONFLICT",()=>ResourceAdmissionGate.CreateForOriginal(storage,binding,()=>!fixture.HasExited));
      }
      using(var storage=Open(path,System.IO.FileMode.Open)) Fails("CONFLICT",()=>ResourceAdmissionGate.CloseForRecovery(storage,
       new RuntimeResourceBinding(job,scope,controller,new OwnerIdentity(files.Owner.ProcessId,files.Owner.CreationFileTime+1,sid),proof,entries),()=>fixture.HasExited));
      using(var storage=Open(path,System.IO.FileMode.Open)) Fails("CONFLICT",()=>ResourceAdmissionGate.CloseForRecovery(storage,
       new RuntimeResourceBinding(job,System.Guid.NewGuid().ToString("D"),controller,files.Owner,proof,entries),()=>fixture.HasExited));
      using(var storage=Open(path,System.IO.FileMode.Open)) Fails("CONFLICT",()=>ResourceAdmissionGate.CloseForRecovery(storage,
       new RuntimeResourceBinding(job,scope,controller,files.Owner,proof,new[]{new ResourceIdentity(System.Guid.NewGuid().ToString("D"),"CACHE")}),()=>fixture.HasExited));
      System.IO.File.Delete(path);
      using(var storage=Open(path,System.IO.FileMode.CreateNew)) {
       var cold=ResourceAdmissionGate.CloseForRecovery(storage,binding,()=>fixture.HasExited);
       Need(cold.AdmissionClosed&&!cold.HadOriginalAdmission);
       Fails("CONFLICT",()=>ResourceAdmissionGate.CreateForOriginal(storage,binding,()=>!fixture.HasExited));
      }
      using(var storage=new System.IO.FileStream(path,System.IO.FileMode.Append,System.IO.FileAccess.Write)) {
       storage.WriteByte(1); storage.Flush(true);
      }
      byte[] before=System.IO.File.ReadAllBytes(path);
      using(var storage=Open(path,System.IO.FileMode.Open)) Fails("OUTCOME_UNKNOWN",()=>ResourceAdmissionGate.CloseForRecovery(storage,binding,()=>fixture.HasExited));
      Need(System.Convert.ToBase64String(before)==System.Convert.ToBase64String(System.IO.File.ReadAllBytes(path)));
      System.IO.File.Delete(path); System.IO.File.Delete(scopePath);
      Need(System.IO.Directory.GetFileSystemEntries(root).Length==0); return "RESOURCE_GATE_OK:7";
     }
    } finally {
     fixture.StandardInput.Close();
     if(!fixture.WaitForExit(1000)) { fixture.Kill(); fixture.WaitForExit(); }
    }
   }
  }
 }
 public static class CacheBatchProbe {
  static void Need(bool value) { if(!value) throw new System.Exception("CACHE_BATCH_ASSERTION"); }
  static void Fails(string code,System.Action action) {
   try { action(); } catch(System.IO.IOException error) { Need(error.Message==code); return; }
   throw new System.Exception("CACHE_BATCH_MISSING_FAILURE");
  }
  public static string Run(string root) {
   Need(System.IO.Directory.Exists(root)&&System.IO.Directory.GetFileSystemEntries(root).Length==0);
   string sid=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value,scope=System.Guid.NewGuid().ToString("D"),controller=System.Guid.NewGuid().ToString("D");
   string scopePath=System.IO.Path.Combine(root,"scope.json"),path=System.IO.Path.Combine(root,"user-cache.db");
   System.IO.File.WriteAllText(scopePath,"{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}"); ScopeRecordProbe.Protect(scopePath,sid);
   using(var owner=System.Diagnostics.Process.GetCurrentProcess()) using(var files=new OriginalUser(owner.Handle,sid)) {
    var proof=files.Capture(scopePath); System.IO.File.WriteAllText(path,"initial-A"); var destination=files.AdmitDestination(path);
    for(int scenario=0;scenario<4;scenario++) {
     string resource=System.Guid.NewGuid().ToString("D"); var identity=new ResourceIdentity(resource,"CACHE");
     var binding=new RuntimeResourceBinding(System.Guid.NewGuid().ToString("D"),scope,controller,files.Owner,proof,new[]{identity});
     bool exited=false; int reads=0;
     using(var mayRead=new System.Threading.ManualResetEvent(scenario!=0))
     using(var readStarted=new System.Threading.ManualResetEvent(false)) {
      var batch=new RuntimeCacheResources(files,binding,new[]{new MutableResourceInput(identity,destination)},(name,mode)=>{
       Need(name=="cache-"+resource+".db"||name=="publication-"+resource+".journal");
       if(mode==System.IO.FileMode.Open) {
        System.Threading.Interlocked.Increment(ref reads); readStarted.Set();
        if(!mayRead.WaitOne(10000)) throw new System.IO.IOException("PERSISTENCE_FAILED");
       }
       return new System.IO.FileStream(System.IO.Path.Combine(root,name),mode,System.IO.FileAccess.ReadWrite,
        System.IO.FileShare.Read,65536,System.IO.FileOptions.WriteThrough);
      },()=>exited);
      try {
       System.IO.File.WriteAllText(path,"latest-A"); batch.CaptureAtCommit();
       Fails("CONFLICT",batch.CaptureAtCommit);
       var mapped=batch.ConfigurationPaths(root); string retained=mapped["vpn-control-mutable:"+resource];
       Need(mapped.Count==1&&System.IO.File.ReadAllText(retained)=="latest-A");
       // This ordinary second writer is the same file-opening boundary used by the captured runtime.
       System.IO.File.WriteAllText(retained,"latest-owned-B");
       if(scenario!=3) batch.MarkCommitIntent();
       Fails("BUSY",batch.BeginPublicationAfterExit); Need(reads==0&&System.IO.File.ReadAllText(path)=="latest-A");
       if(scenario==1) System.IO.File.WriteAllText(path,"external-writer");
       if(scenario==2) System.IO.File.AppendAllText(scopePath," ");
       exited=true; batch.BeginPublicationAfterExit();
       if(scenario==0) {
        Need(readStarted.WaitOne(5000)); var timer=System.Diagnostics.Stopwatch.StartNew();
        Need(batch.Snapshot()==null&&timer.ElapsedMilliseconds<1000); Fails("BUSY",batch.CloseRetainedStreams); mayRead.Set();
       }
       batch.WaitForPublication(); var results=batch.Snapshot(); Need(results!=null&&results.Length==1);
       if(scenario==1) {
        Need(results[0].Disposition=="PENDING_PUBLICATION"&&results[0].Code=="CONFLICT"&&
         System.IO.File.ReadAllText(path)=="external-writer"&&System.IO.File.ReadAllText(retained)=="latest-owned-B");
       } else if(scenario==2) {
        Need(results[0].Disposition=="PENDING_PUBLICATION"&&results[0].Code=="CONFLICT"&&
         System.IO.File.ReadAllText(path)=="latest-A"&&System.IO.File.ReadAllText(retained)=="latest-owned-B");
       } else if(scenario==3) {
        Need(results[0].Disposition=="NO_MUTABLE_HANDOFF"&&reads==0&&System.IO.File.ReadAllText(path)=="latest-A");
       } else {
        Need(results[0].Disposition=="PUBLISHED"&&System.IO.File.ReadAllText(path)=="latest-owned-B");
        System.IO.File.WriteAllText(path,"later-user-write"); batch.BeginPublicationAfterExit(); batch.WaitForPublication();
        Need(reads==1&&System.IO.File.ReadAllText(path)=="later-user-write");
       }
      } finally {
       exited=true; mayRead.Set(); batch.WaitForPublication(); batch.CloseRetainedStreams();
       if(scenario==2) System.IO.File.WriteAllText(scopePath,"{\"schemaVersion\":1,\"scopeId\":\""+scope+"\"}");
      }
      foreach(string name in batch.OwnedNames()) System.IO.File.Delete(System.IO.Path.Combine(root,name));
     }
    }
    System.IO.File.Delete(path); System.IO.File.Delete(scopePath);
    Need(System.IO.Directory.GetFileSystemEntries(root).Length==0); return "CACHE_BATCH_OK:4";
   }
  }
 }
}

namespace VpnScopedStorage {
 public static class ResourceWireProbe {
  static RuntimeResourcePreparation Read(byte[] bytes,OwnerIdentity expected) {
   using(var stream=new System.IO.MemoryStream(bytes))
   using(var reader=new System.IO.BinaryReader(stream,new System.Text.UTF8Encoding(false,true),true)) {
    var result=RuntimeResourcePreparation.ReadForOwner(reader,expected);
    if(stream.Position!=stream.Length) throw new System.IO.IOException("Unconsumed preparation metadata");
    return result;
   }
  }
  static void Need(bool value) { if(!value) throw new System.IO.IOException("Resource preparation contract failed"); }
  public static string Run(string root) {
   string path=System.IO.Path.Combine(root,"preparation.bin");byte[] bytes=System.IO.File.ReadAllBytes(path);
   var owner=new OwnerIdentity(123,456,"S-1-5-21-1-2-3-1001");var preparation=Read(bytes,owner);
   Need(preparation.Binding.JobId=="00000000-0000-0000-0000-000000000031"&&
    preparation.Binding.ScopeId=="00000000-0000-0000-0000-000000000032"&&
    preparation.Binding.ControllerId=="00000000-0000-0000-0000-000000000033");
   Need(preparation.Inputs.Length==2&&preparation.Inputs[0].Identity.Kind=="CACHE"&&preparation.Inputs[1].Identity.Kind=="OUTPUT");
   byte[] roundtrip;
   using(var output=new System.IO.MemoryStream()) {
    using(var writer=new System.IO.BinaryWriter(output,new System.Text.UTF8Encoding(false,true),true)) preparation.Write(writer);
    roundtrip=output.ToArray();
   }
   Need(System.Convert.ToBase64String(bytes)==System.Convert.ToBase64String(roundtrip)&&bytes.Length>65536);
   var copy=preparation.Inputs;copy[0]=null;var entries=preparation.Binding.Resources;entries[0]=null;
   Need(preparation.Inputs[0]!=null&&preparation.Binding.Resources[0]!=null);
   foreach(var foreign in new[]{new OwnerIdentity(124,456,owner.Sid),new OwnerIdentity(123,457,owner.Sid),new OwnerIdentity(123,456,"S-1-5-18")}) {
    bool rejected=false;try { Read(bytes,foreign); } catch(System.IO.IOException failure) { rejected=failure.Message=="PERMISSION_DENIED"; }
    Need(rejected);
   }
   byte[] partial=new byte[bytes.Length-1];System.Buffer.BlockCopy(bytes,0,partial,0,partial.Length);
   bool incomplete=false;try { Read(partial,owner); } catch(System.IO.IOException failure) { incomplete=failure.Message=="OUTCOME_UNKNOWN"; }
   Need(incomplete);
   string digest;using(var hash=System.Security.Cryptography.SHA256.Create()) digest=System.BitConverter.ToString(hash.ComputeHash(roundtrip)).Replace("-","").ToLowerInvariant();
   System.IO.File.Delete(path);return "RESOURCE_WIRE_OK:6:"+digest;
  }
 }
}
