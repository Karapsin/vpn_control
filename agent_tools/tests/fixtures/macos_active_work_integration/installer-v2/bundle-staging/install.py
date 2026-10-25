"""Fixed, zero-argument root installer; SOURCE ONLY until separately admitted.

No password handling, arbitrary command, launchd/service operation or rollback.
The already authorized SecurityAgent route supplies root to this fixed source.
"""
import hashlib,json,os,pwd,signal,stat,subprocess,sys,time,types
from pathlib import Path

CONFIG = {'operationId': 'ca6919f5-137e-4a1e-a68b-bef546c230da', 'originalRun': '2d933a39-0fb6-46a4-9fd9-02221d81c4b9', 'machine': 'ecdc399a-8f2b-5410-b85d-e4db56ddc6c1', 'boot': '87ac272f-619b-4cc0-b9fc-3e32daee5b18', 'bundle': '/Volumes/My Shared Files/bootstrap/active-work-4a9f62cc', 'leafName': 'vpn-tool-recovery-idle-4a9f62cc-6a93-4cd7-86c3-4b4ab81a4dc7', 'intentName': 'vpn-tool-recovery-idle-4a9f62cc-6a93-4cd7-86c3-4b4ab81a4dc7.install-intent.json', 'ruleName': 'vpn-tool-recovery-active-work-4a9f62cc', 'candidateRule': '/usr/local/libexec/vpn-tool-recovery-idle-4a9f62cc-6a93-4cd7-86c3-4b4ab81a4dc7/sudoers.candidate', 'pythonCanonical': '/usr/local/libexec/vpn-tool-recovery-cont-63517582/python/bin/python3.12', 'pythonSha256': '3274dde21f9767655564d093e63c9a5faacefbf1d41bc1e6bf8b6f6e5a441903', 'probeSha256': 'dc535e8943efc18051bf606200174dd0c103aca80bc39bcddc90946f757cc157', 'mainSha256': 'b94198b6c5457a5a6ab438577a9fed8e955a0c32dd3e214d5c7e08bd03af2bbb', 'callerSha256': '950d371680c7d8f42fda76b89ee9af480e046689c51268917b2074de2f2b3eea', 'oldRule': '/private/etc/sudoers.d/vpn-tool-recovery-readonly', 'oldRuleBytes': 'toolrecovery ALL=(root) NOPASSWD: /usr/local/libexec/vpn-tool-recovery-cont-63517582/readonly-probe ""\n', 'newRuleBytes': 'toolrecovery ALL=(root) NOPASSWD: /usr/local/libexec/vpn-tool-recovery-idle-4a9f62cc-6a93-4cd7-86c3-4b4ab81a4dc7/main.py ""\n', 'oldPublicFiles': {'/usr/local/libexec/vpn-tool-recovery-cont-63517582/tart-guest-agent': '8bbbffe09d207164cbabc06a2b2f5085e041290e75247d28db0a0e1fa852646e', '/usr/local/libexec/vpn-tool-recovery-cont-63517582/guest-probe.py': 'b144862272b3bbb5464bcdb3ed57403d76d4f5418c4388c859195f9afb3c38ab', '/usr/local/libexec/vpn-tool-recovery-cont-63517582/guest-probe-main.py': '24609b579b77af73292f91ac8756e9efedfeeebbd04e896f7787df6ec252407a', '/usr/local/libexec/vpn-tool-recovery-cont-63517582/readonly-probe': '988b4b8835b21da9866914e09c86e77fa1446d81c536ebc68cf5a97789d502ab', '/Library/LaunchDaemons/com.vpn-control.tool-recovery.agent.plist': '7dd0b139e5b7f0c567c6a8810e015132699ecb3620c39769768181d28eff0c80'}, 'bundleManifest': {'schemaVersion': 1, 'purpose': 'fixed_active_work_diagnostic_install', 'operationId': 'ca6919f5-137e-4a1e-a68b-bef546c230da', 'originalRun': '2d933a39-0fb6-46a4-9fd9-02221d81c4b9', 'helperPrefix': '/usr/local/libexec/vpn-tool-recovery-idle-4a9f62cc-6a93-4cd7-86c3-4b4ab81a4dc7', 'mainSha256': 'b94198b6c5457a5a6ab438577a9fed8e955a0c32dd3e214d5c7e08bd03af2bbb', 'callerSha256': '950d371680c7d8f42fda76b89ee9af480e046689c51268917b2074de2f2b3eea', 'probeSha256': 'dc535e8943efc18051bf606200174dd0c103aca80bc39bcddc90946f757cc157', 'nativeQualified': False, 'idleAuthority': False, 'inputAuthority': False, 'lifecycleAuthority': False}}
PROBE = b'"""Fixed read-only macOS GUEST probe; no admission, dispatch or lifecycle actions.\n\nOnly the fixture owner may execute main in its isolated guest. Importing this\nmodule never opens a framework or observes the coordinator host. Unqualified\nlaunchd/job baselines deliberately leave complete idle visibility false.\n\nNative API references:\nhttps://developer.apple.com/documentation/systemconfiguration/scdynamicstorecopyconsoleuser(_:_:_:)\nhttps://developer.apple.com/documentation/coregraphics/cgsessioncopycurrentdictionary()\nhttps://developer.apple.com/documentation/coregraphics/cggetonlinedisplaylist(_:_:_:)\nhttps://developer.apple.com/documentation/coregraphics/cgdisplayisasleep(_:)\nhttps://developer.apple.com/documentation/iokit/1514293-ioregistryentrycreatecfproperty\nhttps://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h\n"""\nfrom __future__ import annotations\nimport ctypes as C\nimport json\nimport os\nimport plistlib\nif os.name == \'posix\':\n    import pwd\nelse:\n    pwd = None\nimport re\nimport sys\nimport uuid\n\n\nclass ProbeUnavailable(ValueError):\n    pass\n\n\ndef _uuid(value):\n    if type(value)is not str:\n        raise ProbeUnavailable(\'macos_identity_unavailable\')\n    try:actual=str(uuid.UUID(value))\n    except ValueError:raise ProbeUnavailable(\'macos_identity_unavailable\') from None\n    if actual!=value.lower():raise ProbeUnavailable(\'macos_identity_unavailable\')\n    return actual\n\n\ndef _one(row,keys,kind):\n    values=[row[k] for k in keys if k in row]\n    if not values or any(type(v)is not kind for v in values)or any(v!=values[0]for v in values):return None\n    return values[0]\n\n\ndef console_facts(name,uid,rows,caller=None,global_locked=None):\n    """Never interpret an absent lock key or a non-console caller as unlocked."""\n    result={\'name\':None,\'uid\':None,\'onConsole\':None,\'locked\':None,\'session\':None}\n    if (type(name)is not str or not name or len(name)>256 or any(ord(c)<32 for c in name)\n            or type(uid)is not int or uid<0):return result\n    result.update(name=name,uid=uid)\n    if name in {\'loginwindow\',\'root\',\'_mbsetupuser\'}or uid<501:return result\n    candidates=[]\n    for row in rows if type(rows)is list else []:\n        if type(row)is not dict:continue\n        row_uid=_one(row,(\'kCGSSessionUserIDKey\',\'kCGSessionUserIDKey\'),int)\n        row_name=_one(row,(\'kCGSSessionUserNameKey\',\'kCGSessionUserNameKey\'),str)\n        if row_uid==uid and row_name==name:candidates.append(row)\n    if type(caller)is dict:\n        if (_one(caller,(\'kCGSSessionUserIDKey\',\'kCGSessionUserIDKey\'),int)==uid\n                and _one(caller,(\'kCGSSessionUserNameKey\',\'kCGSessionUserNameKey\'),str)==name):candidates.append(caller)\n    active=[row for row in candidates if _one(row,(\'kCGSSessionOnConsoleKey\',\'kCGSessionOnConsoleKey\'),bool)is True]\n    if not active:return result\n    sessions=[_one(row,(\'kSCSecuritySessionID\',),int)for row in active]\n    if any(s is None or s<0 for s in sessions)or len(set(sessions))!=1:return result\n    result.update(onConsole=True,session=str(sessions[0]))\n    locks=[]\n    for row in active:\n        if any(k in row for k in (\'CGSSessionScreenIsLocked\',\'IOConsoleLocked\')):\n            value=_one(row,(\'CGSSessionScreenIsLocked\',\'IOConsoleLocked\'),bool)\n            if type(value)is not bool:return result\n            locks.append(value)\n    if global_locked is not None:\n        if type(global_locked)is not bool:return result\n        locks.append(global_locked)\n    # A partial/ambiguous dictionary remains unknown, even on the console.\n    if locks and all(type(v)is bool for v in locks)and len(set(locks))==1:result[\'locked\']=locks[0]\n    return result\n\n\ndef display_facts(rows):\n    if (type(rows)is not list or not 1<=len(rows)<=64 or\n            any(type(row)is not tuple or len(row)!=2 or type(row[0])is not int or row[0]<=0\n                or type(row[1])is not bool for row in rows)or len({v[0]for v in rows})!=len(rows)):\n        return \'unknown\'\n    return \'sleeping\' if all(row[1]for row in rows)else \'ready\'\n\n\n_PROTECTED=re.compile(r\'(sing.?box|vpn.?control|openvpn|wireguard|tailscaled|zerotier|charon|strongswan|pppd)\',re.I)\n_INSTALLER=re.compile(r\'^(installer|installd|system_installd|softwareupdated|softwareupdate|osinstallersetupd|osinstaller|startosinstall|installassistant|packagekit)$\',re.I)\n\n\ndef process_facts(first,second,*,observer_pid,observer_uid):\n    """Root must observe every stable process; unqualified baseline blocks idle."""\n    complete=observer_uid==0 and type(first)is list and type(second)is list\n    def project(rows):\n        seen={};facts=[]\n        for row in rows if type(rows)is list else []:\n            if (type(row)is not dict or set(row)!={\'pid\',\'uid\',\'birth\',\'path\'}\n                    or type(row[\'pid\'])is not int or row[\'pid\']<=0\n                    or type(row[\'uid\'])is not int or row[\'uid\']<0\n                    or type(row[\'birth\'])is not tuple or len(row[\'birth\'])!=2\n                    or any(type(n)is not int or n<0 for n in row[\'birth\']) or row[\'birth\'][0]==0 or row[\'birth\'][1]>=1000000\n                    or type(row[\'path\'])is not str or not row[\'path\'].startswith(\'/\')\n                    or row[\'pid\']in seen):raise ProbeUnavailable(\'macos_process_visibility_incomplete\')\n            seen[row[\'pid\']]=row\n            role=(\'verified_probe\'if row[\'pid\']==observer_pid else\n                  \'protected_runtime\'if _PROTECTED.search(row[\'path\'])else\n                  \'installer\'if _INSTALLER.fullmatch(row[\'path\'].rsplit(\'/\',1)[-1])else \'unmanaged\')\n            facts.append({\'pid\':row[\'pid\'],\'uid\':row[\'uid\'],\'birth\':\'darwin:\'+str(row[\'birth\'][0])+\':\'+str(row[\'birth\'][1]),\'executableRole\':role})\n        return seen,sorted(facts,key=lambda r:r[\'pid\'])\n    try:\n        one,rows=project(first);two,_=project(second)\n        complete=complete and one==two and observer_pid in one\n    except ProbeUnavailable:complete=False;rows=[]\n    protected=[row[\'pid\']for row in rows if row[\'executableRole\']==\'protected_runtime\']\n    installers=[row[\'pid\']for row in rows if row[\'executableRole\']==\'installer\']\n    unmanaged=[{\'pid\':row[\'pid\'],\'uid\':row[\'uid\'],\'birth\':row[\'birth\'],\'role\':row[\'executableRole\']}for row in rows if row[\'executableRole\']!=\'verified_probe\']\n    return {\'processVisibilityComplete\':complete,\'processes\':rows,\'protectedProcesses\':protected,\n            \'installerVisibilityComplete\':complete,\'installerBlockers\':installers,\n            \'jobVisibilityComplete\':False,\'runningJobs\':unmanaged,\n            \'unknownJobs\':[{\'role\':\'macos_launchd_and_durable_job_baseline_unqualified\'}]}\n\n\nclass _Bsd(C.Structure):\n    _fields_=[(n,C.c_uint32)for n in (\'flags\',\'status\',\'xstatus\',\'pid\',\'ppid\',\'uid\',\'gid\',\'ruid\',\'rgid\',\'svuid\',\'svgid\',\'reserved\')]+[\n        (\'comm\',C.c_char*16),(\'name\',C.c_char*32)]+[(n,C.c_uint32)for n in (\'nfiles\',\'pgid\',\'pjobc\',\'tdev\',\'tpgid\')]+[\n        (\'nice\',C.c_int32),(\'start_seconds\',C.c_uint64),(\'start_microseconds\',C.c_uint64)]\n\n\nclass _Timeval(C.Structure):\n    _fields_=[(\'seconds\',C.c_long),(\'microseconds\',C.c_int32)]\n\n\nclass Native:\n    """Fixed read-only C entrypoints; instantiated only inside guest collect."""\n    def __init__(self):\n        if sys.platform!=\'darwin\':raise ProbeUnavailable(\'macos_guest_required\')\n        self.cf=C.CDLL(\'/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation\')\n        self.cg=C.CDLL(\'/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics\')\n        self.sc=C.CDLL(\'/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration\')\n        self.io=C.CDLL(\'/System/Library/Frameworks/IOKit.framework/IOKit\')\n        self.lib=C.CDLL(\'/usr/lib/libSystem.B.dylib\',use_errno=True)\n        self.proc=C.CDLL(\'/usr/lib/libproc.dylib\',use_errno=True)\n        self._fn(self.cf,\'CFRelease\',None,[C.c_void_p])\n        self._fn(self.cf,\'CFStringCreateWithCString\',C.c_void_p,[C.c_void_p,C.c_char_p,C.c_uint32])\n        self._fn(self.cf,\'CFPropertyListCreateData\',C.c_void_p,[C.c_void_p,C.c_void_p,C.c_long,C.c_ulong,C.POINTER(C.c_void_p)])\n        self._fn(self.cf,\'CFDataGetLength\',C.c_long,[C.c_void_p]);self._fn(self.cf,\'CFDataGetBytePtr\',C.c_void_p,[C.c_void_p])\n        self._fn(self.sc,\'SCDynamicStoreCopyConsoleUser\',C.c_void_p,[C.c_void_p,C.POINTER(C.c_uint32),C.POINTER(C.c_uint32)])\n        self._fn(self.cg,\'CGSessionCopyCurrentDictionary\',C.c_void_p,[])\n        self._fn(self.cg,\'CGGetOnlineDisplayList\',C.c_int,[C.c_uint32,C.POINTER(C.c_uint32),C.POINTER(C.c_uint32)])\n        self._fn(self.cg,\'CGDisplayIsAsleep\',C.c_uint32,[C.c_uint32])\n        self._fn(self.io,\'IORegistryGetRootEntry\',C.c_uint32,[C.c_uint32])\n        self._fn(self.io,\'IOServiceMatching\',C.c_void_p,[C.c_char_p]);self._fn(self.io,\'IOServiceGetMatchingService\',C.c_uint32,[C.c_uint32,C.c_void_p])\n        self._fn(self.io,\'IORegistryEntryCreateCFProperty\',C.c_void_p,[C.c_uint32,C.c_void_p,C.c_void_p,C.c_uint32])\n        self._fn(self.io,\'IOObjectRelease\',C.c_int,[C.c_uint32])\n        self._fn(self.lib,\'sysctlbyname\',C.c_int,[C.c_char_p,C.c_void_p,C.POINTER(C.c_size_t),C.c_void_p,C.c_size_t])\n        self._fn(self.proc,\'proc_listallpids\',C.c_int,[C.c_void_p,C.c_int])\n        self._fn(self.proc,\'proc_pidinfo\',C.c_int,[C.c_int,C.c_int,C.c_uint64,C.c_void_p,C.c_int])\n        self._fn(self.proc,\'proc_pidpath\',C.c_int,[C.c_int,C.c_void_p,C.c_uint32])\n    @staticmethod\n    def _fn(lib,name,result,args):\n        fn=getattr(lib,name);fn.restype=result;fn.argtypes=args\n    def value(self,owned):\n        if not owned:return None\n        data=None;error=C.c_void_p()\n        try:\n            data=self.cf.CFPropertyListCreateData(None,owned,100,0,C.byref(error))\n            if not data:raise ProbeUnavailable(\'macos_property_unavailable\')\n            size=self.cf.CFDataGetLength(data)\n            if not 0<size<=2*1024*1024:raise ProbeUnavailable(\'macos_property_overflow\')\n            return plistlib.loads(C.string_at(self.cf.CFDataGetBytePtr(data),size))\n        finally:\n            if error.value:self.cf.CFRelease(error)\n            if data:self.cf.CFRelease(data)\n            self.cf.CFRelease(owned)\n    def property(self,service,key):\n        text=self.cf.CFStringCreateWithCString(None,key.encode(\'ascii\'),0x08000100)\n        if not text:raise ProbeUnavailable(\'macos_property_unavailable\')\n        try:return self.value(self.io.IORegistryEntryCreateCFProperty(service,text,None,0))\n        finally:self.cf.CFRelease(text)\n    def machine(self):\n        entry=self.io.IOServiceGetMatchingService(0,self.io.IOServiceMatching(b\'IOPlatformExpertDevice\'))\n        if not entry:raise ProbeUnavailable(\'macos_identity_unavailable\')\n        try:return _uuid(self.property(entry,\'IOPlatformUUID\'))\n        finally:self.io.IOObjectRelease(entry)\n    def boot(self):\n        buffer=C.create_string_buffer(128);size=C.c_size_t(len(buffer))\n        if self.lib.sysctlbyname(b\'kern.bootsessionuuid\',buffer,C.byref(size),None,0)or not 1<size.value<=128:raise ProbeUnavailable(\'macos_boot_unavailable\')\n        boot=_uuid(buffer.value.decode(\'ascii\'))\n        value=_Timeval();size=C.c_size_t(C.sizeof(value))\n        if self.lib.sysctlbyname(b\'kern.boottime\',C.byref(value),C.byref(size),None,0)or size.value!=C.sizeof(value)or value.seconds<=0 or not 0<=value.microseconds<1000000:raise ProbeUnavailable(\'macos_boot_unavailable\')\n        return boot,{\'seconds\':value.seconds,\'microseconds\':value.microseconds}\n    def console(self):\n        uid=C.c_uint32();gid=C.c_uint32()\n        name=self.value(self.sc.SCDynamicStoreCopyConsoleUser(None,C.byref(uid),C.byref(gid)))\n        entry=self.io.IORegistryGetRootEntry(0)\n        try:\n            rows=self.property(entry,\'IOConsoleUsers\')if entry else None\n            locked=self.property(entry,\'IOConsoleLocked\')if entry else None\n        finally:\n            if entry:self.io.IOObjectRelease(entry)\n        caller=self.value(self.cg.CGSessionCopyCurrentDictionary())\n        return console_facts(name,uid.value,rows,caller,locked)\n    def displays(self):\n        def snapshot():\n            count=C.c_uint32()\n            if self.cg.CGGetOnlineDisplayList(0,None,C.byref(count))or not 1<=count.value<=64:return None\n            expected=count.value;array=(C.c_uint32*expected)()\n            if self.cg.CGGetOnlineDisplayList(expected,array,C.byref(count))or count.value!=expected:return None\n            values=[(int(d),self.cg.CGDisplayIsAsleep(d))for d in array]\n            if any(v not in (0,1)for _,v in values):return None\n            return [(d,bool(v))for d,v in values]\n        first=snapshot();second=snapshot()\n        return display_facts(first)if first is not None and first==second else \'unknown\'\n    def processes(self):\n        total=self.proc.proc_listallpids(None,0)\n        if not 0<total<65536:raise ProbeUnavailable(\'macos_process_visibility_incomplete\')\n        capacity=min(total+256,65536);array=(C.c_int*capacity)()\n        count=self.proc.proc_listallpids(array,C.sizeof(array))\n        if not 0<count<capacity:raise ProbeUnavailable(\'macos_process_visibility_incomplete\')\n        result=[]\n        for pid in array[:count]:\n            if pid==0:continue # kernel task is outside the user-process namespace\n            info=_Bsd();path=C.create_string_buffer(4096)\n            if (pid<0 or self.proc.proc_pidinfo(pid,3,0,C.byref(info),C.sizeof(info))!=C.sizeof(info)\n                    or info.pid!=pid):raise ProbeUnavailable(\'macos_process_visibility_incomplete\')\n            path_size=self.proc.proc_pidpath(pid,path,len(path))\n            if not 0<path_size<len(path):raise ProbeUnavailable(\'macos_process_visibility_incomplete\')\n            result.append({\'pid\':pid,\'uid\':info.uid,\'birth\':(info.start_seconds,info.start_microseconds),\'path\':path.value.decode(\'utf-8\',\'strict\')})\n        return result\n\n\ndef collect(ordinary_account):\n    if os.name!=\'posix\' or pwd is None:raise ProbeUnavailable(\'macos_guest_required\')\n    if type(ordinary_account)is not str or re.fullmatch(r\'[A-Za-z][A-Za-z0-9_-]{0,63}\',ordinary_account)is None:raise ProbeUnavailable(\'macos_ordinary_account_unavailable\')\n    try:account=pwd.getpwnam(ordinary_account)\n    except KeyError:raise ProbeUnavailable(\'macos_ordinary_account_unavailable\')from None\n    if account.pw_uid<501 or not account.pw_dir.startswith(\'/Users/\'):raise ProbeUnavailable(\'macos_ordinary_account_unavailable\')\n    try:native=Native()\n    except (OSError,AttributeError):raise ProbeUnavailable(\'macos_native_api_unavailable\')from None\n    machine=native.machine();boot,boot_time=native.boot()\n    observer=pwd.getpwuid(os.geteuid())\n    try:console=native.console()\n    except (OSError,ValueError,TypeError,AttributeError):console=console_facts(None,None,None)\n    try:display=native.displays()\n    except (OSError,ValueError,TypeError,AttributeError):display=\'unknown\'\n    try:first=native.processes();second=native.processes()\n    except (OSError,ValueError,UnicodeError):first=second=None\n    facts=process_facts(first,second,observer_pid=os.getpid(),observer_uid=os.geteuid())\n    final_boot,final_time=native.boot()\n    if final_boot!=boot or final_time!=boot_time or native.machine()!=machine:raise ProbeUnavailable(\'macos_identity_changed\')\n    return {\'machine\':machine,\'boot\':boot,\'bootTime\':boot_time,\'uid\':account.pw_uid,\n            \'account\':account.pw_name,\'home\':account.pw_dir,\n            \'observerUid\':os.geteuid(),\'observerAccount\':observer.pw_name,\'observerHome\':observer.pw_dir,\n            \'console\':console,\'display\':display,**facts}\n\n\ndef main():\n    try:value=collect(globals().get(\'__ordinary_account__\'))\n    except (ProbeUnavailable,OSError,UnicodeError)as error:\n        reason=str(error)if isinstance(error,ProbeUnavailable)else \'macos_observation_unavailable\'\n        print(json.dumps({\'state\':\'blocked\',\'reason\':reason},sort_keys=True));raise SystemExit(3)\n    print(json.dumps(value,sort_keys=True))\n\nif __name__==\'__main__\':main()\n'
_CODE = sys._getframe().f_code
MAX_SOURCE = 262144
class Refused(ValueError): pass
def need(value,reason):
    if not value: raise Refused(reason)
def generation(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def directory_identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)
def write_all(fd,raw):
    offset=0
    while offset<len(raw):
        n=os.write(fd,raw[offset:]);need(n>0,'write_unavailable');offset+=n
def strict_json(raw):
    def pairs(items):
        out={}
        for k,v in items:
            need(k not in out,'duplicate_json');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Refused('nonfinite_json')))
class Held:
    """No-follow named ancestry and held files. Directories use structural IDs:
    own create-only installation legitimately changes their ctime/nlink.
    """
    def __init__(self):self.fds=[];self.links=[]
    def open(self,path,*,protected,regular=False,limit=MAX_SOURCE,digest=None):
        parts=Path(path).parts;need(parts and parts[0]=='/','absolute_path_required')
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self.fds.append((parent,directory_identity(os.fstat(parent)),True))
        for index,name in enumerate(parts[1:]):
            before=os.stat(name,dir_fd=parent,follow_symlinks=False)
            is_dir=stat.S_ISDIR(before.st_mode);last=index==len(parts)-2
            need(is_dir or last and regular and stat.S_ISREG(before.st_mode),'source_type')
            if protected:need(before.st_uid==0 and before.st_mode&0o022==0,'source_owner_mode')
            flags=os.O_RDONLY|os.O_NOFOLLOW|(os.O_DIRECTORY if is_dir else os.O_NONBLOCK)
            fd=os.open(name,flags,dir_fd=parent);after=os.fstat(fd)
            need(generation(before)==generation(after),'source_replaced')
            identity=directory_identity(before) if is_dir else generation(before)
            self.fds.append((fd,identity,is_dir));self.links.append((parent,name,identity,is_dir));parent=fd
        if regular:
            info=os.fstat(parent);need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=limit,'source_size_links')
            raw=b''
            while len(raw)<=limit:
                part=os.read(parent,min(65536,limit-len(raw)+1))
                if not part:break
                raw+=part
            need(len(raw)==info.st_size and len(raw)<=limit,'source_read')
            if digest is not None:need(hashlib.sha256(raw).hexdigest()==digest,'source_digest')
            self.guard();return raw
        need(stat.S_ISDIR(os.fstat(parent).st_mode),'parent_type');self.guard();return parent
    def guard(self):
        for fd,pin,is_dir in self.fds:
            current=os.fstat(fd);need((directory_identity(current) if is_dir else generation(current))==pin,'held_source_changed')
        for fd,name,pin,is_dir in self.links:
            current=os.stat(name,dir_fd=fd,follow_symlinks=False)
            need((directory_identity(current) if is_dir else generation(current))==pin,'named_source_changed')
    def close(self):
        for fd,_,_ in reversed(self.fds):os.close(fd)
        self.fds=[];self.links=[]
def absent(parent,name):
    try:os.stat(name,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError:return
    raise Refused('original_installation_present')
def exclusive(parent,name,raw,mode):
    need(type(raw) is bytes and len(raw)<=MAX_SOURCE,'write_limit')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
    try:
        write_all(fd,raw);os.fchown(fd,0,0);os.fchmod(fd,mode);os.fsync(fd)
        result=generation(os.fstat(fd))
    finally:os.close(fd)
    os.fsync(parent);return list(result)
def record(parent,name,value,mode=0o600):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    return exclusive(parent,name,raw,mode)
def identity(probe):
    machine=probe.machine();boot,_=probe.boot()
    need(machine==CONFIG['machine'] and boot==CONFIG['boot'],'selected_guest_changed')
    ordinary=pwd.getpwnam('toolrecovery');admin=pwd.getpwnam('toolbootstrap')
    need((ordinary.pw_uid,ordinary.pw_dir)==(502,'/Users/toolrecovery') and admin.pw_uid==501,'account_changed')
    need(80 not in os.getgrouplist(ordinary.pw_name,ordinary.pw_gid) and 80 in os.getgrouplist(admin.pw_name,admin.pw_gid),'account_privilege_changed')
    return {'machine':machine,'boot':boot,'ordinaryUid':502,'administratorUid':501}
def validate_rule(rule,leaf):
    # A fixed allowlisted executable and one fixed candidate pathname. No shell,
    # caller-supplied argument, stdin command or password channel is accepted.
    need(rule==CONFIG['candidateRule'],'rule_path_changed')
    child=subprocess.Popen(['/usr/sbin/visudo','-cf',rule],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
    record(leaf,'visudo-child-started.json',{'schemaVersion':1,'pid':child.pid,'state':'owned_direct_child_wait_pending','absenceQualified':False})
    # wait() times out without signaling. A timeout leaves the once intent and
    # exact own-child record UNKNOWN; it cannot silently publish authorization.
    try:code=child.wait(timeout=5)
    except subprocess.TimeoutExpired:raise Refused('sudoers_validation_pending') from None
    record(leaf,'visudo-child-waited.json',{'schemaVersion':1,'pid':child.pid,'returnCode':code,'waitpidCompleted':True})
    need(type(code)is int and code==0,'sudoers_validation_failed')
def run():
    need(len(sys.argv)==1 and sys.platform=='darwin' and os.geteuid()==0 and os.getuid()==0,'installer_context')
    signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(40)
    held=Held()
    try:
        # __source_digest__ is injected ONLY by the exact pinned source gate;
        # neither the caller nor installer exposes a CLI override.
        need(type(globals().get('__source_digest__'))is str,'source_gate_missing')
        own=held.open(CONFIG['bundle']+'/install.py',protected=False,regular=True,digest=__source_digest__)
        need(_CODE==compile(own,__file__,'exec',dont_inherit=True),'executed_source_changed')
        need(hashlib.sha256(PROBE).hexdigest()==CONFIG['probeSha256'],'captured_probe_changed')
        m=types.ModuleType('_fixed_install_probe');exec(compile(PROBE,'<fixed-install-probe>','exec'),m.__dict__)
        probe=m.Native();initial=identity(probe)
        need(os.path.realpath(sys.executable)==CONFIG['pythonCanonical'],'interpreter_changed')
        held.open(CONFIG['pythonCanonical'],protected=True,regular=True,limit=134217728,digest=CONFIG['pythonSha256'])
        for path,digest in CONFIG['oldPublicFiles'].items():held.open(path,protected=True,regular=True,limit=134217728,digest=digest)
        old_rule=held.open(CONFIG['oldRule'],protected=True,regular=True,limit=4096)
        need(old_rule==CONFIG['oldRuleBytes'].encode(),'old_sudoers_changed')
        main=held.open(CONFIG['bundle']+'/main.py',protected=False,regular=True,digest=CONFIG['mainSha256'])
        caller=held.open(CONFIG['bundle']+'/caller.py',protected=False,regular=True,digest=CONFIG['callerSha256'])
        manifest=held.open(CONFIG['bundle']+'/bundle.json',protected=False,regular=True,limit=16384)
        need(strict_json(manifest)==CONFIG['bundleManifest'],'bundle_manifest_changed')
        held.open(CONFIG['bundle']+'/authorization.applescript',protected=False,regular=True,limit=32768)
        parent=held.open('/usr/local/libexec',protected=True)
        rules=held.open('/private/etc/sudoers.d',protected=True)
        for fd,name in ((parent,CONFIG['leafName']),(parent,CONFIG['intentName']),(rules,CONFIG['ruleName'])):absent(fd,name)
        held.guard();need(identity(probe)==initial,'selected_guest_changed')
        # Once intent comes BEFORE the first code or authorization leaf write.
        # A lost ACK/partial install must be observed, never re-run or removed.
        intent={'schemaVersion':1,'kind':'fixed_diagnostic_install_intent','operationId':CONFIG['operationId'],'originalRun':CONFIG['originalRun'],'identity':initial,'installerSha256':__source_digest__,'mainSha256':CONFIG['mainSha256'],'callerSha256':CONFIG['callerSha256'],'pid':os.getpid(),'state':'once_installation_started','idleAuthority':False}
        record(parent,CONFIG['intentName'],intent)
        os.mkdir(CONFIG['leafName'],0o755,dir_fd=parent);os.fsync(parent)
        leaf=os.open(CONFIG['leafName'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            # mkdir is subject to the administrator's inherited umask. Establish
            # and verify the exact root:wheel0755 leaf before copying any code.
            os.fchown(leaf,0,0);os.fchmod(leaf,0o755)
            leaf_info=os.fstat(leaf)
            need(stat.S_ISDIR(leaf_info.st_mode)and(leaf_info.st_uid,leaf_info.st_gid,stat.S_IMODE(leaf_info.st_mode))==(0,0,0o755),'new_leaf_owner_mode')
            main_pin=exclusive(leaf,'main.py',main,0o555);caller_pin=exclusive(leaf,'caller.py',caller,0o444)
            exclusive(leaf,'sudoers.candidate',CONFIG['newRuleBytes'].encode(),0o400)
            held.open('/usr/local/libexec/'+CONFIG['leafName']+'/main.py',protected=True,regular=True,digest=CONFIG['mainSha256'])
            held.open('/usr/local/libexec/'+CONFIG['leafName']+'/caller.py',protected=True,regular=True,digest=CONFIG['callerSha256'])
            held.open(CONFIG['candidateRule'],protected=True,regular=True,limit=4096,digest=hashlib.sha256(CONFIG['newRuleBytes'].encode()).hexdigest())
            held.guard();need(identity(probe)==initial,'selected_guest_changed');validate_rule(CONFIG['candidateRule'],leaf)
            # visudo is an actual asynchronous boundary. Reclose source and
            # identity AFTER its original wait and BEFORE the privilege effect.
            held.guard();need(identity(probe)==initial,'selected_guest_changed')
            # The old zero-arg rule is untouched. The new exact leaf is the last
            # privilege effect, after code/source/identity and syntax validation.
            rule_pin=exclusive(rules,CONFIG['ruleName'],CONFIG['newRuleBytes'].encode(),0o440)
            held.open('/private/etc/sudoers.d/'+CONFIG['ruleName'],protected=True,regular=True,limit=4096,digest=hashlib.sha256(CONFIG['newRuleBytes'].encode()).hexdigest())
            held.guard();need(identity(probe)==initial,'selected_guest_changed')
            receipt={'schemaVersion':1,'kind':'fixed_diagnostic_installation_complete','operationId':CONFIG['operationId'],'originalRun':CONFIG['originalRun'],'identity':initial,'installerSha256':__source_digest__,'publicFiles':{'main.py':{'sha256':CONFIG['mainSha256'],'generation':main_pin},'caller.py':{'sha256':CONFIG['callerSha256'],'generation':caller_pin}},'sudoers':{'sha256':hashlib.sha256(CONFIG['newRuleBytes'].encode()).hexdigest(),'generation':rule_pin},'idleAuthority':False,'inputAuthority':False,'lifecycleAuthority':False,'state':'installed_not_native_qualified'}
            record(leaf,'installation-complete.json',receipt,0o444)
        finally:os.close(leaf)
        held.guard();need(identity(probe)==initial,'selected_guest_changed')
        print('{"schemaVersion":1,"state":"installed_not_native_qualified","idleAuthority":false}')
    finally:held.close()
if __name__=='__main__':
    try:run()
    except Exception:
        # Arbitrary exception text can include source paths. Emit finite state;
        # once intent / partial leaf preserve the original effect for observation.
        print('{"schemaVersion":1,"state":"blocked_installation_observe_original","idleAuthority":false}')
        raise SystemExit(3)
