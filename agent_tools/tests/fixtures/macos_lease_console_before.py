"""Fixed guest-only macOS assertion leases, pending native Tart qualification.

This internal adapter never chooses a transport or a guest. Its caller supplies
the original trusted namespace and actual guest binding. Rendering is inert;
acquisition executes inside the admitted ordinary guest. There is deliberately
no public source, executable, environment, settings or credential parameter.
Status uses retained original receipts; cancellation addresses the original UUID
and never signals a PID. Reconciliation can only attest assertion absence after
the original child has exited and the durable wrapper has closed its streams.

The controlled socket backend is a private test fixture. It proves the durable
protocol, not macOS behavior. No Tart capability is enabled by this module.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import sys
import uuid

from . import durable_remote_job as jobs

_EXECUTING_CODE = sys._getframe().f_code
MAX_TTL_SECONDS = 18_000
NATIVE_QUALIFIED = False
_PURPOSE = "tart-macos-assertion-lease-v1"
_KINDS = ("PreventUserIdleSystemSleep", "PreventUserIdleDisplaySleep")


class MacLeaseError(ValueError):
    """Finite nonsecret reason only."""


def _need(value, reason):
    if not value:
        raise MacLeaseError(reason)


@dataclass(frozen=True)
class MacLeaseBinding:
    target: str
    machine: str
    boot: str
    account: str
    principal: str
    home: str
    session: str

    def __post_init__(self):
        self.job_binding()
        for key in ("machine", "boot"):
            value = getattr(self, key)
            try:
                _need(type(value) is str and str(uuid.UUID(value)) == value.lower(), "macos_binding_invalid")
            except (ValueError, AttributeError, TypeError):
                raise MacLeaseError("macos_binding_invalid") from None
        _need(type(self.account) is str and re.fullmatch(r"[1-9][0-9]{2,9}", self.account)
              and 501 <= int(self.account) <= 2**32-2, "macos_account_invalid")
        _need(type(self.principal) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", self.principal)
              and self.principal not in {"root", "loginwindow"}, "macos_account_invalid")
        _need(self.home == "/Users/" + self.principal, "macos_home_invalid")
        _need(type(self.session) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", self.session),
              "macos_session_invalid")

    def job_binding(self):
        return jobs.MachineBinding(self.target, self.machine, self.boot, self.account)


def _ttl(value):
    _need(type(value) in (int, float) and math.isfinite(value) and .1 <= value <= MAX_TTL_SECONDS,
          "macos_lease_ttl_invalid")
    return value


def _program(root, operation, binding, ttl, *, controlled=None):
    _need(type(binding) is MacLeaseBinding, "macos_binding_invalid")
    if controlled is None:
        binding.__post_init__()
    operation = jobs._uuid(operation)
    root = jobs._root(root)
    payload = {"root": str(root), "operationId": operation, "binding": asdict(binding),
               "ttlSeconds": _ttl(ttl), "controlled": controlled}
    # Copy a fixed repository-owned probe, never a caller-selected source. The
    # backend's source custody must pin this dependency before any guest effect.
    probe = b""
    if controlled is None:
        probe = (Path(__file__).parent / "tart_macos_probe.py").read_bytes()
        _need(len(probe) <= 262144, "macos_probe_source_invalid")
        compile(probe, "fixed-macos-probe", "exec")
    source = ("import sys,types\nDmod=types.ModuleType('macos_lease_job_snapshot')\n"
              "sys.modules[Dmod.__name__]=Dmod\nD=Dmod.__dict__\nexec(" + repr(jobs.owner_source()) + ",D)\n"
              "Pmod=types.ModuleType('macos_lease_probe_snapshot')\nsys.modules[Pmod.__name__]=Pmod\n"
              "P=Pmod.__dict__\nexec(" + repr(probe) + ",P)\n" +
              _ASSERTIONS + _CONTROLLED + _OWNER + "\nmacos_lease_run(" + repr(payload) + ")\n").encode()
    return jobs.Program(_PURPOSE, source, stream_limit=8192)


def program(root, operation, binding, ttl):
    """Render only the finite guest assertion owner, with fixed native probe."""
    return _program(root, operation, binding, ttl)


def acquire(root, operation, binding, ttl, *, generation):
    """Guest-side only. Duplicate UUID/source observes its original admission."""
    root = jobs._root(root, generation)
    jobs.submit(root, operation, binding.job_binding(), program(root, operation, binding, ttl), generation=generation)
    return inspect(root, operation, binding, generation=generation)


def _record(root, operation, binding, name):
    intent = jobs._intent(root / operation, operation, binding.job_binding())
    _need(intent["purpose"] == _PURPOSE, "macos_original_program_mismatch")
    value = jobs._record(root / operation / name)
    jobs._correlate(value, intent)
    return intent, value


def _terminal(value):
    _need(set(value) == {"operationId", "generation", "binding", "programSha256", "schemaVersion",
                        "state", "reason", "restored", "acquired", "leaseOwner", "assertions"}
          and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["state"] in {"expired", "cancelled", "failed", "restore_blocked"}
          and value["reason"] in {"lease_deadline_reached", "original_lease_cancelled", "macos_lease_failed",
                                  "macos_assertion_release_unverified"}
          and type(value["restored"]) is bool and type(value["acquired"]) is bool,
          "macos_lease_receipt_invalid")
    _identity(value["leaseOwner"])
    _ids(value["assertions"])


def _identity(value):
    _need(type(value) is dict and set(value) == {"pid", "birth"} and type(value["pid"]) is int
          and value["pid"] > 0 and type(value["birth"]) is str and 1 <= len(value["birth"]) <= 128,
          "macos_lease_owner_invalid")


def _ids(value):
    _need(type(value) is list and len(value) <= 2
          and all(type(item) is int and 0 < item <= 2**32-1 for item in value)
          and len(set(value)) == len(value),
          "macos_assertion_ids_invalid")


def inspect(root, operation, binding, *, generation):
    """Pure local guest observation; no framework, readiness or assertion calls."""
    root = jobs._root(root, generation); operation = jobs._uuid(operation)
    status = jobs.observe(root, operation, binding.job_binding(), generation=generation)
    result = {"schemaVersion": 1, "operationId": operation, "provider": "tart-macos",
              "state": "unknown", "jobState": status["state"], "reason": status["reason"],
              "replayAllowed": False, "nextAction": "observe_original"}
    job = root / operation
    try:
        if (job / "lease-terminal.json").exists() or (job / "lease-terminal.json").is_symlink():
            _, value = _record(root, operation, binding, "lease-terminal.json"); _terminal(value)
            result.update(state=value["state"], reason=value["reason"], restored=value["restored"])
            if status["state"] == "terminal":
                jobs.collect(root, operation, binding.job_binding(), generation=generation)
                result["nextAction"] = "none" if value["restored"] else "resolve_restoration_blocker"
            else:
                result["state"] = "unknown" if status["state"] == "unknown" else "restore_pending"
        elif (job / "lease-acquired.json").exists() or (job / "lease-acquired.json").is_symlink():
            _, value = _record(root, operation, binding, "lease-acquired.json")
            _acquired(value, binding)
            if status["state"] == "running" and jobs._birth(value["leaseOwner"]["pid"]) == value["leaseOwner"]["birth"]:
                result.update(state="active", reason="original_lease_owner_running")
        if (job / "lease-resolution.json").exists() or (job / "lease-resolution.json").is_symlink():
            _, value = _record(root, operation, binding, "lease-resolution.json")
            _need(set(value) == {"operationId", "generation", "binding", "programSha256", "schemaVersion",
                                "restored", "leaseOwner", "acquiredSha256", "terminalSha256"}
                  and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
                  and value["restored"] is True and status["state"] == "terminal", "macos_resolution_invalid")
            _, acquired = _record(root, operation, binding, "lease-acquired.json"); _acquired(acquired, binding)
            _need(value["leaseOwner"] == acquired["leaseOwner"]
                  and jobs._birth(value["leaseOwner"]["pid"]) != value["leaseOwner"]["birth"]
                  and hashlib.sha256(jobs._read(job / "lease-acquired.json", jobs.MAX_RECORD_BYTES)).hexdigest()
                      == value["acquiredSha256"]
                  and hashlib.sha256(jobs._read(job / "terminal.json", jobs.MAX_RECORD_BYTES)).hexdigest()
                      == value["terminalSha256"], "macos_resolution_invalid")
            jobs.collect(root, operation, binding.job_binding(), generation=generation)
            result.update(state="restored", reason="original_assertion_owner_exited", restored=True, nextAction="none")
    except (ValueError, OSError, KeyError, TypeError):
        result.update(state="unknown", reason="macos_original_receipt_unavailable", nextAction="resolve_blocker")
    return result


def _acquired(value, binding):
    _need(set(value) == {"operationId", "generation", "binding", "programSha256", "schemaVersion",
                        "leaseOwner", "assertions", "ttlSeconds", "session", "backend"}
          and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["session"] == binding.session and value["backend"] in {"native", "controlled"},
          "macos_lease_receipt_invalid")
    _identity(value["leaseOwner"]); _ids(value["assertions"]); _ttl(value["ttlSeconds"])
    _need(len(value["assertions"]) == 2, "macos_lease_receipt_invalid")


def cancel(root, operation, binding, *, generation):
    """Publish a correlated original request; never kill or signal a process."""
    root = jobs._root(root, generation); operation = jobs._uuid(operation)
    intent = jobs._intent(root / operation, operation, binding.job_binding())
    _need(intent["purpose"] == _PURPOSE, "macos_original_program_mismatch")
    jobs._binding_live(binding.job_binding())
    request = {key: intent[key] for key in ("operationId", "generation", "binding", "programSha256")}
    request["schemaVersion"] = 1
    try:
        jobs._publish(root / operation / "lease-cancel.json", request)
    except FileExistsError:
        _need(jobs._record(root / operation / "lease-cancel.json") == request, "macos_cancel_invalid")
    return inspect(root, operation, binding, generation=generation)


def reconcile(root, operation, binding, *, generation):
    """Guest-only absence proof. Never reassert or replace the original owner."""
    return _reconcile(root, operation, binding, generation=generation)


def _reconcile(root, operation, binding, *, generation, controlled=None):
    root = jobs._root(root, generation); operation = jobs._uuid(operation)
    result = inspect(root, operation, binding, generation=generation)
    if result.get("restored") is True and result["jobState"] == "terminal":
        return result
    status, _, _ = jobs.collect(root, operation, binding.job_binding(), generation=generation)
    intent, acquired = _record(root, operation, binding, "lease-acquired.json"); _acquired(acquired, binding)
    jobs._binding_live(binding.job_binding())
    owner = acquired["leaseOwner"]
    _need(jobs._birth(owner["pid"]) != owner["birth"], "macos_original_owner_still_running")
    # Native getters only. This does not require an unlocked/current console.
    scope = {"D": vars(jobs)}
    if controlled is None:
        from . import tart_macos_probe as probe
        scope["P"] = vars(probe)
    exec(_ASSERTIONS + _CONTROLLED, scope)
    _need(acquired["backend"] == ("native" if controlled is None else "controlled"), "macos_backend_mismatch")
    api = scope["MacAssertions"](asdict(binding)) if controlled is None else scope["ControlledAssertions"](controlled)
    _need(api.owner_absent(owner), "macos_assertion_absence_unverified")
    job = root / operation
    value = {key: intent[key] for key in ("operationId", "generation", "binding", "programSha256")}
    value.update(schemaVersion=1, restored=True, leaseOwner=owner,
                 acquiredSha256=hashlib.sha256(jobs._read(job / "lease-acquired.json", jobs.MAX_RECORD_BYTES)).hexdigest(),
                 terminalSha256=hashlib.sha256(jobs._read(job / "terminal.json", jobs.MAX_RECORD_BYTES)).hexdigest())
    try:
        jobs._publish(job / "lease-resolution.json", value)
    except FileExistsError:
        _need(jobs._record(job / "lease-resolution.json") == value, "macos_resolution_invalid")
    return inspect(root, operation, binding, generation=generation)


_ASSERTIONS = r'''
import ctypes as C, os, pwd, uuid

class MacAssertions:
    def __init__(self, binding):
        self.binding=binding;self.created={}
        self.native=P['Native']()
        self.validate_identity()
        self.cf=self.native.cf; self.io=self.native.io
        fn=self.native._fn
        fn(self.io,'IOPMAssertionCreateWithDescription',C.c_int,[C.c_void_p]*5+[C.c_double,C.c_void_p,C.POINTER(C.c_uint32)])
        fn(self.io,'IOPMAssertionRelease',C.c_int,[C.c_uint32])
        fn(self.io,'IOPMAssertionCopyProperties',C.c_void_p,[C.c_uint32])
        fn(self.io,'IOPMCopyAssertionsByProcess',C.c_int,[C.POINTER(C.c_void_p)])
        fn(self.cf,'CFDictionaryGetCount',C.c_long,[C.c_void_p])
        fn(self.cf,'CFDictionaryGetKeysAndValues',None,[C.c_void_p,C.c_void_p,C.c_void_p])
        fn(self.cf,'CFGetTypeID',C.c_ulong,[C.c_void_p])
        fn(self.cf,'CFNumberGetTypeID',C.c_ulong,[])
        fn(self.cf,'CFArrayGetTypeID',C.c_ulong,[])
        fn(self.cf,'CFNumberGetValue',C.c_bool,[C.c_void_p,C.c_int,C.c_void_p])
        fn(self.cf,'CFArrayGetCount',C.c_long,[C.c_void_p])
    def validate_identity(self):
        current=pwd.getpwuid(os.geteuid());boot,_=self.native.boot()
        D['_need'](os.geteuid()>=501 and self.native.machine()==self.binding['machine'].lower()
            and str(uuid.UUID(boot))==self.binding['boot'].lower()
            and str(os.geteuid())==self.binding['account'] and current.pw_name==self.binding['principal']
            and current.pw_dir==self.binding['home'],'macos_guest_identity_changed')
    def admit(self):
        self.validate_identity();facts=self.native.console()
        D['_need'](type(facts.get('uid'))is int and facts['uid']==int(self.binding['account'])
            and facts.get('name')==self.binding['principal'] and facts.get('session')==self.binding['session']
            and facts.get('onConsole')is True and facts.get('locked')is False
            and facts.get('loginDone')is True,'macos_usable_console_unverified')
        D['_need'](self.native.displays()=='ready','macos_display_not_ready')
    def create(self, kind, ttl):
        self.admit();texts=[]
        try:
            for value in (kind,'VPNControlTemporaryGUILease','Owned temporary GUI test lease','TimeoutActionRelease'):
                text=self.cf.CFStringCreateWithCString(None,value.encode('ascii'),0x08000100)
                D['_need'](bool(text),'macos_assertion_string_unavailable');texts.append(text)
            identity=C.c_uint32()
            rc=self.io.IOPMAssertionCreateWithDescription(texts[0],texts[1],texts[2],None,None,ttl,texts[3],C.byref(identity))
            # Even an unexpected failing return with a nonzero output ID must
            # release that exact owned ID in the outer finally path.
            if identity.value:self.created[identity.value]=ttl
            D['_need'](rc==0 and identity.value>0,'macos_assertion_create_failed')
            return identity.value
        finally:
            for text in texts:self.cf.CFRelease(text)
    def verified(self, identity, kind):
        self.validate_identity();value=self.native.value(self.io.IOPMAssertionCopyProperties(identity))
        return (type(value)is dict and value.get('AssertType')==kind and type(value.get('AssertLevel'))is int
            and value['AssertLevel']==255
            and value.get('AssertName')=='VPNControlTemporaryGUILease'
            and value.get('TimeoutAction')=='TimeoutActionRelease'
            and type(value.get('TimeoutSeconds'))in (int,float)
            and 0<value['TimeoutSeconds']<=self.created[identity]+.001)
    def release(self, identity, expired):
        self.validate_identity();rc=self.io.IOPMAssertionRelease(identity)
        # IOReturn.h: iokit_common_err(0x2f0), a confirmed timed-out release.
        D['_need'](rc==0 or (expired and (rc&0xffffffff)==0xe00002f0),'macos_assertion_release_failed')
        properties=self.io.IOPMAssertionCopyProperties(identity)
        if properties:self.cf.CFRelease(properties)
        D['_need'](not properties,'macos_assertion_release_unverified')
    def owner_absent(self, owner):
        self.validate_identity();dictionary=C.c_void_p()
        D['_need'](self.io.IOPMCopyAssertionsByProcess(C.byref(dictionary))==0 and dictionary.value,
            'macos_assertion_inventory_unavailable')
        try:
            count=self.cf.CFDictionaryGetCount(dictionary)
            D['_need'](0<=count<=65536,'macos_assertion_inventory_invalid')
            keys=(C.c_void_p*count)();values=(C.c_void_p*count)()
            self.cf.CFDictionaryGetKeysAndValues(dictionary,keys,values)
            seen=set();absent=True
            for key,value in zip(keys,values):
                pid=C.c_int64()
                D['_need'](self.cf.CFGetTypeID(key)==self.cf.CFNumberGetTypeID()
                    and self.cf.CFNumberGetValue(key,4,C.byref(pid)) and 0<pid.value<2**31
                    and pid.value not in seen and self.cf.CFGetTypeID(value)==self.cf.CFArrayGetTypeID(),
                    'macos_assertion_inventory_invalid')
                seen.add(pid.value);size=self.cf.CFArrayGetCount(value)
                D['_need'](0<=size<=65536,'macos_assertion_inventory_invalid')
                if pid.value==owner['pid'] and size:absent=False
            return absent
        finally:self.cf.CFRelease(dictionary)
'''


_CONTROLLED = r'''
import json, socket

class ControlledAssertions:
    def __init__(self, endpoint):self.endpoint=endpoint
    def request(self, action, **fields):
        packet={'action':action,'owner':{'pid':os.getpid(),'birth':D['_birth'](os.getpid())},**fields}
        with socket.create_connection(('127.0.0.1',self.endpoint),timeout=2)as connection:
            connection.sendall(json.dumps(packet).encode()+b'\n');raw=b''
            while not raw.endswith(b'\n'):
                chunk=connection.recv(4096);D['_need'](bool(chunk),'controlled_assertion_reply_missing');raw+=chunk
                D['_need'](len(raw)<=4096,'controlled_assertion_reply_overflow')
        result=json.loads(raw)
        D['_need'](type(result)is dict and set(result)=={'ok','value'} and result['ok']is True,
            'controlled_assertion_rejected')
        return result['value']
    def admit(self):self.request('admit')
    def create(self,kind,ttl):return self.request('create',kind=kind,ttl=ttl)
    def verified(self,identity,kind):return self.request('verified',identity=identity,kind=kind)is True
    def release(self,identity,expired):
        D['_need'](self.request('release',identity=identity,expired=expired)is True,'controlled_release_unverified')
    def owner_absent(self,owner):return self.request('absent',originalOwner=owner)is True
'''


_OWNER = r'''
import fcntl, time
from pathlib import Path

def macos_lease_run(config):
    root=Path(config['root']);job=root/config['operationId']
    mb=D['MachineBinding'](**{key:config['binding'][key]for key in ('target','machine','boot','account')})
    D['_binding_live'](mb);intent=D['_intent'](job,config['operationId'],mb)
    correlation={key:intent[key]for key in ('operationId','generation','binding','programSha256')}
    correlation['schemaVersion']=1
    identity={'pid':os.getpid(),'birth':D['_birth'](os.getpid())}
    D['_need'](identity['birth']is not None,'macos_owner_generation_unavailable')
    assertions=[];api=None;lockfd=None;acquired=False;restored=True
    state='failed';reason='macos_lease_failed';deadline=time.monotonic()+config['ttlSeconds']
    try:
        lock=root/'macos-assertions.lock'
        try:D['_create'](lock,b'macos-assertions-lock-v1\n')
        except FileExistsError:pass
        info=D['_private'](lock,directory=False)
        lockfd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);actual=os.fstat(lockfd)
        D['_need']((info.st_dev,info.st_ino)==(actual.st_dev,actual.st_ino),'macos_assertion_resource_changed')
        fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Another original admission without a verified release blocks new work,
        # even when its process disappeared. A crash is never idle proof.
        for entry in root.iterdir():
            if entry==job or entry.name=='macos-assertions.lock':continue
            D['_need'](len(entry.name)==36,'macos_previous_lease_unresolved')
            D['_uuid'](entry.name);D['_private'](entry,directory=True)
            old=D['_record'](entry/'intent.json')
            D['_need'](old.get('purpose')=='tart-macos-assertion-lease-v1'
                and type(old.get('binding'))is dict
                and all(old['binding'].get(key)==intent['binding'][key]for key in ('target','machine','account')),
                'macos_previous_lease_unresolved')
            oldmb=D['MachineBinding'].from_dict(old['binding'])
            old=D['_intent'](entry,entry.name,oldmb)
            terminal=entry/'lease-terminal.json';resolution=entry/'lease-resolution.json'
            receipt=D['_record'](resolution if resolution.exists()else terminal)
            D['_correlate'](receipt,old)
            D['_need'](receipt.get('restored')is True,'macos_previous_lease_unresolved')
            if resolution.exists():
                import hashlib
                prior=D['_record'](entry/'lease-acquired.json');D['_correlate'](prior,old)
                owner=prior.get('leaseOwner');D['_need'](type(owner)is dict and set(owner)=={'pid','birth'}
                    and type(owner['pid'])is int and owner['pid']>0 and type(owner['birth'])is str
                    and receipt.get('leaseOwner')==owner and D['_birth'](owner['pid'])!=owner['birth']
                    and receipt.get('acquiredSha256')==hashlib.sha256(D['_read'](entry/'lease-acquired.json',16384)).hexdigest()
                    and receipt.get('terminalSha256')==hashlib.sha256(D['_read'](entry/'terminal.json',16384)).hexdigest(),
                    'macos_previous_lease_unresolved')
            status=D['observe'](root,entry.name,oldmb,generation=D['root_generation'](root))
            D['_need'](status['state']=='terminal','macos_previous_lease_unresolved')
            D['collect'](root,entry.name,oldmb,generation=D['root_generation'](root))
        api=MacAssertions(config['binding'])if config['controlled']is None else ControlledAssertions(config['controlled'])
        api.admit()
        for kind in ('PreventUserIdleSystemSleep','PreventUserIdleDisplaySleep'):
            remaining=deadline-time.monotonic();D['_need'](remaining>0,'macos_lease_deadline_reached')
            identity_value=api.create(kind,remaining);assertions.append(identity_value)
            D['_need'](api.verified(identity_value,kind),'macos_assertion_unverified')
        D['_publish'](job/'lease-acquired.json',{**correlation,'leaseOwner':identity,'assertions':assertions,
            'ttlSeconds':config['ttlSeconds'],'session':config['binding']['session'],
            'backend':'native'if config['controlled']is None else 'controlled'})
        acquired=True;state='expired';reason='lease_deadline_reached'
        while time.monotonic()<deadline:
            request=job/'lease-cancel.json'
            if request.exists()or request.is_symlink():
                value=D['_record'](request);D['_need'](value==correlation,'macos_cancel_invalid')
                state='cancelled';reason='original_lease_cancelled';break
            time.sleep(min(.05,max(0,deadline-time.monotonic())))
    except Exception:
        state='failed';reason='macos_lease_failed'
    finally:
        pending=list(dict.fromkeys(assertions+list(getattr(api,'created',{}))))
        for assertion in reversed(pending):
            try:api.release(assertion,time.monotonic()>=deadline)
            except Exception:restored=False
        if not restored:state='restore_blocked';reason='macos_assertion_release_unverified'
        D['_publish'](job/'lease-terminal.json',{**correlation,'state':state,'reason':reason,'restored':restored,
            'acquired':acquired,'leaseOwner':identity,'assertions':assertions})
        if lockfd is not None:os.close(lockfd)
        print(json.dumps({'state':state,'reason':reason,'restored':restored},sort_keys=True))
'''


def _controlled_program(root, operation, binding, ttl, port):
    """Private loopback fixture; cannot create a native assertion."""
    _need(type(port) is int and 1024 <= port <= 65535, "controlled_endpoint_invalid")
    return _program(root, operation, binding, ttl, controlled=port)
