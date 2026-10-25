"""One durable, compare-before-write repair of an original Android lease.

This internal adapter accepts no public program, path or ownership flag. The
facade obtains its fixed bridge configuration from the original private lease
admission and a freshly verified registered transport. The original lease and
its failed receipt remain immutable. A separately fenced restoration operation
can clear that lease's setting, but can never acquire another assertion.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

from . import durable_remote_job as jobs
from . import readiness_leases as leases

_EXECUTING_CODE = sys._getframe().f_code
_FILES = (Path(__file__), Path(jobs.__file__), Path(leases.__file__))
_LOADED = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in _FILES}
_PURPOSE = "temporary-keep-awake-restore-v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class LeaseReconciliationError(ValueError):
    pass


def _need(yes, reason):
    if not yes:
        raise LeaseReconciliationError(reason)


def restoration_id(operation):
    return str(uuid.uuid5(uuid.UUID(jobs._uuid(operation)), "temporary-keep-awake-restore-v1"))


def _sources_live():
    _need({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in _FILES} == _LOADED,
          "lease_restore_loaded_source_changed")


def _original(root, operation, binding, generation):
    root = jobs._root(root, generation)
    operation = jobs._uuid(operation)
    status = jobs.observe(root, operation, binding, generation=generation)
    _need(status["state"] == "terminal", "lease_restore_original_not_terminal")
    job = root / operation
    intent = jobs._intent(job, operation, binding)
    _need(intent["purpose"] == "temporary-keep-awake-v1", "lease_restore_original_invalid")
    original = leases._lease_record(root, operation, binding, "lease-original.json")
    failed = leases._lease_record(root, operation, binding, "lease-terminal.json")
    _need(original.get("backend") == "android" and failed.get("state") == "restore_blocked"
          and failed.get("restored") is False and failed.get("reason") == "original_setting_restoration_unverified"
          and original.get("applied") == "7" and (original.get("original") == "null" or
              type(original.get("original")) is str and re.fullmatch(r"[0-7]", original["original"])),
          "lease_restore_original_invalid")
    return root, job, intent, original, failed


def _hash_record(path):
    return hashlib.sha256(jobs._read(path, 262144)).hexdigest()


def _config(value):
    fields = {"adbPath", "adbSerial", "adbPort", "guestBoot", "guestAvd", "guestAccount", "daemonPin"}
    _need(type(value) is dict and set(value) == fields and type(value["adbPath"]) is str
          and Path(value["adbPath"]).is_absolute() and type(value["adbSerial"]) is str
          and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value["adbSerial"]))
          and type(value["adbPort"]) is int and 1024 <= value["adbPort"] <= 65535
          and type(value["guestAvd"]) is str and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value["guestAvd"]))
          and type(value["guestAccount"]) is str and bool(re.fullmatch(r"[0-9]{1,10}", value["guestAccount"])),
          "lease_restore_config_invalid")
    jobs._uuid(value["guestBoot"])
    _pin(value["daemonPin"])
    return dict(value)


def _pin(value):
    _need(type(value) is dict and set(value) == {"pid", "birth", "uid", "commandSha256", "executable"}
          and type(value["pid"]) is int and value["pid"] > 0 and type(value["uid"]) is int and value["uid"] >= 0
          and type(value["birth"]) is str and 0 < len(value["birth"]) <= 128
          and type(value["commandSha256"]) is str and bool(_HEX.fullmatch(value["commandSha256"]))
          and type(value["executable"]) is str and Path(value["executable"]).is_absolute(), "lease_restore_daemon_invalid")


def _bridge():
    scope = {"_need": _need, "_birth": jobs._birth}
    exec(_BRIDGE, scope)
    return scope


def capture_adb_pin(adb_path, port, connection):
    """Capture an already owned registered daemon, never start one."""
    path = str(Path(adb_path).resolve(strict=True))
    _need(str(adb_path) in leases.ADB_PATHS and type(connection) is str, "lease_restore_daemon_invalid")
    parts = connection.split(":", 2)
    _need(len(parts) == 3 and parts[0] == "adb" and parts[1].isdigit(), "lease_restore_daemon_invalid")
    helper = _bridge()
    pin = helper["capture_pin"](int(parts[1]), port)
    _need(pin["birth"] == parts[2] and pin["executable"] == path, "lease_restore_daemon_changed")
    helper["guard_pin"](pin, port)
    return pin


def _admission(job, intent, operation):
    value = jobs._record(job / "lease-restore-admission.json")
    correlation = {key: intent[key] for key in ("operationId", "generation", "binding", "programSha256")}
    fields = set(correlation) | {"schemaVersion", "restorationOperationId", "restorationProgramSha256",
                                "originalReceiptSha256", "failedReceiptSha256", "config", "sources"}
    _need(set(value) == fields and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and all(value[key] == item for key, item in correlation.items())
          and value["restorationOperationId"] == restoration_id(operation)
          and all(type(value[key]) is str and _HEX.fullmatch(value[key]) for key in (
              "restorationProgramSha256", "originalReceiptSha256", "failedReceiptSha256"))
          and type(value["sources"]) is dict and set(value["sources"]) == set(_LOADED)
          and all(type(item) is str and _HEX.fullmatch(item)
                                                   for item in value["sources"].values()), "lease_restore_admission_invalid")
    _config(value["config"])
    _need(value["originalReceiptSha256"] == _hash_record(job / "lease-original.json")
          and value["failedReceiptSha256"] == _hash_record(job / "lease-terminal.json"),
          "lease_restore_original_changed")
    _need(hashlib.sha256(jobs._read(job / "lease-restore-program.py", jobs.MAX_PROGRAM_BYTES)).hexdigest()
          == value["restorationProgramSha256"], "lease_restore_program_changed")
    return value


def _resolution(job, original_intent, admission, restore_intent):
    value = jobs._record(job / "lease-resolution.json")
    correlation = {key: original_intent[key] for key in ("operationId", "generation", "binding", "programSha256")}
    fields = set(correlation) | {"schemaVersion", "restored", "originalReceiptSha256", "failedReceiptSha256",
                                "restorationOperationId", "restorationGeneration", "restorationProgramSha256",
                                "restorationOwner", "originalValue", "appliedValue", "daemonPin"}
    _need(set(value) == fields and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and all(value[key] == item for key, item in correlation.items()) and value["restored"] is True
          and value["restorationOperationId"] == admission["restorationOperationId"]
          and value["restorationGeneration"] == restore_intent["generation"]
          and value["restorationProgramSha256"] == admission["restorationProgramSha256"] == restore_intent["programSha256"]
          and value["originalReceiptSha256"] == admission["originalReceiptSha256"]
          and value["failedReceiptSha256"] == admission["failedReceiptSha256"]
          and value["daemonPin"] == admission["config"]["daemonPin"], "lease_restore_resolution_invalid")
    original = jobs._record(job / "lease-original.json")
    _need(value["originalValue"] == original["original"] and value["appliedValue"] == original["applied"],
          "lease_restore_resolution_invalid")
    owner = value["restorationOwner"]
    _need(type(owner) is dict and set(owner) == {"pid", "birth"} and type(owner["pid"]) is int
          and owner["pid"] > 0 and type(owner["birth"]) is str, "lease_restore_resolution_invalid")
    return value


def observe(root, operation, binding, *, generation):
    """Pure local inspection of the same original and derived durable owner."""
    root, job, intent, _, _ = _original(root, operation, binding, generation)
    derived = restoration_id(operation)
    base = {"operationId": operation, "restorationOperationId": derived, "replayAllowed": False}
    path = job / "lease-restore-admission.json"
    if not path.exists() and not path.is_symlink():
        _need(not (root / derived).exists() and not (root / derived).is_symlink()
              and not (job / "lease-resolution.json").exists(), "lease_restore_admission_missing")
        if (job / "lease-restore-program.py").exists() or (job / "lease-restore-program.py").is_symlink():
            return {**base, "state": "unknown", "reason": "lease_restore_preparation_unresolved"}
        return {**base, "state": "unsubmitted", "reason": "lease_restore_not_admitted"}
    admission = _admission(job, intent, operation)
    status = jobs.observe(root, derived, binding, generation=generation)
    if status["state"] == "unsubmitted":
        # The admission itself is a dispatch fence. A crash before actual
        # submission remains unresolved rather than silently starting again.
        return {**base, "state": "unknown", "reason": "lease_restore_dispatch_unresolved"}
    restore_job = root / derived
    restore_intent = jobs._intent(restore_job, derived, binding)
    _need(restore_intent["purpose"] == _PURPOSE and restore_intent["programSha256"] == admission["restorationProgramSha256"],
          "lease_restore_original_owner_changed")
    proof = None
    if (job / "lease-resolution.json").exists() or (job / "lease-resolution.json").is_symlink():
        proof = _resolution(job, intent, admission, restore_intent)
    if status["state"] == "terminal":
        terminal, _, _ = jobs.collect(root, derived, binding, generation=generation)
        if proof is None or terminal["terminal"]["exitCode"] != 0:
            return {**base, "state": "blocked", "reason": "lease_restore_original_attempt_failed"}
        child = jobs._record(restore_job / "lease-restoration.json")
        jobs._correlate(child, restore_intent)
        _need(child.get("restored") is True and child.get("owner") == proof["restorationOwner"],
              "lease_restore_resolution_invalid")
        return {**base, "state": "terminal", "reason": "original_lease_restored_after_transport_recovery", "restored": True}
    if status["state"] == "running" or status["reason"] == "record_unavailable":
        return {**base, "state": "running", "reason": "lease_restore_original_owner_running", "restored": proof is not None}
    return {**base, "state": "unknown", "reason": "lease_restore_original_owner_unknown"}


def overlay(result, root, operation, binding, *, generation):
    """Add only locally verified restoration facts; never access transport."""
    if result.get("state") != "restore_blocked" or result.get("jobState") != "terminal":
        return result
    original = leases._lease_record(jobs._root(root, generation), operation, binding, "lease-original.json")
    if original.get("backend") != "android":
        return result
    status = observe(root, operation, binding, generation=generation)
    shared = {**result, "restorationState": status["state"],
              "restorationOperationId": status["restorationOperationId"], "reason": status["reason"]}
    if status["state"] == "terminal":
        return {**shared, "state": "restored", "restored": True, "jobState": "terminal", "nextAction": "none"}
    if status["state"] == "running":
        return {**shared, "state": "restoring", "jobState": "running", "nextAction": "observe_original"}
    if status["state"] == "unsubmitted":
        return {**shared, "nextAction": "reconcile_original"}
    return {**shared, "nextAction": "resolve_blocker"}


def _program(root, operation, binding, config, original_intent, original_hash, failed_hash):
    derived = restoration_id(operation)
    payload = {"root": str(root), "operationId": operation, "restorationOperationId": derived,
               "binding": jobs.asdict(binding), "config": _config(config),
               "originalIntent": {key: original_intent[key] for key in ("operationId", "generation", "binding", "programSha256")},
               "originalReceiptSha256": original_hash, "failedReceiptSha256": failed_hash}
    source = ("import sys,types\nM=types.ModuleType('lease_restore_owner_snapshot');sys.modules[M.__name__]=M\n"
              "exec(" + repr(jobs.owner_source()) + ",M.__dict__)\nD=M.__dict__\n"
              "_need=D['_need'];_birth=D['_birth']\n" + _BRIDGE + _RESTORE +
              "\nrestore_lease(" + repr(payload) + ")\n").encode()
    return jobs.Program(_PURPOSE, source, stream_limit=4096)


def admit(root, operation, binding, config, *, generation):
    """Admit one separate restoration, never replace an existing attempt."""
    root, job, intent, _, _ = _original(root, operation, binding, generation)
    current = observe(root, operation, binding, generation=generation)
    if current["state"] != "unsubmitted":
        return current
    _sources_live()
    config = _config(config)
    _bridge()["guard_pin"](config["daemonPin"], config["adbPort"])
    original_hash, failed_hash = _hash_record(job / "lease-original.json"), _hash_record(job / "lease-terminal.json")
    program = _program(root, operation, binding, config, intent, original_hash, failed_hash)
    admission = {key: intent[key] for key in ("operationId", "generation", "binding", "programSha256")}
    admission.update(schemaVersion=1, restorationOperationId=restoration_id(operation),
                     restorationProgramSha256=program.digest, originalReceiptSha256=original_hash,
                     failedReceiptSha256=failed_hash, config=config, sources=dict(_LOADED))
    try:
        jobs._create(job / "lease-restore-program.py", program.source)
        jobs._publish(job / "lease-restore-admission.json", admission)
    except FileExistsError:
        return observe(root, operation, binding, generation=generation)
    _sources_live()
    jobs.submit(root, restoration_id(operation), binding, program, generation=generation)
    return observe(root, operation, binding, generation=generation)


# Embedded in subsequent fixed assertion owners. A bare successful JSON file is
# insufficient: both original and derived durable owners must have closed,
# integrity-checked streams and terminal receipts for their exact sources.
_RESTORED_HISTORY = r'''
def lease_restored_history(old_job,binding):
    import uuid
    need=D['_need'];root=old_job.parent;generation=D['root_generation'](root)
    old=D['_intent'](old_job,old_job.name,binding)
    original_status,_,_=D['collect'](root,old_job.name,binding,generation=generation)
    need(original_status['state']=='terminal','lease_previous_restoration_unknown')
    admission=D['_record'](old_job/'lease-restore-admission.json');D['_correlate'](admission,old)
    resolution=D['_record'](old_job/'lease-resolution.json');D['_correlate'](resolution,old)
    derived=str(uuid.uuid5(uuid.UUID(old_job.name),'temporary-keep-awake-restore-v1'))
    need(admission['restorationOperationId']==resolution['restorationOperationId']==derived,'lease_previous_restoration_unknown')
    need(resolution['schemaVersion']==1 and resolution['restored']is True,'lease_previous_restoration_unknown')
    for filename,key in (('lease-original.json','originalReceiptSha256'),('lease-terminal.json','failedReceiptSha256')):
        digest=hashlib.sha256(D['_read'](old_job/filename,262144)).hexdigest()
        need(digest==admission[key]==resolution[key],'lease_previous_restoration_unknown')
    original=D['_record'](old_job/'lease-original.json');D['_correlate'](original,old)
    need(original['backend']=='android'and resolution['originalValue']==original['original']and resolution['appliedValue']==original['applied'],'lease_previous_restoration_unknown')
    derived_job=root/derived;child_intent=D['_intent'](derived_job,derived,binding)
    need(child_intent['purpose']=='temporary-keep-awake-restore-v1'and resolution['restorationGeneration']==child_intent['generation'],'lease_previous_restoration_unknown')
    need(child_intent['programSha256']==admission['restorationProgramSha256']==resolution['restorationProgramSha256']==hashlib.sha256(D['_read'](old_job/'lease-restore-program.py',D['MAX_PROGRAM_BYTES'])).hexdigest(),'lease_previous_restoration_unknown')
    status,_,_=D['collect'](root,derived,binding,generation=generation)
    child=D['_record'](derived_job/'lease-restoration.json');D['_correlate'](child,child_intent)
    need(status['state']=='terminal'and status['terminal']['exitCode']==0 and child['restored']is True and child['owner']==resolution['restorationOwner']and resolution['daemonPin']==admission['config']['daemonPin'],'lease_previous_restoration_unknown')
'''


_BRIDGE = r'''
import ctypes,hashlib,json,os,subprocess,sys,time
from pathlib import Path
def executable(pid):
    if sys.platform=='darwin':
        library=ctypes.CDLL('/usr/lib/libproc.dylib');call=library.proc_pidpath
        call.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32];call.restype=ctypes.c_int
        out=ctypes.create_string_buffer(4096);_need(call(pid,out,len(out))>0,'lease_restore_daemon_unavailable')
        return str(Path(os.fsdecode(out.value)).resolve(strict=True))
    _need(sys.platform.startswith('linux'),'lease_restore_daemon_unavailable')
    return str(Path(os.readlink('/proc/'+str(pid)+'/exe')).resolve(strict=True))
def listener_pids(port):
    if sys.platform=='darwin':
        value=subprocess.run(['/usr/sbin/lsof','-nP','-iTCP:'+str(port),'-sTCP:LISTEN','-Fp'],stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
        _need(value.returncode==0 and not value.stderr and 0<len(value.stdout)<=65536,'lease_restore_daemon_unavailable')
        return {int(line[1:])for line in value.stdout.decode('ascii').splitlines()if line.startswith('p')and line[1:].isdigit()}
    _need(sys.platform.startswith('linux'),'lease_restore_daemon_unavailable')
    inodes=set()
    for name in ('tcp','tcp6'):
        lines=Path('/proc/net/'+name).read_text().splitlines();_need(len(lines)<=100000,'lease_restore_daemon_unavailable')
        for line in lines[1:]:
            row=line.split()
            if row[3]=='0A' and int(row[1].split(':')[1],16)==port:inodes.add(row[9])
    _need(bool(inodes),'lease_restore_daemon_unavailable');found=set();matched=set()
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:
            fds=list((path/'fd').iterdir());_need(len(fds)<=10000,'lease_restore_daemon_unavailable')
            for fd in fds:
                try:link=os.readlink(fd)
                except FileNotFoundError:continue
                if link.startswith('socket:[')and link[8:-1]in inodes:
                    found.add(int(path.name));matched.add(link[8:-1])
        except (FileNotFoundError,PermissionError):continue
    _need(matched==inodes,'lease_restore_daemon_unavailable')
    return found
def capture_pin(pid,port):
    birth=_birth(pid);_need(birth is not None,'lease_restore_daemon_unavailable')
    def ps(field):
        value=subprocess.run(['ps','-ww','-p',str(pid),'-o',field+'='],stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
        _need(value.returncode==0 and not value.stderr and 0<len(value.stdout)<=65536,'lease_restore_daemon_unavailable')
        return value.stdout.decode('utf-8').strip()
    uid=ps('uid');_need(uid.isdigit()and int(uid)==os.geteuid(),'lease_restore_daemon_changed')
    command=ps('command');path=executable(pid)
    _need(_birth(pid)==birth and listener_pids(port)=={pid},'lease_restore_daemon_changed')
    return {'pid':pid,'birth':birth,'uid':int(uid),'commandSha256':hashlib.sha256(command.encode()).hexdigest(),'executable':path}
def guard_pin(pin,port):
    _need(capture_pin(pin['pid'],port)==pin,'lease_restore_daemon_changed')
'''

_RESTORE = r'''
def restore_lease(payload):
    root=Path(payload['root']);operation=payload['operationId'];derived=payload['restorationOperationId'];binding=D['MachineBinding'].from_dict(payload['binding'])
    job=root/derived;original_job=root/operation;config=payload['config']
    D['_binding_live'](binding);intent=D['_intent'](job,derived,binding);original_intent=D['_intent'](original_job,operation,binding)
    _need(all(original_intent[k]==v for k,v in payload['originalIntent'].items()),'lease_restore_original_changed')
    def checked_record(name,digest):
        raw=D['_read'](original_job/name,262144);_need(hashlib.sha256(raw).hexdigest()==digest,'lease_restore_original_changed')
        value=D['_record'](original_job/name);D['_correlate'](value,original_intent);return value
    original=checked_record('lease-original.json',payload['originalReceiptSha256']);failed=checked_record('lease-terminal.json',payload['failedReceiptSha256'])
    _need(original['backend']=='android'and original['applied']=='7'and failed['restored']is False and failed['state']=='restore_blocked','lease_restore_original_invalid')
    value=original['original'];_need(value=='null'or value in tuple(str(n)for n in range(8)),'lease_restore_original_invalid')
    owner={'pid':os.getpid(),'birth':D['_birth'](os.getpid())};_need(owner['birth']is not None,'lease_restore_owner_unknown')
    D['_create'](job/'restoration-fence',b'original-lease-restoration-once-v1\n')
    correlation={k:intent[k]for k in ('operationId','generation','binding','programSha256')}
    def command(tail,shell=True):
        guard_pin(config['daemonPin'],config['adbPort'])
        argv=[config['adbPath'],'-H','127.0.0.1','-P',str(config['adbPort']),'-s',config['adbSerial']]+(['shell']if shell else[])+tail
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=5,env={'PATH':os.defpath},close_fds=True)
        guard_pin(config['daemonPin'],config['adbPort'])
        _need(result.returncode==0 and len(result.stdout)<=1024 and len(result.stderr)<=1024,'lease_restore_transport_unavailable')
        return result.stdout.decode('ascii').strip()
    def identity():
        _need(command(['emu','avd','name'],False).splitlines()==[config['guestAvd'],'OK'],'lease_restore_guest_changed')
        _need(command(['cat','/proc/sys/kernel/random/boot_id'])==config['guestBoot'],'lease_restore_boot_changed')
        _need(command(['am','get-current-user'])==config['guestAccount'],'lease_restore_account_changed')
    def read():
        identity();current=command(['settings','get','global','stay_on_while_plugged_in'])
        _need(current=='null'or current in tuple(str(n)for n in range(8)),'lease_restore_setting_invalid');return current
    restored=False;reason='lease_restore_original_attempt_failed'
    try:
        current=read();_need(current in (value,original['applied']),'lease_restore_setting_changed')
        if current!=value:
            identity()
            command(['settings','delete','global','stay_on_while_plugged_in']if value=='null'else['settings','put','global','stay_on_while_plugged_in',value])
        _need(read()==value,'lease_restore_unverified')
        checked_record('lease-original.json',payload['originalReceiptSha256']);checked_record('lease-terminal.json',payload['failedReceiptSha256'])
        resolution={k:original_intent[k]for k in ('operationId','generation','binding','programSha256')}
        resolution.update(schemaVersion=1,restored=True,originalReceiptSha256=payload['originalReceiptSha256'],failedReceiptSha256=payload['failedReceiptSha256'],
            restorationOperationId=derived,restorationGeneration=intent['generation'],restorationProgramSha256=intent['programSha256'],
            restorationOwner=owner,originalValue=value,appliedValue=original['applied'],daemonPin=config['daemonPin'])
        D['_publish'](original_job/'lease-resolution.json',resolution);restored=True;reason='original_lease_restored_after_transport_recovery'
    except Exception:
        reason='lease_restore_original_attempt_failed'
    D['_publish'](job/'lease-restoration.json',{**correlation,'schemaVersion':1,'restored':restored,'reason':reason,'owner':owner})
    print(json.dumps({'restored':restored,'reason':reason},sort_keys=True))
    if not restored:raise SystemExit(1)
'''
