"""Fixed read-only Tart guest bytes/signature observer for Mac machine acceptance.

This intentionally omits resource, owner, public, and secure UI admission. It
cannot authorize a native mutation by itself. No command or path is supplied by
an MCP request; the only argument is an exact source SHA for the fixed guest.
"""
from __future__ import annotations

import json
import re
import subprocess
from typing import Any, Mapping

from . import macos_machine_acceptance as gate
from .macos_machine_boundary import MacMachineBoundaryError, NativeCampaign, NativeTerminalQuery, VerifiedPair


_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_GUEST_CODE = r'''import hashlib,json,os,pathlib,plistlib,stat,subprocess,sys
source=sys.argv[1]
if len(source)!=40 or any(x not in '0123456789abcdef' for x in source):raise ValueError('source')
suffix=source[:7];root=pathlib.Path('/Users/admin/macos-parity'+suffix)
app=pathlib.Path('/Applications/vpn-control-parity'+suffix+'.app')
def directory(path):
 parts=path.parts
 current=pathlib.Path(parts[0])
 for part in parts[1:]:
  current=current/part
  info=current.lstat()
  if not stat.S_ISDIR(info.st_mode):raise ValueError('directory')
def digest(path):
 directory(path.parent)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_size<=0 or before.st_size>512*1024*1024:raise ValueError('file')
  h=hashlib.sha256()
  while True:
   block=os.read(fd,1024*1024)
   if not block:break
   h.update(block)
  after=os.fstat(fd);current=os.stat(path,follow_symlinks=False)
  if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns):raise ValueError('changed')
  return h.hexdigest()
 finally:os.close(fd)
def only_dmg(label):
 parent=root/'pair'/'packages'/label
 directory(parent)
 names=list(parent.iterdir())
 if len(names)!=1 or not names[0].name.startswith('vpn-control-') or not names[0].name.endswith('.dmg'):raise ValueError('dmg inventory')
 return digest(names[0])
directory(app)
info=app.stat()
jar_parent=app/'Contents'/'app';directory(jar_parent)
jars=[p for p in jar_parent.iterdir() if p.name.startswith('desktopApp-') and p.name.endswith('.jar')]
if len(jars)!=1:raise ValueError('jar inventory')
jar_hash=digest(jars[0]);base_hash=only_dmg('base');target_hash=only_dmg('target')
signed=subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],capture_output=True,timeout=30,check=False)
print(json.dumps({'schemaVersion':1,'sourceSha':source,'vmName':'vpn-control-boot-control53',
 'app':str(app),'guestRoot':str(root),'baseDevice':info.st_dev,'baseInode':info.st_ino,
 'baseRootOwned':info.st_uid==0,'baseSignatureValid':signed.returncode==0,
 'baseJarSha256':jar_hash,'baseDmgSha256':base_hash,'targetDmgSha256':target_hash},sort_keys=True,separators=(',',':')))
'''


class TartReadOnlyProvider:
    """Diagnostic-only provider; every native mutation method fails closed."""

    def __init__(self, *, runner=subprocess.run):
        self.runner = runner

    def _require_running(self) -> None:
        try:
            result = self.runner(["tart", "list", "--format", "json"], capture_output=True,
                                 text=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise MacMachineBoundaryError("Tart running-state observation is unavailable.") from error
        if result.returncode != 0 or len(result.stdout) > 65536:
            raise MacMachineBoundaryError("Tart running-state observation failed.")
        try:
            rows = json.loads(result.stdout)
        except (TypeError, ValueError) as error:
            raise MacMachineBoundaryError("Tart running-state observation is malformed.") from error
        matched = [row for row in rows if isinstance(row, dict) and row.get("Name") == gate.VM_NAME] \
            if isinstance(rows, list) and len(rows) <= 128 else []
        if len(matched) != 1 or matched[0].get("Source") != "local" or \
                matched[0].get("Running") is not True or matched[0].get("State") != "running":
            raise MacMachineBoundaryError("The exact Tart guest is not already running.")

    def observe_admission(self, vm_name: str, source_sha: str,
                          pair: VerifiedPair | None = None) -> Mapping[str, Any]:
        if vm_name != gate.VM_NAME or not isinstance(source_sha, str) or not _SOURCE.fullmatch(source_sha):
            raise MacMachineBoundaryError("Tart source or VM identity is invalid.")
        self._require_running()
        argv = ["tart", "exec", gate.VM_NAME, "/usr/bin/python3", "-c", _GUEST_CODE, source_sha]
        try:
            completed = self.runner(argv, capture_output=True, text=True, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise MacMachineBoundaryError("Fixed Tart readback is unavailable.") from error
        if completed.returncode != 0 or len(completed.stdout) > 4096:
            raise MacMachineBoundaryError("Fixed Tart readback failed.")
        try:
            value = json.loads(completed.stdout)
        except (TypeError, ValueError) as error:
            raise MacMachineBoundaryError("Fixed Tart readback is malformed.") from error
        fixed = gate._fixed_paths({"sourceSha": source_sha})
        if not isinstance(value, dict) or set(value) != {
                "schemaVersion", "sourceSha", "vmName", "app", "guestRoot", "baseDevice",
                "baseInode", "baseRootOwned", "baseSignatureValid", "baseJarSha256",
                "baseDmgSha256", "targetDmgSha256"} or value.get("schemaVersion") != 1 or \
                any(value.get(key) != expected for key, expected in
                    {"sourceSha": source_sha, **fixed}.items()):
            raise MacMachineBoundaryError("Fixed Tart readback identity changed.")
        # Resource reservation, owner generation and public controller proof are
        # deliberately absent. The machine acceptance gate rejects this snapshot.
        return {**value, "vmRunning": True, "resourceAdmitted": False, "ownerReady": False}

    def submit_public(self, vm_name: str, campaign: NativeCampaign) -> Mapping[str, Any]:
        raise MacMachineBoundaryError("Read-only Tart provider cannot submit an install.")

    def observe_prompt(self, vm_name: str, job_id: str, operation_id: str) -> Mapping[str, Any]:
        raise MacMachineBoundaryError("Read-only Tart provider cannot attest a secure prompt.")

    def authorize_visible_prompt(self, vm_name: str, job_id: str, operation_id: str) -> None:
        raise MacMachineBoundaryError("Read-only Tart provider cannot authorize a secure prompt.")

    def observe_terminal(self, vm_name: str, query: NativeTerminalQuery) -> Mapping[str, Any]:
        raise MacMachineBoundaryError("Read-only Tart provider cannot attest a terminal job.")
