"""Create-only source-closed installer component staging and fresh read admission.

This is tooling provenance, never installed-launcher or bundled-runtime acceptance.
The explicit installer runner retains the unchanged TLS/action lifecycle.
Baseline entry points remain read-only; no entry point owns a VM.
"""
from __future__ import annotations
import ast
import base64
import builtins
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import types
import uuid

FILES = (
    'agent_tools/android_admission_readback.py',
    'agent_tools/android_api29_current_owner_observation.py',
    'agent_tools/android_api29_current_permission_observation.py',
    'agent_tools/android_api29_external_java_observation.py',
    'agent_tools/android_avd_census_diagnostic.py',
    'agent_tools/android_avd_coldboot.py',
    'agent_tools/android_avd_fixture_recovery.py',
    'agent_tools/android_avd_launch_recovery.py',
    'agent_tools/android_avd_sdk_alias_census.py',
    'agent_tools/android_avd_sdk_alias_observation.py',
    'agent_tools/android_cli_stage.py',
    'agent_tools/android_coldboot_product_observation.py',
    'agent_tools/android_component_command_transport.py',
    'agent_tools/android_device_availability.py',
    'agent_tools/android_endpoint_admission.py',
    'agent_tools/android_external_java_component_transport.py',
    'agent_tools/android_installer_component_adapter.py',
    'agent_tools/android_installer_component_bundle.py',
    'agent_tools/android_installer_routing_backup.py',
    'agent_tools/android_api35_large_routing_observation.py',
    'agent_tools/tests/test_android_api35_large_routing_observation.py',
    'agent_tools/android_installer_dispatch.py',
    'agent_tools/android_installer_target.py',
    'agent_tools/android_installer_tool_bundle.py',
    'agent_tools/android_native_fixture.py',
    'agent_tools/android_native_fixture_lifecycle.py',
    'agent_tools/android_observation.py',
    'agent_tools/android_owned_endpoint_bind_recovery.py',
    'agent_tools/android_package_install.py',
    'agent_tools/android_public_inspect.py',
    'agent_tools/native_artifact_registry.py',
    'agent_tools/ssh_connection_recovery.py',
    'agent_tools/ssh_transfer.py',
    'agent_tools/ssh_transport.py',
    'scripts/android_fixture_preflight.py',
    'scripts/android_fixture_transport.py',
    'scripts/android_fixture_trust.py',
    'scripts/android_installer_lifecycle.py',
    'scripts/android_no_update_tls_preflight.py',
    'scripts/integration/android_update_fixture.py',
)
LIMIT = 8_388_608


def _raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def _pin(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _parents(path):
    """Descriptor pins for every absolute parent, refusing symlinks."""
    if (os.name!='posix' or not all(callable(getattr(os,name,None)) for name in ('getuid','geteuid','getgid','getegid','getgroups')) or
        not all(hasattr(os,name) for name in ('O_DIRECTORY','O_NOFOLLOW'))):
        raise ValueError('component_bundle_posix_fd_required')
    path=Path(path).absolute(); chain=[]
    try:
        fd=os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        chain.append(('/',fd))
        for part in path.parts[1:]:
            fd=os.open(part,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=chain[-1][1])
            chain.append((str(Path(chain[-1][0])/part),fd))
        pins={name:_pin(os.fstat(fd))[:5] for name,fd in chain}
        for name,fd in chain:
            if _pin(os.stat(name,follow_symlinks=False))[:5]!=pins[name]:
                raise ValueError('component_bundle_parent_changed')
        return chain,pins
    except BaseException:
        for _,fd in reversed(chain):os.close(fd)
        raise


def _close(chain):
    for _,fd in reversed(chain):os.close(fd)


def _read(path, private=False):
    chain,parents=_parents(Path(path).parent);fd=None
    try:
        fd=os.open(Path(path).name,os.O_RDONLY | os.O_NOFOLLOW,dir_fd=chain[-1][1])
        info=os.fstat(fd);pin=_pin(info)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>LIMIT or
            info.st_uid!=os.getuid() or (private and stat.S_IMODE(info.st_mode)!=0o600)):
            raise ValueError('component_bundle_file_unsafe')
        chunks=[];size=0
        while chunk:=os.read(fd,65536):
            chunks.append(chunk);size+=len(chunk)
            if size>LIMIT:raise ValueError('component_bundle_file_limit')
        if _pin(os.fstat(fd))!=pin or _pin(os.stat(Path(path).name,dir_fd=chain[-1][1],follow_symlinks=False))!=pin:
            raise ValueError('component_bundle_file_changed')
        for name,parent in chain:
            if _pin(os.fstat(parent))[:5]!=parents[name] or _pin(os.stat(name,follow_symlinks=False))[:5]!=parents[name]:
                raise ValueError('component_bundle_parent_changed')
        raw=b''.join(chunks)
        return raw,{'generation':pin,'parents':parents,'sha256':hashlib.sha256(raw).hexdigest()}
    finally:
        if fd is not None:os.close(fd)
        _close(chain)


def _evidence_generation_closure(expected):
    """All opens precede a final generation-only private-leaf/parent pass.

    Each expected pin comes from a completed full read. Fresh descriptors may
    never adopt a new generation, even when a later body read changed an earlier
    file. No body or catalogue read follows the first final leaf comparison.
    """
    held=[]
    try:
        for path,pin in expected.items():
            chain,parents=_parents(Path(path).parent)
            fd=None
            try:
                fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=chain[-1][1])
                held.append((Path(path),pin,chain,parents,fd));fd=None
            finally:
                if fd is not None:os.close(fd)
                if not held or held[-1][2] is not chain:_close(chain)
        for path,pin,chain,parents,fd in held:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or
                info.st_uid!=os.getuid() or info.st_nlink!=1 or
                _raw(_pin(info))!=_raw(pin['generation']) or
                _raw(_pin(os.stat(path.name,dir_fd=chain[-1][1],follow_symlinks=False)))!=_raw(pin['generation']) or
                _raw(parents)!=_raw(pin['parents'])):
                raise ValueError('component_evidence_generation_changed')
            for name,parent in chain:
                if (_raw(_pin(os.fstat(parent))[:5])!=_raw(parents[name]) or
                    _raw(_pin(os.stat(name,follow_symlinks=False))[:5])!=_raw(parents[name])):
                    raise ValueError('component_evidence_parent_changed')
    finally:
        for _,_,chain,_,fd in reversed(held):
            os.close(fd);_close(chain)


def _directory(path):
    chain,pins=_parents(path)
    try:
        info=os.fstat(chain[-1][1])
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('component_bundle_directory_unsafe')
        return {'generation':_pin(info),'parents':pins}
    finally:_close(chain)



def _new_directory(path,receiver_root=None):
    path=Path(path).absolute()
    if '..' in path.parts:raise ValueError('component_bundle_directory_unsafe')
    chain,pins=_parents(path.parent)
    try:
        info=os.fstat(chain[-1][1])
        receiver_parent=(receiver_root is not None and path.parent==Path(receiver_root).absolute() and
                         os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0 and
                         info.st_uid==info.st_gid==1000 and
                         re.fullmatch(r'android-installer-component-(?:bundle|baseline)-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',path.name) is not None)
        if (info.st_uid!=os.getuid() and not receiver_parent) or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('component_bundle_directory_unsafe')
        os.mkdir(path.name,mode=0o700,dir_fd=chain[-1][1])
        for name,fd in chain:
            if _pin(os.fstat(fd))[:5]!=pins[name] or _pin(os.stat(name,follow_symlinks=False))[:5]!=pins[name]:
                raise ValueError('component_bundle_parent_changed')
        os.fsync(chain[-1][1])
    finally:_close(chain)


def _write(path,raw):
    chain,_=_parents(Path(path).parent)
    try:
        info=os.fstat(chain[-1][1])
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('component_bundle_directory_unsafe')
        fd=os.open(Path(path).name,os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600,dir_fd=chain[-1][1])
        try:
            with os.fdopen(fd,'wb',closefd=False) as stream:
                stream.write(raw);stream.flush();os.fsync(fd)
            if _pin(os.fstat(fd))!=_pin(os.stat(Path(path).name,dir_fd=chain[-1][1],follow_symlinks=False)):
                raise ValueError('component_bundle_write_changed')
        finally:os.close(fd)
        os.fsync(chain[-1][1])
    finally:_close(chain)


def _tree(files):
    return {'schema':1,'kind':'android-installer-component-source-tree',
            'files':[{'path':name,'size':len(files[name][0]),'sha256':files[name][1]['sha256']} for name in FILES]}


def reviewed_tree(root):
    """Read-only full source closure; its digest is explicit staging authority."""
    files={name:_read(Path(root)/name) for name in FILES};tree=_tree(files)
    if files!={name:_read(Path(root)/name) for name in FILES}:
        raise ValueError('component_bundle_source_changed')
    return {'treeSha256':hashlib.sha256(_raw(tree)).hexdigest(),'manifest':tree}


def prepare(root,destination,expected_reviewed_tree_sha256):
    """Create a fresh private snapshot. Never reuse or overwrite a destination."""
    root=Path(root).absolute();destination=Path(destination).absolute()
    if type(expected_reviewed_tree_sha256)is not str or not re.fullmatch('[0-9a-f]{64}',expected_reviewed_tree_sha256):
        raise ValueError('component_bundle_review_required')
    files={name:_read(root/name) for name in FILES};tree=_tree(files)
    digest=hashlib.sha256(_raw(tree)).hexdigest()
    if digest!=expected_reviewed_tree_sha256:raise ValueError('component_bundle_source_changed')
    receipt=_stage(destination,files,tree,digest)
    if files!={name:_read(root/name) for name in FILES}:raise ValueError('component_bundle_source_changed')
    return receipt


def _stage(destination,files,tree,digest,receiver_root=None):
    destination=Path(destination).absolute()
    if receiver_root is None:_directory(destination.parent)
    elif destination.parent!=Path(receiver_root).absolute():raise ValueError('component_bundle_receiver_root_changed')
    _new_directory(destination,receiver_root)
    directories={'.'}
    for name in FILES:
        parent=destination/Path(name).parent
        parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        directories.update(str(p.relative_to(destination)) for p in (parent,*parent.parents) if p!=destination and destination in p.parents)
        _write(destination/name,files[name][0])
    _write(destination/'manifest.json',_raw(tree))
    receipt={'schema':1,'kind':'android-installer-component-bundle','directory':str(destination),
             'treeSha256':digest,'files':{name:_read(destination/name,True)[1] for name in (*FILES,'manifest.json')},
             'directories':{name:_directory(destination/name) for name in sorted(directories)}}
    load(receipt)
    return receipt


def load(receipt):
    """Verify inventory, manifest and every descriptor generation at each use."""
    if (type(receipt)is not dict or set(receipt)!={'schema','kind','directory','treeSha256','files','directories'} or
        type(receipt['schema'])is not int or receipt['schema']!=1 or receipt['kind']!='android-installer-component-bundle' or
        type(receipt['directory'])is not str or not Path(receipt['directory']).is_absolute() or
        type(receipt['files'])is not dict or set(receipt['files'])!={*FILES,'manifest.json'}):
        raise ValueError('component_bundle_receipt_invalid')
    root=Path(receipt['directory']);dirs={'.'};names=set()
    for folder,subdirs,entries in os.walk(root,followlinks=False):
        _directory(Path(folder))
        for name in subdirs:dirs.add(str((Path(folder)/name).relative_to(root)))
        for name in entries:names.add(str((Path(folder)/name).relative_to(root)))
    if names!={*FILES,'manifest.json'} or dirs!=set(receipt['directories']):raise ValueError('component_bundle_inventory_changed')
    if {name:_directory(root/name) for name in dirs}!=receipt['directories']:
        raise ValueError('component_bundle_directory_changed')
    files={name:_read(root/name,True) for name in (*FILES,'manifest.json')}
    if {name:pin for name,(_,pin) in files.items()}!=receipt['files']:raise ValueError('component_bundle_file_changed')
    tree=_tree(files)
    if files['manifest.json'][0]!=_raw(tree) or hashlib.sha256(_raw(tree)).hexdigest()!=receipt['treeSha256']:
        raise ValueError('component_bundle_manifest_changed')
    if {name:_read(root/name,True)[1] for name in files}!=receipt['files'] or {name:_directory(root/name) for name in dirs}!=receipt['directories']:
        raise ValueError('component_bundle_changed_while_loading')
    return {name:files[name][0] for name in FILES}


def modules(receipt):
    """Execute full staged sources under a finite importer, never repository fallback."""
    files=load(receipt);root=Path(receipt['directory']);cache={}
    prefix='_android_component_'+hashlib.sha256(_raw(receipt)).hexdigest()
    paths={name[:-3].replace('/','.'):name for name in FILES}
    aliases={name.removeprefix('scripts/').removesuffix('.py'):name[:-3].replace('/','.')
             for name in FILES if name.startswith('scripts/android_fixture_')}
    packages={'agent_tools','scripts','scripts.integration'}
    def get(name):
        name=aliases.get(name,name)
        if name in cache:return cache[name]
        if name not in paths and name not in packages:raise ImportError('component_bundle_unstaged_import')
        module=types.ModuleType(prefix+'.'+name);cache[name]=module;sys.modules[module.__name__]=module
        module.__package__=prefix+'.'+(name if name in packages else name.rpartition('.')[0])
        if name in packages:module.__path__=[];return module
        module.__file__=str(root/paths[name])
        def importer(import_name,globals=None,locals=None,fromlist=(),level=0):
            if level:
                resolved=importlib.util.resolve_name('.'*level+import_name,(globals or {}).get('__package__',''))
                if not resolved.startswith(prefix+'.'):raise ImportError('component_bundle_crossed_import')
                import_name=resolved[len(prefix)+1:]
            mapped=aliases.get(import_name,import_name)
            if mapped.split('.')[0] in ('agent_tools','scripts') or import_name in aliases:
                value=get(mapped)
                for child in fromlist:
                    if child=='*':raise ImportError('component_bundle_star_import')
                    candidate=mapped+'.'+child
                    if candidate in paths or candidate in packages:setattr(value,child,get(candidate))
                return value if fromlist else get(mapped.split('.')[0])
            if mapped.split('.')[0] not in sys.stdlib_module_names and mapped!='__future__':
                raise ImportError('component_bundle_external_import')
            return builtins.__import__(import_name,globals,locals,fromlist,level)
        module.__dict__['__builtins__']={**vars(builtins),'__import__':importer}
        before=sys.path[:]
        try:exec(compile(files[paths[name]],module.__file__,'exec',dont_inherit=True),module.__dict__)
        finally:sys.path[:]=before
        load(receipt)
        return module
    for name in ('agent_tools.android_installer_component_adapter','scripts.android_installer_lifecycle','scripts.android_no_update_tls_preflight'):
        get(name)
    return {'adapter':get('agent_tools.android_installer_component_adapter'),
            'transport':get('agent_tools.android_component_command_transport'),
            'lifecycle':get('scripts.android_installer_lifecycle'),'tls':get('scripts.android_no_update_tls_preflight')}


def namespace_source(receipt,prepared):
    """Finite source API: verified bundle loader plus command factory prefix only."""
    files=load(receipt)
    # Import uses the reviewed local transport only for its factory and source pins.
    from . import android_component_command_transport as command
    source=command.namespace_source(prepared)
    if files['agent_tools/android_component_command_transport.py']!=_read(command.__file__)[0]:
        raise ValueError('component_bundle_transport_source_changed')
    own=_read(__file__)[0]
    if files['agent_tools/android_installer_component_bundle.py']!=own:raise ValueError('component_bundle_factory_changed')
    bootstrap=("import types\nCOMPONENT_BUNDLE=types.ModuleType('component_bundle_bootstrap')\n"
               "COMPONENT_BUNDLE.__file__="+repr(str(Path(receipt['directory'])/'agent_tools/android_installer_component_bundle.py'))+"\n"
               "exec(compile("+repr(own)+",COMPONENT_BUNDLE.__file__,'exec'),COMPONENT_BUNDLE.__dict__)\n"
               "COMPONENT_RECEIPT="+repr(copy.deepcopy(receipt))+"\n"
               "COMPONENT_MODULES=COMPONENT_BUNDLE.modules(COMPONENT_RECEIPT)\n")
    result=bootstrap+source+'\nGETTER_RECORDS={}\n'
    compile(result,'<closed-installer-component-namespace>','exec')
    load(receipt)
    return result


def payload(receipt):
    """Transfer exact reviewed tooling bytes; FD identities are measured remotely."""
    files=load(receipt)
    return {'schema':1,'kind':'android-installer-component-transfer',
            'treeSha256':receipt['treeSha256'],
            'files':{name:base64.b64encode(files[name]).decode('ascii') for name in FILES}}


def stage_payload(value,destination,expected_reviewed_tree_sha256,*,_receiver_root=None):
    """Create-only receiving half, with an independently bound reviewed digest."""
    if (type(value)is not dict or set(value)!={'schema','kind','treeSha256','files'} or
        type(value['schema'])is not int or value['schema']!=1 or value['kind']!='android-installer-component-transfer' or
        type(value['files'])is not dict or set(value['files'])!=set(FILES) or
        type(expected_reviewed_tree_sha256)is not str or not re.fullmatch('[0-9a-f]{64}',expected_reviewed_tree_sha256) or
        value['treeSha256']!=expected_reviewed_tree_sha256):
        raise ValueError('component_bundle_transfer_invalid')
    files={};total=0
    for name in FILES:
        encoded=value['files'][name]
        if type(encoded)is not str or len(encoded)>LIMIT*2:raise ValueError('component_bundle_transfer_invalid')
        try:raw=base64.b64decode(encoded,validate=True)
        except ValueError as error:raise ValueError('component_bundle_transfer_invalid') from error
        total+=len(raw)
        if len(raw)>LIMIT or total>LIMIT:raise ValueError('component_bundle_transfer_limit')
        files[name]=(raw,{'sha256':hashlib.sha256(raw).hexdigest()})
    tree=_tree(files);digest=hashlib.sha256(_raw(tree)).hexdigest()
    if digest!=expected_reviewed_tree_sha256:raise ValueError('component_bundle_transfer_changed')
    return _stage(Path(destination).absolute(),files,tree,digest,_receiver_root)


def carrier_source(receipt,prepared,correlation_id):
    """Fixed host-receiving source; invoke through the operator's existing carrier.

    It initializes the command factory, then stages only the reviewed complete
    tooling under its measured ROOT. It executes no installer or TLS action.
    The measured root supervisor authenticates protected history and its current
    owned process. Commands retain c9 child credential drop to UID/GID1000. The
    exact source-bound ROOT may be user1000 owned; new stage stays root private.
    Do not send a large source through an argv transport.
    """
    if type(correlation_id)is not str or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',correlation_id):
        raise ValueError('component_bundle_correlation_required')
    files=load(receipt)
    from . import android_component_command_transport as command
    prefix=command.namespace_source(prepared)
    if files['agent_tools/android_component_command_transport.py']!=_read(command.__file__)[0] or files['agent_tools/android_installer_component_bundle.py']!=_read(__file__)[0]:
        raise ValueError('component_bundle_factory_changed')
    roots=[node for node in ast.parse(prefix).body if isinstance(node,ast.Assign) and
           any(isinstance(target,ast.Name) and target.id=='ROOT' for target in node.targets)]
    if len(roots)!=1:raise ValueError('component_bundle_receiver_root_required')
    root_value=roots[0].value
    if (not isinstance(root_value,ast.Call) or ast.unparse(root_value.func)!='pathlib.Path' or
        len(root_value.args)!=1 or root_value.keywords or not isinstance(root_value.args[0],ast.Constant) or
        type(root_value.args[0].value)is not str or not Path(root_value.args[0].value).is_absolute() or
        '..' in Path(root_value.args[0].value).parts):
        raise ValueError('component_bundle_receiver_root_required')
    root_source='pathlib.Path('+repr(root_value.args[0].value)+')'
    destination='android-installer-component-bundle-'+correlation_id
    result=prefix+"\nGETTER_RECORDS={}\ncommand_host_guard()\nif COMMAND_HOST['uid']!=0 or COMMAND_HOST['euid']!=0 or COMMAND_HOST['gid']!=0 or COMMAND_HOST['egid']!=0:raise ValueError('component_bundle_receiver_identity_unadmitted')\nimport types\nCOMPONENT_BUNDLE=types.ModuleType('component_bundle_bootstrap')\n"
    result+="if ROOT!="+root_source+":raise ValueError('component_bundle_receiver_root_changed')\n"
    result+="COMPONENT_BUNDLE.__file__=str(ROOT/"+repr(destination)+"/'agent_tools/android_installer_component_bundle.py')\n"
    result+="exec(compile("+repr(files['agent_tools/android_installer_component_bundle.py'])+",COMPONENT_BUNDLE.__file__,'exec'),COMPONENT_BUNDLE.__dict__)\n"
    result+="COMPONENT_RECEIPT=COMPONENT_BUNDLE.stage_payload("+repr(payload(receipt))+",ROOT/"+repr(destination)+","+repr(receipt['treeSha256'])+",_receiver_root=ROOT)\n"
    result+="COMPONENT_MODULES=COMPONENT_BUNDLE.modules(COMPONENT_RECEIPT)\ncommand_host_guard()\n"
    compile(result,'<installer-component-host-carrier>','exec');load(receipt)
    return result

# Fixed read-only guest process catalogue. No caller supplies command text.
_PROCESS_READ = 'for n in adbd zygote zygote64; do for p in $(pidof "$n"); do printf \'%s\\t%s\\t\' "$n" "$p"; cat /proc/$p/stat; done; done'
_PROPERTIES=(('sdk','ro.build.version.sdk'),('abi','ro.product.cpu.abi'),
             ('kernelAvd','ro.kernel.qemu.avd_name'),('bootAvd','ro.boot.qemu.avd_name'),
             ('bootCompleted','sys.boot_completed'))

# Only this closed carrier gets the aggregate of the ten existing budgets.
# Ten separately base64-encoded stdout/stderr pairs can have one extra quartet
# each; the remaining 256 bytes per frame and 128-byte envelope are fixed.
_PHYSICAL_FRAME_LIMIT=16384
_PHYSICAL_BATCH_LIMIT=10*(4*((16384+2)//3)+4+256)+128
_PHYSICAL_ABI = 'component-physical-batch-profile4.v1/source-sha256:0fa6510875119ca3da6a5097d484a0c3e8b384b547512ca375411a59bdd22598'

_PROFILE4_PROGRAM = 'set -eu\nprintf \'PHYSICAL-READONLY-4\\n\'\nuid=$(id -u);printf \'UID %s\\n\' "$uid"\nshellmap=$(/system/bin/toybox readlink /proc/$$/exe)\nutilitymap=$(/system/bin/toybox readlink /proc/self/exe)\nprintf \'SHELL %s\\nUTILITY %s\\n\' "$shellmap" "$utilitymap"\nng=$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/sh)\nprintf \'NAMED-SH-GENERATION %s\\n\' "$ng"\nif test -L /system/bin/sh; then\n link=$(/system/bin/toybox readlink /system/bin/sh);kind=symlink\nelse\n link=NONE;kind=regular\nfi\nprintf \'SH-KIND %s\\nSH-TARGET %s\\n\' "$kind" "$link"\nprintf \'KSH-VERSION \'\nprintf \'%s\' "${KSH_VERSION-}" | /system/bin/toybox base64 -w 0\nprintf \'\\n\'\nprintf \'PRINCIPAL \'; /system/bin/toybox id\nboot=$(cat /proc/sys/kernel/random/boot_id);printf \'BOOT %s\\n\' "$boot"\nprintf \'INHERITED-LIMITS \'; /system/bin/toybox base64 -w 0 /proc/$$/limits;printf \'\\n\'\ntest "$uid" = 2000\ntest "$utilitymap" = /system/bin/toybox\ncase "$shellmap" in /system/bin/sh|/system/bin/mksh) ;; *) exit 91;; esac\ncase "$kind:$link:$shellmap" in regular:NONE:/system/bin/sh|symlink:mksh:/system/bin/mksh|symlink:/system/bin/mksh:/system/bin/mksh) ;; *) exit 92;; esac\ncase "${KSH_VERSION-}" in \'@(#)MIRBSD KSH R\'[0-9]*\' \'*) ;; *) exit 93;; esac\ntest -f "$shellmap" && test ! -L "$shellmap"\ntest -f /system/bin/toybox && test ! -L /system/bin/toybox\nfor binary in "$shellmap" /system/bin/toybox; do\n principal=$(/system/bin/toybox stat -c \'%u:%g:%a:%h\' "$binary")\n case "$principal" in 0:0:755:1|0:2000:755:1) ;; *) exit 94;; esac\ndone\nsg=$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' "$shellmap")\ntg=$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/toybox)\nshellhash=$(/system/bin/toybox sha256sum "$shellmap");toyhash=$(/system/bin/toybox sha256sum /system/bin/toybox)\nprintf \'SHELL-GENERATION %s\\nTOYBOX-GENERATION %s\\nSHELL-HASH %s\\nTOYBOX-HASH %s\\n\' "$sg" "$tg" "$shellhash" "$toyhash"\ntest "$(printf \'a\\nb\\n\' | /system/bin/toybox base64 -w 0)" = \'YQpiCg==\'\nexec 4</system/bin/toybox\nexec 5</system/bin/toybox\nbg=$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/toybox)\ntest "$bg" = "$tg"\nexpected=$(/system/bin/toybox sha256sum /system/bin/toybox);expected=${expected%% *}\ntest "$expected" = "${toyhash%% *}"\nfor fd in 4 5; do\n test "$(/system/bin/toybox stat -L -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /proc/$$/fd/$fd)" = "$bg"\ndone\nh4=$(/system/bin/toybox sha256sum /proc/self/fd/4 4>&4);h4=${h4%% *}\nh5=$(/system/bin/toybox sha256sum /proc/self/fd/5 5>&5);h5=${h5%% *}\nexec 4<&-;exec 5<&-\nprintf \'FD4 %s\\nFD5 %s\\n\' "$h4" "$h5"\ntest "$h4" = "$expected" && test "$h5" = "$expected"\ntest "$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/toybox)" = "$bg"\nbefore=$(/system/bin/toybox cat /proc/uptime);set -- $before;before=$1\nset +e\nwd=$(/system/bin/toybox timeout -s KILL 1 "$shellmap" -c __WD_CHILD__)\nrc=$?\nset -e\nafter=$(/system/bin/toybox cat /proc/uptime);set -- $after;after=$1\nprintf \'%s\\nWATCHDOG %s\\nWATCHDOG-TIME %s %s\\n\' "$wd" "$rc" "$before" "$after"\ntest "$rc" = 137 || exit 95\nset -- $wd;test "$#" = 5;test "$1" = WATCHDOG-CHILD;test "$2" = __WD_CORR__;pid=$3;ticks=$4;test "$5" = 2000\ncase "$pid:$ticks" in *[!0-9:]*|:*|*:) exit 96;; esac;test "$pid" -gt 0;test "$ticks" -gt 0\nset +e\npost=$(/system/bin/toybox stat -L -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /proc/$pid 2>&1);postrc=$?\nset -e\nprintf \'WATCHDOG-POST %s \' "$postrc";printf \'%s\' "$post" | /system/bin/toybox base64 -w 0;printf \'\\n\'\ntest "$postrc" = 1\ntest "$post" = "stat: \'/proc/$pid\': No such file or directory"\nlimit=$( (ulimit -f 32; /system/bin/toybox cat /proc/self/limits) )\nprintf \'LIMIT-PROOF \';printf \'%s\' "$limit" | /system/bin/toybox base64 -w 0;printf \'\\n\'\ntest "$(printf \'%s\\n\' "$limit" | /system/bin/toybox grep -E \'^Max file size[[:space:]]+16384[[:space:]]+16384[[:space:]]+bytes[[:space:]]*$\')" != \'\'\ntest "$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' "$shellmap")" = "$sg"\ntest "$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/toybox)" = "$tg"\ntest "$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/sh)" = "$ng"\ntest "$(/system/bin/toybox sha256sum "$shellmap")" = "$shellhash"\ntest "$(/system/bin/toybox sha256sum /system/bin/toybox)" = "$toyhash"\ntest "$(/system/bin/toybox readlink /proc/$$/exe)" = "$shellmap"\ntest "$(cat /proc/sys/kernel/random/boot_id)" = "$boot"\nprintf \'EOF READONLY-4 COMPLETE\\n\'\n'

_PROFILE4_CHILD = 'set -eu\nuid=$(/system/bin/toybox id -u);test "$uid" = 2000\nline=$(/system/bin/toybox cat /proc/$$/stat)\ncase "$line" in "$$ ("*") "*) ;; *) exit 96;; esac\nrest=${line##*) };set -- $rest;test "$#" -ge 20;shift 19;ticks=$1\ncase "$ticks" in \'\'|*[!0-9]*) exit 96;; esac;test "$ticks" -gt 0\nprintf \'WATCHDOG-CHILD __WD_CORR__ %s %s %s\\n\' "$$" "$ticks" "$uid"\nexec /system/bin/toybox sleep 2\n'

def _profile4_source(correlation):
    """One fixed readonly command, positively bound to a canonical UUID."""
    if type(correlation) is not str or str(uuid.UUID(correlation)) != correlation:
        raise ValueError('abi_packet_identity_changed')
    child = _PROFILE4_CHILD.replace('__WD_CORR__', correlation)
    return _PROFILE4_PROGRAM.replace('__WD_CHILD__', shlex.quote(child)).replace('__WD_CORR__', correlation)

def _profile4_parse(raw, correlation, expected_boot):
    """Strict bounded ABI facts only, with no native/product authority."""
    if type(correlation) is not str or type(expected_boot) is not str or re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', correlation) is None or (re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', expected_boot) is None):
        raise ValueError('abi_packet_identity_changed')
    if type(raw) is not str or len(raw.encode()) > 16384 or (not raw.endswith('\n')):
        raise ValueError('abi_packet_reply_unknown')
    lines = raw.splitlines()
    keys = ('PHYSICAL-READONLY-4', 'UID', 'SHELL', 'UTILITY', 'NAMED-SH-GENERATION', 'SH-KIND', 'SH-TARGET', 'KSH-VERSION', 'PRINCIPAL', 'BOOT', 'INHERITED-LIMITS', 'SHELL-GENERATION', 'TOYBOX-GENERATION', 'SHELL-HASH', 'TOYBOX-HASH', 'FD4', 'FD5', 'WATCHDOG-CHILD', 'WATCHDOG', 'WATCHDOG-TIME', 'WATCHDOG-POST', 'LIMIT-PROOF', 'EOF')
    if len(lines) != len(keys) or lines[0] != keys[0] or lines[-1] != 'EOF READONLY-4 COMPLETE':
        raise ValueError('abi_packet_reply_unknown')
    values = {}
    for line, key in zip(lines[1:], keys[1:]):
        if not line.startswith(key + ' '):
            raise ValueError('abi_packet_reply_unknown')
        values[key] = line[len(key) + 1:]
    shell = values['SHELL']
    if values['UID'] != '2000' or shell not in ('/system/bin/sh', '/system/bin/mksh') or values['UTILITY'] != '/system/bin/toybox':
        raise ValueError('abi_packet_mapping_unknown')
    if (values['SH-KIND'], values['SH-TARGET'], shell) not in (('regular', 'NONE', '/system/bin/sh'), ('symlink', 'mksh', '/system/bin/mksh'), ('symlink', '/system/bin/mksh', '/system/bin/mksh')):
        raise ValueError('abi_packet_mapping_unknown')
    import stat
    for key in ('NAMED-SH-GENERATION', 'SHELL-GENERATION', 'TOYBOX-GENERATION'):
        generation = values[key]
        if re.fullmatch('[0-9]+:[1-9][0-9]*:[0-9a-f]+:0:(?:0|2000):1:[0-9]+:[^\\n]+:[^\\n]+', generation) is None:
            raise ValueError('abi_packet_generation_unknown')
        mode = int(generation.split(':')[2], 16)
        link = key == 'NAMED-SH-GENERATION' and values['SH-KIND'] == 'symlink'
        if (not stat.S_ISLNK(mode) if link else not stat.S_ISREG(mode)) or (not link and stat.S_IMODE(mode) != 493):
            raise ValueError('abi_packet_generation_unknown')

    def decode(key, limit):
        try:
            value = base64.b64decode(values[key], validate=True)
        except Exception:
            raise ValueError('abi_packet_reply_unknown') from None
        if len(value) > limit or base64.b64encode(value).decode() != values[key]:
            raise ValueError('abi_packet_reply_unknown')
        return value
    version = decode('KSH-VERSION', 512)
    if re.fullmatch(b'@\\(#\\)MIRBSD KSH R[0-9]+ [ -~]{1,256}', version) is None:
        raise ValueError('abi_packet_shell_family_unknown')
    if re.fullmatch('uid=2000\\([^\\n()]+\\) gid=2000\\([^\\n()]+\\)(?: groups=[^\\n]+)?', values['PRINCIPAL']) is None:
        raise ValueError('abi_packet_principal_unknown')
    if re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', values['BOOT']) is None or values['BOOT'] != expected_boot:
        raise ValueError('abi_packet_boot_unknown')
    inherited = decode('INHERITED-LIMITS', 8192)
    limit_proof = decode('LIMIT-PROOF', 8192)
    if len(re.findall(b'^Max file size\\s+(?:[0-9]+|unlimited)\\s+(?:[0-9]+|unlimited)\\s+bytes\\s*$', inherited, re.M)) != 1 or len(re.findall(b'^Max file size\\s+16384\\s+16384\\s+bytes\\s*$', limit_proof, re.M)) != 1:
        raise ValueError('abi_packet_limits_unknown')
    for key, path in (('SHELL-HASH', shell), ('TOYBOX-HASH', '/system/bin/toybox')):
        if re.fullmatch('[0-9a-f]{64}  ' + re.escape(path), values[key]) is None:
            raise ValueError('abi_packet_hash_unknown')
    if values['WATCHDOG'] != '137' or re.fullmatch('[0-9a-f]{64}', values['FD4']) is None or values['FD5'] != values['FD4'] or (values['FD4'] != values['TOYBOX-HASH'][:64]):
        raise ValueError('abi_packet_capability_unknown')
    child = re.fullmatch(re.escape(correlation) + ' ([1-9][0-9]*) ([1-9][0-9]*) 2000', values['WATCHDOG-CHILD'])
    if child is None:
        raise ValueError('abi_packet_watchdog_child_unknown')
    times = re.fullmatch('([0-9]+\\.[0-9]+) ([0-9]+\\.[0-9]+)', values['WATCHDOG-TIME'])
    if times is None:
        raise ValueError('abi_packet_watchdog_time_unknown')
    from decimal import Decimal
    elapsed = Decimal(times[2]) - Decimal(times[1])
    if not Decimal('0.75') <= elapsed <= Decimal('1.75'):
        raise ValueError('abi_packet_watchdog_time_unknown')
    post = values['WATCHDOG-POST'].split(' ')
    if len(post) != 2 or post[0] != '1':
        raise ValueError('abi_packet_watchdog_child_unknown')
    try:
        absence = base64.b64decode(post[1], validate=True)
    except Exception:
        raise ValueError('abi_packet_watchdog_child_unknown') from None
    if base64.b64encode(absence).decode() != post[1] or absence != ("stat: '/proc/" + child[1] + "': No such file or directory").encode():
        raise ValueError('abi_packet_watchdog_child_unknown')
    return {'kind': 'utility-abi-only', 'profileVersion': 4, 'shellPath': shell, 'shellSha256': values['SHELL-HASH'][:64], 'toyboxSha256': values['TOYBOX-HASH'][:64], 'fdSha256': values['FD4'], 'utilityGenerations': {k: values[k] for k in ('NAMED-SH-GENERATION', 'SHELL-GENERATION', 'TOYBOX-GENERATION')}, 'guestBootId': values['BOOT'], 'family': 'mksh-capability-checked', 'shellVersion': version.decode(), 'fileLimit': 16384, 'watchdogExit': 137, 'watchdogChildPid': int(child[1]), 'watchdogChildStartTicks': int(child[2]), 'watchdogElapsedSeconds': str(elapsed), 'watchdogChildAbsent': True, 'ownerAdmission': False, 'runtimeAdmission': False, 'batchEnabled': False, 'overflowWriteProven': False, 'nativeAcceptance': False}


def _physical_abi_parse(raw, correlation, expected_boot):
    """Distinct batch utility admission; exact alpha-derived profile4 parser."""
    proof = _profile4_parse(raw, correlation, expected_boot)
    lines = raw.splitlines()
    return {
        'protocol': 'component-physical-batch-profile4.v1',
        'profileSourceSha256': '0fa6510875119ca3da6a5097d484a0c3e8b384b547512ca375411a59bdd22598',
        'calibrationRaw': raw, 'calibrationCorrelationId': correlation,
        'proof': proof, 'shellPath': proof['shellPath'],
        'shellSha256': proof['shellSha256'], 'toyboxSha256': proof['toyboxSha256'],
        'guestBootId': proof['guestBootId'],
        'utilityGenerations': copy.deepcopy(proof['utilityGenerations']),
        'namedShellKind': lines[5].removeprefix('SH-KIND '),
        'namedShellTarget': lines[6].removeprefix('SH-TARGET '),
        'shellVersion': proof['shellVersion'],
        'watchdogExit': 137, 'stepSeconds': 20, 'frameLimit': 16384,
        'fileLimit': 16384, 'failedPrivateStreamBytesMaximum': 32768,
    }


def _physical_batch_source(correlation,abi):
    """Fixed shell catalogue; no caller command, guest path or timeout selector.

    Acquired-parent authority uses the approved single shell-UID2000 operator
    model. It does not promise protection from a concurrent authorized UID2000
    writer before directory acquisition. Descriptor/name closure starts at cd.
    """
    if (str(uuid.UUID(correlation)) != correlation or type(abi) is not dict or
            abi != _physical_abi_parse(abi.get('calibrationRaw'), abi.get('calibrationCorrelationId'), abi.get('guestBootId'))):
        raise ValueError('component_guard_batch_abi_unknown')
    opening='''set -eu
umask 077
test "$(/system/bin/toybox id -u)" = 2000
guard_utilities() {
 test "$(/system/bin/toybox cat /proc/sys/kernel/random/boot_id)" = BOOT
 test "$(/system/bin/toybox readlink /proc/$$/exe)" = SHELLPATH
 test "$(/system/bin/toybox readlink /proc/self/exe)" = /system/bin/toybox
 test -f SHELLPATH && test ! -L SHELLPATH
 test -f /system/bin/toybox && test ! -L /system/bin/toybox
 case SHKIND in
  regular) test ! -L /system/bin/sh;;
  symlink) test -L /system/bin/sh && test "$(/system/bin/toybox readlink /system/bin/sh)" = SHTARGET;;
  *) exit 91;;
 esac
 test "$(/system/bin/toybox stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' /system/bin/sh)" = NAMEDGEN
 test "$(/system/bin/toybox stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' SHELLPATH)" = SHELLGEN
 test "$(/system/bin/toybox stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' /system/bin/toybox)" = TOYGEN
 test "$(/system/bin/toybox sha256sum /system/bin/toybox)" = TOYHASH
 test "$(/system/bin/toybox sha256sum SHELLPATH)" = SHHASH
}
guard_utilities
p=__VC_SPOOL__
/system/bin/toybox mkdir "$p"
test ! -L "$p"
cd "$p"
parent=$(/system/bin/toybox stat -c '%d:%i:%f:%u:%g' .)
test "$(/system/bin/toybox stat -c '%a:%u:%g' .)" = '700:2000:2000'
guard_parent() {
 test ! -L "$p"
 test "$(/system/bin/toybox stat -c '%d:%i:%f:%u:%g' .)" = "$parent"
 test "$(/system/bin/toybox stat -c '%d:%i:%f:%u:%g' "$p")" = "$parent"
}
generation() { /system/bin/toybox stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' "$1"; }
guard_file() {
 test ! -L "$1" && test -f "$1"
 test "$(/system/bin/toybox stat -c '%a:%u:%g:%h' "$1")" = '600:2000:2000:1'
}
run() {
 n=$1; shift
 guard_parent
 set -C
 exec 4>"$n.o"
 exec 5>"$n.e"
 set +C
 guard_file "$n.o"; guard_file "$n.e"
 test "$(/system/bin/toybox stat -L -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' /proc/$$/fd/4 4>&4)" = "$(generation "$n.o")"
 test "$(/system/bin/toybox stat -L -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' /proc/$$/fd/5 5>&5)" = "$(generation "$n.e")"
 set +e
 (ulimit -f 32; /system/bin/toybox timeout -s KILL 20 "$@" 4>&4 5>&5 >&4 2>&5)
 rc=$?
 set -e
 test "$(/system/bin/toybox stat -L -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' /proc/$$/fd/4 4>&4)" = "$(generation "$n.o")"
 test "$(/system/bin/toybox stat -L -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' /proc/$$/fd/5 5>&5)" = "$(generation "$n.e")"
 exec 4>&-; exec 5>&-
 guard_parent; guard_file "$n.o"; guard_file "$n.e"
 og=$(generation "$n.o"); eg=$(generation "$n.e")
 os=$(/system/bin/toybox stat -c '%s' "$n.o"); es=$(/system/bin/toybox stat -c '%s' "$n.e")
 test "$((os+es))" -le 16384
 oh=$(printf '%s' "$og" | /system/bin/toybox sha256sum); oh=${oh%% *}
 eh=$(printf '%s' "$eg" | /system/bin/toybox sha256sum); eh=${eh%% *}
 case "$n" in GENERATION_SAVE esac
 printf 'FRAME\t%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "$rc" "$os" "$es" "$oh" "$eh"
 /system/bin/toybox base64 -w 0 "$n.o"; printf '\n'
 /system/bin/toybox base64 -w 0 "$n.e"; printf '\n'
 test "$(generation "$n.o")" = "$og" && test "$(generation "$n.e")" = "$eg"
 guard_parent
}
printf 'PHYSICAL-1 CORRELATION\n'
'''
    opening=opening.replace('BOOT',shlex.quote(abi['guestBootId'])).replace('TOYHASH',shlex.quote(abi['toyboxSha256']+'  /system/bin/toybox')).replace('SHHASH',shlex.quote(abi['shellSha256']+'  '+abi['shellPath'])).replace('__VC_SPOOL__',shlex.quote('/data/local/tmp/vpn-control-physical-'+correlation)).replace('CORRELATION',correlation)
    opening = (opening.replace('SHELLPATH', shlex.quote(abi['shellPath']))
        .replace('SHKIND', shlex.quote(abi['namedShellKind']))
        .replace('SHTARGET', shlex.quote(abi['namedShellTarget']))
        .replace('NAMEDGEN', shlex.quote(abi['utilityGenerations']['NAMED-SH-GENERATION']))
        .replace('SHELLGEN', shlex.quote(abi['utilityGenerations']['SHELL-GENERATION']))
        .replace('TOYGEN', shlex.quote(abi['utilityGenerations']['TOYBOX-GENERATION'])))
    lines=[]
    commands=[['/system/bin/getprop',prop] for _,prop in _PROPERTIES]+[['/system/bin/toybox','id','-u'],['/system/bin/toybox','cat','/proc/sys/kernel/random/boot_id'],['/system/bin/sh','-c',_PROCESS_READ.replace('pidof ', '/system/bin/toybox pidof ').replace('cat ', '/system/bin/toybox cat ')],['/system/bin/pm','path','com.kardinal.vpncontrol']]
    for n,words in enumerate(commands,1):lines.append('run '+str(n)+' '+' '.join(shlex.quote(word) for word in words))
    lines.append('''package=$(/system/bin/toybox cat 9.o)
case "$package" in package:/data/app/*/base.apk) ;; *) exit 92;; esac
package=${package#package:}
case "$package" in *[!-A-Za-z0-9_./+~=]*) exit 92;; esac
case "/$package/" in */../*) exit 92;; esac
run 10 /system/bin/toybox sha256sum "$package"
guard_parent
test "$(/system/bin/toybox find . -mindepth 1 -maxdepth 1 -type f | /system/bin/toybox wc -l)" -eq 20
for n in 1 2 3 4 5 6 7 8 9 10; do
 guard_parent; guard_file "$n.o"; guard_file "$n.e"
 case "$n" in GENERATION_CHECK esac
 /system/bin/toybox rm "$n.o" "$n.e"
done
guard_parent
cd /data/local/tmp
/system/bin/toybox rmdir "$p"
guard_utilities
printf 'EOF CORRELATION CLEANED\n'
'''.replace('CORRELATION',correlation))
    result=opening+'\n'.join(lines)
    result=result.replace('GENERATION_SAVE',' '.join(str(n)+') og'+str(n)+'=$og; eg'+str(n)+'=$eg;;' for n in range(1,11)))
    result=result.replace('GENERATION_CHECK',' '.join(str(n)+') test "$(generation "$n.o")" = "$og'+str(n)+'" && test "$(generation "$n.e")" = "$eg'+str(n)+'";;' for n in range(1,11)))
    return result


def _physical_batch_parse(raw,correlation):
    if type(raw)is not str or len(raw.encode())>_PHYSICAL_BATCH_LIMIT:
        raise ValueError('component_guard_batch_capture_unknown')
    lines=raw.split('\n')
    if len(lines)!=33 or lines[0]!='PHYSICAL-1 '+correlation or lines[-2]!='EOF '+correlation+' CLEANED' or lines[-1]!='':
        raise ValueError('component_guard_batch_capture_unknown')
    records=[]
    for n in range(1,11):
        header=lines[1+(n-1)*3].split('\t')
        if len(lines[1+(n-1)*3].encode())>256 or len(header)!=7 or header[:2]!=['FRAME',str(n)] or any(re.fullmatch('[0-9]{1,5}',x)is None for x in header[2:5]) or any(re.fullmatch('[0-9a-f]{64}',x)is None for x in header[5:]):
            raise ValueError('component_guard_batch_capture_unknown')
        status,out_size,err_size=map(int,header[2:5])
        if status>255 or out_size+err_size>16384:raise ValueError('component_guard_batch_capture_unknown')
        try:
            out=base64.b64decode(lines[2+(n-1)*3],validate=True);err=base64.b64decode(lines[3+(n-1)*3],validate=True)
            if len(out)!=out_size or len(err)!=err_size or base64.b64encode(out).decode()!=lines[2+(n-1)*3] or base64.b64encode(err).decode()!=lines[3+(n-1)*3]:raise ValueError()
            output=out.decode('utf-8');error=err.decode('utf-8')
        except (ValueError,UnicodeError):raise ValueError('component_guard_batch_capture_unknown')
        records.append({'ordinal':n,'returncode':status,'stdoutRaw':output,'stderrRaw':error,
                        'stdoutGenerationSha256':header[5],'stderrGenerationSha256':header[6]})
    return records


def _process_facts(raw):
    """Roles come only from the fixed pidof command, independently of stat comm."""
    if type(raw)is not str or not raw or len(raw.encode())>16384:
        raise ValueError('component_guard_process_unknown')
    facts=[];roles=set();pids=set()
    for line in raw.splitlines():
        match=re.fullmatch(r'(adbd|zygote|zygote64)\t([1-9][0-9]*)\t([1-9][0-9]*) \((adbd|zygote|zygote64|main)\) (.+)',line)
        if match is None:raise ValueError('component_guard_process_unknown')
        role,pid,stat_pid,name,fields=match.groups();pid=int(pid)
        if pid!=int(stat_pid) or pid in pids or name not in ((role,) if role=='adbd' else (role,'main')):
            raise ValueError('component_guard_process_unknown')
        fields=fields.split()
        if len(fields)<20 or not fields[19].isdigit() or int(fields[19])<1:
            raise ValueError('component_guard_process_unknown')
        facts.append({'role':role,'pid':pid,'name':name,'startTicks':int(fields[19])});roles.add(role);pids.add(pid)
    if len(facts)>8 or 'adbd' not in roles or not roles.intersection({'zygote','zygote64'}):
        raise ValueError('component_guard_process_unknown')
    return sorted(facts,key=lambda item:(item['role'],item['pid']))


def _context_device(backend,device,api,avd,serial,cli,package):
    """Task-bound finite context selection, before any generated function call."""
    expected={'android-api29':(29,'emulator-5684','api29'),
              'android-api35':(35,'emulator-5682','api35')}
    if type(device)is not str or device not in expected:
        raise ValueError('component_guard_crossed_binding')
    fixed_api,fixed_serial,launch_device=expected[device]
    if (type(api)is not int or api!=fixed_api or serial!=fixed_serial or
        backend['EXTERNAL']['serial']!=fixed_serial or
        backend['LAUNCH'].get('device')!=launch_device or
        type(avd)is not str or not avd or avd!=backend['LAUNCH']['avd'] or
        str(cli)!=backend['GETTER']['cli'] or package!=backend['GETTER']['packageSha256']):
        raise ValueError('component_guard_crossed_binding')
    return launch_device


def _selected_modules(receipt,selected):
    expected={'adapter':'agent_tools/android_installer_component_adapter.py',
              'transport':'agent_tools/android_component_command_transport.py',
              'lifecycle':'scripts/android_installer_lifecycle.py',
              'tls':'scripts/android_no_update_tls_preflight.py'}
    load(receipt)
    if type(selected)is not dict or set(selected)!=set(expected):raise ValueError('component_guard_modules_required')
    for name,path in expected.items():
        if not isinstance(selected[name],types.ModuleType) or Path(selected[name].__file__)!=Path(receipt['directory'])/path:
            raise ValueError('component_guard_unstaged_module')
    # Authenticate the context selector and its sole source-defined import value;
    # caller mutation of either a function or its globals cannot alter code proof.
    adapter=selected['adapter'];adapter_path=Path(receipt['directory'])/expected['adapter']
    adapter_raw,_=_read(adapter_path,True);adapter_tree=ast.parse(adapter_raw)
    adapter_code=compile(adapter_raw,str(adapter_path),'exec',dont_inherit=True)
    for name in ('production_imports','_semantic_code','_module','install'):
        original=next(value for value in adapter_code.co_consts if isinstance(value,types.CodeType) and value.co_name==name)
        actual=getattr(adapter,name,None)
        if not isinstance(actual,types.FunctionType) or actual.__globals__ is not adapter.__dict__ or actual.__code__!=original:
            raise ValueError('component_guard_context_source_changed')
    imports=next(ast.literal_eval(node.value) for node in adapter_tree.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='_PRODUCTION_IMPORTS' for target in node.targets))
    if adapter._PRODUCTION_IMPORTS!=imports:raise ValueError('component_guard_context_source_changed')
    for name,functions in [('lifecycle',('invoke','main','write_cli_evidence','reply_binding')),('tls',('verify_public_baseline','public_no_update_probe','public_cli_argv','public_cli_environment'))]:
        path=expected[name]
        selected['adapter']._module(selected[name],receipt['files'][path]['sha256'],functions)


def _guard_backend(selected,backend,device):
    """Authenticate fixed getter/transport functions, never caller callbacks."""
    transport=selected['transport'];reader=transport.readonly
    sources=[(transport.REMOTE+'\n'+transport._bounded_source(),
              ('component_command','command_binary','command_request','command_host_identity','command_host_guard','command_bounded')),
             (reader.getter_source._GETTER.replace('__GETTER__',repr({})),('getter_stage',)),
             (reader.getter_source.coldboot._BOOT.replace('__LAUNCH__',repr({})),('child_identity','session_guest','qemu_fact')),
             (reader.proven._REMOTE.replace('__EXTERNAL__',repr({})),('external_file','external_jdk','external_jdk_guard'))]
    # Match the command factory's normalized AST and imported module context.
    # Python 3.14 optimizes imported-module attributes during compilation.
    context=selected['adapter'].production_imports(device)
    for raw,names in sources:
        tree=ast.parse(raw)
        for name in names:
            nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==name]
            if len(nodes)!=1:raise ValueError('component_guard_fixed_source_changed')
            code=compile(context+ast.unparse(ast.Module(body=nodes,type_ignores=[])),'<guard-fixed-function>','exec',dont_inherit=True)
            expected=next(value for value in code.co_consts if isinstance(value,types.CodeType) and value.co_name==name)
            actual=backend.get(name)
            if (not isinstance(actual,types.FunctionType) or actual.__globals__ is not backend or
                selected['adapter']._semantic_code(actual.__code__)!=selected['adapter']._semantic_code(expected)):
                raise ValueError('component_guard_fixed_backend_required:'+name)
    return {name:(value,value.__code__) for name,value in backend.items() if isinstance(value,types.FunctionType)}


def _fixture_asset_pin(path):
    chain,parents=_parents(Path(path).parent);fd=None
    try:
        fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=chain[-1][1])
        info=os.fstat(fd);generation=_pin(info)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or
            info.st_uid!=os.getuid() or info.st_gid!=os.getgid() or not 0<info.st_size<=67108864):
            raise ValueError('component_guard_fixture_asset_unsafe')
        digest=hashlib.sha256();size=0
        while part:=os.read(fd,524288):
            size+=len(part)
            if size>67108864:raise ValueError('component_guard_fixture_asset_limit')
            digest.update(part)
        pin={'generation':generation,'parents':parents,'sha256':digest.hexdigest()}
        _evidence_generation_closure({str(path):pin})
        if size!=generation[6] or _raw(_pin(os.fstat(fd)))!=_raw(generation):
            raise ValueError('component_guard_fixture_asset_changed')
        return pin
    finally:
        if fd is not None:os.close(fd)
        _close(chain)


def _fixture_asset_record(path):
    pin=_fixture_asset_pin(path)
    if pin['generation'][6]>65536:raise ValueError('component_guard_fixture_asset_record_invalid')
    chain,_=_parents(Path(path).parent);fd=None
    try:
        fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=chain[-1][1])
        raw=b''
        while part:=os.read(fd,65536):
            raw+=part
            if len(raw)>65536:raise ValueError('component_guard_fixture_asset_record_invalid')
        if hashlib.sha256(raw).hexdigest()!=pin['sha256'] or _raw(_pin(os.fstat(fd)))!=_raw(pin['generation']):
            raise ValueError('component_guard_fixture_asset_changed')
        _evidence_generation_closure({str(path):pin})
        return raw,pin
    finally:
        if fd is not None:os.close(fd)
        _close(chain)


class CurrentGuard:
    """Fresh measured guard; old getter_generation is never admission authority.

    Construction measures hardware/boot/process/package/stage/current public owner
    and durably records all raw reads. Calling reobserves the same generation.
    Post-install drift remains unknown and requires a separate resumed admission.
    """
    def __init__(self, receipt, selected_modules, backend, args):
        if set(selected_modules)!={'adapter','transport','lifecycle','tls'}:
            raise ValueError('component_guard_modules_required')
        self.receipt=copy.deepcopy(receipt);self.modules=selected_modules
        _selected_modules(self.receipt,selected_modules)
        self.backend=backend;self.args=args;self.sequence=0;self.expected=None
        self.intent=selected_modules['lifecycle'].target_admission.load_intent(args.intent_file)
        self.intent_pin=_read(args.intent_file,True)[1]
        if (self.intent.get('host')!='archlinux' or self.intent['pair'].get('sourceSha')!=_PRODUCT_SHA or
            type(args.api) not in (str,int) or str(args.api)!=str(self.intent['expectedApi']) or
            args.avd!=self.intent['expectedAvd']):raise ValueError('component_guard_crossed_binding')
        self.context_device=_context_device(backend,self.intent.get('device'),self.intent['expectedApi'],
            self.intent['expectedAvd'],args.serial,args.cli,self.intent['pair']['baseSha256'])
        self.function_pins=_guard_backend(selected_modules,backend,self.context_device)
        self.phase='installer';self.phase_pins={};self.accepted_operation=None;self.handoff=None
        self.action_intent=None;self.setup_expected=None;self.fixture_assets_raw=None
        self.reservation=copy.deepcopy(backend['LAUNCH']['intent']['reservation'])
        self.measurement={'avd':self.intent['expectedAvd'],'api':self.intent['expectedApi'],
                          'packageSha256':self.intent['pair']['baseSha256']}
        self._task_guard()
        self.owner=self.intent['expectedOwner'];self.revision=self.intent['expectedRevision']
        backend['command_request'](['status'],self.owner,self.revision,'baseline')
        if (args.serial!=backend['EXTERNAL']['serial'] or str(args.cli)!=backend['GETTER']['cli'] or
            self.intent['expectedAvd']!=backend['LAUNCH']['avd'] or
            str(self.intent['expectedApi'])!=('29' if args.serial=='emulator-5684' else '35') or
            self.intent['pair']['baseSha256']!=backend['GETTER']['packageSha256']):
            raise ValueError('component_guard_crossed_binding')
        self.host=backend['command_host_identity']()
        backend['command_host_guard']()
        self.stage=copy.deepcopy(backend['getter_stage']())
        self.expected=self._physical()
        self._public()
        self._evidence('current-admission',{'facts':self.expected,'stage':self.stage,
                         'host':self.host,'owner':self.owner,'revision':self.revision,
                         'intentPin':self.intent_pin,'lease':self.lease_record})
        self.admission_pin=_read(args.output/'component-guard-current-admission.json',True)[1]

    def bind_fixture_assets(self, stage_pin):
        """Bind create-only custody record before fixture/installer release.

        Does not modify physical generations, owner, phase pins or lease. The
        original staged/custody generations remain authority through cleanup.
        """
        if type(self)is not CurrentGuard:raise ValueError('component_guard_installer_asset_scope_required')
        if self.fixture_assets_raw is not None:raise ValueError('component_guard_fixture_assets_already_bound')
        path=self.args.output/'asset-stage.json'
        raw,pin=_fixture_asset_record(path)
        if _raw(pin)!=_raw(stage_pin):raise ValueError('component_guard_fixture_asset_changed')
        record=json.loads(raw)
        if (type(record)is not dict or set(record)!={'schema','correlationId','origins','staged','caPrivateKeyTransferred'} or
            type(record['schema'])is not int or record['schema']!=1 or record['correlationId']!=self.intent['correlationId'] or
            record['caPrivateKeyTransferred']is not False or type(record['origins'])is not dict or type(record['staged'])is not dict):
            raise ValueError('component_guard_fixture_asset_record_invalid')
        names={'base.apk':'base_apk','target.apk':'target_apk','ca.pem':'ca_certificate','leaf.pem':'leaf_certificate','key.pem':'private_key'}
        staged={str(self.args.output/'assets'/name):getattr(self.args,attr) for name,attr in names.items()}
        if set(record['staged'])!=set(staged) or any(str(value)!=key for key,value in staged.items()):
            raise ValueError('component_guard_fixture_asset_paths_changed')
        root=Path(self.backend['ROOT']);origin=root/('android-complete-update-inputs-'+self.intent['correlationId'])
        paths={str(origin/name) for name in names}|{str(origin/'receipt.json'),str(root/('android-native-device-'+self.intent['device']+'.lease'))}
        if set(record['origins'])!=paths:raise ValueError('component_guard_fixture_asset_paths_changed')
        for group in ('origins','staged'):
            for name,value in record[group].items():
                if (type(value)is not dict or set(value)!={'path','generation','parents','sha256'} or value['path']!=name or
                    type(value['generation'])is not list or len(value['generation'])!=9 or any(type(v)is not int for v in value['generation']) or
                    type(value['parents'])is not dict or not value['parents'] or any(type(k)is not str or type(v)is not list or len(v)!=5 or any(type(n)is not int for n in v)for k,v in value['parents'].items()) or
                    type(value['sha256'])is not str or len(value['sha256'])!=64 or any(c not in '0123456789abcdef' for c in value['sha256'])):
                    raise ValueError('component_guard_fixture_asset_record_invalid')
        for name in names:
            dest=record['staged'][str(self.args.output/'assets'/name)];src=record['origins'][str(origin/name)]
            if dest['sha256']!=src['sha256'] or dest['generation'][6]!=src['generation'][6]:
                raise ValueError('component_guard_fixture_asset_changed')
        for name,key in [('base.apk','baseSha256'),('target.apk','targetSha256')]:
            if record['staged'][str(self.args.output/'assets'/name)]['sha256']!=self.intent['pair'][key]:
                raise ValueError('component_guard_fixture_asset_changed')
        receipt=json.loads(_fixture_asset_record(origin/'receipt.json')[0])
        if (type(receipt.get('schema'))is not int or receipt['schema']!=1 or receipt.get('campaignId')!=self.intent['correlationId'] or
            receipt.get('kind')!='android-disposable-fixture-tls' or receipt.get('testOnly')is not True or
            receipt.get('sourceFacts',{}).get('sourceSha')!=_PRODUCT_SHA or
            receipt.get('sourceFacts',{}).get('targetArtifactId')!='sha256-'+self.intent['pair']['targetSha256']):
            raise ValueError('component_guard_fixture_asset_record_invalid')
        for name,source in [('ca.pem','ca.pem'),('leaf.pem','leaf.pem'),('key.pem','leaf-key.pem')]:
            value=record['origins'][str(origin/name)];detail=receipt.get('files',{}).get(source,{})
            if type(detail.get('bytes'))is not int or detail['bytes']!=value['generation'][6] or detail.get('sha256')!=value['sha256']:
                raise ValueError('component_guard_fixture_asset_changed')
        immutable=_raw({'path':str(path),'pin':pin,'record':record})
        self.fixture_assets_raw=immutable
        try:self._fixture_assets_guard(full=True)
        except BaseException:self.fixture_assets_raw=None;raise

    def _fixture_assets_guard(self, full=False):
        if self.fixture_assets_raw is None:return
        bound=json.loads(self.fixture_assets_raw);record=bound['record'];expected={bound['path']:bound['pin']}
        if full and _fixture_asset_record(bound['path'])[0]!=_raw(record):
            raise ValueError('component_guard_fixture_asset_changed')
        for group in ('origins','staged'):
            for path,pin in record[group].items():
                expected[path]={key:pin[key]for key in ('generation','parents','sha256')}
                if full and _raw(_fixture_asset_pin(path))!=_raw(expected[path]):raise ValueError('component_guard_fixture_asset_changed')
        names={'base.apk':'base_apk','target.apk':'target_apk','ca.pem':'ca_certificate','leaf.pem':'leaf_certificate','key.pem':'private_key'}
        if any(str(getattr(self.args,attr))!=str(self.args.output/'assets'/name) for name,attr in names.items()):
            raise ValueError('component_guard_fixture_asset_paths_changed')
        # Every body read precedes this original all-leaf generation-only pass.
        _evidence_generation_closure(expected)

    def _task_guard(self):
        self._fixture_assets_guard()
        if self.backend['LAUNCH']['intent']['reservation']!=self.reservation:
            raise ValueError('component_guard_reservation_changed')
        for path,pin in self.phase_pins.items():
            if _read(path,True)[1]!=pin:raise ValueError('component_guard_phase_changed')
        if _read(self.args.intent_file,True)[1]!=self.intent_pin:
            raise ValueError('component_guard_intent_changed')
        device=self.intent.get('device');host=self.intent.get('host')
        if (device not in ('android-api29','android-api35') or host!='archlinux' or
            self.intent['pair'].get('sourceSha')!=_PRODUCT_SHA):
            raise ValueError('component_guard_installer_lease_required')
        api,serial,launch_device={'android-api29':(29,'emulator-5684','api29'),
                                 'android-api35':(35,'emulator-5682','api35')}[device]
        if (type(self.intent.get('expectedApi'))is not int or self.intent['expectedApi']!=api or
            type(self.args.api) not in (str,int) or str(self.args.api)!=str(api) or
            self.args.serial!=serial or self.backend['EXTERNAL']['serial']!=serial or
            self.backend['LAUNCH'].get('device')!=launch_device or
            self.intent.get('expectedAvd')!=self.backend['LAUNCH']['avd'] or
            self.args.avd!=self.intent.get('expectedAvd') or
            str(self.args.cli)!=self.backend['GETTER']['cli']):
            raise ValueError('component_guard_crossed_binding')
        expected={'owner':'android-installer','host':host,'device':device,
                  'correlationId':self.intent['correlationId']}
        path=Path(self.backend['ROOT'])/('android-native-device-'+device+'.lease')
        raw,pin=_read(path,True)
        if json.loads(raw)!=expected:raise ValueError('component_guard_installer_lease_changed')
        if hasattr(self,'lease_pin') and pin!=self.lease_pin:raise ValueError('component_guard_installer_lease_changed')
        self.lease_pin=pin
        self.lease_record={'path':str(path),'pin':pin,'value':expected}
        if self.phase not in ('installer','installer-action','installer-reconciliation'):
            raise ValueError('component_guard_phase_unknown')
        action=self.args.output/'component-guard-action-admission.json'
        if self.phase=='installer':
            if self.action_intent is not None or self.accepted_operation is not None or self.handoff is not None:
                raise ValueError('component_guard_unadmitted_phase')
        else:
            if action not in self.phase_pins:raise ValueError('component_guard_unadmitted_phase')
            admitted=json.loads(_read(action,True)[0])['record']
            if admitted.get('originalIntentPin')!=self.intent_pin or admitted.get('sameCampaignAndLease')!=self.lease_record:
                raise ValueError('component_guard_phase_binding_changed')
            derived={**copy.deepcopy(self.intent),'expectedOwner':admitted['owner'],'expectedRevision':admitted['revision'],
                'componentActionAdmission':{'path':str(action),'pin':self.phase_pins[action]}}
            if self.action_intent!=derived:raise ValueError('component_guard_action_binding_changed')
            if self.phase=='installer-action' and (self.expected!=admitted['actionFacts'] or self.owner!=admitted['owner'] or self.revision!=admitted['revision']):
                raise ValueError('component_guard_action_binding_changed')
            if self.phase=='installer-reconciliation':
                path=self.args.output/'component-guard-reconciliation-admission.json'
                if path not in self.phase_pins:raise ValueError('component_guard_unadmitted_phase')
                terminal=json.loads(_read(path,True)[0])['record']
                if (self.expected!=terminal['facts'] or self.owner!=terminal['owner'] or self.revision!=terminal['revision'] or
                    terminal['handoff']!=self.handoff or terminal['originalIntentPin']!=self.intent_pin):
                    raise ValueError('component_guard_reconciliation_binding_changed')
        accepted=self.args.output/'component-guard-accepted-operation.json'
        if self.accepted_operation is not None:
            if accepted not in self.phase_pins or json.loads(_read(accepted,True)[0])['record']['operationId']!=self.accepted_operation:
                raise ValueError('component_guard_operation_binding_changed')
        handoff=self.args.output/'component-guard-handoff-session.json'
        if self.handoff is not None:
            if handoff not in self.phase_pins or json.loads(_read(handoff,True)[0])['record']['identity']!=self.handoff:
                raise ValueError('component_guard_handoff_binding_changed')
        self._fixture_assets_guard()

    def _evidence(self,name,value):
        lifecycle=self.modules['lifecycle']
        evidence_args=types.SimpleNamespace(intent=self.intent,output=self.args.output)
        lifecycle.write_cli_evidence(evidence_args,'component-guard-'+name+'.json',
            {'schema':1,'kind':'android-installer-component-current-guard',
             'binding':lifecycle.reply_binding(evidence_args),'record':copy.deepcopy(value),
             'componentRuntime':'EXTERNAL_JDK','installedLauncherAccepted':False,
             'bundledRuntimeAccepted':False,'replayAllowed':False})

    def _capture(self,value):
        self.sequence+=1
        self._evidence('read-%05d'%self.sequence,value)

    def _adb(self, words):
        import time
        def clock():
            value = time.monotonic()
            if type(value) not in (int, float) or not 0 < value < float('inf'):
                raise ValueError('component_guard_read_clock_unknown')
            return value
        begin_sequence = getattr(self, 'read_begin_sequence', 0)
        if (type(begin_sequence) is not int or not 0 <= begin_sequence < 8192
                or type(self.sequence) is not int or self.sequence < 0):
            raise ValueError('component_guard_read_begin_bound')
        ordinal = begin_sequence + 1
        started = clock()
        begin = {'scope': 'component-read', 'ordinal': ordinal, 'phase': self.phase,
                 'wordsSha256': hashlib.sha256(_raw(words)).hexdigest(),
                 'startedMonotonic': started, 'commandDeadlineSeconds': 20,
                 'carrierLimit': 16384}
        if len(_raw(begin)) > 1024:
            raise ValueError('component_guard_read_begin_bound')
        if isinstance(self, BaselineGuard):
            binding = copy.deepcopy(self.request)
        else:
            evidence_args = types.SimpleNamespace(intent=self.intent, output=self.args.output)
            binding = self.modules['lifecycle'].reply_binding(evidence_args)
        envelope = {
            'schema': 1, 'kind': 'android-installer-component-read-begin',
            'binding': binding, 'record': begin, 'componentRuntime': 'EXTERNAL_JDK',
            'phase': self.phase, 'installerLeaseGranted': False,
            'nativeActionAllowed': False, 'replayAllowed': False, 'productAcceptance': False}
        expected_begin = _raw(envelope)
        if len(expected_begin) > 4096:
            raise ValueError('component_guard_read_begin_bound')
        # Use the same virtual evidence writer as final reads. Baseline and
        # owner-admission collectors pin its existing schema and numbered catalog.
        before_names = set(os.listdir(self.args.output))
        previous_sequence = self.sequence
        try:
            self._capture(begin)
        except BaseException:
            self.sequence = previous_sequence
            raise
        after_names = set(os.listdir(self.args.output))
        added_names = after_names - before_names
        if not before_names <= after_names or len(added_names) != 1:
            raise ValueError('component_guard_read_begin_changed')
        begin_raw = _read(self.args.output/added_names.pop(), True)[0]
        if len(begin_raw) > 4096:
            raise ValueError('component_guard_read_begin_bound')
        if json.loads(begin_raw).get('record') != begin:
            raise ValueError('component_guard_read_begin_changed')
        self.read_begin_sequence = ordinal
        b = self.backend; previous = b['GETTER_RECORDS']; isolated = {}; result = None
        failure = None; failures = []; ended = None; elapsed = None
        b['GETTER_RECORDS'] = isolated
        try:
            b['command_host_guard']()
            launch = b['LAUNCH']
            result = b['command_binary'](Path(launch['adbPath']), launch['adbFacts']['generation'],
                ['-s', self.args.serial, *words], launch['environment'], limit=16384, timeout=20)
        except BaseException as exc:
            failure = exc; failures.append(('transport', exc))
        finally:
            b['GETTER_RECORDS'] = previous
            try:
                ended = clock()
                if ended < started:
                    raise ValueError('component_guard_read_clock_unknown')
                elapsed = ended - started
            except BaseException as exc:
                ended = None; elapsed = None
                failures.append(('timing', exc))
                if failure is None: failure = exc
            try:
                self._capture({'words': words, 'result': result,
                    'captures': isolated.get('captures', []),
                    'startedMonotonic': started, 'endedMonotonic': ended,
                    'elapsedSeconds': elapsed,
                    'primaryExceptionClass': type(failure).__name__ if failure is not None else None})
            except BaseException as exc:
                failures.append(('capture', exc))
                if failure is None: failure = exc
        self.read_failures = [{'phase': phase, 'type': type(exc).__name__,
            'errno': exc.errno if isinstance(exc, OSError) and type(exc.errno) is int else None}
            for phase, exc in failures]
        if failure is not None: raise failure
        return result

    def _text(self,words):
        value=self._adb(words)
        if (type(value.get('returncode'))is not int or value['returncode']!=0 or
            type(value.get('stdoutRaw'))is not str or value.get('stderrRaw')!=''):
            raise ValueError('component_guard_guest_read_unknown')
        return value['stdoutRaw'].strip()

    def enable_physical_batch(self):
        """Explicit separate fixture admission after this same genuine admission.

        Utility profile4 remains diagnostic, with batchEnabled=False. Its
        authentic source is alpha-derived above; the original importer is exact.
        Native batch authorization remains a caller prerequisite.
        """
        if (type(self) not in (CurrentGuard, BaselineGuard) or self.expected is None
                or not hasattr(self, 'admission_pin')
                or _read(self.args.output/'component-guard-current-admission.json', True)[1] != self.admission_pin):
            raise ValueError('component_guard_batch_current_admission_required')
        admitted = json.loads(_read(self.args.output/'component-guard-current-admission.json', True)[0])['record']
        if any(admitted.get(key) != expected for key, expected in (
                ('facts', self.expected), ('stage', self.stage), ('host', self.host),
                ('owner', self.owner), ('revision', self.revision))):
            raise ValueError('component_guard_batch_current_admission_required')
        facts = self._physical()
        correlation = str(uuid.uuid4())
        source = _profile4_source(correlation)
        self._evidence('batch-abi-attempt', {
            'facts': facts, 'sourceSha256': hashlib.sha256(_PHYSICAL_ABI.encode()).hexdigest(),
            'profileSourceSha256': '0fa6510875119ca3da6a5097d484a0c3e8b384b547512ca375411a59bdd22598',
            'calibrationSourceSha256': hashlib.sha256(source.encode()).hexdigest(),
            'calibrationCorrelationId': correlation,
            'fixtureEffects': 'future private shell-UID2000 spool only',
            'productEffectsAllowed': False})
        result = self._adb(['shell', '-T', '/system/bin/sh -c '+shlex.quote(source)])
        if (type(result) is not dict or type(result.get('returncode')) is not int
                or result['returncode'] != 0 or type(result.get('stdoutRaw')) is not str
                or result.get('stderrRaw') != ''):
            raise ValueError('component_guard_guest_read_unknown')
        abi = _physical_abi_parse(result['stdoutRaw'], correlation, facts['guestBootId'])
        if self._physical() != facts:
            raise ValueError('component_guard_batch_abi_changed')
        if _read(self.args.output/'component-guard-current-admission.json', True)[1] != self.admission_pin:
            raise ValueError('component_guard_batch_current_admission_required')
        self._evidence('batch-abi', {
            'abi': abi, 'calibrationFacts': facts,
            'sourceSha256': hashlib.sha256(_PHYSICAL_ABI.encode()).hexdigest(),
            'calibrationSourceSha256': hashlib.sha256(source.encode()).hexdigest(),
            'temporalBoundary': 'one continuously held executable and parent closure per epoch',
            'nativeAcceptance': False})
        path = self.args.output/'component-guard-batch-abi.json'
        raw, pin = _read(path, True)
        self.batch_admission = {'path': path, 'pin': pin, 'raw': raw, 'abi': abi, 'facts': facts}

    def _batch_reads(self):
        if getattr(self,'batch_uncertain',False):
            raise ValueError('component_guard_batch_unknown_consumed')
        admitted=self.batch_admission
        if _read(admitted['path'],True)!=(admitted['raw'],admitted['pin']):
            raise ValueError('component_guard_batch_abi_changed')
        value=json.loads(admitted['raw'])['record']
        if value['abi']!=admitted['abi'] or value['calibrationFacts']!=admitted['facts'] or value['sourceSha256']!=hashlib.sha256(_PHYSICAL_ABI.encode()).hexdigest():
            raise ValueError('component_guard_batch_abi_changed')
        import time
        started = time.monotonic()
        if type(started) not in (int, float) or not 0 < started < float('inf'):
            raise ValueError('component_guard_read_clock_unknown')
        correlation=str(uuid.uuid4())
        self.batch_sequence=correlation
        source=_physical_batch_source(correlation,admitted['abi'])
        self._evidence('batch-epoch-'+correlation,{'correlationId':correlation,
            'abiAdmissionPin':admitted['pin'],'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),
            'startedMonotonic':started,'stepSeconds':20,'totalSeconds':200,
            'replayAllowed':False,'outcome':'unknown-until-complete-current-physical-validation'})
        self.batch_uncertain=True
        b=self.backend;previous=b['GETTER_RECORDS'];isolated={};result=None
        words=['shell','-T','/system/bin/sh -c '+shlex.quote(source)]
        b['GETTER_RECORDS']=isolated
        failure=None;failures=[];ended=None;elapsed=None
        try:
            b['command_host_guard']()
            launch=b['LAUNCH']
            result=b['command_binary'](Path(launch['adbPath']),launch['adbFacts']['generation'],
                ['-s',self.args.serial,*words],launch['environment'],limit=_PHYSICAL_BATCH_LIMIT,timeout=200)
        except BaseException as exc:
            failure=exc;failures.append(('transport',exc))
        finally:
            b['GETTER_RECORDS']=previous
            try:
                ended = time.monotonic()
                if type(ended) not in (int, float) or not started <= ended < float('inf'):
                    raise ValueError('component_guard_read_clock_unknown')
                elapsed = ended - started
            except BaseException as exc:
                ended = None; elapsed = None
                failures.append(('timing',exc))
                if failure is None:failure=exc
            try:
                self._capture({'kind':'physical-batch-transport','correlationId':correlation,
                    'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),'words':words,
                    'result':result,'captures':isolated.get('captures',[]),
                    'stepSeconds':20,'totalSeconds':200,'carrierLimit':_PHYSICAL_BATCH_LIMIT,
                    'startedMonotonic':started,'endedMonotonic':ended,'elapsedSeconds':elapsed,
                    'primaryExceptionClass':type(failure).__name__ if failure is not None else None,
                    'temporalBoundary':'one continuously held executable and parent closure',
                    'fixtureEffects':'private acquired shell-UID2000 directory/exclusive files/owned cleanup'})
            except BaseException as exc:
                failures.append(('capture',exc))
                if failure is None:failure=exc
            finally:
                # Even an evidence write/fsync failure must close authority.
                # Source failure remains fail-closed before invoking backend
                # functions whose source can no longer be authenticated.
                try:
                    load(self.receipt);self._task_guard();b['command_host_guard']();b['external_jdk_guard']()
                    if b['command_host_identity']()!=self.host or b['getter_stage']()!=self.stage:
                        raise ValueError('component_guard_batch_closing_changed')
                    if any(b.get(name)is not function or function.__code__ is not code for name,(function,code) in self.function_pins.items()):
                        raise ValueError('component_guard_backend_changed')
                    historical=b['GETTER']['generation'];child=b['child_identity'](historical['child']['pid'])
                    if child!=historical['child'] or b['session_guest'](child,{'qemuFact':b['qemu_fact']()})!=historical['guest']:
                        raise ValueError('component_guard_owned_process_changed')
                except BaseException as exc:
                    failures.append(('closing',exc))
                    if failure is None:failure=exc
        # Preserve the first actual exception; later failures cannot mask it.
        # Secondary diagnostic metadata contains no exception/argv/raw text.
        self.batch_failures=[{'phase':phase,'type':type(exc).__name__,
            'errno':exc.errno if isinstance(exc,OSError) and type(exc.errno)is int else None}
            for phase,exc in failures]
        if failure is not None:raise failure
        if type(result)is not dict or type(result.get('returncode'))is not int or result['returncode']!=0 or result.get('stderrRaw')!='':
            raise ValueError('component_guard_guest_read_unknown')
        rows=_physical_batch_parse(result.get('stdoutRaw'),correlation)
        self._capture({'kind':'physical-batch-logical-observations','transportCorrelationId':correlation,
            'independentAdbChildren':False,'observations':rows})
        values=[]
        for row in rows:
            if row['returncode']!=0 or row['stderrRaw']!='':raise ValueError('component_guard_guest_read_unknown')
            values.append(row['stdoutRaw'].strip())
        if values[6]!=admitted['abi']['guestBootId']:
            raise ValueError('component_guard_batch_abi_changed')
        return values

    def _physical(self,candidate_sha=None):
        load(self.receipt)
        self._task_guard()
        b=self.backend
        measurement=self.measurement
        if candidate_sha is not None:
            if candidate_sha not in (self.intent['pair']['baseSha256'],self.intent['pair']['targetSha256']):
                raise ValueError('component_guard_candidate_package_unknown')
            measurement={**measurement,'packageSha256':candidate_sha}
        if any(b.get(name)is not function or function.__code__ is not code for name,(function,code) in self.function_pins.items()):
            raise ValueError('component_guard_backend_changed')
        b['command_host_guard']();b['external_jdk_guard']()
        if b['command_host_identity']()!=self.host:raise ValueError('component_guard_host_changed')
        if b['getter_stage']()!=self.stage:raise ValueError('component_guard_stage_changed')
        # Reobserve the exact already-owned supervisor and guest process identities;
        # the obsolete historical device block is deliberately excluded.
        historical=b['GETTER']['generation']
        child=b['child_identity'](historical['child']['pid'])
        guest=b['session_guest'](child,{'qemuFact':b['qemu_fact']()})
        if child!=historical['child'] or guest!=historical['guest']:
            raise ValueError('component_guard_owned_process_changed')
        values=self._batch_reads() if hasattr(self,'batch_admission') else None
        facts={key:(values[n] if values is not None else self._text(['shell','-T','getprop',prop])) for n,(key,prop) in enumerate(_PROPERTIES)}
        facts['shellUid']=values[5] if values is not None else self._text(['shell','-T','id','-u'])
        facts['guestBootId']=values[6] if values is not None else self._text(['shell','-T','cat','/proc/sys/kernel/random/boot_id'])
        if (facts['sdk']!=str(measurement['api']) or facts['abi']!='x86_64' or
            facts['shellUid']!='2000' or facts['bootCompleted']!='1' or
            measurement['avd'] not in (facts['kernelAvd'],facts['bootAvd']) or
            any(facts[key] not in ('',measurement['avd']) for key in ('kernelAvd','bootAvd')) or
            not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',facts['guestBootId'])):
            raise ValueError('component_guard_device_unadmitted')
        processes=values[7] if values is not None else self._text(['shell','-T','sh -c '+shlex.quote(_PROCESS_READ)])
        facts['processes']=_process_facts(processes)
        package=values[8] if values is not None else self._text(['shell','-T','pm','path','com.kardinal.vpncontrol'])
        match=re.fullmatch(r'package:(/data/app/[A-Za-z0-9_./+~=-]+/base\.apk)',package)
        if match is None or '..' in Path(match[1]).parts:raise ValueError('component_guard_package_path_unknown')
        digest=(values[9] if values is not None else self._text(['shell','-T','sha256sum',match[1]])).split()
        if digest!=[measurement['packageSha256'],match[1]]:
            raise ValueError('component_guard_package_changed')
        facts['packagePath']=match[1];facts['packageSha256']=digest[0]
        if candidate_sha is None and self.expected is not None and facts!=self.expected:raise ValueError('component_guard_generation_changed')
        if values is not None:
            self._evidence('batch-complete-'+self.batch_sequence,{'facts':facts,'fixtureCleanupObserved':True,'replayAllowed':False})
            self.batch_uncertain=False
        return facts

    def _public(self):
        b=self.backend;command_records=b['GETTER_RECORDS']
        b['GETTER_RECORDS']={}
        try:self._public_reads()
        finally:b['GETTER_RECORDS']=command_records

    def _public_reads(self):
        b=self.backend
        statuses=[]
        for words in (['status'],['operations','list'],['status']):
            result=b['component_command'](words,self.owner,self.revision,'baseline',
                                          self._physical,self._capture)
            value=result.get('stdout')
            if (result.get('returncode')!=0 or type(value)is not dict or value.get('ok')is not True or
                value.get('final')is not True or value.get('code')!='OK' or value.get('controllerId')!=self.owner or
                type(value.get('configurationRevision'))is not int or value['configurationRevision']!=self.revision or
                type(value.get('data'))is not dict):raise ValueError('component_guard_owner_changed')
            if words==['status']:
                if value['data'].get('runtimeRunning')is not False or value['data'].get('runtimeObservation')!='stopped':
                    raise ValueError('component_guard_runtime_changed')
                statuses.append(value['data'])
            else:
                entries=value['data'].get('operations')
                if type(entries)is not list or any(type(item)is not dict or type(item.get('final'))is not bool or
                    (item['final']is False and (self.phase!='installer-action' or getattr(self,'accepted_operation',None) is None or
                     item.get('id')!=self.accepted_operation)) for item in entries):
                    raise ValueError('component_guard_operations_unknown')
        if statuses[0]!=statuses[1]:raise ValueError('component_guard_public_changed')

    def __call__(self):
        if _read(self.args.output/'component-guard-current-admission.json',True)[1]!=self.admission_pin:
            raise ValueError('component_guard_admission_changed')
        self._physical();self._public();self._physical()
        self._fixture_assets_guard()


    def _phase_record(self,name,value):
        if name not in ('action-admission','accepted-operation','handoff-session','reconciliation-admission'):
            raise ValueError('component_guard_phase_name_unknown')
        self._evidence(name,value)
        path=self.args.output/('component-guard-'+name+'.json')
        self.phase_pins[path]=_read(path,True)[1]
        return copy.deepcopy(self.phase_pins[path])

    def _candidate_physical(self,sha):
        return self._physical(candidate_sha=sha)

    def _fresh_reply(self,words,owner,facts,sha):
        # Fixed read-only discovery/reconciliation, never update actions. This
        # uses the already authenticated descriptor-bound external JVM reader.
        if words not in (['status'],['operations','list'],['updates','status']):
            raise ValueError('component_guard_fresh_command_unknown')
        if owner is None and words!=['status']:raise ValueError('component_guard_fresh_owner_required')
        b=self.backend
        if self._candidate_physical(sha)!=facts:raise ValueError('component_guard_fresh_generation_changed')
        jdk=b['EXTERNAL']['selectedJdk'];path=Path(jdk['root'])/'bin/java'
        appdir=str(Path(b['GETTER']['cli']).parent.parent/'lib/app')
        argv=[*[option.replace('$APPDIR',appdir) for option in b['EXTERNAL']['javaOptions']],
              '-cp',':'.join(appdir+'/'+name for name in b['EXTERNAL']['classpath']),
              'com.kardinal.vpncontrol.desktop.MainKt','--json','--android','--serial',self.args.serial,
              '--timeout-seconds','30',*(['--controller-id',owner] if owner is not None else []),*words]
        records=b['GETTER_RECORDS'];isolated={};result=None;stage=copy.deepcopy(self.stage)
        b['GETTER_RECORDS']=isolated
        try:
            b['external_jdk_guard']();stage=b['getter_stage']()
            environment=self.modules['tls'].public_cli_environment(b['LAUNCH']['adbPath'],Path(b['GETTER']['cli']),b['LAUNCH']['environment'])
            result=b['command_binary'](path,jdk['files']['bin/java']['generation'],argv,environment,limit=1048576,timeout=45)
        finally:
            b['GETTER_RECORDS']=records
            self._capture({'freshWords':words,'freshOwner':owner,'result':result,'captures':isolated.get('captures',[])})
            b['external_jdk_guard']()
            if b['getter_stage']()!=stage:raise ValueError('component_guard_stage_changed')
            if self._candidate_physical(sha)!=facts:raise ValueError('component_guard_fresh_generation_changed')
        captures=isolated.get('captures',[])
        if (type(result)is not dict or type(result.get('returncode'))is not int or result['returncode']!=0 or
            type(result.get('stdoutRaw'))is not str or result.get('stderrRaw')!='' or len(captures)!=1):
            raise ValueError('component_guard_fresh_capture_unknown')
        capture=captures[0]
        if (capture.get('failure')is not None or type(capture.get('returncode'))is not int or capture['returncode']!=0 or
            capture.get('stdoutBase64')!=base64.b64encode(result['stdoutRaw'].encode()).decode() or
            capture.get('stderrBase64')!='' or type(capture.get('stdoutBytes'))is not int or
            capture['stdoutBytes']!=len(result['stdoutRaw'].encode()) or type(capture.get('stderrBytes'))is not int or capture.get('stderrBytes')!=0):
            raise ValueError('component_guard_fresh_capture_unknown')
        value=json.loads(result['stdoutRaw'])
        if (type(value)is not dict or value.get('ok')is not True or value.get('final')is not True or value.get('code')!='OK' or
            type(value.get('controllerId'))is not str or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',value['controllerId']) or
            (owner is not None and value['controllerId']!=owner) or type(value.get('configurationRevision'))is not int or
            value['configurationRevision']<0 or type(value.get('data'))is not dict):
            raise ValueError('component_guard_fresh_owner_unknown')
        return value

    def _fresh_owner(self,facts,sha):
        first=self._fresh_reply(['status'],None,facts,sha)
        owner=first['controllerId'];revision=first['configurationRevision']
        operations=self._fresh_reply(['operations','list'],owner,facts,sha)
        last=self._fresh_reply(['status'],owner,facts,sha)
        if (last['controllerId']!=owner or last['configurationRevision']!=revision or
            last['data']!=first['data'] or operations['configurationRevision']!=revision or
            first['data'].get('runtimeRunning')is not False or first['data'].get('runtimeObservation')!='stopped' or
            type(operations['data'].get('operations'))is not list or
            any(type(item)is not dict or item.get('final')is not True for item in operations['data']['operations'])):
            raise ValueError('component_guard_fresh_stopped_owner_unknown')
        return owner,revision

    def _admit_action(self,tls_args,adb):
        if self.phase!='installer' or self.action_intent is not None:
            raise ValueError('component_guard_action_consumed')
        self._task_guard()
        tls=self.modules['tls']
        if (Path(tls_args.output)!=self.args.output or tls_args.intent!=self.intent or
            tls_args.serial!=self.args.serial or str(tls_args.cli)!=str(self.args.cli) or
            tls_args.base_sha256!=self.intent['pair']['baseSha256'] or tls_args.device_port!=45600+self.intent['expectedApi'] or
            tls_args.receipt!=self.args.output/'lifecycle-receipt.json'):
            raise ValueError('component_guard_setup_binding_changed')
        # Actual retained setup records and current guest measurements, not
        # receipt booleans supplied by a caller, authorize this one transition.
        tls.guard_proxy_evidence(tls_args)
        if (adb.shell_id()!='uid=2000' or adb.reverse_mapping(tls_args.device_port)!=tls_args.host_port or
            tls.fixture_proxy_snapshot(adb)!=json.loads(_read(tls_args.receipt.with_name(tls_args.receipt.name+'.proxy-owned.json'),True)[0])['owned']):
            raise ValueError('component_guard_setup_transport_changed')
        paths=[tls_args.receipt.with_name(tls_args.receipt.name+'.proxy-baseline.json'),
               tls_args.receipt.with_name(tls_args.receipt.name+'.proxy-owned.json')]
        transport=[]
        for path in paths:
            raw,pin=_read(path,True);value=json.loads(raw)
            if (value.get('installerIntent')!=self.intent or value.get('serial')!=self.args.serial or
                value.get('devicePort')!=tls_args.device_port or value.get('hostPort')!=tls_args.host_port or
                value.get('baseSha256')!=self.intent['pair']['baseSha256'] or
                value.get('sourceAuthority')!=tls.proxy_source_authority(tls_args)):
                raise ValueError('component_guard_setup_evidence_changed')
            self.phase_pins[path]=pin;transport.append({'path':str(path),'pin':pin})
        facts=self._candidate_physical(self.intent['pair']['baseSha256'])
        old=copy.deepcopy(self.expected)
        if ({k:v for k,v in facts.items() if k!='processes'}!={k:v for k,v in old.items() if k!='processes'} or
            [item for item in facts['processes'] if item['role']!='adbd']!=
            [item for item in old['processes'] if item['role']!='adbd']):
            raise ValueError('component_guard_setup_foreign_generation')
        owner,revision=self._fresh_owner(facts,self.intent['pair']['baseSha256'])
        if revision!=self.revision:raise ValueError('component_guard_setup_revision_changed')
        pin=self._phase_record('action-admission',{'originalIntentPin':self.intent_pin,'setupFacts':old,
            'actionFacts':facts,'owner':owner,'revision':revision,'transport':transport,
            'sameCampaignAndLease':self.lease_record,'reservation':self.reservation})
        self.setup_expected=old;self.expected=facts;self.owner=owner;self.revision=revision
        self.action_intent={**copy.deepcopy(self.intent),'expectedOwner':owner,'expectedRevision':revision,
            'componentActionAdmission':{'path':str(self.args.output/'component-guard-action-admission.json'),'pin':pin}}
        self.phase='installer-action'
        self()
        return copy.deepcopy(self.action_intent)

    def _command_binding(self):
        self._task_guard()
        intent=copy.deepcopy(self.action_intent or self.intent)
        if self.phase=='installer-reconciliation':
            intent.update(expectedOwner=self.owner,expectedRevision=self.revision)
        return intent

    def _command_begin(self,words,phase,mutation):
        self._task_guard()
        if mutation:
            if self.phase!='installer-action':raise ValueError('component_guard_action_admission_required')
            if self.accepted_operation is not None and not (phase=='operation-cancel' and words==['operations','cancel',self.accepted_operation]):
                raise ValueError('component_guard_operation_effect_consumed')
        if (words==['updates','status'] and self.phase=='installer-action' and self.handoff is not None and
            (self.args.output/'continue').exists()):
            self._admit_reconciliation()
        if self.phase=='installer-reconciliation' and words not in (['updates','status'],['status'],['operations','list']):
            raise ValueError('component_guard_reconciliation_read_only')

    def _command_capture(self,record,pin):
        # Called only AFTER exact private raw retention, before the transport's
        # AFTER guard. The same raw capture is rechecked here before admission.
        if record.get('phase') not in ('install-interactive','operation-status','operation-wait'):return
        if self.phase!='installer-action':raise ValueError('component_guard_capture_phase_changed')
        if (record.get('owner')!=self.owner or type(record.get('revision'))is not int or record.get('revision')!=self.revision or
            type(record.get('returncode'))is not int or record.get('returncode')!=0 or record.get('stderrRaw')!='' or type(record.get('stdoutRaw'))is not str):return
        captures=record.get('captures')
        if type(captures)is not list or len(captures)!=1:return
        capture=captures[0]
        if (capture.get('failure')is not None or type(capture.get('returncode'))is not int or capture.get('returncode')!=0 or
            capture.get('stdoutBase64')!=base64.b64encode(record['stdoutRaw'].encode()).decode() or
            capture.get('stderrBase64')!='' or type(capture.get('stdoutBytes'))is not int or capture.get('stdoutBytes')!=len(record['stdoutRaw'].encode()) or type(capture.get('stderrBytes'))is not int or capture.get('stderrBytes')!=0):return
        path=Path(pin.get('path',''))
        if path.parent!=self.args.output or not re.fullmatch(r'component-cli-[0-9]{5}\.json',path.name):
            raise ValueError('component_guard_capture_path_unknown')
        retained=self.modules['adapter'].transport.readonly.availability._snapshot(path)
        if list(retained[0])!=list(pin.get('snapshot',[])) or hashlib.sha256(retained[1]).hexdigest()!=pin.get('sha256'):
            raise ValueError('component_guard_capture_generation_changed')
        raw,raw_pin=_read(path,True)
        if json.loads(raw).get('record')!=record or hashlib.sha256(raw).hexdigest()!=pin['sha256']:
            raise ValueError('component_guard_capture_body_changed')
        value=json.loads(record['stdoutRaw'])
        if (type(value)is not dict or value.get('controllerId')!=self.owner or
            type(value.get('configurationRevision'))is not int or value['configurationRevision']!=self.revision):return
        if record['phase']=='install-interactive':
            operation=value.get('operationId')
            if (record.get('words')!=['updates','install'] or value.get('ok')is not True or value.get('final')is not False or
                value.get('code')!='ACCEPTED' or type(operation)is not str or
                not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',operation)):
                return
            if self.accepted_operation is not None:raise ValueError('component_guard_accepted_operation_consumed')
            self._phase_record('accepted-operation',{'operationId':operation,'owner':self.owner,
                'revision':self.revision,'rawReplyPin':pin,'actionAdmission':self.action_intent['componentActionAdmission']})
            self.phase_pins[path]=raw_pin
            self.accepted_operation=operation
        elif self.accepted_operation is not None and self.handoff is None:
            if record.get('words') not in (['operations','status',self.accepted_operation],['operations','wait',self.accepted_operation]):return
            try:identity=self.modules['lifecycle'].handoff_identity({'exit':0,'response':value},self.accepted_operation,
                    self.intent['pair']['targetVersion'],self.intent['pair']['targetSha256'],self.owner)
            except RuntimeError:return
            self._phase_record('handoff-session',{'identity':identity,'rawReplyPin':pin})
            self.phase_pins[path]=raw_pin
            self.handoff=identity

    def _admit_reconciliation(self):
        if self.phase!='installer-action' or self.handoff is None or self.accepted_operation is None:
            raise ValueError('component_guard_handoff_required')
        lifecycle=self.modules['lifecycle']
        action_args=types.SimpleNamespace(**vars(self.args));action_args.intent=self._command_binding()
        callback=lifecycle.verify_governed_callback(action_args,'continue')
        if any(callback.get(key)!=self.handoff[key] for key in ('operationId','receiptId','sessionId')):
            raise ValueError('component_guard_reconciliation_session_changed')
        handoff_raw,handoff_pin=_read(self.args.output/'handoff.json',True)
        if json.loads(handoff_raw).get('identity')!=self.handoff:
            raise ValueError('component_guard_reconciliation_handoff_changed')
        continue_raw,continue_pin=_read(self.args.output/'continue',True)
        if continue_raw!=b'continue\n':raise ValueError('component_guard_continue_unknown')
        retained={self.args.output/'handoff.json':handoff_pin,self.args.output/'continue':continue_pin}
        for name in ('callback-continue-evidence.json','callback-continue-ui.xml'):
            path=self.args.output/name;retained[path]=_read(path,True)[1]
        expected=self.intent.get('expectedTerminal')
        if expected not in ('installed','cancelled'):raise ValueError('component_guard_terminal_scope_required')
        sha=self.intent['pair']['targetSha256' if expected=='installed' else 'baseSha256']
        facts=self._candidate_physical(sha)
        if ({key:value for key,value in facts.items() if key not in ('processes','packagePath','packageSha256')}!=
            {key:value for key,value in self.expected.items() if key not in ('processes','packagePath','packageSha256')} or
            [item for item in facts['processes'] if item['role']!='adbd']!=
            [item for item in self.expected['processes'] if item['role']!='adbd']):
            raise ValueError('component_guard_reconciliation_generation_changed')
        owner,revision=self._fresh_owner(facts,sha)
        package=self._text(['shell','-T','dumpsys','package','com.kardinal.vpncontrol'])
        version=self.intent['pair']['targetVersion' if expected=='installed' else 'baseVersion']
        code=self.intent['pair']['targetCode' if expected=='installed' else 'baseCode']
        if (not re.search(r'(?:^|\s)versionName='+re.escape(version)+r'(?=\s|$)',package) or
            not re.search(r'(?:^|\s)versionCode='+str(code)+r'(?=\s|$)',package) or 'DEBUGGABLE' in package):
            raise ValueError('component_guard_reconciliation_package_unknown')
        terminal=self._fresh_reply(['updates','status'],owner,facts,sha)
        if not lifecycle.reconciled_terminal({'exit':0,'response':terminal},self.handoff,expected):
            raise ValueError('component_guard_reconciliation_terminal_unknown')
        self._phase_record('reconciliation-admission',{'handoff':self.handoff,'facts':facts,'owner':owner,
            'revision':revision,'expectedTerminal':expected,'callbackPins':{str(p):v for p,v in retained.items()},
            'terminal':terminal,'originalIntentPin':self.intent_pin,'sameCampaignAndLease':self.lease_record})
        self.phase_pins.update(retained)
        self.expected=facts;self.measurement={**self.measurement,'packageSha256':sha}
        self.owner=owner;self.revision=revision;self.phase='installer-reconciliation'
        self()


def installer_tls_run(guard,tls_args,action,original,**kwargs):
    """One fixed unchanged TLS lifecycle, then explicit fresh action admission."""
    if type(guard)is not CurrentGuard or guard.phase!='installer' or action is not guard.modules['lifecycle'].action:
        raise ValueError('component_guard_fixed_action_required')
    api=guard.intent['expectedApi'];target='/apex/com.android.conscrypt/cacerts' if api==35 else '/system/etc/security/cacerts'
    if kwargs!={'target_install':True,'ca_store_target':target,'expected_proxy':'null'}:
        raise ValueError('component_guard_fixed_tls_scope_required')
    def admitted_action(args,adb,receipt):
        effective=guard._admit_action(args,adb)
        action_args=types.SimpleNamespace(**vars(args));action_args.intent=effective
        return action(action_args,adb,receipt)
    return original(tls_args,admitted_action,**kwargs)


def cleanup_readmission(guard):
    """Separate read-only target authority after this campaign's TLS cleanup.

    The installer guard and every historical phase pin stay immutable. Only the
    measured adbd generation may differ; the target owner, boot, zygotes, APK,
    reservation, original lease and exact accepted session must remain bound.
    """
    if type(guard)is not CurrentGuard or guard.phase!='installer-reconciliation':
        raise ValueError('component_cleanup_reconciliation_required')
    guard.modules['adapter']._phase_protocol(guard,{})
    guard._task_guard()
    lifecycle=guard.modules['lifecycle'];output=guard.args.output
    names=('intent.json','component-guard-current-admission.json','component-guard-action-admission.json',
           'component-guard-reconciliation-admission.json','probe.json','handoff.json','lifecycle-receipt.json')
    retained={output/name:_read(output/name,True) for name in names}
    if (_raw(retained[output/'intent.json'][1])!=_raw(guard.intent_pin) or
        any(_raw(retained[path][1])!=_raw(guard.phase_pins[path]) for path in
            (output/'component-guard-action-admission.json',output/'component-guard-reconciliation-admission.json'))):
        raise ValueError('component_cleanup_original_pin_changed')
    original=json.loads(retained[output/'component-guard-current-admission.json'][0])['record']
    action=json.loads(retained[output/'component-guard-action-admission.json'][0])['record']
    reconciliation=json.loads(retained[output/'component-guard-reconciliation-admission.json'][0])['record']
    if (type(guard.revision)is not int or
        _raw(original['stage'])!=_raw(guard.stage) or _raw(original['host'])!=_raw(guard.host) or
        _raw(original['intentPin'])!=_raw(guard.intent_pin) or _raw(original['lease'])!=_raw(guard.lease_record) or
        _raw(action['reservation'])!=_raw(guard.reservation) or
        _raw(reconciliation['facts'])!=_raw(guard.expected) or reconciliation['owner']!=guard.owner or
        _raw(reconciliation['revision'])!=_raw(guard.revision) or
        _raw(reconciliation['handoff'])!=_raw(guard.handoff) or
        reconciliation['expectedTerminal']!='installed'):
        raise ValueError('component_cleanup_historical_binding_changed')
    historical_pins={**copy.deepcopy(guard.phase_pins),output/'intent.json':copy.deepcopy(guard.intent_pin),
        output/'component-guard-current-admission.json':copy.deepcopy(guard.admission_pin)}
    fixed_binding=_raw({'expected':guard.expected,'stage':guard.stage,'host':guard.host,'intent':guard.intent,
        'intentPin':guard.intent_pin,'lease':guard.lease_record,'reservation':guard.reservation,
        'phasePins':{str(p):pin for p,pin in guard.phase_pins.items()},'owner':guard.owner,'revision':guard.revision,'handoff':guard.handoff})
    receipt=json.loads(retained[output/'lifecycle-receipt.json'][0])
    if (type(receipt)is not dict or receipt.get('serial')!=guard.args.serial or
        receipt.get('targetInstall')is not True or receipt.get('cleanupFailures')!=[] or
        any(key in receipt for key in ('failure','retainedStaging','unknownMount'))):
        raise ValueError('component_cleanup_receipt_unknown')
    terminal=lifecycle.target_admission._terminal(guard.intent,json.loads(retained[output/'probe.json'][0]),
        receipt,json.loads(retained[output/'handoff.json'][0]),intent_path=output/'intent.json')
    if (terminal['terminal']!='installed' or terminal['operationId']!=guard.accepted_operation or
        terminal['receiptId']!=guard.handoff['receiptId'] or terminal['sessionId']!=guard.handoff['sessionId'] or
        terminal['terminalOwner']!=guard.owner or terminal['terminalRevision']!=guard.revision):
        raise ValueError('component_cleanup_terminal_changed')
    commands=receipt.get('commands')
    if (type(commands)is not list or not 1<=len(commands)<=4096 or any(type(row)is not dict or
        type(row.get('args'))is not list or not row['args'] or any(type(word)is not str for word in row['args']) or
        type(row.get('exit'))is not int or row['exit']!=0 or row.get('stderr')!='' or
        row.get('stderrTruncated')is not False for row in commands)):
        raise ValueError('component_cleanup_commands_unknown')
    zygotes=[item['pid'] for item in guard.expected['processes'] if item['role']=='zygote64']
    if len(zygotes)!=1:raise ValueError('component_cleanup_zygote_unknown')
    target='/apex/com.android.conscrypt/cacerts' if guard.intent['expectedApi']==35 else '/system/etc/security/cacerts'
    staging='/data/local/tmp/vpn-control-installer-api'+str(guard.intent['expectedApi'])
    argv=[row['args'] for row in commands]
    required=[['shell','nsenter','-t',str(zygotes[0]),'-m','--','umount',target],['shell','rm','-r',staging],['unroot'],['wait-for-device']]
    indices=[];at=0
    for words in required:
        found=next((i for i in range(at,len(argv)) if argv[i]==words),None)
        if found is None:raise ValueError('component_cleanup_command_lineage_unknown')
        indices.append(found);at=found+1
    sha=guard.intent['pair']['targetSha256'];facts=guard._candidate_physical(sha)
    def same(a,b):return _raw(a)==_raw(b)
    def stable(a,b):
        return (same({k:v for k,v in a.items() if k!='processes'},{k:v for k,v in b.items() if k!='processes'}) and
            same([row for row in a['processes'] if row['role']!='adbd'],[row for row in b['processes'] if row['role']!='adbd']))
    if not stable(facts,guard.expected):raise ValueError('component_cleanup_foreign_generation')
    owner,revision=guard._fresh_owner(facts,sha)
    if owner!=guard.owner or type(revision)is not int or _raw(revision)!=_raw(guard.revision):
        raise ValueError('component_cleanup_owner_changed')
    observed=guard._fresh_reply(['updates','status'],owner,facts,sha)
    if not lifecycle.reconciled_terminal({'exit':0,'response':observed},guard.handoff,'installed'):
        raise ValueError('component_cleanup_session_changed')
    if guard._text(['reverse','--list'])!='' or guard._text(['shell','-T','settings','get','global','http_proxy'])!='null':
        raise ValueError('component_cleanup_transport_changed')
    if not same(guard._candidate_physical(sha),facts):raise ValueError('component_cleanup_generation_changed')
    for path,(raw,pin) in retained.items():
        current,current_pin=_read(path,True)
        if current!=raw or not same(current_pin,pin):raise ValueError('component_cleanup_evidence_changed')
    _evidence_generation_closure({**historical_pins,**{leaf:old_pin for leaf,(_,old_pin) in retained.items()}})
    value={'schema':1,'kind':'android-installer-component-cleanup-readmission','originalIntentPin':guard.intent_pin,
        'actionAdmissionPin':guard.phase_pins[output/'component-guard-action-admission.json'],
        'reconciliationAdmissionPin':guard.phase_pins[output/'component-guard-reconciliation-admission.json'],
        'sameCampaignAndLease':guard.lease_record,'facts':facts,'owner':owner,'revision':revision,'terminal':terminal,
        'cleanupReceiptPin':retained[output/'lifecycle-receipt.json'][1],'cleanupCommandIndices':indices,
        'installerEffectsAllowed':False,'replayAllowed':False}
    path=output/'component-cleanup-readmission.json';_write(path,_raw(value));raw,pin=_read(path,True)
    fixed_facts=_raw(facts);fixed_value=_raw(value)
    fixed_receipt=_raw(guard.receipt);fixed_args=guard.args
    fixed_modules=tuple((name,module) for name,module in guard.modules.items())
    class CleanupReadGuard:
        def __init__(self):
            self.modules=guard.modules;self.receipt=copy.deepcopy(guard.receipt);self.args=guard.args
            self.owner=owner;self.revision=revision
        def __call__(self):
            if (self.owner!=owner or type(self.revision)is not int or self.revision!=revision or
                _raw(self.receipt)!=fixed_receipt or self.args is not fixed_args or
                tuple(self.modules.items())!=fixed_modules):
                raise ValueError('component_cleanup_binding_changed')
            guard.modules['adapter']._phase_protocol(guard,{})
            guard._task_guard()
            current,current_pin=_read(path,True)
            if current!=raw or not same(current_pin,pin) or _raw(json.loads(current))!=fixed_value:
                raise ValueError('component_cleanup_admission_changed')
            for leaf,(original,original_pin) in retained.items():
                now,now_pin=_read(leaf,True)
                if now!=original or not same(now_pin,original_pin):raise ValueError('component_cleanup_evidence_changed')
            if _raw(guard._candidate_physical(sha))!=fixed_facts:raise ValueError('component_cleanup_generation_changed')
            observed_owner,observed_revision=guard._fresh_owner(json.loads(fixed_facts),sha)
            if observed_owner!=owner or observed_revision!=revision:raise ValueError('component_cleanup_owner_changed')
            final=guard._fresh_reply(['updates','status'],owner,json.loads(fixed_facts),sha)
            if not lifecycle.reconciled_terminal({'exit':0,'response':final},guard.handoff,'installed'):
                raise ValueError('component_cleanup_session_changed')
            if guard._text(['reverse','--list'])!='' or guard._text(['shell','-T','settings','get','global','http_proxy'])!='null':
                raise ValueError('component_cleanup_transport_changed')
            if _raw(guard._candidate_physical(sha))!=fixed_facts:raise ValueError('component_cleanup_generation_changed')
            if fixed_binding!=_raw({'expected':guard.expected,'stage':guard.stage,'host':guard.host,'intent':guard.intent,
                'intentPin':guard.intent_pin,'lease':guard.lease_record,'reservation':guard.reservation,
                'phasePins':{str(p):old_pin for p,old_pin in guard.phase_pins.items()},'owner':guard.owner,'revision':guard.revision,'handoff':guard.handoff}):
                raise ValueError('component_cleanup_historical_binding_changed')
            _evidence_generation_closure({**historical_pins,**{leaf:old_pin for leaf,(_,old_pin) in retained.items()},path:pin})
    successor=CleanupReadGuard();successor()
    return successor


def routing_backup(receipt,backend,request):
    """Fixed staged backup entry, authenticating code/globals/import authority."""
    selected=modules(receipt)
    importer=selected['adapter'].__dict__['__builtins__']['__import__']
    module=importer('agent_tools.android_installer_routing_backup',{},None,('create',),0)
    path=Path(receipt['directory'])/'agent_tools/android_installer_routing_backup.py'
    raw=load(receipt)['agent_tools/android_installer_routing_backup.py']
    if Path(module.__file__)!=path or _read(path,True)[0]!=raw:
        raise ValueError('component_backup_staged_source_changed')
    compiled=compile(raw,str(path),'exec',dont_inherit=True)
    for code in compiled.co_consts:
        if not isinstance(code,types.CodeType):continue
        function=getattr(module,code.co_name,None)
        if (not isinstance(function,types.FunctionType) or function.__globals__ is not module.__dict__ or
            selected['adapter']._semantic_code(function.__code__)!=selected['adapter']._semantic_code(code)):
            raise ValueError('component_backup_staged_code_changed')
    if module.bundle.__file__!=str(Path(receipt['directory'])/'agent_tools/android_installer_component_bundle.py'):
        raise ValueError('component_backup_staged_import_changed')
    result=module.create(receipt,backend,request)
    if _read(path,True)[0]!=raw:raise ValueError('component_backup_staged_source_changed')
    load(receipt)
    return result


def installed_baseline(receipt,backend,args):
    """Unchanged lifecycle admission through the adapter; no TLS/install effects.

    Caller supplies the original lifecycle's exact task-owned intent/backup/APK
    arguments. A successful return covers baseline reads only.
    """
    selected=modules(receipt)
    guard=CurrentGuard(receipt,selected,backend,args)
    restore=selected['adapter'].install(selected['lifecycle'],selected['tls'],backend,args,guard)
    try:
        intent=selected['lifecycle'].validate_intent(args)
        guard()
        return {'state':'component-installed-baseline-observed','intent':intent,
                'componentRuntime':'EXTERNAL_JDK','installedLauncherAccepted':False,
                'bundledRuntimeAccepted':False,'acceptanceComplete':False,'replayAllowed':False}
    finally:restore()


_BASELINE_KEYS={'host','device','correlationId','sourceSha','expectedOwner','expectedRevision',
                'expectedAvd','expectedApi','packageSha256','reservation'}
_PRODUCT_SHA='d32f719a08db57e5d40ce2bf77e0d7c5b42de557'


class BaselineGuard(CurrentGuard):
    """Fixed read-only phase: owns evidence only, grants no installer lease."""
    def __init__(self,receipt,selected_modules,backend,request):
        if (type(request)is not dict or set(request)!=_BASELINE_KEYS or
            request['host']!='archlinux' or request['device'] not in ('android-api29','android-api35') or
            request['sourceSha']!=_PRODUCT_SHA or type(request['expectedAvd'])is not str or
            type(request['expectedApi'])is not int or request['expectedApi'] not in (29,35) or
            request['device']!='android-api'+str(request['expectedApi']) or
            type(request['reservation'])is not dict or not request['reservation'] or
            type(request['packageSha256'])is not str or not re.fullmatch('[0-9a-f]{64}',request['packageSha256']) or
            type(request['correlationId'])is not str or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',request['correlationId'])):
            raise ValueError('component_baseline_fixed_request_required')
        self.receipt=copy.deepcopy(receipt);self.modules=selected_modules;self.backend=backend
        _selected_modules(self.receipt,selected_modules)
        serial='emulator-5684' if request['expectedApi']==29 else 'emulator-5682'
        self.context_device=_context_device(backend,request['device'],request['expectedApi'],
            request['expectedAvd'],serial,backend['GETTER']['cli'],request['packageSha256'])
        if backend['LAUNCH']['intent']['reservation']!=request['reservation']:
            raise ValueError('component_baseline_reservation_changed')
        self.function_pins=_guard_backend(selected_modules,backend,self.context_device)
        self.request=copy.deepcopy(request);self.phase='baseline-read-only';self.sequence=0;self.expected=None;self.fixture_assets_raw=None
        self.owner=request['expectedOwner'];self.revision=request['expectedRevision']
        backend['command_request'](['status'],self.owner,self.revision,'baseline')
        serial='emulator-5684' if request['expectedApi']==29 else 'emulator-5682'
        if (backend['EXTERNAL']['serial']!=serial or request['packageSha256']!=backend['GETTER']['packageSha256'] or
            backend['LAUNCH']['avd']!=request['expectedAvd']):raise ValueError('component_baseline_crossed_binding')
        root=Path(backend['ROOT'])
        output=root/('android-installer-component-baseline-'+request['correlationId'])
        _new_directory(output,receiver_root=root)
        self.args=types.SimpleNamespace(output=output,serial=serial,cli=Path(backend['GETTER']['cli']))
        self.measurement={'avd':request['expectedAvd'],'api':request['expectedApi'],'packageSha256':request['packageSha256']}
        self.host=backend['command_host_identity']();backend['command_host_guard']()
        self.stage=copy.deepcopy(backend['getter_stage']());self._task_guard()
        self.expected=self._physical();self._public()
        package=self._text(['shell','-T','dumpsys','package','com.kardinal.vpncontrol'])
        if 'versionName=2.2.2' not in package or 'versionCode=16840' not in package or 'DEBUGGABLE' in package:
            raise ValueError('component_baseline_installed_version_changed')
        self._evidence('current-admission',{'facts':self.expected,'stage':self.stage,'host':self.host,
            'owner':self.owner,'revision':self.revision,'installedPackageDump':package})
        self.admission_pin=_read(output/'component-guard-current-admission.json',True)[1]

    def _task_guard(self):
        load(self.receipt)
        if self.backend['LAUNCH']['intent']['reservation']!=self.request['reservation']:
            raise ValueError('component_baseline_reservation_changed')

    def _evidence(self, name, value):
        batch = (name.startswith('batch-epoch-') or name.startswith('batch-complete-')
                 or value.get('kind') in ('physical-batch-transport', 'physical-batch-logical-observations'))
        cleaned = (name.startswith('batch-complete-')
                   or value.get('kind') == 'physical-batch-logical-observations')
        effects = ({'guestFixtureEffects': 'private acquired UID2000 spool observed-cleaned' if cleaned
                    else 'private acquired UID2000 spool possible'} if batch else {})
        _write(self.args.output/('component-guard-'+name+'.json'), _raw({
            'schema': 1, 'kind': 'android-installer-component-baseline-read', 'phase': self.phase,
            'binding': self.request, 'record': copy.deepcopy(value), 'componentRuntime': 'EXTERNAL_JDK',
            'installerLeaseGranted': False, 'guestMutationPerformed': (True if cleaned else None) if batch else False,
            'installedLauncherAccepted': False, 'bundledRuntimeAccepted': False, 'replayAllowed': False,
            **effects}))


def baseline_read_only(receipt,backend,request):
    """Positively measured installed base; no installer claim or effect dispatch."""
    selected=modules(receipt);guard=BaselineGuard(receipt,selected,backend,request);guard()
    return {'state':'component-installed-baseline-observed','phase':'baseline-read-only',
            'evidenceDirectory':str(guard.args.output),'owner':guard.owner,'revision':guard.revision,
            'facts':copy.deepcopy(guard.expected),'componentRuntime':'EXTERNAL_JDK',
            'installerLeaseGranted':False,'guestMutationPerformed':False,
            'installedLauncherAccepted':False,'bundledRuntimeAccepted':False,
            'acceptanceComplete':False,'replayAllowed':False}
