"""Source-qualified local Apple restore image; grants capacity accounting only."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import shutil
from uuid import UUID
import zipfile

from agent_tools import durable_remote_job as jobs
from agent_tools import private_inventory_lock as private
try:
    from . import native_fixture_storage as storage
except ImportError:
    import native_fixture_storage as storage

SOURCE_URL = 'https://updates.cdn-apple.com/2023FallFCS/fullrestores/042-55833/C0830847-A2F8-458F-B680-967991820931/UniversalMac_13.6_22G120_Restore.ipsw'
SOURCE_BYTES = 12_893_555_341
SOURCE_SHA256 = '9bf095739b8b2d5ebd20f7e8de938f10bc449f9843de21c4a41ae54d73526728'
ZIP_ENTRIES = 1031
ZIP_STAGING_BYTES = 15_008_521_015
RAW_CAPACITY_BYTES = 25_000_000_000
_AUTHORITY = object()


class RestoreImageError(ValueError):
    pass


def _need(condition):
    if not condition:
        raise RestoreImageError('fixture_restore_source_unverified')


def _json(raw):
    def pairs(rows):
        result = {}
        for key,value in rows:
            _need(key not in result); result[key] = value
        return result
    value = json.loads(raw,object_pairs_hook=pairs); _need(type(value) is dict)
    return value


def _original_absent(plans, actor):
    actual = jobs._birth(actor['pid'])
    if actual is not None:
        _need(actual != actor['birth'])
    else:
        # Missing birth visibility alone is not positive actor absence.
        plans._absent(actor['pid'])


class VerifiedRestoreImage:
    """Held source bytes and original terminal, never a caller success flag."""
    def __init__(self, authority, stack, guards, plans, source_id, source_plan, fd, generation, binding, job_root, operation, job_generation, terminal, actor):
        _need(authority is _AUTHORITY)
        self._stack=stack; self._guards=guards; self._plans=plans; self._source_id=source_id
        self._source_plan=source_plan; self._fd=fd; self._generation=generation
        self._binding=binding; self._job_root=job_root; self._operation=operation
        self._job_generation=job_generation; self._terminal=terminal; self._actor=actor
        self._authority=authority

    def guard(self, plans, state):
        _need(self._authority is _AUTHORITY and self._stack is not None and plans.directory==self._plans.directory)
        for guard in self._guards: guard()
        _need(private._generation(os.fstat(self._fd))==self._generation)
        _need(state['plans'].get(self._source_id)==self._source_plan and self._source_plan['state']=='retained')
        observed=jobs.observe(self._job_root,self._operation,self._binding,generation=self._job_generation)
        _need(observed==self._terminal and observed['state']=='terminal' and observed['terminal']['exitCode']==0)
        for actor in (self._actor,observed['terminal']['owner']):
            _original_absent(plans,actor)

    def bootstrap_growth(self, disks):
        _need(self._authority is _AUTHORITY and self._stack is not None and type(disks) is list and len(disks)==1)
        disk=disks[0]
        _need(type(disk) is dict and set(disk)=={'path','capacityBytes'} and type(disk['capacityBytes']) is int
              and disk['capacityBytes']==RAW_CAPACITY_BYTES and type(disk['path']) is str and Path(disk['path']).name=='disk.img')
        return RAW_CAPACITY_BYTES+ZIP_STAGING_BYTES, ZIP_STAGING_BYTES

    def close(self):
        if self._stack is not None:self._stack.close();self._stack=None

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def verify_restore_image(project_root, plans, operation_id):
    """Verify one approved original image download, retaining its source FD.

    The path, source digest, ZIP staging and raw capacity come from this source.
    Reusing this capability requires the same retained claim and terminal job.
    """
    stack=ExitStack()
    try:
        _need(type(operation_id) is str and str(UUID(operation_id))==operation_id)
        base=Path(project_root).resolve()/'.runtime/tool-recovery/tart'/('apple-asset-'+operation_id)
        presented=private.PresentedPath(base);directory=stack.enter_context(private.Directory(presented.canonical))
        _need(stat.S_IMODE(os.fstat(directory.fd).st_mode)==0o700)
        guards=[presented.guard,directory.guard]
        ledger_presented=private.PresentedPath(plans.directory)
        _need(ledger_presented.canonical==plans.directory)
        ledger_directory=stack.enter_context(private.Directory(ledger_presented.canonical))
        guards.extend((ledger_presented.guard,ledger_directory.guard))
        def record(name):
            held=stack.enter_context(private.Snapshot(directory,name));guards.append(held.guard);return _json(held.body)
        intent=record('intent.json');verified=record('verified-source.json');actor=record('actor.json')
        _need(set(intent)=={'operationId','storageFixtureId','source','programSha256','hostBinding','jobRootGeneration','noVmAdmission'}
              and intent['operationId']==operation_id and intent['noVmAdmission'] is True
              and intent['source']=={'url':SOURCE_URL,'bytes':SOURCE_BYTES,'sha256':SOURCE_SHA256})
        source_id='apple-ventura-source-'+operation_id[:8]
        _need(intent['storageFixtureId']==source_id and set(actor)=={'operationId','pid','birth'}
              and actor['operationId']==operation_id and type(actor['pid']) is int and actor['pid']>0 and type(actor['birth']) is str)
        image=base/'Restore.ipsw'
        _need(set(verified)=={'operationId','sourceUrl','bytes','sha256','path','actor'}
              and verified=={'operationId':operation_id,'sourceUrl':SOURCE_URL,'bytes':SOURCE_BYTES,'sha256':SOURCE_SHA256,'path':str(image),'actor':actor})
        binding=jobs.MachineBinding(**intent['hostBinding']);job_generation=tuple(intent['jobRootGeneration']);job_root=base/'jobs'
        terminal,_,_=jobs.collect(job_root,operation_id,binding,generation=job_generation)
        _need(terminal['terminal']['programSha256']==intent['programSha256'] and terminal['terminal']['exitCode']==0)
        original_directory=stack.enter_context(private.Directory(job_root/operation_id));guards.append(original_directory.guard)
        for name in ('intent.json','terminal.json','owner.json','program.py'):
            held=stack.enter_context(private.Snapshot(original_directory,name));guards.append(held.guard)
            if name=='program.py':_need(held.digest==intent['programSha256'])
        for original in (actor,terminal['terminal']['owner']):_original_absent(plans,original)
        fd=os.open('Restore.ipsw',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory.fd);stack.callback(os.close,fd)
        info=os.fstat(fd);generation=private._generation(info)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600
              and info.st_nlink==1 and info.st_size==SOURCE_BYTES)
        def image_guard():
            directory.guard();_need(private._generation(os.fstat(fd))==generation
                and private._generation(os.stat('Restore.ipsw',dir_fd=directory.fd,follow_symlinks=False))==generation)
        guards.append(image_guard)
        digest=hashlib.sha256()
        while True:
            raw=os.read(fd,8*1024**2)
            if not raw:break
            digest.update(raw)
        _need(digest.hexdigest()==SOURCE_SHA256);image_guard()
        with os.fdopen(os.dup(fd),'rb') as source, zipfile.ZipFile(source) as archive:
            entries=archive.infolist();_need(len(entries)==ZIP_ENTRIES and sum(entry.file_size for entry in entries)==ZIP_STAGING_BYTES)
        image_guard()
        # Atomic ledger replacement makes this read-only row projection safe;
        # verification must not create a missing ledger or lock file.
        source_plan=plans._read()['plans'].get(source_id)
        _need(source_plan is not None and source_plan['state']=='retained' and source_plan['platform']=='macos'
              and source_plan['directory']==str(base) and source_plan['disks']==[{'path':str(image),'capacityBytes':SOURCE_BYTES}]
              and source_plan['workingBytes']==0 and source_plan.get('stagingBytes',0)==0 and source_plan['writerPid']==actor['pid'])
        result=VerifiedRestoreImage(_AUTHORITY,stack,guards,plans,source_id,source_plan,fd,generation,binding,job_root,operation_id,job_generation,terminal,actor)
        result.guard(plans,plans._read())
        return result
    except BaseException as error:
        stack.close()
        if isinstance(error,(KeyboardInterrupt,SystemExit)):raise
        raise RestoreImageError('fixture_restore_source_unverified') from None


def reserve_verified_bootstrap(proof, plans, fixture_id, directory, *, writer_pid=None):
    """Claim finite installation growth; this grants no VM or memory slot.

    The ordinary unknown-source bootstrap floor remains unchanged. Only this
    held, approved immutable input replaces that estimate with exact raw disk
    and all ZIP staging capacity. The retained source claim stays in the ledger.
    """
    _need(type(proof) is VerifiedRestoreImage)
    proof.guard(plans,plans._read())
    directory=Path(directory).absolute()
    disks=[{'path':str(directory/'disk.img'),'capacityBytes':RAW_CAPACITY_BYTES}]
    working,staging=proof.bootstrap_growth(disks)
    plan={'platform':'macos','directory':str(directory),'disks':disks,'workingBytes':working,
          'writerPid':writer_pid,'state':'pending','stagingBytes':staging}
    plans._validate(fixture_id,plan)
    with plans._locked():
        state=plans._read();proof.guard(plans,state)
        _need(fixture_id != proof._source_id)
        existing=state['plans'].get(fixture_id)
        if existing is not None:
            keys=('platform','directory','disks','workingBytes','stagingBytes')
            _need(all(existing.get(key)==plan[key] for key in keys) and existing['state']!='retired'
                  and (writer_pid is None or existing['writerPid']==writer_pid))
        else:
            state['plans'][fixture_id]=plan
        destination=directory
        while not destination.exists():
            _need(destination!=destination.parent);destination=destination.parent
        device=destination.stat().st_dev;seen=set()
        current=state['plans'][fixture_id]
        candidate=max(working,plans._growth(current,device,seen))
        # This exact existing input is immutable for the capability lifetime;
        # its allocated bytes are already reflected in actual free space.
        _need(Path(proof._source_plan['directory']).stat().st_dev==device)
        plans._growth(proof._source_plan,device,seen)
        retained=sum(plans._growth(value,device,seen) for key,value in state['plans'].items()
                     if key not in {fixture_id,proof._source_id})
        free=shutil.disk_usage(destination).free
        _need(type(free) is int and free>=0)
        required=candidate+retained+storage.HEADROOM_BYTES
        if free<required:
            raise storage.FixtureStorageError('fixture_disk_capacity_insufficient')
        proof.guard(plans,state)
        if existing is None:plans._save(state)
        proof.guard(plans,plans._read())
        result={'platform':'macos','phase':'verified-restore-bootstrap','freeBytes':free,'requiredBytes':required,
                'candidateGrowthBytes':candidate,'otherOwnedGrowthBytes':retained,'headroomBytes':storage.HEADROOM_BYTES,'planCount':len(state['plans'])}
    proof.guard(plans,plans._read())
    return result
