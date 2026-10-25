"""Fixed internal host-source publisher. No guest/root/UI/provider mutation.

There is no public action or caller source/path/ownership flag. Inputs come from
one fixed provider-owned source enrollment and exact reviewed five-file hashes.
All functions below are SOURCE-ONLY candidates until integrated/reviewed.
"""
from . import readiness_tart_macos_registry as mac
from . import readiness_fixture_registry as registry
from . import readiness_tart_macos_active_work_sources as sources
from . import readiness_tart_macos_active_work_original as original
from contextlib import ExitStack
import base64,hashlib,json,os,stat,sys,time
from pathlib import Path
_CODE=sys._getframe().f_code

def need(value,reason):
    if not value:raise mac.MacBlocked(reason)
def _json(raw):return json.loads(raw,parse_constant=lambda _:(_ for _ in ()).throw(mac.MacBlocked('macos_publication_nonfinite')))
def _source(c):
    path=c.lifecycle_root/('active-work-install-source-'+sources.INSTALL_OPERATION+'.json')
    value,pin=c._registry._json(path)
    need(type(value)is dict and set(value)=={'schemaVersion','role','originalRun','target','machine','files'}and type(value['schemaVersion'])is int and value['schemaVersion']==1 and value['role']==sources.ROLE,'macos_publication_input_invalid')
    need((value['originalRun'],value['target'],value['machine'])==(c.run_intent['operationId'],c.binding.target,c.binding.machine)and set(value['files'])==sources.FILES,'macos_publication_input_target_changed')
    parent=c.lifecycle_root/('active-work-install-source-'+sources.INSTALL_OPERATION)/'bundle'
    held=ExitStack();proofs=[]
    try:
        record=held.enter_context(mac.PublicProof(path,pin));proofs.append(record)
        for name in sorted(sources.FILES):
            ref=value['files'][name]
            need(ref['path']==str(parent/name)and ref['pin']['sha256']==sources.EXPECTED_FILES[name]['sha256']and ref['pin']['generation'][6]==sources.EXPECTED_FILES[name]['bytes'],'macos_fixed_publication_source_changed')
            proof=held.enter_context(mac.PublicProof(parent/name,ref['pin']));proofs.append(proof)
        return held,proofs,{'path':str(path),'pin':pin}
    except BaseException:held.close();raise

def prepare_source_enrollment(custody,*,deadline):
    """Create-only HOST staging from the one reviewed fixed bundle. No share
    append or installer execution. A partial staging generation is never
    adopted/replaced by this method; retain it for original observation.
    """
    need(type(custody)is mac.MacCustody,'macos_current_custody_required');c=custody
    with c.operator(deadline=deadline):
        c.guard(deadline=deadline)
        need(set(c.descriptor['sourceAdmission'])==sources.ORIGINAL_KEYS,'macos_publication_already_extended')
        reviewed=c.root/'.runtime/tool-recovery/macos-active-work-install-packet-v2/bundle-staging'
        with ExitStack()as held:
            proofs={}
            for name in sorted(sources.FILES):
                path=reviewed/name;raw,pin=c._registry._body(path)
                need(pin['sha256']==sources.EXPECTED_FILES[name]['sha256']and len(raw)==sources.EXPECTED_FILES[name]['bytes'],'macos_reviewed_bundle_changed')
                proofs[name]=held.enter_context(mac.PublicProof(path,pin))
            base=c.lifecycle_root/('active-work-install-source-'+sources.INSTALL_OPERATION)
            base.mkdir(mode=0o700);(base/'bundle').mkdir(mode=0o700)
            with mac.private.Directory(base/'bundle')as output:
                for name,proof in proofs.items():
                    mac._limit(deadline);c.guard(deadline=deadline)
                    for item in proofs.values():item.guard()
                    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=output.fd)
                    try:_write(fd,proof.body)
                    finally:os.close(fd)
                    os.fsync(output.fd)
                output.guard();files={}
                for name,proof in proofs.items():
                    proof.guard();path=base/'bundle'/name;raw,pin=c._registry._body(path)
                    need(raw==proof.body,'macos_fixed_source_copy_changed');files[name]={'path':str(path),'pin':pin}
                c.guard(deadline=deadline)
                record={'schemaVersion':1,'role':sources.ROLE,'originalRun':c.run_intent['operationId'],'target':c.binding.target,'machine':c.binding.machine,'files':files}
                path=c.lifecycle_root/('active-work-install-source-'+sources.INSTALL_OPERATION+'.json')
                mac.jobs._create(path,(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode())
                c.guard(deadline=deadline);return {'path':str(path),'pin':c._registry._json(path)[1]}

def program(custody,operation):
    """Pure captured Program. Paths/source pins derive only from actual custody."""
    need(type(custody)is mac.MacCustody,'macos_current_custody_required');c=custody;mac.jobs._uuid(operation)
    held,proofs,source_ref=_source(c)
    try:
        loader=c.root/'agent_tools/source_module_loader.py'
        raw,pin=c._registry._body(loader,private_file=False)
        config={'schemaVersion':1,'root':str(c.root),'fixtureId':c.fixture_id,'descriptor':{'path':str(c._descriptor_path),'pin':c.descriptor_pin},'operationId':operation,'jobRoot':str(c.run_owner.root),'jobRootGeneration':list(c.run_owner.generation),'hostBinding':mac.jobs.asdict(c.host_binding),'sourceInput':source_ref,'loaderSha256':hashlib.sha256(raw).hexdigest(),'sources':c.descriptor['sources']}
        wrapper='''import hashlib,os,sys,types
from pathlib import Path
CONFIG=__CONFIG__
root=Path(CONFIG['root']);path=root/'agent_tools/source_module_loader.py'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 def g(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 before=g(os.fstat(fd));raw=b''
 while len(raw)<=4194304:
  part=os.read(fd,min(65536,4194305-len(raw)))
  if not part:break
  raw+=part
 if not 0<len(raw)<=4194304 or hashlib.sha256(raw).hexdigest()!=CONFIG['loaderSha256']:raise SystemExit(73)
 if before!=g(os.fstat(fd)) or before!=g(path.lstat()):raise SystemExit(73)
 loader=types.ModuleType('_fixed_publication_loader');loader.__file__=str(path)
 exec(compile(raw,str(path),'exec',dont_inherit=True),loader.__dict__)
 session=loader.SourceSession(root/'agent_tools','readiness_tart_macos_active_work_publication')
 try:session.module._owned_publish(CONFIG);session.guard()
 finally:session.close()
finally:os.close(fd)
'''.replace('__CONFIG__',repr(config))
        return mac.jobs.Program(original.PUBLICATION_PURPOSE,wrapper.encode(),16384)
    finally:held.close()

def prepare(custody,operation,*,deadline):
    """Internal prepare-only metadata; does not submit or append."""
    need(type(custody)is mac.MacCustody,'macos_current_custody_required');c=custody
    with c.operator(deadline=deadline):
        c.guard(deadline=deadline);need(set(c.descriptor['sourceAdmission'])==sources.ORIGINAL_KEYS,'macos_publication_already_extended');p=program(c,operation)
        need(not(c.run_owner.root/operation).exists()and not(c.run_owner.root/operation).is_symlink(),'macos_publication_original_present')
        plan={'schemaVersion':1,'role':sources.ROLE,'state':'captured_before_first_append','originalRun':c.run_intent['operationId'],'predecessor':{'path':str(c._descriptor_path),'pin':c.descriptor_pin},'originalReferences':c.descriptor['sourceAdmission'],'publisherOperationId':operation,'publisherProgram':{'path':str(c.run_owner.root/operation/'program.py'),'sha256':p.digest},'fixedFiles':sources.EXPECTED_FILES,'operatorPath':str(c._operator.path)}
        path=c.lifecycle_root/('active-work-publication-'+sources.INSTALL_OPERATION+'.intent.json')
        mac.jobs._create(path,(json.dumps(plan,sort_keys=True,separators=(',',':'))+'\n').encode())
        c.guard(deadline=deadline);return p

def submit_prepared(custody,operation,*,deadline):
    """Internal one-shot submit, not a tool/action or generic executor API."""
    need(type(custody)is mac.MacCustody,'macos_current_custody_required');c=custody;mac.jobs._uuid(operation)
    with c.operator(deadline=deadline):
        c.guard(deadline=deadline);need(set(c.descriptor['sourceAdmission'])==sources.ORIGINAL_KEYS,'macos_publication_already_extended');p=program(c,operation)
        intent=c._record({'path':str(c.lifecycle_root/('active-work-publication-'+sources.INSTALL_OPERATION+'.intent.json')),'pin':c._registry._json(c.lifecycle_root/('active-work-publication-'+sources.INSTALL_OPERATION+'.intent.json'))[1]})
        need(intent['publisherOperationId']==operation and intent['publisherProgram']=={'path':str(c.run_owner.root/operation/'program.py'),'sha256':p.digest}and intent['predecessor']=={'path':str(c._descriptor_path),'pin':c.descriptor_pin},'macos_publication_preparation_changed')
        # The fixed once marker is durable BEFORE generic submit; a lost ACK
        # may only observe/collect this original owner. No marker recreation.
        marker=c.lifecycle_root/('active-work-publication-submit-'+operation+'.json')
        mac.jobs._create(marker,(json.dumps({'operationId':operation,'programSha256':p.digest,'state':'unknown_before_submit'},sort_keys=True)+'\n').encode())
        return mac.jobs.submit(c.run_owner.root,operation,c.host_binding,p,generation=c.run_owner.generation)

def _write(fd,raw):
    offset=0
    while offset<len(raw):
        n=os.write(fd,raw[offset:]);need(n>0,'macos_publication_write');offset+=n
def _owned_publish(config):
    """Only the exact detached captured Program may enter this fixed operation.
    Wait is bounded and performs no share writes; no lock is held while waiting
    for the parent to create the BEFORE-append durable original association.
    """
    group=time.monotonic()+90
    root=Path(config['root']);fixture_id=registry._id(config['fixtureId']);operation=mac.jobs._uuid(config['operationId'])
    descriptor,pin=registry._json(root/'.rag_index/readiness-fixtures'/(fixture_id+'.json'))
    need(config['descriptor']=={'path':str(root/'.rag_index/readiness-fixtures'/(fixture_id+'.json')),'pin':pin}and config['sources']==descriptor['sources']==mac._source_pins(),'macos_publication_source_epoch_changed')
    c=mac.MacCustody(root,fixture_id,descriptor,pin);input_hold=None;view=None
    try:
        need((str(c.run_owner.root),list(c.run_owner.generation),mac.jobs.asdict(c.host_binding))==(config['jobRoot'],config['jobRootGeneration'],config['hostBinding']),'macos_publication_host_changed')
        expected=program(c,operation);job=c.run_owner.root/operation
        intent=mac.jobs._intent(job,operation,c.host_binding)
        need(intent['purpose']==original.PUBLICATION_PURPOSE and intent['programSha256']==expected.digest and mac.jobs._read(job/'program.py',mac.jobs.MAX_PROGRAM_BYTES)==expected.source,'macos_publication_program_changed')
        owner=mac.jobs._record(job/'owner.json');identity=mac.jobs._owner_identity(owner)
        need(os.getppid()==identity['pid']and mac.jobs._birth(identity['pid'])==identity['birth'],'macos_publication_owner_changed')
        input_hold,proofs,input_ref=_source(c);need(input_ref==config['sourceInput'],'macos_publication_input_changed')
        association=c.lifecycle_root/('active-work-original-observer-'+sources.INSTALL_OPERATION+'.json')
        print('{"schemaVersion":1,"state":"waiting_for_durable_original_association"}',flush=True)
        while True:
            mac._limit(group)
            try:association.lstat();break
            except FileNotFoundError:time.sleep(min(.025,mac._limit(group)))
        with c.operator(deadline=group):
            # Full ordinary guard is the authority BEFORE the one append. The
            # readonly view is used only for after-effect observation, never as
            # new execution authority. Existing/new work cannot use that view.
            c.guard(deadline=group)
            view=original.prepare_current(c,deadline=group)
            for proof in proofs:proof.guard()
            share=Path(c.run_intent['plan']['bootstrapShare'])
            presented=mac.private.PresentedPath(share)
            with mac.private.Directory(presented.canonical)as parent:
                try:os.stat(sources.BUNDLE,dir_fd=parent.fd,follow_symlinks=False)
                except FileNotFoundError:pass
                else:raise mac.MacBlocked('macos_publication_bundle_already_present')
                os.mkdir(sources.BUNDLE,0o700,dir_fd=parent.fd);os.fsync(parent.fd)
                fd=os.open(sources.BUNDLE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent.fd)
                try:
                    for name in sorted(sources.FILES):
                        mac._limit(group)
                        for proof in proofs:proof.guard()
                        source=next(proof for proof in proofs if proof.path.name==name)
                        child=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
                        try:_write(child,source.body);os.fchmod(child,0o444);os.fsync(child)
                        finally:os.close(child)
                        os.fsync(fd)
                    os.fchmod(fd,0o555);os.fsync(fd)
                finally:os.close(fd)
                presented.guard();parent.guard();view._guard(group)
                actual=sources.observe_five_files(share/sources.BUNDLE,sources.EXPECTED_FILES)
                for proof in proofs:proof.guard()
                record={'schemaVersion':1,'role':sources.ROLE,'operationId':sources.INSTALL_OPERATION,'originalRun':c.run_intent['operationId'],'target':c.binding.target,'machine':c.binding.machine,'rawBoot':c.guest_proof['initialPacket']['agent']['rawBoot'],'previousDescriptor':config['descriptor'],'previousSourcePins':descriptor['sources'],'originalReferences':descriptor['sourceAdmission'],'originalRowsSha256':sources.sha(sources.canonical(view._rows)),'share':str(share),'bundle':str(share/sources.BUNDLE),'guestBundle':'/Volumes/My Shared Files/bootstrap/'+sources.BUNDLE,**actual,'state':'published_public_source_not_installed','qualification':{'inputAuthority':False,'idleAuthority':False,'lifecycleAuthority':False,'nativeQualified':False}}
                mac.jobs._create(c.lifecycle_root/('active-work-install-'+sources.INSTALL_OPERATION+'.json'),(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode())
                view._guard(group)
        print('{"schemaVersion":1,"state":"fixed_source_published_not_installed","nativeQualified":false,"idleAuthority":false}',flush=True)
    finally:
        if view is not None:view.close()
        if input_hold is not None:input_hold.close()
        c.close()
