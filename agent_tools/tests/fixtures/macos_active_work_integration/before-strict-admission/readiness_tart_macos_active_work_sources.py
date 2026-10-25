"""Finite internal diagnostic source role; source publication grants no capability.

Only the registry owner may wire this finite optional role into held custody.
All context arguments below must then be derived from actual provider holders;
accepting an equivalent public mapping must never be treated as that authority.
This file imports no provider and performs no guest/registry/share mutation.
"""
import hashlib,json,os,re,stat,uuid
from pathlib import Path

ORIGINAL_KEYS=frozenset(('originalManifest','continuation','logPreparation'))
FILES=frozenset(('install.py','main.py','caller.py','bundle.json','authorization.applescript'))
ROLE='fixed_active_work_diagnostic_install'
BUNDLE='active-work-4a9f62cc'
INSTALL_OPERATION='ca6919f5-137e-4a1e-a68b-bef546c230da'
ORIGINAL_RUN='2d933a39-0fb6-46a4-9fd9-02221d81c4b9'
TARGET='tart:vpn-tool-recovery-tart-macos-7686d4aa'
MACHINE='ecdc399a-8f2b-5410-b85d-e4db56ddc6c1'
BOOT='87ac272f-619b-4cc0-b9fc-3e32daee5b18'
FIELDS=frozenset(('schemaVersion','role','operationId','originalRun','target','machine','rawBoot','previousDescriptor','previousSourcePins','originalReferences','originalRowsSha256','share','bundle','guestBundle','bundleGeneration','files','state','qualification'))
class Invalid(ValueError):pass
def need(ok,reason):
    if not ok:raise Invalid(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def generation(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
def strict(raw):
    need(type(raw)is bytes and len(raw)<=65536,'record_limit')
    def pairs(items):
        out={}
        for key,value in items:need(key not in out,'duplicate_key');out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Invalid('nonfinite')))
def pin(value,limit=262144):
    need(type(value)is dict and set(value)=={'generation','sha256'},'pin_fields')
    g=value['generation'];digest=value['sha256']
    need(type(g)is list and len(g)==9 and all(type(v)is int for v in g),'pin_generation')
    need(type(digest)is str and re.fullmatch('[0-9a-f]{64}',digest),'pin_digest')
    need(stat.S_ISREG(g[2]) and g[2]&0o022==0 and g[5]==1 and 0<g[6]<=limit,'pin_file')
def reference(value):
    need(type(value)is dict and set(value)=={'path','pin'} and type(value['path'])is str and Path(value['path']).is_absolute(),'reference_fields')
    pin(value['pin'],134217728)
def validate(raw,*,previous_descriptor_ref,previous_sources,original_references,original_rows,share,raw_boot,expected_files):
    """Validate only; return proposed rows, never an executor/observing authority.
    Registry integration MUST authenticate every supplied context from original
    retained provider holders and check current operator/actor/source custody.
    """
    value=strict(raw)
    need(type(value)is dict and set(value)==FIELDS,'admission_fields')
    need(type(value['schemaVersion'])is int and value['schemaVersion']==1 and value['role']==ROLE,'admission_role')
    need((value['operationId'],value['originalRun'],value['target'],value['machine'])==(INSTALL_OPERATION,ORIGINAL_RUN,TARGET,MACHINE),'original_binding')
    need(type(raw_boot)is str and str(uuid.UUID(raw_boot)).lower()==BOOT and value['rawBoot']==raw_boot,'boot_binding')
    reference(value['previousDescriptor'])
    need(value['previousDescriptor']==previous_descriptor_ref and value['previousSourcePins']==previous_sources,'predecessor_changed')
    need(type(original_references)is dict and set(original_references)==ORIGINAL_KEYS and value['originalReferences']==original_references,'historical_references_changed')
    for ref in original_references.values():reference(ref)
    need(value['originalRowsSha256']==sha(canonical(original_rows)),'historical_rows_changed')
    need(type(share)is str and Path(share).is_absolute() and value['share']==share,'share_binding')
    need(value['bundle']==str(Path(share)/BUNDLE) and value['guestBundle']=='/Volumes/My Shared Files/bootstrap/'+BUNDLE,'bundle_binding')
    need(value['state']=='published_public_source_not_installed' and value['qualification']=={'inputAuthority':False,'idleAuthority':False,'lifecycleAuthority':False,'nativeQualified':False},'authority_forbidden')
    need(type(value['files'])is dict and set(value['files'])==FILES and type(expected_files)is dict and set(expected_files)==FILES,'fixed_five_files')
    directory=value['bundleGeneration']
    need(type(directory)is list and len(directory)==9 and all(type(n)is int for n in directory) and stat.S_ISDIR(directory[2]) and directory[2]&0o022==0,'bundle_generation')
    rows=[{'path':BUNDLE,'kind':'directory','generation':directory}]
    for name in sorted(FILES):
        observed=value['files'][name];pin(observed)
        need(observed['sha256']==expected_files[name]['sha256'] and observed['generation'][6]==expected_files[name]['bytes'],'fixed_source_changed')
        need(observed['generation'][3]==directory[3],'bundle_owner')
        rows.append({'path':BUNDLE+'/'+name,'kind':'file',**observed})
    return {'state':'schema_validated_only_not_provider_authority','originalRowsPreserved':original_rows,'proposedAdditionalRows':rows,'inputAuthority':False,'idleAuthority':False,'lifecycleAuthority':False}

def observe_five_files(bundle,expected_files):
    """Host local metadata read only. No publication/admission; no recursion.
    Real publication must additionally hold its parent source route in registry.
    """
    root=Path(bundle);before=root.lstat()
    need(stat.S_ISDIR(before.st_mode) and before.st_mode&0o022==0 and before.st_uid==os.geteuid(),'bundle_owner_mode')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        need(generation(os.fstat(fd))==generation(before) and set(os.listdir(fd))==FILES,'bundle_entries')
        result={}
        for name in sorted(FILES):
            initial=os.stat(name,dir_fd=fd,follow_symlinks=False)
            need(stat.S_ISREG(initial.st_mode) and initial.st_nlink==1 and initial.st_uid==before.st_uid and initial.st_mode&0o022==0 and 0<initial.st_size<=262144,'bundle_file_type')
            child=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=fd)
            try:
                need(generation(os.fstat(child))==generation(initial),'bundle_file_replaced')
                chunks=[];length=0
                while length<=262144:
                    part=os.read(child,min(65536,262145-length))
                    if not part:break
                    chunks.append(part);length+=len(part)
                raw=b''.join(chunks)
                need(length==initial.st_size and sha(raw)==expected_files[name]['sha256'] and length==expected_files[name]['bytes'],'bundle_content_changed')
                need(generation(os.fstat(child))==generation(initial)==generation(os.stat(name,dir_fd=fd,follow_symlinks=False)),'bundle_file_changed')
                result[name]={'generation':generation(initial),'sha256':sha(raw)}
            finally:os.close(child)
        need(generation(root.lstat())==generation(before)==generation(os.fstat(fd)) and set(os.listdir(fd))==FILES,'bundle_changed')
        return {'bundleGeneration':generation(before),'files':result}
    finally:os.close(fd)

def publish_record(directory_fd,name,raw):
    """Create-only metadata record primitive; NOT a share/bundle publisher."""
    need(type(name)is str and re.fullmatch(r'active-work-install-[0-9a-f-]{36}\.json',name) and name=='active-work-install-'+INSTALL_OPERATION+'.json','record_name')
    strict(raw);before=os.fstat(directory_fd)
    need(stat.S_ISDIR(before.st_mode) and before.st_uid==os.geteuid() and before.st_mode&0o777==0o700,'private_directory')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory_fd)
    try:
        offset=0
        while offset<len(raw):
            n=os.write(fd,raw[offset:]);need(n>0,'record_write');offset+=n
        os.fsync(fd)
    finally:os.close(fd)
    os.fsync(directory_fd)
    after=os.fstat(directory_fd)
    need((before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid)==(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid),'private_directory_changed')

def observe_pending_subset(share,original_rows,expected_files):
    """Data-only source view. Provider MUST hold its actual publication/operator
    lock across this call and opaque association admission. No flag/DTO proves
    that lock. Two exact bounded censuses plus held named ancestry close a
    first-walk/post-validation append race; partial bytes are never read.
    """
    root=Path(share)
    need(root.is_absolute()and root.resolve(strict=True)==root,'share_route')
    old={row['path']:row for row in original_rows}
    need(len(old)==len(original_rows)and not any(name==BUNDLE or name.startswith(BUNDLE+'/')for name in old),'historical_bundle_overlap')
    need(set(expected_files)==FILES,'fixed_five_files')
    allowed={BUNDLE}|{BUNDLE+'/'+name for name in FILES};fds=[];named=[]
    def structural(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)
    def route_guard():
        for fd,pin in fds:need(structural(os.fstat(fd))==pin,'held_route_changed')
        for fd,name,pin in named:need(structural(os.stat(name,dir_fd=fd,follow_symlinks=False))==pin,'named_route_changed')
    def census():
        rows={}
        for directory,dirs,files in os.walk(root,followlinks=False):
            for leaf in (*dirs,*files):
                path=(Path(directory)/leaf).relative_to(root).as_posix()
                need(path not in rows and len(rows)<10000 and(path in old or path in allowed),'unexpected_source_entry')
                rows[path]=generation((root/path).lstat())
        return rows
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append((parent,structural(os.fstat(parent))))
        for part in root.parts[1:]:
            before=os.stat(part,dir_fd=parent,follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode),'route_type')
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            need(structural(os.fstat(fd))==structural(before),'route_replaced')
            named.append((parent,part,structural(before)));fds.append((fd,structural(before)));parent=fd
        root_before=generation(os.fstat(parent));route_guard()
        need(root_before[3]==os.geteuid()and root_before[2]&0o022==0,'share_owner_mode')
        first=census();need(set(old)<=set(first),'historical_entry_missing')
        for name,row in old.items():
            info=(root/name).lstat()
            need(generation(info)==first[name]==row['generation']and info.st_uid==os.geteuid(),'historical_entry_changed')
            if row['kind']=='symlink':need(stat.S_ISLNK(info.st_mode)and os.readlink(root/name)==row['target']and(root/name).resolve(strict=True).is_relative_to(root),'historical_link_changed')
            else:need(info.st_mode&0o022==0 and(stat.S_ISDIR(info.st_mode)if row['kind']=='directory'else stat.S_ISREG(info.st_mode)),'historical_type_mode')
        pending=sorted(set(first)-set(old))
        for name in pending:
            pin=first[name];need(pin[3]==os.geteuid()and pin[2]&0o022==0,'pending_owner_mode')
            if name==BUNDLE:need(stat.S_ISDIR(pin[2]),'pending_directory')
            else:need(stat.S_ISREG(pin[2])and pin[5]==1 and 0<=pin[6]<=expected_files[name.split('/')[-1]]['bytes'],'pending_file_metadata')
        # This is deliberately an exact SECOND census, not merely rechecking
        # names from first. A late unlisted file must not disappear from view.
        second=census();need(second==first,'source_census_changed')
        route_guard();need(generation(os.fstat(parent))==root_before==generation(root.lstat()),'share_changed')
        return {'state':'original_observation_metadata_view_only','optionalPresentEntryCount':len(pending),'newDispatchAuthority':False,'installationAuthority':False,'idleAuthority':False}
    finally:
        for fd,_ in reversed(fds):os.close(fd)

EXPECTED_FILES={'authorization.applescript': {'sha256': '0789f24b63699510350dfd1ca5af37c82c3551442fe1c05befc1fbe46079b713', 'bytes': 1585}, 'bundle.json': {'sha256': 'f455a83e9cc64870810ac09cdd8ccd0904750b9b4b54b579822898ba39f03ff1', 'bytes': 659}, 'caller.py': {'sha256': '950d371680c7d8f42fda76b89ee9af480e046689c51268917b2074de2f2b3eea', 'bytes': 9114}, 'install.py': {'sha256': '6b89032e966861dbee0664d96f6c7a2b610708948a66b1bf6e57998e5a3ef42e', 'bytes': 31367}, 'main.py': {'sha256': 'b94198b6c5457a5a6ab438577a9fed8e955a0c32dd3e214d5c7e08bd03af2bbb', 'bytes': 186511}}

def admit_optional(custody,reference,original_rows):
    """Only registered provider metadata selects this optional source role."""
    from . import readiness_tart_macos_registry as mac
    need(type(custody)is mac.MacCustody,'actual_current_custody_required')
    c=custody;record=c._record(reference)
    previous=record.get('previousDescriptor')
    need(type(previous)is dict and set(previous)=={'path','pin'},'previous_descriptor')
    path=Path(previous['path']);need(path.parent==c.root/'.rag_index/readiness-fixtures'and path.suffix=='.json','previous_descriptor_route')
    c._registry._id(path.stem);descriptor,pin=c._registry._json(path)
    need(pin==previous['pin']and descriptor.get('provider')=='tart-macos','previous_descriptor_changed')
    held=c._held.enter_context(mac.PublicProof(path,pin));c._records.append(held)
    original={key:value for key,value in c.descriptor['sourceAdmission'].items()if key!='activeWorkInstall'}
    need(set(original)==ORIGINAL_KEYS and descriptor['sourceAdmission']==original,'original_references_changed')
    def physical(d):return {key:value for key,value in d.items()if key not in{'fixtureId','sources','sourceAdmission'}}
    need(physical(descriptor)==physical(c.descriptor),'physical_custody_changed')
    need(record['originalRun']==c.run_intent['operationId']and record['target']==c.binding.target and record['machine']==c.binding.machine,'selected_provider_changed')
    need(record['previousSourcePins']==descriptor['sources']and record['originalReferences']==original and record['originalRowsSha256']==sha(canonical(original_rows)),'previous_epoch_changed')
    need(record['operationId']==INSTALL_OPERATION and record['role']==ROLE and record['state']=='published_public_source_not_installed','source_role_invalid')
    need(record['qualification']=={'inputAuthority':False,'idleAuthority':False,'lifecycleAuthority':False,'nativeQualified':False},'source_capability_forbidden')
    share=c.run_intent['plan']['bootstrapShare']
    need(record['share']==share and record['bundle']==str(Path(share)/BUNDLE)and record['guestBundle']=='/Volumes/My Shared Files/bootstrap/'+BUNDLE,'bundle_route')
    actual=observe_five_files(Path(share)/BUNDLE,EXPECTED_FILES)
    need(actual['files']==record['files']and actual['bundleGeneration']==record['bundleGeneration'],'published_generation_changed')
    # The immutable provider-created association must predate this append.
    from . import readiness_tart_macos_active_work_original as original_observer
    association=c.lifecycle_root/('active-work-original-observer-'+INSTALL_OPERATION+'.json')
    value,association_pin=c._registry._json(association)
    need(value['descriptor']==previous and value['sourceAdmission']==original and value['originalRun']==c.run_intent['operationId']and value['fixedFiles']==EXPECTED_FILES,'publication_association_changed')
    held=c._held.enter_context(mac.PublicProof(association,association_pin));c._records.append(held)
    # Actual captured publisher terminal0/fullstreams and exact original intent
    # close the append. UNKNOWN is observable but cannot admit the full union.
    plan=c._record(value['publicationPlan']);operation=mac.jobs._uuid(plan['publisherOperationId'])
    intent=mac.jobs._intent(c.run_owner.root/operation,operation,c.host_binding)
    need(intent['purpose']==original_observer.PUBLICATION_PURPOSE and plan['publisherProgram']=={'path':str(c.run_owner.root/operation/'program.py'),'sha256':intent['programSha256']},'publisher_source_changed')
    program=mac.jobs.Program(intent['purpose'],mac.jobs._read(c.run_owner.root/operation/'program.py',mac.jobs.MAX_PROGRAM_BYTES),intent['streamLimit'])
    owner=mac.OriginalOwner(c.run_owner.root,c.run_owner.generation,operation,c.host_binding,program)
    terminal=owner.observe();need(terminal['state']=='terminal'and type(terminal['terminal']['exitCode'])is int and terminal['terminal']['exitCode']==0,'publication_not_closed')
    return [{'path':BUNDLE,'kind':'directory','generation':actual['bundleGeneration']}]+[{'path':BUNDLE+'/'+name,'kind':'file',**actual['files'][name]}for name in sorted(FILES)]
