"""Explicit root-approved unsubmitted source epoch; no remote/native effects."""
from pathlib import Path
import os,json,hashlib,uuid,stat,difflib
repo=Path.cwd();old=repo/'.runtime/tool-recovery/ssh-full-ordinary-successor/ff515dd6-8430-42cc-8aa6-965f278ba3a7';new=old.parent/str(uuid.uuid4());new.mkdir(mode=0o700)
def gen(i):return[i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]
def save(p,raw,mode=0o600):
 p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
def sha(raw):return hashlib.sha256(raw).hexdigest()
oldcheckpoint=(old/'source-checkpoint.json').read_bytes();assert sha(oldcheckpoint)=='0823d6c915a881375023b57fe874c2d0d6b25d8387beaca9f635848393904ab2'
origins={}
for mode in('direct','nested'):
 c=old/mode;assert not(c/'.rag_index').exists()and not(c/'.vm-hosts.local.json').exists()and not(c/'operation.json').exists()
 assert not(old/('local-owner-'+mode)).exists()
 origins[mode]={'originGeneration':gen(os.lstat(c/'capsule-origin.json')),'originSha256':sha((c/'capsule-origin.json').read_bytes()),'plannedGeneration':gen(os.lstat(c/'planned-operation.json')),'plannedSha256':sha((c/'planned-operation.json').read_bytes()),'namespaceAbsent':True,'runtimeInventoryAbsent':True,'operationReceiptAbsent':True,'localOwnerNamespaceAbsent':True}
for name in('controller.py','controller.4674.before.source','ordinary_retention.py','prepare_sources.py','prepare_routes.py','bin/ssh','local-owner-source/local_owner.py'):
 save(new/name,(old/name).read_bytes(),0o700 if name=='bin/ssh' else 0o600)
assert sha((new/'controller.py').read_bytes())=='a088df1dfcd24fdc836b16d8c5011cb61e26397bcfc3265630624e2814926e51'
save(new/'previous-source-checkpoint.before.json',oldcheckpoint)
save(new/'controller-vs4674-absolute-deadline.diff',''.join(difflib.unified_diff((old/'controller.4674.before.source').read_text().splitlines(True),(old/'controller.py').read_text().splitlines(True),fromfile='controller.4674.before.source',tofile='controller.py')).encode())
record=json.loads(oldcheckpoint);record['controllerSha256']=sha((new/'controller.py').read_bytes());record['metadataPins']={p:sha((repo/p).read_bytes())for p in record['metadataPins']}
assert record['metadataPins']['agent_tools/affected_agent_test_dependencies.json']=='885f8875f68f153e35ab219479e81ab076c2134019b657c2c5120ca9b95f61ef'
record['previousUnsubmittedSourceCheckpoint']={'sha256':sha(oldcheckpoint),'controllerSha256':'46748882bd73fd27b51ccb03e33da057749b7e805c4b20b8b3634310e3a77660','previousEpoch':str(old),'previousCapsulesUnsubmitted':origins,'retainedPublicSourcesPerCapsule':693,'regenerationPurpose':'restricted absolute-deadline controller plus final metadata885; no operation ever admitted'}
record['ordinaryLocalOwnerSourceSha256']=sha((new/'local-owner-source/local_owner.py').read_bytes())
save(new/'source-checkpoint.json',(json.dumps(record,sort_keys=True,indent=2)+'\n').encode())
proof={'schemaVersion':1,'originalEpoch':str(old),'newEpoch':str(new),'oldCheckpointSha256':sha(oldcheckpoint),'newCheckpointSha256':sha((new/'source-checkpoint.json').read_bytes()),'oldPublicOrigins':origins,'oldArtifactsRetained':True,'remoteOperationsReusedOnlyBecauseProvenNeverAdmitted':True,'connections':0,'jobs':0,'nativeGo':False}
save(new/'unsubmitted-regeneration-proof.json',(json.dumps(proof,indent=2)+'\n').encode())
save(old/'new-source-epoch.json',(json.dumps({'newEpoch':str(new),'newSourceCheckpointSha256':proof['newCheckpointSha256'],'stage':'source-only; no native GO'},indent=2)+'\n').encode())
print(json.dumps({'newEpoch':str(new),'checkpointSha256':proof['newCheckpointSha256'],'sourceOnly':True,'old693originsPreserved':True}))
