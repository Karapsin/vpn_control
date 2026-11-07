#!/usr/bin/env python3
"""Collect an original owned remote frame for the existing visual driver API.

Local files only: no guest action, SSH, credential read or visual verdict. The
operator proves native UAC activation/cancellation separately. capture-local
owns the existing HEAD/target-SHA gate and provenance stamp and names this
deployment explicitly as --target deployment:<deployment-id>; comparison and
individual image review remain required.
"""
from __future__ import annotations
import argparse,ast,base64,hashlib,io,json,os,re,stat,sys,uuid
from pathlib import Path
from PIL import Image

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT)not in sys.path:sys.path.insert(0,str(ROOT))
from agent_tools.native_review_source_closure import _Held,generation

FRAME_OWNERS=('windows_vm_deploy.py','windows_vm_deploy_remote.py','windows_vm_instance.py','windows_vm_unattend.py','native_vm_spec.py')


def require(value,reason):
    if not value:raise ValueError(reason)


def pairs(rows):
    value={}
    for key,item in rows:
        require(key not in value,'duplicate JSON field');value[key]=item
    return value


def read(held,path,limit,*,private=True):
    """Bounded no-follow owned-file read, retained through output closure."""
    path=Path(path);parent=held.directory(str(path.parent))
    fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid()and info.st_nlink==1,'unowned evidence file')
        require(not info.st_mode&(0o077 if private else 0o022),'unsafe evidence permissions')
        require(0<info.st_size<=limit,'evidence size bound')
        raw=b''
        while len(raw)<info.st_size:
            chunk=os.read(fd,min(65536,info.st_size-len(raw)));require(chunk,'short evidence read');raw+=chunk
        require(generation(os.fstat(fd))==generation(info),'evidence changed during read')
        return held.read(str(path),hashlib.sha256(raw).hexdigest(),generation(info),max_bytes=limit)
    finally:os.close(fd)


def document(held,path,limit=131072,*,private=True,mapping=True):
    value=json.loads(read(held,path,limit,private=private),object_pairs_hook=pairs)
    require(not mapping or type(value)is dict,'evidence JSON object required');return value


def bindings(raw,names):
    value={}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in names:
            name=node.targets[0].id;require(name not in value,'duplicate caller binding');value[name]=ast.literal_eval(node.value)
    require(set(value)==set(names),'missing caller binding');return value


def collect(root,*,deployment_id,operation_id,journal_id,manifest,scenes,output):
    require(os.name=='posix'and hasattr(os,'O_NOFOLLOW'),'POSIX capture coordinator required')
    root=Path(root).absolute()
    for value in (deployment_id,operation_id):require(type(value)is str and str(uuid.UUID(value))==value,'canonical operation UUID required')
    require(type(journal_id)is str and re.fullmatch('[0-9a-f]{32}',journal_id),'canonical journal ID required')
    require(Path(manifest).absolute()==root/'visual-tests/scenes.json','canonical visual manifest required')
    held=_Held()
    try:
        require(document(held,Path(scenes).absolute(),private=False,mapping=False)==['windows-uac'],'only windows-uac may be collected')
        inventory=document(held,Path(manifest),private=False)
        scene=[s for s in inventory['scenes']if s.get('id')=='windows-uac']
        require(len(scene)==1 and scene[0].get('geometry_required')is False and 'windows'in scene[0]['platforms'],'native Windows UAC scene required')
        intent=document(held,root/'.rag_index/windows-vm-deploy-intents'/(deployment_id+'.intent.json'))
        require(set(intent)=={'spec','setup','context','correlationId','mode','callerSha256'}and intent['mode']=='start','original deployment intent required')
        require(intent['spec']['deploymentId']==deployment_id and re.fullmatch('[0-9a-f]{32}',intent['correlationId']),'deployment identity mismatch')
        require(set(intent['setup'])=={'imageName','locale','user','administrator','purpose'}and intent['setup']['purpose']=='windowsUacVisual'and intent['setup']['locale']=='en-US','qualified visual-purpose deployment required')
        original=root/'.runtime/windows-vm-deploy'/intent['correlationId']/'caller.py'
        source=read(held,original,8*1024**2)
        require(hashlib.sha256(source).hexdigest()==intent['callerSha256'],'original start caller changed')
        wanted={'SPEC':intent['spec'],'SETUP':intent['setup'],'CONTEXT':intent['context'],'MODE':'start'}
        require(bindings(source,wanted)==wanted,'original start context mismatch')

        journal=root/'.runtime/windows-vm-deploy'/journal_id
        request=document(held,journal/'request.json')
        require(set(request)=={'spec','mode','correlationId','callerSha256'}and request['correlationId']==journal_id
                and request['mode']in ('frame','frame-collect')and request['spec']==intent['spec'],'original frame request mismatch')
        caller=read(held,journal/'caller.py',8*1024**2)
        require(hashlib.sha256(caller).hexdigest()==request['callerSha256'],'frame caller changed')
        expected={**{k:wanted[k]for k in ('SPEC','SETUP','CONTEXT')},'OPERATION_ID':operation_id,
            'LEAF':'setup-frame-'+uuid.UUID(operation_id).hex+'.png','PROBE':False,'RETURN_FRAME':True,
            'READ_EXISTING':request['mode']=='frame-collect','FRAME_INPUT':None}
        require(bindings(caller,expected)==expected,'frame operation/context mismatch')
        require(document(held,journal/'closing.json')=={'sourceClosing':True,'correlationId':journal_id},'frame source closing missing')
        terminal=document(held,journal/'native-terminal.json')
        require(terminal.get('complete')is True and type(terminal.get('returnCode'))is int and terminal['returnCode']==0
                and terminal.get('timeout')is False and terminal.get('overflow')is False and terminal.get('sendError')is None
                and terminal.get('eof')=={'stdout':True,'stderr':True},'original frame transport is incomplete')

        capsule=document(held,journal/'sources/manifest.json')
        require(capsule.get('schemaVersion')==1 and capsule.get('sourceClosingBeforeTransfer')is True
                and type(capsule.get('sources'))is list and 1<=len(capsule['sources'])<=64,'frame source capsule required')
        rows={r['name']:r for r in capsule['sources']}
        require(len(rows)==len(capsule['sources']),'duplicate captured source')
        for name in (*FRAME_OWNERS,'caller.py'):
            require(name in rows,'frame source owner missing');row=rows[name]
            origin=journal/'caller.py'if name=='caller.py'else root/'agent_tools'/name
            require(row['sourcePath']==str(origin),'frame source origin mismatch')
            raw=read(held,journal/'sources'/name,8*1024**2)
            require(type(row['bytes'])is int and len(raw)==row['bytes']and hashlib.sha256(raw).hexdigest()==row['sha256'],'captured frame source changed')
            require(read(held,origin,8*1024**2,private=name=='caller.py')==raw,'frame source differs from current owner')

        native=document(held,journal/'native-result.json',5*1024**2)
        require(native.get('state')=='observed','original native frame is unknown')
        capture=native.get('capture',{})
        require(type(capture)is dict and type(capture.get('eof'))is dict,'original native capture object required');eof=capture['eof']
        require(capture.get('complete')is True and type(capture.get('returnCode'))is int and capture['returnCode']==0
                and capture.get('timeout')is False and capture.get('refusal')is None
                and set(eof)in ({'stdout','tty'},{'stdout','stderr'})and all(v is True for v in eof.values()),'original inner frame transport is incomplete')
        frame=native['result']
        require(type(frame)is dict and set(frame)=={'engineeringOnly','state','deploymentId','operationId','frame','bytes','sha256','base64','nativeActionAllowed','replayAllowed'}
                and frame['engineeringOnly']is True and frame['state']=='frame-read-observed'
                and frame['deploymentId']==deployment_id and frame['operationId']==operation_id
                and frame['frame']==expected['LEAF']and frame['nativeActionAllowed']is False and frame['replayAllowed']is False
                and type(frame['bytes'])is int and 0<frame['bytes']<=3*1024**2,'canonical frame result required')
        raw=read(held,journal/'frame.png',3*1024**2)
        require(len(raw)==frame['bytes']and hashlib.sha256(raw).hexdigest()==frame['sha256']
                and base64.b64decode(frame['base64'],validate=True)==raw,'original frame bytes mismatch')
        with Image.open(io.BytesIO(raw))as image:
            require(image.format=='PNG'and image.size==(1280,800),'full-screen 1280x800 PNG required');image.load()
        held.finish()
        output=Path(output).absolute();parent=held.directory(str(output));path=output/'windows-uac.png'
        try:fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        except FileExistsError:require(read(held,path,3*1024**2)==raw,'existing output belongs to another capture')
        else:
            try:
                offset=0
                while offset<len(raw):
                    count=os.write(fd,raw[offset:]);require(count>0,'short output write');offset+=count
                os.fsync(fd)
            finally:os.close(fd)
            require(read(held,path,3*1024**2)==raw,'copied frame changed')
        held.finish()
        return {'deploymentId':deployment_id,'operationId':operation_id,'journalId':journal_id,'sha256':frame['sha256'],'bytes':len(raw),'visualReviewRequired':True}
    finally:held.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment-id',required=True);parser.add_argument('--operation-id',required=True);parser.add_argument('--journal-id',required=True)
    parser.add_argument('--platform',required=True,choices=('windows',));parser.add_argument('--target',required=True);parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--scenes',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        require(args.target=='deployment:'+args.deployment_id,'explicit deployment target mismatch')
        collect(ROOT,deployment_id=args.deployment_id,operation_id=args.operation_id,journal_id=args.journal_id,manifest=args.manifest,scenes=args.scenes,output=args.output)
    except (OSError,ValueError,KeyError,TypeError)as error:
        print('Remote Windows frame collection refused: '+str(error),file=sys.stderr);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
