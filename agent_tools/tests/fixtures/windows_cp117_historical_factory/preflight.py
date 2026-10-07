"""Whole historical main over owned TempFS; no host history/native authority.

Protocol seams supply synthetic admission DTOs at existing authority APIs. All
source guards, named/held bundle guards, raw capture, programme factories,
command/frame caps and consume-before-dispatch flow remain actual code.
"""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import uuid


def run(case, fixture):
    from agent_tools import windows_cp117_base_source_refresh as worker
    identifier=str(uuid.uuid4()); nonce=str(uuid.uuid4()); barriers=[]
    with tempfile.TemporaryDirectory(prefix='cp117-public-whole-main-') as td:
        root=Path(td).resolve(); (root/'.runtime/parity-evidence').mkdir(parents=True)
        test=root/'agent_tools/tests/test_windows_cp117_base_source_refresh.py'
        test.parent.mkdir(parents=True); test.write_bytes(Path(fixture.__file__).read_bytes())
        source=(fixture.DIRECT_FIXTURE_TRANSFER_FACTORY_SOURCE+'\nHELPER_SHA='
                +repr(hashlib.sha256(Path(worker.__file__).read_bytes()).hexdigest())
                +'\nTEST_SHA='+repr(hashlib.sha256(test.read_bytes()).hexdigest())
                +'\n'+fixture.DIRECT_FIXTURE_TRANSFER_MAIN_SOURCE+'\n')
        caller=root/'preflight.py'; caller.write_text(source); caller.chmod(0o600)
        ns={'__name__':'synthetic_no_child_preflight','__file__':str(caller)}
        exec(compile(source,str(caller),'exec'),ns)
        ns['DOWNLOAD_CORRELATION']=identifier; ns['DOWNLOAD_NONCE']=nonce
        # Own harmless bundle and all historical body bytes; none are native receipts.
        bundle=b'public synthetic fixture ZIP protocol bytes'
        ns['BUNDLE_SHA']=hashlib.sha256(bundle).hexdigest(); ns['BUNDLE_SIZE']=len(bundle)
        path=root/'bundle.bin'; path.write_bytes(bundle); path.chmod(0o600); ns['BUNDLE_PATH']=str(path)
        bodies={'HOST_RESULT':{'result':{'state':'staged','sha256':ns['BUNDLE_SHA'],'length':len(bundle)},
                             **{k:False for k in ('guestExecution','installerAction','taskAction','runtimeAction','replayAllowed')}},
                'BASELINE':{'syntheticProtocol':True}, 'MANIFEST':{'syntheticProtocol':True}}
        for name,body in bodies.items():
            p=root/(name.lower()+'.json'); raw=json.dumps(body).encode(); p.write_bytes(raw); p.chmod(0o600)
            ns[name+'_PATH']=str(p); ns[name+'_SHA']=hashlib.sha256(raw).hexdigest()
        record=fixture.DirectRecoveredGenerationTests().actual_record()
        (root/'.runtime/parity-evidence'/('windows-cp117-recovery-'+ns['installed'].precise.owner.guest.recovery.CORRELATION)).mkdir(mode=0o700)
        raw=json.dumps(record).encode(); r=ns['installed'].precise.owner.guest.recovery
        pair={'syntheticProtocol':True}; execution={'syntheticProtocol':True}; outer={'syntheticProtocol':True}
        # Only declared source files or owned TempFS can reach actual bound reader.
        original_bound=r.authority._read_bound_file
        public={Path(m.__file__).resolve() for m in (worker,ns['transfer'],ns['installed'],ns['installed'].precise,
                ns['installed'].public,ns['installed'].precise.owner,ns['flow'],ns['installed'].precise.owner.guest,r.authority.closure.base)}
        def bound(path,*args,**kwargs):
            p=Path(path).resolve()
            if p not in public and not p.is_relative_to(root):
                raise AssertionError('outside-public-tempfs-source:'+p.name)
            return original_bound(path,*args,**kwargs)
        def local_read(capture,name,pin):
            if name == ns['installed'].precise.owner.guest.ORIGINAL['name']:
                return raw
            for index,item in enumerate(record['authority']):
                if name == 'authority-%d.json'%index:
                    return json.dumps(item['frame']).encode()
            raise AssertionError('unknown-synthetic-record')
        def no_child(argv,route,capture,guard,frame):
            guard(); barriers.append({'argvCount':len(argv),'frameBytes':len(frame),'routeBytes':len(route.getvalue())})
            raise RuntimeError('LOCAL_NO_CHILD_PREFLIGHT')
        ns['listener_collect']=no_child
        with ExitStack() as stack:
            for obj,name,value in ((Path,'cwd',lambda:root),(r.authority,'_read_bound_file',bound),
                    (r,'_local_read',local_read),(ns['installed'],'pair',lambda root:pair),
                    (ns['flow'],'_execution_source_proof',lambda root,record:execution),
                    (r.authority,'_outer_authority',lambda root:outer),
                    (r.authority,'_verify_outer',lambda root,proof:case.assertEqual(proof,{'outerAuthority':outer})),
                    (r.authority.closure.base,'_descriptor',lambda root:({'syntheticProtocol':True},None,None)),
                    (r.authority.closure.base.ssh_transport,'build_ssh_argv',lambda config,host,timeout,command:('synthetic-no-native',*command))):
                stack.enter_context(patch.object(obj,name,value))
            stack.enter_context(patch('subprocess.Popen',side_effect=AssertionError('NO_NATIVE_CHILD')))
            result=ns['main']()
        case.assertEqual(len(barriers),1,json.loads((root/'.runtime/parity-evidence'/result['evidenceLeaf']/'unknown.json').read_bytes())); case.assertEqual(result['state'],'unknown')
        case.assertFalse(result['installerAction']); case.assertFalse(result['replayAllowed'])
        leaf=root/'.runtime/parity-evidence'/result['evidenceLeaf']
        error=json.loads((leaf/'unknown.json').read_bytes())
        case.assertEqual(error['error'],'LOCAL_NO_CHILD_PREFLIGHT'); case.assertIsNone(error['localObservation'])
        case.assertFalse((leaf/'local-child.json').exists()); case.assertFalse((Path(str(leaf)+'-listener')/'local-child.json').exists())
        case.assertTrue((leaf.parent/(leaf.name+'-listener')/'attempt.json').exists())
