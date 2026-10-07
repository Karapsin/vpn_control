"""Portable complete context entry over owned files and recorded public fixtures.

Current remote authority APIs have explicit NoNetwork seams. Historical terminal
validation, source/FD custody, current producer and all six builders execute their
actual implementations. This fixture grants no current guest admission.
"""
import ast,base64,gzip,hashlib,json,os,tempfile,sys,zipfile
from pathlib import Path
from types import ModuleType,SimpleNamespace as S
from unittest.mock import patch
from contextlib import contextmanager
from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
from agent_tools import windows_cp117_base_source_refresh as worker
from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests

HERE=Path(__file__).resolve().parent

def exercise(*, old_guard=False,tamper=False,late_unlink=False,old_closure=False):
    from agent_tools.tests.test_windows_cp117_public_update_flow import PublicConcreteBuilderTests,PublicSavedRecordAdmissionTests,PublicHistoricalStageCompositionTests
    provenance=json.loads((HERE/'provenance.json').read_bytes());bodies={}
    for name,pin in provenance['inputs'].items():
        raw=(HERE/name).read_bytes()
        if len(raw)!=pin['size']or hashlib.sha256(raw).hexdigest()!=pin['sha256']:raise ValueError('whole-context-fixture-source')
        bodies[name]=raw
    seed,_=PublicConcreteBuilderTests().context();repo=HERE.parents[3]
    with tempfile.TemporaryDirectory()as directory:
        root=Path(directory).resolve();base=root/'.runtime/parity-evidence';base.mkdir(parents=True);caps=[];history={}
        def cap(name):
            (base/name).mkdir(mode=0o700);c=AuthorityCapture(root,name);caps.append(c);return c
        def put(c,name,raw):
            p=c.create(name,raw);history[str(c.path/name)]=p;return p
        callers=cap('public-callers');entry=callers.path/'old-context.py';put(callers,entry.name,bodies['original-context-caller.source'])
        module=ModuleType('public_whole_context_fixture');module.__file__=str(entry);sys.modules[module.__name__]=module
        ns=module.__dict__
        try:
            exec(compile(bodies['original-context-caller.source'],str(entry),'exec'),ns)
            exec(compile(bodies['old-context.source']if old_closure else bodies['current-context.source'],'<actual-current-context>','exec'),ns)
            if old_guard:
                tree=ast.parse(bodies['current-context.source']);prepare=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='prepare_public_context');guard=next(n for n in prepare.body if isinstance(n,ast.If));guard.test.values[1].comparators[0]=ast.Name(id='TEST_SHA',ctx=ast.Load());guard.test.values[2].comparators[0]=ast.Name(id='READ_BINDING_TEST_SHA',ctx=ast.Load());exec(compile(ast.fix_missing_locations(ast.Module(body=[prepare],type_ignores=[])),'<actual-historical-guard>','exec'),ns)
            archive=root/'.runtime/parity-evidence/windows-public-context-testpin-successor';archive.mkdir(mode=0o700)
            for source,dest in [('original-base-test.source','original-base-test-ec314.source'),('original-server-test.source','original-server-test-f6d09.source')]:
                p=archive/dest;p.write_bytes(bodies[source]);p.chmod(0o600)
            (root/'agent_tools/tests').mkdir(parents=True)
            for name in ('test_windows_cp117_base_source_refresh.py','test_windows_cp117_server_preflight.py'):
                (root/'agent_tools/tests'/name).write_bytes((repo/'agent_tools/tests'/name).read_bytes())
            original_stage=cap('public-original-stage');prior=callers.path/'stage-caller.py';put(callers,prior.name,bodies['original-stage-caller.source'])
            oldvalue=json.loads(bodies['original-stage-result.json']);corr=oldvalue['events'][0]['event']['diagnosticId']
            for index,item in enumerate(oldvalue['events']):item['pin']=put(original_stage,corr+'-event-%d.json'%index,json.dumps(item['event'],sort_keys=True).encode())
            put(original_stage,'result.json',json.dumps(oldvalue,sort_keys=True).encode());put(original_stage,'remote.py',bodies['original-stage-remote.source']);put(original_stage,'exit.json',bodies['original-stage-exit.json'])
            record=ScreenTests().record();record['result']['qemu']=oldvalue['result']['qemu']
            original=cap('windows-cp117-recovery-public-fixture');originalpin=put(original,'record.json',json.dumps(record,sort_keys=True).encode())
            tls=cap('windows-direct-fixture-tls-bb2e85e5-4281-4f70-b70e-618f5604093b');tls_public={'fileSha256':{'public-fixture':'0'*64}};put(tls,'request.json',json.dumps({'tlsPublic':tls_public}).encode())
            source_module=callers.path/'fixture-source.py';put(callers,source_module.name,b'# inert public source fixture\n')
            fixture_receipt={'manifest':ns['SERVER_MANIFEST']};bundle=root/'public-fixture.zip'
            with zipfile.ZipFile(bundle,'w')as z:
                z.writestr('server/prepare_desktop_update_fixture.py',bodies['fixture-script.source']);z.writestr('fixture-receipt.json',json.dumps(fixture_receipt))
            bundle.chmod(0o600);bundle_raw=bundle.read_bytes()
            actual_r=worker.installed.precise.owner.guest.recovery
            # NoNetwork replacements provide only owned local source checks, never
            # fake a live route, token, package or current guest admission.
            outer={'scope':'NoNetwork-owned-source-only','currentVmAdmission':False}
            def verify_outer(_root,value):
                if value['outerAuthority']!=outer:raise ValueError('whole-context-outer-fixture')
            authority=S(_read_bound_file=actual_r.authority._read_bound_file,_outer_authority=lambda _:outer,_verify_outer=verify_outer,closure=S(base=S(__file__=actual_r.authority.closure.base.__file__,_descriptor=lambda _:(None,None,None),ssh_transport=S(build_ssh_argv=lambda *a,**kw:(_ for _ in ()).throw(AssertionError('GUEST_CHILD_FORBIDDEN'))))))
            r=S(authority=authority,CORRELATION='public-fixture',HOST='NoNetwork',_local_read=actual_r._local_read,_validate_frame=actual_r._validate_frame)
            guest=S(recovery=r,__file__=worker.installed.precise.owner.guest.__file__,ORIGINAL={'name':'record.json','pin':originalpin})
            precise=S(__file__=worker.installed.precise.__file__,owner=S(guest=guest))
            installed=S(__file__=worker.installed.__file__,precise=precise,public=worker.installed.public,pair=lambda _:worker.PAIR_EXPECTED,program_current=worker.installed.program_current)
            flow=S(__file__=worker.installed.precise.flow.__file__,_execution_source_proof=lambda *_:{'scope':'owned-record-source','nativeAdmission':False})
            ns.update(installed=installed,worker=worker,flow=flow,HISTORY=history,PRIOR_LEAF=original_stage.path.name,PRIOR_CALLER=str(prior),STAGE_MODULE_PATH=str(source_module),BUNDLE_PATH=str(bundle),BUNDLE_SIZE=len(bundle_raw),BUNDLE_SHA=hashlib.sha256(bundle_raw).hexdigest(),MEMBERS={'server/prepare_desktop_update_fixture.py':hashlib.sha256(bodies['fixture-script.source']).hexdigest()},successor_stage_proof=lambda _:PublicHistoricalStageCompositionTests().exercise(),server_tls_prior=lambda *args:{'credentialHashes':tls_public['fileSha256']})
            if tamper:(archive/'original-base-test-ec314.source').write_bytes(b'FOREIGN_SOURCE=True\n')
            with patch('os.getcwd',return_value=str(root)),patch('subprocess.Popen',side_effect=AssertionError('GUEST_CHILD_FORBIDDEN')):
                context=ns['prepare_public_context']()
                try:
                    if late_unlink:
                        import inspect
                        target=archive/'original-base-test-ec314.source';original_lstat=Path.lstat;seen=[]
                        def late(path,*args,**kwargs):
                            value=original_lstat(path,*args,**kwargs);caller=inspect.currentframe().f_back
                            if path==archive and caller.f_code.co_name=='verify'and 'pfd'in caller.f_locals and target.exists():
                                target.unlink();seen.append('after-parent-lstat')
                            return value
                        with patch.object(Path,'lstat',late):context['verify']()
                        return {'namedExists':target.exists(),'seam':seen,'nativeAdmission':False}
                    if context['original_source']!=installed.program_current(record,worker.PAIR_EXPECTED)[0]:raise ValueError('whole-context-current-producer')
                    context.update({key:value for key,value in seed.items()if key not in ('original_source','qemu')})
                    # The context return producer is checked before test seed data
                    # is attached; the seed contains only immutable phase assets.
                    builders_ns={};exec(gzip.decompress(base64.b64decode(__import__('agent_tools.tests.test_windows_cp117_public_update_flow',fromlist=['PUBLIC_BUILDERS_GZIP']).PUBLIC_BUILDERS_GZIP)),builders_ns);builders=builders_ns['make_builders'](context)
                    _,submission,_=PublicSavedRecordAdmissionTests().fixture();submission.update(taskSha256=hashlib.sha256(context['assets']['public-task.draft.ps1'].encode()).hexdigest(),imageSha256=hashlib.sha256(context['assets']['target-image.input.json'].encode()).hexdigest(),role='SYSTEM',taskActor='S-1-5-21-2404255130-2183793310-3766671872-1002',taskRunLevel='Limited')
                    binding={'jobId':'00000000-0000-4000-8000-000000000001','owner':{'pid':1234,'birth':'134357366809483508'},'requestedHelper':{'path':r'C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-install-helper.exe','sha256':'ea6043aff284850be3a7cb9ff28f179743fc0a4e1a2c7f58107b09f619e38921'},'records':[]};count=0
                    for phase,kwargs in [('preflight',{}),('public-start',{}),('authorization-read',{'submission':submission}),('terminal-read',{'submission':submission}),('consent-observe',{'binding':binding}),('post-consent',{'binding':binding,'adminSid':'S-1-5-21-1-2-3-1004'})]:
                        context['current_phase']=phase;packet=builders[phase](context,**kwargs);compile(packet['source'],phase,'exec');context['verify']();count+=1
                    return {'scope':'owned-TempFS-NoNetwork','builders':count,'guestSubmissionAttempted':False,'nativeAdmission':False}
                finally:context['close']()
        finally:
            for c in reversed(caps):c.close()
            sys.modules.pop(module.__name__,None)
