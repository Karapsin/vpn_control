"""DIRECT inventory retention regression; own TempFS and explicit inert transport seams."""
from pathlib import Path
import errno,importlib.util,json,os,tempfile,unittest
from unittest import mock
from agent_tools import ssh_direct_nested_channel as canonical_direct
COORDINATOR_CAPABLE=canonical_direct.coordinator_capable()
if COORDINATOR_CAPABLE:
    from agent_tools import private_inventory_lock as private
    _CONTEXT=Path(__file__).parent/'fixtures'/'ssh_direct_inventory_diagnostic'/'backend_context.py'
    _spec=importlib.util.spec_from_file_location('inventory_diagnostic_public_context',_CONTEXT)
    ctx=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(ctx)

@unittest.skipUnless(COORDINATOR_CAPABLE,'POSIX private inventory descriptors required')
class DirectInventoryDiagnosticTests(unittest.TestCase):
    source_before=False
    def setUp(self):self.opening=ctx.fd_count()
    def tearDown(self):self.assertEqual(ctx.fd_count(),self.opening,'owned parent or leaf FD leaked')
    def test_direct_status_forwards_actual_missing_config_classification(self):
        provider=ctx.fixed_module('direct_before.py') if self.source_before else canonical_direct
        events=[]
        with tempfile.TemporaryDirectory() as name:
            with mock.patch.object(ctx.channel,'_collect',side_effect=AssertionError('forbidden transport')):
                try:result=provider.status(Path(name),ctx.channel.HOST,ctx.CORR,_private_inventory_diagnostic=events.append)
                except TypeError:result={'state':'unknown'}
        self.assertEqual(result['state'],'unknown')
        self.assertEqual(len(events),1,'DIRECT status discarded existing inventory diagnostic hook')
        self.assertEqual(events[0]['exceptionClass'],'FileNotFoundError')
        self.assertEqual(events[0]['role'],'config_snapshot')
        self.assertEqual(events[0]['errno'],errno.ENOENT)

    def test_whole_retained_builder_preserves_actual_missing_inventory_event(self):
        with tempfile.TemporaryDirectory() as name,ctx.context(Path(name),self.source_before) as c:
            result=c.refused_route()
            self.assertEqual(result['state'],'unknown')
            self.assertEqual(result['failurePhase'],'inventory')
            event_path=c.capture.path/'selected-inventory-finite.json'
            self.assertTrue(event_path.is_file(),'original legacy-only hook lost DIRECT inventory failure')
            record=c.capture.json(event_path.name);event=record['event']
            self.assertEqual(event['exceptionClass'],'FileNotFoundError')
            self.assertEqual(event['role'],'config_snapshot')
            self.assertEqual(event['errno'],errno.ENOENT)
            self.assertFalse(record['nativeActionAllowed']);self.assertFalse(record['replayAllowed'])
            self.assertNotIn('path',event);self.assertNotIn('message',event)
            self.assertLessEqual(event_path.stat().st_size,1024)
            self.assertTrue(c.capture.json('selected-status-finite.json')['inventoryDiagnosticRetained'])
            self.assertGreater(c.source_checks,0)

    def test_actual_busy_flock_is_classified_without_promoting_unknown(self):
        with tempfile.TemporaryDirectory() as name,ctx.context(Path(name)) as c:
            ctx.configured(c.root)
            with private.ownership(c.root) as (presented,directory,lock):
                result=c.refused_route();lock.guard();directory.guard();presented.guard()
            self.assertEqual(result['state'],'unknown')
            event=c.capture.json('selected-inventory-finite.json')['event']
            self.assertEqual(event['role'],'ownership_lock_acquisition')
            self.assertEqual(event['exceptionClass'],'BlockingIOError')
            self.assertEqual(event['inventoryOperation'],'config_lock_flock_nonblocking')
            self.assertIn(event['errno'],{errno.EAGAIN,errno.EWOULDBLOCK})
            self.assertFalse(event['authority'])

    def test_actual_mode_refusal_never_serializes_config_or_exception_text(self):
        with tempfile.TemporaryDirectory() as name,ctx.context(Path(name)) as c:
            ctx.configured(c.root,0o640);result=c.refused_route()
            event=c.capture.json('selected-inventory-finite.json')['event']
            self.assertEqual(result['state'],'unknown')
            self.assertEqual(event['exceptionClass'],'ValueError')
            self.assertEqual(event['role'],'config_snapshot')
            self.assertNotIn(b'harmlessPublicFixture',b''.join(c.capture.bodies().values()))
            self.assertNotIn('message',event);self.assertNotIn('args',event);self.assertNotIn('path',event)

    def test_publication_denial_preserves_original_unknown_and_reports_secondary_failure(self):
        with tempfile.TemporaryDirectory() as name,ctx.context(Path(name)) as c:
            c.capture.fail_inventory=True;result=c.refused_route()
            self.assertEqual(result['state'],'unknown')
            self.assertFalse((c.capture.path/'selected-inventory-finite.json').exists())
            finite=c.capture.json('selected-status-finite.json')
            self.assertFalse(finite['inventoryDiagnosticRetained'])
            self.assertEqual(finite['inventoryDiagnosticPublicationFailureClass'],'OSError')
            self.assertFalse(finite['nativeActionAllowed'])

    def test_invalid_diagnostic_payload_refuses_without_private_field_leak(self):
        with tempfile.TemporaryDirectory() as name,ctx.context(Path(name)) as c:
            original=ctx.replacement_status(c.provider,"""def status(root,host,corr,*,_private_capture=None,_private_inventory_diagnostic=None):
 try:_private_inventory_diagnostic({'path':'harmless secret sentinel','message':'never forward'})
 except ValueError:pass
 return {'state':'unknown','failurePhase':'inventory','nativeActionAllowed':False,'replayAllowed':False}
""")
            c.originals=(c.originals[0],c.provider.status,c.originals[2])
            try:
                result=c.build(lambda _:c.provider.status(c.root,ctx.channel.HOST,ctx.CORR))
                finite=c.capture.json('selected-status-finite.json')
                self.assertEqual(result['state'],'unknown')
                self.assertFalse(finite['inventoryDiagnosticRetained'])
                self.assertEqual(finite['inventoryDiagnosticPublicationFailureClass'],'ValueError')
                self.assertNotIn(b'harmless secret sentinel',b''.join(c.capture.bodies().values()))
            finally:c.provider.status=original;c.originals=(c.originals[0],original,c.originals[2])

    def test_direct_route_serialization_and_receipt_guard_are_unchanged(self):
        before=ctx.fixed_module('direct_before.py');after=ctx.fixed_module('direct_after.py');results=[]
        source="""def status(root,host,corr):
 return {'state':'ready','receiptSha256':'b'*64,'outerAuthoritySha256':'c'*64}
"""
        for provider in (before,after):
            ctx.replacement_status(provider,source)
            results.append(provider.route_options(Path('.'),ctx.channel.HOST,ctx.CORR,ctx.RECEIPT))
            with self.assertRaises(ValueError):provider.route_options(Path('.'),ctx.channel.HOST,ctx.CORR,'d'*64)
        self.assertEqual(results[0],results[1])
        self.assertEqual(results[0]['transportMode'],'direct')
        self.assertEqual(results[0]['outerOptions'],canonical_direct.OUTER_OPTIONS)
        self.assertEqual(results[0]['innerOptions'][0:2],('-S','/tmp/vpn-channel-'+ctx.CORR+'/m'))

    def test_legacy_raw_and_public_serialization_remain_byte_identical(self):
        all_bodies=[]
        for before in (True,False):
            with tempfile.TemporaryDirectory() as name,ctx.context(Path(name),before) as c:
                old=ctx.replacement_status(ctx.channel,"""def status(root,host,corr,*,_private_capture=None,_private_inventory_diagnostic=None):
 if _private_capture is not None:_private_capture({'stdout':b'public fixture output','stderr':b'','counts':{'stdout':21,'stderr':0},'eof':{'stdout':True,'stderr':True},'returnCode':0,'complete':True,'overflow':False,'timeout':False,'readError':False})
 return {'state':'ready','receiptSha256':'b'*64}
""")
                c.originals=(ctx.channel.status,c.originals[1],c.originals[2])
                try:
                    result=c.build(lambda _:ctx.channel.status(c.root,ctx.channel.HOST,ctx.CORR))
                    self.assertEqual(result['state'],'ready')
                    bodies=c.capture.bodies()
                    # Fresh capture generations are independently authenticated,
                    # while payload and manifest structure must remain exact.
                    for stream in ('stdout','stderr'):
                        manifest_name='selected-status-'+stream+'-manifest.json'
                        manifest=json.loads(bodies[manifest_name])
                        payload=b''.join(bodies[row['name']] for row in manifest['chunks'])
                        self.assertEqual(manifest['bytes'],len(payload))
                        self.assertEqual(manifest['sha256'],ctx.hashlib.sha256(payload).hexdigest())
                        for row in manifest['chunks']:
                            self.assertEqual(set(row),{'name','pin'})
                            self.assertEqual(set(row['pin']),{'generation','sha256'})
                            path=c.capture.path/row['name']
                            self.assertEqual(row['pin']['generation'],ctx.generation(path.stat()))
                            self.assertEqual(row['pin']['sha256'],ctx.hashlib.sha256(bodies[row['name']]).hexdigest())
                            row['pin']['generation']=['authenticated-fresh-capture-generation']
                        bodies[manifest_name]=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
                    all_bodies.append(bodies)
                finally:ctx.channel.status=old;c.originals=(old,c.originals[1],c.originals[2])
        self.assertEqual(all_bodies[0],all_bodies[1])
        self.assertNotIn('selected-inventory-finite.json',all_bodies[1])

    def test_foreign_correlation_refuses_and_restores_both_providers(self):
        with tempfile.TemporaryDirectory() as name,ctx.context(Path(name)) as c:
            with self.assertRaisesRegex(ValueError,'route_capture_query_binding'):
                c.build(lambda _:c.provider.status(c.root,ctx.channel.HOST,'d'*32))
            self.assertEqual(c.capture.bodies(),{})


_IMPORT_DISCOVERY_SOURCE="import builtins,json,sys,unittest\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\n# The stdlib test bootstrap may load these on a POSIX host.\n# Remove them before testing the genuinely unavailable-module context.\npreloaded=[name for name in ('fcntl','pwd') if name in sys.modules]\nfor name in ('fcntl','pwd'):sys.modules.pop(name,None)\noriginal=builtins.__import__;blocked=[]\ndef guarded(name,*args,**kwargs):\n    if name.split('.')[0] in ('fcntl','pwd'):\n        blocked.append(name);raise ImportError('POSIX dependency forbidden by isolated control')\n    return original(name,*args,**kwargs)\nbuiltins.__import__=guarded\nfrom agent_tools import ssh_direct_nested_channel as direct\ndirect.coordinator_capable=lambda:False\ndef unopened():raise AssertionError('unsupported import opened private dependencies')\ndirect._dependencies=unopened\nbootstrap_blocked=list(blocked);blocked.clear()\npath=Path(sys.argv[2]);loader=unittest.TestLoader()\nsuite=loader.discover(str(path.parent),pattern=path.name)\ndef leaves(node):\n    for child in node:\n        if isinstance(child,unittest.TestSuite):yield from leaves(child)\n        else:yield child\ncases=list(leaves(suite));failed=[case for case in cases if isinstance(case,unittest.loader._FailedTest)]\nif failed:\n    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(failed))\n    print(json.dumps({'preloadedPosixModules':preloaded,'bootstrapBlocked':bootstrap_blocked,'blocked':blocked,'discoveryErrors':len(result.errors),'cases':len(cases)}));sys.exit(1)\nposix=[case for case in cases if type(case).__name__=='DirectInventoryDiagnosticTests']\nassert len(posix)==9 and all(getattr(type(case),'__unittest_skip__',False) for case in posix)\nresult=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(posix))\nassert result.testsRun==9 and len(result.skipped)==9 and not result.errors and not result.failures\nassert blocked==[]\nassert 'fcntl' not in sys.modules and 'pwd' not in sys.modules\nprint(json.dumps({'preloadedPosixModules':preloaded,'bootstrapBlocked':bootstrap_blocked,'blocked':blocked,'discoveredCases':len(cases),'runPosixCases':result.testsRun,'skips':len(result.skipped),'privateDependenciesOpened':False,'posixModulesAbsent':True}))\n"

class PortableInventoryImportTests(unittest.TestCase):
    def test_unsupported_import_and_discovery_skip_before_posix_dependencies(self):
        import subprocess,sys
        result=subprocess.run([sys.executable,'-I','-B','-c',_IMPORT_DISCOVERY_SOURCE,
            str(Path(canonical_direct.__file__).parent.parent),str(Path(__file__).absolute())],
            capture_output=True,text=True,timeout=15,check=False)
        self.assertEqual(result.returncode,0,result.stderr)
        record=json.loads(result.stdout)
        self.assertEqual(record['blocked'],[])
        self.assertEqual(record['runPosixCases'],9)
        self.assertEqual(record['skips'],9)
        self.assertFalse(record['privateDependenciesOpened'])
        self.assertTrue(record['posixModulesAbsent'])

if __name__=='__main__':unittest.main()
