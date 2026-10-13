"""Routine controls for the fixed engineering CLI selector; no native effects."""
import ast
from contextlib import ExitStack
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import android_qualified_cli_observation as qualified
from agent_tools import android_observation as ordinary
from agent_tools import mcp_server as server, ssh_direct_nested_channel as direct, ssh_transport as transport

PROFILE = {"adb": "/approved/adb", "cli": "/configured/vpn-control", "serial": "emulator-5682", "expectedAvd": "vpn-control-parity113-api35", "api": 35}
REMOTE_PATH = Path(qualified.__file__).with_name("android_qualified_cli_remote.source")

def selected_probe():
    source = REMOTE_PATH.read_text()
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "PROBE" for t in n.targets))
    return ast.literal_eval(node.value)

def image_methods(root):
    # Only these actual production methods execute. The sole portability seam
    # substitutes the fixture host UID for the fixed remote UID 1000; there is
    # no transport, native run, source snapshot, authority or product callback.
    tree = ast.parse(selected_probe())
    names = {"gen", "ident", "sha_fd", "hold_parents", "hold_file", "source_closing", "image_closing"}
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    class FixtureUid(ast.NodeTransformer):
        def visit_Constant(self, node):
            return ast.copy_location(ast.Constant(os.getuid()), node) if node.value == 1000 else node
    unit = ast.fix_missing_locations(FixtureUid().visit(ast.Module(body=nodes, type_ignores=[])))
    env = {"os": os, "hashlib": hashlib, "stat": stat, "Path": Path, "IMAGE": root,
           "held": [], "parents": {}, "leaves": {}, "image_files": {}, "image_dirs": {}}
    exec(compile(unit, "authentic-qualified-image-methods", "exec"), env)
    return env

class QualifiedCliSelectorTest(unittest.TestCase):
    def test_fixed_selector_only(self):
        qualified.validate_selection("archlinux", "api35", qualified.SELECTOR, 15)
        for selector in (None, "configured", "/tmp/vpn-control", "sha256-" + "a"*64,
                         {"cli": "/tmp/vpn-control"}, {"qualified": True}, "qualified-d32-fae-2.2.3"):
            with self.subTest(selector=selector), self.assertRaises(qualified.QualifiedCliError):
                qualified.validate_selection("archlinux", "api35", selector, 15)
        for host, device, seconds in (("other", "api35", 15), ("archlinux", "api29", 15),
                                      ("archlinux", "api35", True), ("archlinux", "api35", 60)):
            with self.subTest(host=host, device=device, seconds=seconds), self.assertRaises(qualified.QualifiedCliError):
                qualified.validate_selection(host, device, qualified.SELECTOR, seconds)
    def test_exact_source_and_profile_binding(self):
        source = REMOTE_PATH.read_text(); corr = "c"*32
        bound = qualified._programme(source, PROFILE, corr)
        node = next(n for n in ast.parse(bound).body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "PROBE" for t in n.targets))
        probe = ast.literal_eval(node.value)
        self.assertIn("PROFILE = " + repr(PROFILE), probe)
        self.assertIn("mcp-observe-" + corr, probe)
        for changed in (source + "\n# drift", source.replace("PACKAGE_SHA=", "FOREIGN_SHA=", 1), ""):
            with self.assertRaises(qualified.QualifiedCliError): qualified._programme(changed, PROFILE, corr)
        for key, value in (("api", 29), ("serial", "emulator-5554"), ("expectedAvd", "foreign")):
            with self.assertRaises(qualified.QualifiedCliError): qualified._programme(source, {**PROFILE, key:value}, corr)
        with self.assertRaises(qualified.QualifiedCliError): qualified._programme(source, PROFILE, "../foreign")
    def test_cli_environment_source_drift_refuses(self):
        source = REMOTE_PATH.read_text()
        with mock.patch.object(ordinary,"_canonical_cli_environment_source",return_value="def public_cli_environment(): return 'foreign'"):
            with self.assertRaisesRegex(qualified.QualifiedCliError,"environment source changed"):
                qualified._programme(source,PROFILE,"c"*32)
    def test_complete_projection_uses_canonical_owner_consistency(self):
        actual = json.loads((Path(__file__).parent / "fixtures/android_qualified_cli/direct-result.public.json").read_bytes())["remote"]
        value=qualified._project_observation(actual)
        self.assertEqual((True,"available","consistent"),(value["available"],value["outcome"],value["ownerConsistency"]))
        self.assertEqual(0,value["operations"]["operationCount"])
        changed=copy.deepcopy(actual);changed["arch"]["androidObservation"]["trials"][1]["controllerId"]="foreign-owner"
        value=qualified._project_observation(changed)
        self.assertEqual((False,"unknown","owner_replaced"),(value["available"],value["outcome"],value["reason"]))
        for mutate in (lambda n:n.update(sourceAndImageClosing=False),
                       lambda n:n.update(packageSha256="a"*64),
                       lambda n:n.update(guestMutationPerformed=True),
                       lambda n:n["trials"][1].update(stderrBytes=72,quietContractPassed=False)):
            changed=copy.deepcopy(actual);mutate(changed["arch"]["androidObservation"])
            with self.assertRaises(qualified.QualifiedCliError):qualified._project_observation(changed)

    def test_default_dispatch_compatibility(self):
        configured = types.SimpleNamespace(android_devices={"api35":PROFILE})
        config = types.SimpleNamespace(hosts={"archlinux":configured})
        expected = {"available":True,"outcome":"available","ownerConsistency":"consistent","reason":"ok"}
        with mock.patch.object(transport, "load_config", return_value=config), \
             mock.patch.object(ordinary, "observe", return_value=expected) as old, \
             mock.patch.object(qualified, "observe") as selected:
            value = server._ssh_workflow_impl("android-observe", "archlinux", 15, device="api35")
        old.assert_called_once_with(server.REPO_ROOT, "archlinux", PROFILE, 15)
        selected.assert_not_called()
        self.assertEqual({"tool":"ssh_workflow","ok":True,**expected},value)
    def test_qualified_dispatch_never_invokes_configured_cli(self):
        configured = types.SimpleNamespace(android_devices={"api35":PROFILE})
        config = types.SimpleNamespace(hosts={"archlinux":configured})
        value = {"state":"observed","available":True,"engineeringOnly":True,"productAcceptance":False,"sourceClosing":True}
        with mock.patch.object(transport, "load_config", return_value=config), \
             mock.patch.object(ordinary, "observe", return_value={"available":False,"reason":"wrong_cli_context"}) as wrong, \
             mock.patch.object(qualified, "observe", return_value=value) as selected:
            result = server._ssh_workflow_impl("android-observe", "archlinux", 15,
                        identity={"cliArtifact":qualified.SELECTOR},device="api35")
        selected.assert_called_once_with(server.REPO_ROOT,"archlinux","api35",qualified.SELECTOR,15)
        wrong.assert_not_called()
        self.assertTrue(result["ok"])
        self.assertTrue(result["engineeringOnly"])
        self.assertFalse(result["productAcceptance"])
    def test_untyped_or_extra_identity_refuses_before_observer(self):
        for identity in ({}, {"cliArtifact":qualified.SELECTOR,"cli":"/arbitrary"},
                         {"cliArtifact":qualified.SELECTOR,"authority":True}, []):
            with self.subTest(identity=identity), mock.patch.object(qualified,"observe") as call:
                result = server._ssh_workflow_impl("android-observe","archlinux",15,identity=identity,device="api35")
            self.assertFalse(result["ok"]);call.assert_not_called()
        with mock.patch.object(qualified,"observe") as call:
            result=server._ssh_workflow_impl("android-observe","archlinux",15,
                    identity={"cliArtifact":qualified.SELECTOR},transfer={},device="api35")
        self.assertFalse(result["ok"]);call.assert_not_called()

@unittest.skipUnless(direct.coordinator_capable(), "qualified image custody requires POSIX descriptors")
class QualifiedCliCustodyTest(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve(strict=True); root.chmod(0o700); f = root / "member"; f.write_bytes(b"qualified bytes");f.chmod(0o600)
        env = image_methods(root)
        self.addCleanup(lambda: [os.close(fd) for fd in reversed(env["held"])])
        digest = hashlib.sha256(f.read_bytes()).hexdigest(); pin=env["gen"](f.stat())
        fd=env["hold_file"](f, f.stat().st_size, digest, pin)
        env["image_files"]["member"]=(fd,pin,digest,f.stat().st_size)
        return root,f,env
    def test_whole_qualified_adapter_inert_transport_and_source_closing(self):
        from agent_tools.native_review_source_closure import _Held
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve(strict=True)
        (root / "scripts").mkdir()
        (root / ".runtime").mkdir(mode=0o700)
        helper = Path(ordinary.__file__).resolve().parents[1] / "scripts/android_no_update_tls_preflight.py"
        (root / "scripts/android_no_update_tls_preflight.py").write_bytes(helper.read_bytes())
        target = transport.SshHost(alias="archlinux",host="inert",port=22,user="fixture",identity_file=None,known_hosts_file=None,transport="nested",gateway="pi",
                  password="INERT_FIXTURE_PASSPHRASE",remote_host_alias="inert",android_devices={"api35":PROFILE})
        gateway = transport.SshHost(alias="pi",host="inert",port=22,user="fixture",identity_file=None,known_hosts_file=None)
        config = transport.SshConfig(root=root,hosts={"archlinux":target,"pi":gateway})
        class SourceFixtureGuard:
            def __init__(self, ignored):
                self.held=_Held();self.config=config;self.source_pins={};self.authority={"configSha256":"a"*64};self.closed=False;self.checks=0
            def guard(self):self.held.finish();self.held.final_identity_pass();self.checks+=1
            def close(self):self.held.close();self.closed=True
        instance=SourceFixtureGuard(root)
        native_fixture=json.loads((Path(__file__).parent / "fixtures/android_qualified_cli/direct-result.public.json").read_bytes())["remote"]
        native_fixture.update(fixtureOnly=True,actualAndroidAuthority=False)
        class InertCustody(qualified.OuterCustody):
            def __init__(self, argv):
                # This replaces SSH only. The real retained collector owns the
                # accepted local child, stdin close, bytes/caps and dual EOF.
                corr=__import__("shlex").split(argv[-1])[5]
                reply={**native_fixture,"correlationId":corr}
                code="import sys;sys.stdin.buffer.read(4097);sys.stdout.write("+repr(json.dumps(reply)+"\n")+")"
                super().__init__([sys.executable,"-I","-B","-c",code])
        with mock.patch.object(direct,"Guard",return_value=instance), \
             mock.patch.object(direct,"outer_prefix",return_value=(["inert"],"endpoint")), \
             mock.patch.object(qualified.subprocess,"check_output",return_value="a"*40+"\n"+"a"*40+"\n"), \
             mock.patch.object(qualified,"OuterCustody",InertCustody):
            value=qualified.observe(root,"archlinux","api35",qualified.SELECTOR,15)
        self.assertEqual("observed",value["state"])
        self.assertTrue(value["sourceClosing"]);self.assertTrue(value["holdersClosed"])
        self.assertTrue(value["fixtureOnly"]);self.assertFalse(value["productAcceptance"])
        self.assertTrue(instance.closed);self.assertEqual(2,instance.checks)
        self.assertEqual(qualified.SELECTOR,value["cliArtifact"])
        self.assertTrue((Path(value["recordDirectory"])/"capture.private.json").is_file())

    def test_actual_owned_home_missing_import_before_and_declared_successor(self):
        import pwd
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        home=Path(directory.name).resolve(strict=True);home.chmod(0o700)
        before=(Path(__file__).parent / "fixtures/android_qualified_cli/missing-pwd.before.source").read_text()
        after=REMOTE_PATH.read_text();tree=ast.parse(after)
        nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))
               or isinstance(n,ast.FunctionDef) and n.name in("owned_home_identity","generation")]
        current="\n".join(ast.get_source_segment(after,n)for n in nodes)+"\n"
        before_scope={};after_scope={}
        exec(compile(before,"actual-missing-pwd-before","exec"),before_scope)
        exec(compile(current,"actual-declared-pwd-after","exec"),after_scope)
        with self.assertRaisesRegex(NameError,"pwd"):
            before_scope["owned_home_identity"]("~/inert-key")
        with mock.patch.object(pwd,"getpwuid",return_value=types.SimpleNamespace(pw_dir=str(home))):
            value=after_scope["owned_home_identity"]("~/inert-key")
        self.assertEqual(str(home/"inert-key"),value["path"])
        self.assertEqual(after_scope["generation"](home.stat()),value["homePin"])
        for scope in(before_scope,after_scope):
            with self.assertRaises(ValueError):scope["owned_home_identity"]("~/../foreign-key")

    def test_current_exact_image_closing_passes(self):
        _,_,env=self.fixture();env["source_closing"]();env["image_closing"]()
    def test_file_bytes_and_generation_drift_refuse(self):
        _,f,env=self.fixture();f.write_bytes(b"foreign bytes")
        with self.assertRaisesRegex(ValueError,"asset_file_changed"):env["source_closing"]()
    def test_leaf_replacement_refuses(self):
        _,f,env=self.fixture();replacement=f.with_name("replacement");replacement.write_bytes(f.read_bytes());replacement.chmod(0o600);os.replace(replacement,f)
        with self.assertRaisesRegex(ValueError,"image_file_changed"):env["image_closing"]()
    def test_ancestor_mode_drift_refuses(self):
        root,_,env=self.fixture();root.chmod(0o750)
        with self.assertRaisesRegex(ValueError,"asset_parent_changed"):env["source_closing"]()
    def test_unknown_image_member_refuses(self):
        root,_,env=self.fixture();(root/"unexpected").write_bytes(b"not in image")
        with self.assertRaisesRegex(ValueError,"image_inventory_changed"):env["image_closing"]()
    def test_caller_authored_wrong_hash_and_generation_refuse(self):
        _,f,env=self.fixture();env2=image_methods(f.parent)
        self.addCleanup(lambda: [os.close(fd) for fd in reversed(env2["held"])])
        with self.assertRaisesRegex(ValueError,"asset_hash_changed"):
            env2["hold_file"](f,f.stat().st_size,"a"*64)
        with self.assertRaisesRegex(ValueError,"asset_generation_changed"):
            env2["hold_file"](f,f.stat().st_size,hashlib.sha256(f.read_bytes()).hexdigest(),[0]*9)



"""Whole-consumer same-child late-evidence controls; no native/private inputs."""
import ast
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

@unittest.skipUnless(direct.coordinator_capable(), "late evidence controls require POSIX local collector fixtures")
class FinalCaptureLocalTest(unittest.TestCase):
    # Injected by qualification runner; routine module binds these to its real
    # module and existing inert whole-adapter fixture after integration.
    qualified = None
    base_case_type = None
    def local_case(self, family):
        q=self.qualified;objects=[];writes={}
        original_init=q.OuterCustody.__init__;original_observe=q.OuterCustody.observe;original_retain=q._retain
        def init(obj,argv,*args,**kwargs):
            argv=list(argv);argv[-1]="import time;time.sleep(.06);"+argv[-1]
            if family=="stderr":argv[-1]+=";sys.stderr.write('INERT_LATE_STDERR')"
            original_init(obj,argv,*args,**kwargs);objects.append(obj)
        def retain(directory,name,value):
            if family=="exception" and name=="accepted.private.json":raise OSError("inert accepted-retention refusal")
            writes[name]=value;return original_retain(directory,name,value)
        case=self.base_case_type('test_whole_qualified_adapter_inert_transport_and_source_closing')
        try:
            with mock.patch.object(q.OuterCustody,'__init__',init), \
                 mock.patch.object(q.OuterCustody,'observe',lambda obj,seconds=45:original_observe(obj,.000001)), \
                 mock.patch.object(q,'_retain',retain):
                try:case.test_whole_qualified_adapter_inert_transport_and_source_closing()
                except AssertionError:pass  # positive fixture oracle differs: UNKNOWN must persist here
            self.assertEqual(1,len(objects),'one accepted original only')
            child=objects[0]
            self.assertTrue(child.closed);self.assertEqual(0,child.child.returncode);self.assertTrue(all(child.eof.values()))
            final=writes.get('final-capture.private.json')
            self.assertIsNotNone(final,'actual natural-drain terminal evidence must be appended')
            self.assertTrue(final['complete']);self.assertEqual(0,final['returnCode']);self.assertTrue(all(final['eof'].values()))
            self.assertEqual(child.child.pid,final['pid']);self.assertEqual(child.counts,final['counts'])
            for name in('stdout','stderr'):
                raw=writes.get('outer-final-'+name+'.private')
                self.assertIsNotNone(raw,'same-child final stream must be retained')
                self.assertEqual(bytes(child.raw[name]),raw)
                self.assertEqual(child.counts[name],len(raw))
            terminal=writes.get('final-terminal.private.json');self.assertIsNotNone(terminal)
            self.assertTrue(terminal['sameOriginalChild']);self.assertTrue(terminal['initialOutcomeUnchanged'])
            result=writes['finite-result.public.json'];self.assertEqual('unknown',result['state']);self.assertFalse(result['available']);self.assertFalse(result['replayAllowed'])
            self.assertEqual(final,result['finalCapture'])
            if family!='exception':
                initial=writes['capture.private.json'];self.assertTrue(initial['timeout']);self.assertFalse(initial['complete']);self.assertIsNone(initial['returnCode'])
                self.assertEqual(0,len(writes['outer-stdout.private']));self.assertEqual(0,len(writes['outer-stderr.private']))
                self.assertGreater(len(writes['outer-final-stdout.private']),0)
            else:
                self.assertEqual('OSError',result['errorClass']);self.assertTrue(result['sourceClosing'])
            if family=='stderr':self.assertEqual(b'INERT_LATE_STDERR',writes['outer-final-stderr.private'])
        finally:case.doCleanups()
    def test_local_late_stdout_final_evidence(self):self.local_case('stdout')
    def test_local_late_stderr_final_evidence(self):self.local_case('stderr')
    def test_local_accepted_exception_final_evidence(self):self.local_case('exception')

@unittest.skipUnless(direct.coordinator_capable(), "gateway controls require POSIX PTY fixtures")
class FinalCaptureRemoteTest(unittest.TestCase):
    remote_path = None
    def remote_case(self,family):
        source=self.remote_path.read_text();scope={'__name__':'inert_remote_fixture'}
        exec(compile(source,'actual-fixed-gateway-source','exec'),scope)
        objects=[];initial_snapshots=[]
        real_start=scope['start_fixed'];real_observe=scope['Custody'].observe
        secret=b'INERT_FIXTURE_PASSPHRASE'
        stdout=b'INERT_LATE_STDOUT'
        tty=b'INERT_LATE_STDERR '+secret if family=='stderr'else b''
        script="import sys,time;time.sleep(.06);sys.stdout.buffer.write("+repr(stdout)+");sys.stderr.buffer.write("+repr(tty)+")"
        def start(argv,secret_value,keys):
            c=real_start([sys.executable,'-I','-B','-c',script],secret_value,keys);objects.append(c);return c
        calls=[0]
        def observe(c,seconds):
            calls[0]+=1
            if family=='exception'and calls[0]==1:raise ValueError('inert_after_acceptance')
            result=real_observe(c,.000001);initial_snapshots.append(result);return result
        guard_reads=[0]
        def pin(*a,**kw):
            guard_reads[0]+=1
            if family=='closing'and guard_reads[0]>2:raise ValueError('inert_closing_changed')
            return {'unsupportedConfigDirectives':False,'publicFixture':True}
        class BootPath:
            def __init__(self,*a):pass
            def read_text(self):return 'a'*8+'-'+'b'*4+'-'+'c'*4+'-'+'d'*4+'-'+'e'*12
        scope.update(bounded_envelope=lambda stream:{'passphrase':secret.decode()},file_pin=pin,
                     effective_route=lambda spec:{'keyMetadata':['/inert-key']},Path=BootPath,
                     fixed_inner=lambda *a:['not-used-inert'],start_fixed=start,_DECODED_SOURCE_SHA='a'*64)
        output=io.StringIO();corr='b'*32
        with mock.patch.object(scope['Custody'],'observe',observe), \
             mock.patch.object(sys,'argv',['inert',corr,'/inert-config','fixture','a'*64]), \
             contextlib.redirect_stdout(output):
            code=scope['remote_main']()
        self.assertEqual(1,len(objects),'one accepted gateway child only')
        c=objects[0];self.assertTrue(c.closed);self.assertEqual(0,c.child.returncode);self.assertTrue(all(c.eof.values()))
        try:value=json.loads(output.getvalue())  # whole single JSON envelope, no second frame
        except json.JSONDecodeError:self.fail('Gateway must retain one complete reply frame after natural closing')
        self.assertEqual(3,code);self.assertEqual('unknown',value['state']);self.assertFalse(value['replayAllowed']);self.assertFalse(value['nativeActionAllowed'])
        final=value.get('finalInnerCapture');self.assertIsNotNone(final,'gateway final capture must follow natural drain')
        self.assertEqual(c.child.pid,final['pid']);self.assertTrue(final['complete']);self.assertEqual(0,final['returnCode']);self.assertTrue(all(final['eof'].values()))
        self.assertEqual(c.counts,final['counts']);self.assertTrue(final['timeout'])
        self.assertEqual(initial_snapshots[0],value['innerCapture']);self.assertFalse(value['innerCapture']['complete'])
        initial=value['_operatorPrivateCapture']['initial'];final_raw=value['_operatorPrivateCapture']['final']
        self.assertEqual(0,initial['stdout']['bytes']);self.assertEqual(stdout,base64.b64decode(final_raw['stdout']['base64']))
        if tty:
            masked=tty.replace(secret,b'\0'*len(secret))
            self.assertEqual(masked,base64.b64decode(final_raw['tty']['base64']));self.assertEqual(1,final_raw['tty']['redactions'])
        else:self.assertEqual(0,final_raw['tty']['bytes'])
        if family in('exception','closing'):self.assertEqual('ValueError',value['errorClass'])
    def test_gateway_late_stdout_final_evidence(self):self.remote_case('stdout')
    def test_gateway_late_tty_final_evidence(self):self.remote_case('stderr')
    def test_gateway_accepted_exception_final_evidence(self):self.remote_case('exception')
    def test_gateway_closing_exception_preserves_initial_timeout(self):self.remote_case('closing')

FinalCaptureLocalTest.qualified = qualified
FinalCaptureLocalTest.base_case_type = QualifiedCliCustodyTest
FinalCaptureRemoteTest.remote_path = REMOTE_PATH



"""Whole-consumer final source/profile/head closure ordering; inert inputs only."""
import json
import os
from pathlib import Path
import unittest
from unittest import mock

@unittest.skipUnless(direct.coordinator_capable(), "closing-order controls require POSIX local fixtures")
class FinalClosingOrderTest(unittest.TestCase):
    qualified=None
    base_case_type=None
    direct=None
    def run_closing_case(self,family):
        q=self.qualified;writes={};mutated=[];checks=[];objects=[]
        retain_original=q._retain;checkpoint_original=q._checkpoint;init_original=q.OuterCustody.__init__;observe_original=q.OuterCustody.observe
        def init(obj,argv,*a,**kw):
            if family in('timeout','exception'):
                argv=list(argv);argv[-1]='import time;time.sleep(.06);'+argv[-1]
            init_original(obj,argv,*a,**kw);objects.append(obj)
        def retain(directory,name,value):
            if family=='exception'and name=='accepted.private.json':raise OSError('inert accepted-retention failure')
            if name=='final-capture.private.json':
                if family in('ordinary','timeout','exception'):
                    helper=directory.parents[2]/'scripts/android_no_update_tls_preflight.py'
                    helper.write_bytes(helper.read_bytes()+b'\n# inert late source mutation\n');mutated.append('helper')
                elif family=='profile':
                    host=self.direct.Guard.return_value.config.hosts['archlinux']
                    current=host.android_devices['api35'];host.android_devices['api35']={**current,'cli':'/inert/foreign-qualified-context'}
                    mutated.append('profile')
                elif family=='head':
                    q.subprocess.check_output.return_value='b'*40+'\n'+'b'*40+'\n';mutated.append('head')
            writes[name]=value;return retain_original(directory,name,value)
        def checkpoint(*a):
            checks.append({'finalRetained':'final-terminal.private.json'in writes})
            if family=='closing'and len(checks)==2:raise ValueError('inert final source refusal')
            return checkpoint_original(*a)
        case=self.base_case_type('test_whole_qualified_adapter_inert_transport_and_source_closing')
        try:
            with mock.patch.object(q,'_retain',retain),mock.patch.object(q,'_checkpoint',checkpoint),mock.patch.object(q.OuterCustody,'__init__',init):
                if family=='timeout':
                    with mock.patch.object(q.OuterCustody,'observe',lambda obj,seconds=45:observe_original(obj,.000001)):
                        try:case.test_whole_qualified_adapter_inert_transport_and_source_closing()
                        except AssertionError:pass
                else:
                    try:case.test_whole_qualified_adapter_inert_transport_and_source_closing()
                    except AssertionError:pass
            self.assertEqual(1,len(objects));self.assertTrue(objects[0].closed)
            self.assertEqual(0,objects[0].child.returncode);self.assertTrue(all(objects[0].eof.values()))
            result=writes['finite-result.public.json']
            self.assertTrue(result['holdersClosed']);self.assertFalse(result['sourceClosing'],'final source/profile/HEAD drift must refuse')
            self.assertEqual('unknown',result['state']);self.assertFalse(result['available']);self.assertFalse(result['replayAllowed'])
            self.assertTrue(result['finalCapture']['complete']);self.assertEqual(0,result['finalCapture']['returnCode'])
            for name in('stdout','stderr'):
                self.assertEqual(bytes(objects[0].raw[name]),writes['outer-final-'+name+'.private'])
            self.assertEqual(2,len(checks));self.assertTrue(checks[-1]['finalRetained'],'closing must follow all final evidence writes')
            self.assertIn('closingFailure',result)
            if family=='exception':self.assertEqual('OSError',result['errorClass'])
            if family=='timeout':self.assertTrue(writes['capture.private.json']['timeout']);self.assertFalse(writes['capture.private.json']['complete'])
        finally:case.doCleanups()
    def test_ordinary_late_source_drift_refuses(self):self.run_closing_case('ordinary')
    def test_timeout_late_source_drift_refuses(self):self.run_closing_case('timeout')
    def test_exception_late_source_drift_refuses(self):self.run_closing_case('exception')
    def test_explicit_final_closing_failure_after_retention(self):self.run_closing_case('closing')
    def test_final_profile_drift_refuses(self):self.run_closing_case('profile')
    def test_final_head_drift_refuses(self):self.run_closing_case('head')

FinalClosingOrderTest.qualified = qualified
FinalClosingOrderTest.base_case_type = QualifiedCliCustodyTest
FinalClosingOrderTest.direct = direct

"""Real registered MCP and fresh CLI routing controls, with inert observers.

Candidate runners may inject server/qualified/ordinary/transport on each class.
When appended to the routine module its existing bindings are the defaults; as
a standalone routine test, the canonical public modules are loaded lazily.
No handler, main, _native_response, or JSON conversion function is substituted.
"""
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


_ROUTING_PROFILE = {
    "adb": "/owned-fixture/adb",
    "cli": "/owned-fixture/configured-cli",
    "serial": "owned-fixture-serial",
    "expectedAvd": "owned-fixture-avd",
    "api": 35,
}


def _routing_bindings(case):
    names = {
        "server": "mcp_server",
        "qualified": "android_qualified_cli_observation",
        "ordinary": "android_observation",
        "transport": "ssh_transport",
    }
    for attribute, module_name in names.items():
        value = getattr(case, attribute, None)
        if value is None:
            value = globals().get(attribute)
        if value is None:
            value = importlib.import_module("agent_tools." + module_name)
        setattr(case, attribute, value)


def _routing_result(route, forwarded):
    return {
        "state": "observed",
        "available": True,
        "engineeringOnly": True,
        "productAcceptance": False,
        "fixtureOnly": True,
        "actualAndroidAuthority": False,
        "fixtureRoute": route,
        "forwarded": forwarded,
    }


class FastMcpQualifiedRoutingTest(unittest.IsolatedAsyncioTestCase):
    server = qualified = ordinary = transport = None

    def setUp(self):
        _routing_bindings(self)
        if self.server.MCP_SERVER is None:
            self.skipTest("MCP SDK unavailable; use agent_tools/requirements-mcp.txt")
        self.directory = tempfile.TemporaryDirectory(prefix="owned-mcp-routing-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    async def test_registered_calltoolrequest_json_selected_and_default_routes(self):
        from mcp import types as mcp_types

        config = types.SimpleNamespace(hosts={
            "archlinux": types.SimpleNamespace(android_devices={"api35": _ROUTING_PROFILE})
        })
        handler = self.server.MCP_SERVER._mcp_server.request_handlers[mcp_types.CallToolRequest]
        for selected in (True, False):
            with self.subTest(selected=selected):
                arguments = {"action": "android-observe", "host": "archlinux", "device": "api35"}
                if selected:
                    arguments["identity"] = {"cliArtifact": self.qualified.SELECTOR}
                request = mcp_types.CallToolRequest.model_validate_json(json.dumps({
                    "method": "tools/call",
                    "params": {"name": "ssh_workflow", "arguments": arguments},
                }))
                forwarded = ([str(self.root), "archlinux", "api35", self.qualified.SELECTOR, 15]
                             if selected else [str(self.root), "archlinux", _ROUTING_PROFILE, 15])
                expected = _routing_result("selected" if selected else "default", forwarded)
                config_patch = (mock.patch.object(self.transport, "load_config", side_effect=AssertionError(
                    "selected MCP route accessed current configuration")) if selected else
                    mock.patch.object(self.transport, "load_config", return_value=config))
                with mock.patch.object(self.server, "REPO_ROOT", self.root), config_patch as config_call, \
                     mock.patch.object(self.qualified, "observe", return_value=expected) as selected_call, \
                     mock.patch.object(self.ordinary, "observe", return_value=expected) as default_call:
                    response = await handler(request)
                self.assertIsInstance(response, mcp_types.ServerResult)
                restored = mcp_types.ServerResult.model_validate_json(response.model_dump_json())
                result = restored.root
                self.assertIsInstance(result, mcp_types.CallToolResult)
                self.assertFalse(result.isError, result.model_dump_json())
                value = result.structuredContent
                self.assertIsInstance(value, dict)
                self.assertEqual([value], [json.loads(item.text) for item in result.content
                                           if isinstance(item, mcp_types.TextContent)])
                self.assertTrue(value["ok"])
                self.assertEqual("ssh_workflow", value["tool"])
                self.assertEqual("archlinux", value["host"])
                self.assertIn("nextAction", value)  # Actual successful _native_response enriched it.
                for key, expected_value in expected.items():
                    self.assertEqual(expected_value, value[key], key)
                if selected:
                    selected_call.assert_called_once_with(
                        self.root, "archlinux", "api35", self.qualified.SELECTOR, 15)
                    default_call.assert_not_called()
                    config_call.assert_not_called()
                else:
                    default_call.assert_called_once_with(self.root, "archlinux", _ROUTING_PROFILE, 15)
                    selected_call.assert_not_called()
                    config_call.assert_called_once_with(self.root)


# This child bootstrap has fixed public module names and receives reviewed file
# paths from the injected module objects. It never selects code from environment
# variables, and calls the actual candidate main with the child's real sys.argv.
_ROUTING_CLI_BOOTSTRAP = r'''
import importlib.util,json,sys,types
from pathlib import Path
fixture=json.loads(FIXTURE_JSON)
sys.path.insert(0,fixture["dependencyRoot"])
import agent_tools
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module
qualified=load("agent_tools.android_qualified_cli_observation",fixture["qualifiedSource"])
server=load("agent_tools.mcp_server_qualified_candidate",fixture["serverSource"])
from agent_tools import android_observation as ordinary,ssh_transport as transport
root=Path(fixture["root"])
server.REPO_ROOT=root
calls={"selected":0,"default":0,"config":0}
def answer(route,forwarded):
    return {"state":"observed","available":True,"engineeringOnly":True,
            "productAcceptance":False,"fixtureOnly":True,"actualAndroidAuthority":False,
            "fixtureRoute":route,"forwarded":forwarded,"fixtureCalls":dict(calls)}
def selected(area,host,device,selector,seconds):
    calls["selected"]+=1
    if fixture["route"]!="selected":raise AssertionError("default CLI invoked selected observer")
    return answer("selected",[str(area),host,device,selector,seconds])
def default(area,host,profile,seconds):
    calls["default"]+=1
    if fixture["route"]!="default":raise AssertionError("selected CLI invoked configured observer")
    return answer("default",[str(area),host,profile,seconds])
def load_config(area):
    calls["config"]+=1
    if fixture["route"]=="selected":raise AssertionError("selected CLI accessed current configuration")
    if area!=root:raise AssertionError("CLI changed owned fixture root")
    return types.SimpleNamespace(hosts={"archlinux":types.SimpleNamespace(
        android_devices={"api35":fixture["profile"]})})
qualified.observe=selected
ordinary.observe=default
transport.load_config=load_config
raise SystemExit(server.main(sys.argv[1:]))
'''


class CliQualifiedRoutingTest(unittest.TestCase):
    server = qualified = ordinary = transport = None

    def setUp(self):
        _routing_bindings(self)
        self.directory = tempfile.TemporaryDirectory(prefix="owned-cli-routing-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_fresh_child_real_main_owned_identity_and_default_json(self):
        # Only reviewed module paths are passed to the isolated local child.
        dependency_root = str(Path(self.server.docs_assistant.__file__).resolve().parent.parent)
        identity_path = self.root / "owned-selector.json"
        identity_path.write_text(json.dumps({"cliArtifact": self.qualified.SELECTOR}), encoding="utf-8")
        for route in ("selected", "default"):
            with self.subTest(route=route):
                fixture = {
                    "dependencyRoot": dependency_root,
                    "serverSource": str(Path(self.server.__file__).resolve()),
                    "qualifiedSource": str(Path(self.qualified.__file__).resolve()),
                    "root": str(self.root), "profile": _ROUTING_PROFILE, "route": route,
                }
                bootstrap = "FIXTURE_JSON=" + repr(json.dumps(fixture)) + "\n" + _ROUTING_CLI_BOOTSTRAP
                arguments = ["ssh-workflow", "android-observe", "--host", "archlinux", "--device", "api35"]
                if route == "selected":
                    arguments.extend(["--identity-file", str(identity_path)])
                child = subprocess.run([sys.executable, "-I", "-B", "-c", bootstrap, *arguments],
                                       cwd=self.root, capture_output=True, text=True, timeout=20, check=False)
                self.assertEqual(0, child.returncode, child.stderr + child.stdout)
                value = json.loads(child.stdout)  # The whole stdout must be one JSON document.
                self.assertTrue(value["ok"])
                self.assertEqual("ssh_workflow", value["tool"])
                self.assertEqual("archlinux", value["host"])
                self.assertIn("nextAction", value)
                forwarded = ([str(self.root), "archlinux", "api35", self.qualified.SELECTOR, 15]
                             if route == "selected" else [str(self.root), "archlinux", _ROUTING_PROFILE, 15])
                for key, expected in _routing_result(route, forwarded).items():
                    self.assertEqual(expected, value[key], key)
                self.assertEqual({"selected": 1, "default": 0, "config": 0} if route == "selected" else
                                 {"selected": 0, "default": 1, "config": 1}, value["fixtureCalls"])



if __name__ == "__main__": unittest.main()
