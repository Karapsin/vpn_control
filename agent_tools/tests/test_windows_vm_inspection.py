"""Canonical diagnostic source, complete key planning and immutable captures."""
import ast
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from agent_tools import windows_vm_instance as instance
from agent_tools.tests.test_native_vm_spec import request


class InspectionTests(unittest.TestCase):
    setup={'imageName':'Windows 11 Pro','locale':'en-US','user':'ordinary','administrator':'fixtureAdmin'}
    context={'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[]}
    operation='98eeb64a-6ea6-4e2e-998f-742cb63c3529'
    def bindings(self,source):
        rows={}
        for node in ast.parse(source).body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                rows.setdefault(node.targets[0].id,[]).append(ast.literal_eval(node.value))
        return rows
    def before_program(self,base):
        folder=Path(__file__).parent/'fixtures/bootstrap_probe_plan';raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        observer=base/'previous.py';old='setup-frame-'+'a'*32+'.png'
        observer.write_text("LEAF="+repr(old)+"\ndef diagnose():\n    try:pass\n    finally:pass\ndiagnose()\n")
        output=base/'emitted.py'
        completed=subprocess.run([sys.executable,'-I',str(folder/'before.source'),'--observer',str(observer),'--output',str(output)],capture_output=True,timeout=5)
        self.assertEqual(0,completed.returncode,completed.stderr.decode('utf8','replace'))
        return output.read_text(),old
    def test_preserved_builder_reuses_old_leaf_current_factory_has_only_fresh_typed_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            before,old=self.before_program(Path(temporary));bindings=self.bindings(before)
            self.assertEqual(old,bindings['LEAF'][-1]);self.assertEqual(2,len(bindings['LEAF']))
            after=instance.inspection_program(request(),self.setup,self.context,self.operation,probe=True)
            current=self.bindings(after);self.assertEqual(['setup-frame-'+self.operation.replace('-','')+'.png'],current['LEAF'])
            self.assertEqual([self.operation],current['OPERATION_ID']);self.assertEqual(1,len(current['SPEC']))
    def test_preserved_encoder_partially_sends_then_refuses_underscore_fixed_plan_has_no_unsupported_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source,_=self.before_program(Path(temporary));main=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='diagnose')
            nodes=[n for n in main.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in ('symbols','deadline')for t in n.targets)or isinstance(n,ast.For)]
            sent=[]
            def key(codes):
                if '_' in codes:raise ValueError('QMP unsupported key')
                sent.append(codes)
            import time
            namespace={'COMMAND':instance.BOOTSTRAP_PROBE,'time':time,'key':key,'require':lambda value,reason:None}
            with self.assertRaisesRegex(ValueError,'QMP unsupported key'):
                exec(compile(ast.Module(body=nodes,type_ignores=[]),'actual preserved key loop','exec'),namespace)
            self.assertGreater(len(sent),0)
            plan=instance.console_key_plan(instance.BOOTSTRAP_PROBE)
            self.assertIn(('shift','minus'),plan);self.assertFalse(any('_' in codes for codes in plan))
            with self.assertRaises(ValueError):instance.console_key_plan('supported-prefix\n')
    @unittest.skipUnless(os.name=='posix','POSIX owned root/capture')
    def test_complete_emitted_entry_refuses_existing_capture_before_any_key_or_overwrite(self):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
            root=Path(temporary);root.chmod(0o700);spec=request();spec['root']=str(root)
            body=instance.inspection_program(spec,self.setup,self.context,self.operation,probe=True)
            frame=root/('setup-frame-'+self.operation.replace('-','')+'.png');frame.write_bytes(b'ORIGINAL_FRAME');frame.chmod(0o600)
            class Boundary(ast.NodeTransformer):
                def visit_FunctionDef(self,node):
                    if node.name=='observed':
                        node.body=ast.parse("return {'guestAgentReady':False,'qemu':{'pid':1,'startTicks':1}}").body
                        return node
                    if node.name=='qmp':
                        node.body=ast.parse("raise AssertionError('No QMP request allowed')").body
                        return node
                    return self.generic_visit(node)
            tree=ast.fix_missing_locations(Boundary().visit(ast.parse(body)))
            actual_open=open
            def observed_open(path,*args,**kwargs):
                return io.StringIO(self.context['hostBootId']) if path=='/proc/sys/kernel/random/boot_id' else actual_open(path,*args,**kwargs)
            output=io.StringIO()
            with mock.patch('builtins.open',side_effect=observed_open),contextlib.redirect_stdout(output):exec(compile(tree,'complete inspection entry','exec'),{})
            value=json.loads(output.getvalue());self.assertEqual('instance_frame_exists',value['reason']);self.assertFalse(value['replayAllowed'])
            self.assertEqual(b'ORIGINAL_FRAME',frame.read_bytes());self.assertEqual([frame],list(root.iterdir()))

    @unittest.skipUnless(os.name=='posix','POSIX owned receipt/frame files')
    def test_complete_capture_and_collect_return_same_saved_bytes_without_recapture(self):
        from agent_tools import windows_vm_deploy as deploy
        from agent_tools.native_vm_spec import FreshWindowsVmSpec
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            root=Path(temporary);root.chmod(0o700);spec=request();spec['root']=str(root)
            receipt=root/'qemu-started.json';receipt.write_text('{"pid":1}');receipt.chmod(0o600)
            png=b'\x89PNG\r\n\x1a\nPUBLIC_UNIT_BYTES';calls=[]
            def qmp(command,arguments=None):
                self.assertEqual('screendump',command);calls.append(command)
                path=Path(arguments['filename']);path.write_bytes(png);path.chmod(0o600)
            class Boundary(ast.NodeTransformer):
                def visit_FunctionDef(self,node):
                    if node.name in ('observed','process','instance_intent'):
                        node.body=ast.parse("return {'guestAgentReady':True,'qemu':{'pid':1,'startTicks':1}}"if node.name=='observed'else 'return None').body
                        return node
                    if node.name=='qmp':node.body=ast.parse('return QMP_UNIT(command,arguments)').body;return node
                    return self.generic_visit(node)
            actual_open=open
            def opened(path,*args,**kwargs):return io.StringIO(self.context['hostBootId'])if path=='/proc/sys/kernel/random/boot_id'else actual_open(path,*args,**kwargs)
            def run(collect):
                raw=instance.inspection_program(spec,self.setup,self.context,self.operation,return_frame=True,read_existing=collect)
                tree=ast.fix_missing_locations(Boundary().visit(ast.parse(raw)));output=io.StringIO()
                with mock.patch('builtins.open',side_effect=opened),contextlib.redirect_stdout(output):exec(compile(tree,'complete frame entry','exec'),{'QMP_UNIT':qmp})
                return json.loads(output.getvalue())
            first=run(False);second=run(True)
            self.assertEqual(first,second);self.assertEqual(['screendump'],calls)
            destination=root/'returned';destination.mkdir(mode=0o700)
            value=deploy._materialize_frame(destination,FreshWindowsVmSpec.parse(spec),self.operation,second)
            self.assertEqual(png,Path(value['framePath']).read_bytes());self.assertNotIn('base64',value)
            for bad in (None,{**second,'sha256':'0'*64},{**second,'operationId':str(__import__('uuid').uuid4())}):
                with self.assertRaises(ValueError):deploy._materialize_frame(destination,FreshWindowsVmSpec.parse(spec),self.operation,bad)
            self.assertEqual('unknown',run(False)['state']);self.assertEqual(['screendump'],calls)


if __name__=='__main__':unittest.main()
