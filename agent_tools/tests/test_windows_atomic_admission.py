"""Whole before/current Windows admission: pure target validation and atomic publication."""
import ast
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import readiness_windows as windows
from agent_tools.tests.test_readiness_windows import snapshot,SID

FIXTURE=Path(__file__).parent/'fixtures/windows_backend_atomic_admission'


def before_module(name='windows.before.source'):
    if name not in {'windows.before.source','windows.content.before.source'}:raise ValueError('unreviewed_beforeimage')
    raw=(FIXTURE/name).read_bytes()
    expected=json.loads((FIXTURE/'provenance.json').read_text())['sources'][name]
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('windows_admission_beforeimage_changed')
    module=types.ModuleType('agent_tools._windows_atomic_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/name)
    exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


def writer(which,path,pipe):
    module=before_module()if which=='before'else windows
    try:
        if which=='before':
            original=module.os.fdopen
            class Paused:
                def __init__(self,*args,**kwargs):self.stream=original(*args,**kwargs)
                def __enter__(self):return self
                def __exit__(self,*args):self.stream.close()
                def write(self,raw):pipe.send('paused');pipe.recv();return self.stream.write(raw)
                def flush(self):return self.stream.flush()
                def fileno(self):return self.stream.fileno()
            with mock.patch.object(module.os,'fdopen',Paused):module._save(path,b'complete-record\n')
        else:
            original=module.os.write
            def paused(fd,raw):pipe.send('paused');pipe.recv();return original(fd,raw)
            with mock.patch.object(module.os,'write',paused):module._save(path,b'complete-record\n')
        pipe.send('done')
    except BaseException as error:pipe.send(type(error).__name__+':'+str(error))


class WindowsAtomicAdmissionTests(unittest.TestCase):
    def test_whole_constructor_before_generates_RED_fixed_pure_GREEN(self):
        for label,module in [('before',before_module()),('fixed',windows)]:
            with self.subTest(source=label),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);root.chmod(0o700)
                with mock.patch.object(module.packets,'program',wraps=module.packets.program)as packet,mock.patch.object(module.leases,'idle_source',wraps=module.leases.idle_source)as lease_packet:
                    module.WindowsBackend(root,snapshot()['binding'],SID)
                self.assertEqual(1 if label=='before'else 0,packet.call_count)
                self.assertEqual(1 if label=='before'else 0,lease_packet.call_count)

    def test_pure_binding_refactor_preserves_complete_packet_target_identity(self):
        raw=(FIXTURE/'remote.before.source').read_bytes()
        expected=json.loads((FIXTURE/'provenance.json').read_text())['sources']['remote.before.source']
        self.assertEqual(expected,hashlib.sha256(raw).hexdigest())
        module=types.ModuleType('agent_tools._windows_packet_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'remote.before.source')
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
        binding=snapshot()['binding'];operation='a0000000-0000-4000-8000-000000000001'
        # Packet procedures evolve independently. Compare every explicit target
        # selector emitted by the complete before/current builders, rather than
        # treating later reviewed host-work logic as a binding regression.
        def selectors(producer):
            result={}
            for node in ast.parse(producer.program(binding,'observe',operation)).body:
                if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in {'SPEC','SETUP','CONTEXT','PROVIDER','URI','DOMAIN','XML_SHA','SOCKET_PATH','OPERATION'}:
                    result[node.targets[0].id]=ast.literal_eval(node.value)
            return result
        old=selectors(module);current=selectors(windows.packets)
        self.assertEqual(9,len(old));self.assertEqual(old,current)
        provider,spec,setup,context=windows.packets.validate_binding(binding)
        self.assertEqual((provider,spec.as_dict(),setup,context),(current['PROVIDER'],current['SPEC'],current['SETUP'],current['CONTEXT']))

    def test_actual_paused_writer_before_exposes_partial_RED_fixed_absent_then_complete_GREEN(self):
        context=multiprocessing.get_context('fork')
        for label in ('before','fixed'):
            with self.subTest(source=label),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);root.chmod(0o700);path=root/'admission.json'
                parent,child=context.Pipe();process=context.Process(target=writer,args=(label,path,child));process.start();child.close()
                try:
                    self.assertTrue(parent.poll(10));self.assertEqual('paused',parent.recv())
                    self.assertEqual(label=='before',path.exists())
                    if path.exists():self.assertEqual(b'',path.read_bytes())
                    parent.send('continue');self.assertTrue(parent.poll(10));self.assertEqual('done',parent.recv())
                    process.join(10);self.assertEqual(0,process.exitcode)
                    self.assertEqual(b'complete-record\n',path.read_bytes());self.assertEqual(1,path.stat().st_nlink)
                    self.assertEqual(0o600,path.stat().st_mode&0o777)
                finally:
                    if process.is_alive():process.terminate();process.join()
                    parent.close()

    def test_existing_file_symlink_and_hardlink_are_never_overwritten_or_adopted(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);root.chmod(0o700);original=root/'original';original.write_bytes(b'old')
            for kind in ('regular','symlink','hardlink'):
                target=root/kind
                if kind=='regular':target.write_bytes(b'old')
                elif kind=='symlink':target.symlink_to(original)
                else:os.link(original,target)
                with self.assertRaises(FileExistsError):windows._save(target,b'new')
                self.assertEqual(b'old',target.read_bytes())
            self.assertFalse(list(root.glob('.*.tmp')))

    def test_whole_save_temporary_content_tamper_before_publishes_RED_fixed_refuses_GREEN(self):
        for label,module in [('before',before_module('windows.content.before.source')),('fixed',windows)]:
            with self.subTest(source=label),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);root.chmod(0o700);path=root/'intent';original=module.os.fsync
                def corrupt(fd):
                    if os.fstat(fd).st_mode&0o170000==0o100000:os.pwrite(fd,b'evil',0)
                    original(fd)
                with mock.patch.object(module.os,'fsync',corrupt):
                    if label=='before':module._save(path,b'good')
                    else:
                        with self.assertRaisesRegex(ValueError,'windows_evidence_generation'):module._save(path,b'good')
                self.assertEqual(label=='before',path.exists())
                if path.exists():self.assertEqual(b'evil',path.read_bytes())
                self.assertFalse(list(root.glob('.*.tmp')))

    def test_stale_publication_primitive_refuses_before_writing(self):
        with tempfile.TemporaryDirectory()as temporary:
            path=Path(temporary)/'intent'
            with mock.patch.object(windows.publication,'_rename_create_only',lambda *args:None):
                with self.assertRaisesRegex(ValueError,'windows_publication_source_changed'):windows._save(path,b'body')
            self.assertFalse(path.exists())


if __name__=='__main__':unittest.main()
