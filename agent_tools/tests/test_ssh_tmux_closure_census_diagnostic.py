import ast
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import ssh_tmux_closure_census_diagnostic as diagnostic


class DiagnosticTests(unittest.TestCase):
    def result(self, phase, pid, ticks, err):
        return {'state':'diagnostic','correlationId':diagnostic.CORRELATION,'phase':phase,'pid':pid,'startTicks':ticks,'errno':err,'nativeActionAllowed':False,'replayAllowed':False,'workspaceProof':False}

    def test_unknown_never_becomes_workspace_or_terminal_proof(self):
        for phase in ('process-cwd-error', 'process-stat-before-error', 'complete'):
            value = self.result(phase, 992 if phase != 'complete' else 0, 44 if phase != 'complete' else 0, 'EACCES' if phase != 'complete' else None)
            diagnostic._validate(value)
            self.assertFalse(value['workspaceProof'])
            self.assertFalse(value['nativeActionAllowed'])
            self.assertFalse(value['replayAllowed'])

    def test_malformed_or_positive_reply_rejected(self):
        for mutate in (lambda x:x.update(workspaceProof=True), lambda x:x.update(nativeActionAllowed=True), lambda x:x.update(phase='workspace-free'), lambda x:x.update(errno='PRIVATE')):
            value=self.result('process-cwd-error',992,44,'EACCES'); mutate(value)
            with self.assertRaises(ValueError): diagnostic._validate(value)

    def test_actual_generated_program_classifies_cwd_eacces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); proc=root/'proc'; proc.mkdir(); (proc/'123').mkdir(); (proc/'123'/'stat').write_bytes(b'123 (worker) S '+b'0 '*18+b'44 '+b'0 '); (proc/'123'/'cmdline').write_bytes(b'fixed\0')
            class Paths:
                @staticmethod
                def Path(path):
                    text=str(path)
                    return proc/text[6:] if text.startswith('/proc/') else proc if text=='/proc' else Path(path)
            proxy=types.SimpleNamespace(**vars(os)); proxy.getpid=lambda:999; proxy.getuid=lambda:os.getuid()
            original_readlink=os.readlink
            def denied(path):
                if str(path).endswith('/cwd'): raise PermissionError(13, 'denied')
                return original_readlink(path)
            proxy.readlink=denied
            terminal={'state':'terminal','correlationId':diagnostic.CORRELATION,'exitCode':0,'terminalPin':diagnostic.closure.pipe.TERMINAL,'artifactVerification':'required','replayAllowed':False}
            namespace={'pathlib':Paths,'os':proxy,'json':json,'sys':types.SimpleNamespace(stdout=types.SimpleNamespace(flush=lambda:None)),'payload':{'action':'status','request':diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST),'stagePin':diagnostic.closure.pipe.STAGE,'anchorPin':diagnostic.closure.pipe.ANCHOR},'job':root/'job','source':root/'source','ns':{'_anchor':lambda *args:{'pane':{'pid':777,'startTicks':1}},'status':lambda *args:terminal}}
            source=diagnostic._DIAGNOSTIC.replace('FIXED_REQUEST',repr(diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST))).replace('FIXED_STAGE',repr(diagnostic.closure.pipe.STAGE)).replace('FIXED_ANCHOR',repr(diagnostic.closure.pipe.ANCHOR)).replace('FIXED_TERMINAL',repr(diagnostic.closure.pipe.TERMINAL))
            exec(source,namespace)
            self.assertEqual(self.result('process-cwd-error',123,44,'EACCES'),namespace['result'])

    def test_original_generic_census_failure_has_a_single_exact_diagnostic_successor(self):
        """The measured generic proc failure must not be retried as a closure proof."""
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); proc=root/'proc'; proc.mkdir(); (proc/'sys/kernel/random').mkdir(parents=True); (proc/'sys/kernel/random/boot_id').write_text(diagnostic.CORRELATION)
            item=proc/'992'; item.mkdir(); item.chmod(0o700)
            fields=[b'S']+[b'0']*20;fields[19]=b'2078693';(item/'stat').write_bytes(b'992 (stage) '+b' '.join(fields));(item/'cmdline').write_bytes(b'python\0')
            local_path=Path
            class Paths:
                @staticmethod
                def Path(path):
                    text=str(path);return proc/text[6:] if text.startswith('/proc/') else proc if text=='/proc' else local_path(path)
            proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:os.getuid();proxy.getpid=lambda:999
            real=os.readlink
            proxy.readlink=lambda path: (_ for _ in ()).throw(PermissionError(13,'denied')) if str(path).endswith('/cwd') else real(path)
            terminal={'state':'terminal','correlationId':diagnostic.CORRELATION,'exitCode':0,'terminalPin':diagnostic.closure.pipe.TERMINAL,'artifactVerification':'required','replayAllowed':False}
            common={'pathlib':Paths,'os':proxy,'hashlib':__import__('hashlib'),'json':json,'time':__import__('time'),'payload':{'action':'status','request':diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST),'stagePin':diagnostic.closure.pipe.STAGE,'anchorPin':diagnostic.closure.pipe.ANCHOR},'action':'status','request':diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST),'job':root/'job','source':root/'source','ns':{'status':lambda *args:terminal,'_anchor':lambda *args:{'pane':{'pid':777,'startTicks':1}}}}
            original=diagnostic.closure._CENSUS.replace('FIXED_REQUEST',repr(diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST))).replace('FIXED_STAGE',repr(diagnostic.closure.pipe.STAGE)).replace('FIXED_ANCHOR',repr(diagnostic.closure.pipe.ANCHOR)).replace('FIXED_TERMINAL',repr(diagnostic.closure.pipe.TERMINAL))
            with self.assertRaisesRegex(ValueError,'closure_process_unknown'):exec(original,dict(common))
            source=diagnostic._DIAGNOSTIC.replace('FIXED_REQUEST',repr(diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST))).replace('FIXED_STAGE',repr(diagnostic.closure.pipe.STAGE)).replace('FIXED_ANCHOR',repr(diagnostic.closure.pipe.ANCHOR)).replace('FIXED_TERMINAL',repr(diagnostic.closure.pipe.TERMINAL))
            exact={**common,'payload':{'action':'status','request':diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST),'stagePin':diagnostic.closure.pipe.STAGE,'anchorPin':diagnostic.closure.pipe.ANCHOR},'sys':types.SimpleNamespace(stdout=types.SimpleNamespace(flush=lambda:None))}
            exec(source,exact)
            self.assertEqual(self.result('process-cwd-error',992,2078693,'EACCES'),exact['result'])

    def test_terminal_or_anchor_second_read_drift_refuses_before_tail_emit(self):
        source=diagnostic._DIAGNOSTIC.replace('FIXED_REQUEST',repr(diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST))).replace('FIXED_STAGE',repr(diagnostic.closure.pipe.STAGE)).replace('FIXED_ANCHOR',repr(diagnostic.closure.pipe.ANCHOR)).replace('FIXED_TERMINAL',repr(diagnostic.closure.pipe.TERMINAL))
        for kind in ('terminal','anchor'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                proc=Path(tmp)/'proc';proc.mkdir();calls=[]
                terminal={'state':'terminal','correlationId':diagnostic.CORRELATION,'exitCode':0,'terminalPin':diagnostic.closure.pipe.TERMINAL,'artifactVerification':'required','replayAllowed':False};anchor_calls=[]
                def status(*_):
                    calls.append('status');return {**terminal,'terminalPin':{'changed':True}} if kind=='terminal' and len(calls)>1 else terminal
                def anchor(*_):
                    anchor_calls.append(True);return {'pane':{'pid':1 if kind=='anchor' and len(anchor_calls)>1 else 777,'startTicks':1}}
                class Paths:
                    @staticmethod
                    def Path(path):
                        text=str(path);return proc if text=='/proc' else proc/text[6:] if text.startswith('/proc/') else Path(path)
                payload={'action':'status','request':diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST),'stagePin':diagnostic.closure.pipe.STAGE,'anchorPin':diagnostic.closure.pipe.ANCHOR}
                proxy=types.SimpleNamespace(**vars(os));proxy.getpid=lambda:999;proxy.getuid=lambda:os.getuid()
                namespace={'pathlib':Paths,'os':proxy,'json':json,'payload':payload,'job':Path(tmp)/'job','source':Path(tmp)/'source','ns':{'status':status,'_anchor':anchor}}
                with self.assertRaisesRegex(ValueError,'diagnostic_terminal_after_changed'):exec(source,namespace)

    def test_remote_program_is_fixed_and_has_no_lifecycle_dispatch(self):
        program=diagnostic.remote_program(); compile(program,'<fixed>','exec')
        self.assertIn('process-cwd-error',program)
        self.assertIn("payload['action']!='status'",program)
        self.assertEqual(1,program.count('print(json.dumps('))
        self.assertEqual(2,program.count("ns['status'](job,source,payload['anchorPin'])"))
        self.assertNotIn("ns['start']",program)
        self.assertNotIn("ns['release']",program)

    def test_real_old_action_prefix_dispatch_and_tail_emit_one_guarded_result(self):
        """Run unmodified inherited prefix/tail bytes against only inert file/proc bodies."""
        payload={'action':'status','request':diagnostic.old.purpose(diagnostic.closure.pipe.REQUEST),'stagePin':diagnostic.closure.pipe.STAGE,'anchorPin':diagnostic.closure.pipe.ANCHOR}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);remote=root/'remote';job=remote/diagnostic.CORRELATION;source=job/'source';source.mkdir(parents=True);proc=root/'proc';proc.mkdir();item=proc/'992';item.mkdir();fields=[b'S']+[b'0']*20;fields[19]=b'2078693';(item/'stat').write_bytes(b'992 (stage) '+b' '.join(fields));(item/'cmdline').write_bytes(b'python\0')
            tool="""import json\nPIN={'generation':[1], 'sha256':'a'*64}\nREQ="""+repr(payload['request'])+"""\nSTAGE="""+repr(payload['stagePin'])+"""\nANCHOR="""+repr(payload['anchorPin'])+"""\nTERM="""+repr(diagnostic.closure.pipe.TERMINAL)+"""\ndef private_dir(path): return {'private':str(path)}\ndef read(path,limit=None):\n raw=path.read_bytes()\n if path.name=='stage-ready.json': return raw,STAGE\n if path.name=='tmux-tool.py': return raw,PIN\n return raw,PIN\ndef source_pin(source,request): return PIN\ndef status(job,source,anchor): return {'state':'terminal','correlationId':REQ['correlationId'],'exitCode':0,'terminalPin':TERM,'artifactVerification':'required','replayAllowed':False}\ndef _anchor(job,source,anchor): return {'pane':{'pid':777,'startTicks':1}}\n"""
            tool_path=job/'tmux-tool.py';tool_path.write_text(tool);tool_path.chmod(0o600)
            drift_tool=tool.replace("def source_pin(source,request): return PIN", "COUNT=0\ndef source_pin(source,request):\n global COUNT;COUNT+=1;return PIN if COUNT==1 else {'generation':[2],'sha256':'b'*64}")
            ready={'request':payload['request'],'toolPin':{'generation':[1],'sha256':'a'*64},'proof':{'source':{'generation':[1],'sha256':'a'*64},'parent':{'private':str(job.parent)},'job':{'private':str(job)}}};(job/'stage-ready.json').write_text(json.dumps(ready));(job/'stage-ready.json').chmod(0o600)
            local_path=Path
            class Paths:
                @staticmethod
                def Path(path):
                    text=str(path)
                    if text.startswith('/proc/'):return proc/text[6:]
                    if text=='/proc':return proc
                    if text.startswith('/home/kardinal/.vpn-control-linux-package-fixture'):return remote/text[len('/home/kardinal/.vpn-control-linux-package-fixture'):].lstrip('/')
                    return local_path(path)
            proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:os.getuid();proxy.getpid=lambda:999;proxy.readlink=lambda _:(_ for _ in ()).throw(PermissionError(13,'denied'))
            output=io.StringIO()
            import sys
            real_sha=__import__('hashlib').sha256
            class Hash:
                def sha256(self,raw):
                    if raw in (tool.encode(),drift_tool.encode()):return types.SimpleNamespace(hexdigest=lambda:diagnostic.old.TOOL_SHA)
                    return real_sha(raw)
            with mock.patch('pathlib.Path',Paths.Path),mock.patch.dict(sys.modules,{'hashlib':Hash()}),mock.patch.object(sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))),mock.patch.object(sys,'stdout',output):
                exec(diagnostic.remote_program(),{'os':proxy})
            rows=output.getvalue().splitlines();self.assertEqual(1,len(rows));value=json.loads(rows[0])
            self.assertEqual('process-cwd-error',value['phase']);self.assertFalse(value['workspaceProof'])
            # The source is stable through dispatch, then changes only for the
            # inherited old tail guard.  It must refuse before the sole emit.
            tool_path.write_text(drift_tool);drift_output=io.StringIO()
            with mock.patch('pathlib.Path',Paths.Path),mock.patch.dict(sys.modules,{'hashlib':Hash()}),mock.patch.object(sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))),mock.patch.object(sys,'stdout',drift_output):
                with self.assertRaises(SystemExit) as refused:exec(diagnostic.remote_program(),{'os':proxy})
            self.assertEqual(33,refused.exception.code);self.assertEqual('',drift_output.getvalue())
