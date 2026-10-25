"""Real framed subprocess pipe; every accepted frame refreshes its observer."""
from dataclasses import replace
import ast
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from agent_tools.tests.test_readiness_tart_macos import binding
from agent_tools import readiness_tart_macos_session_stream as stream


@unittest.skipUnless(os.name=='posix','fixed guest stream requires POSIX signal deadline')
class SessionStreamTests(unittest.TestCase):
    def test_whole_before_postobservation_inode_replacement_red_current_refuses(self):
        before=ast.parse((Path(__file__).parent/'fixtures/macos_session_stream_generation.before.source').read_bytes())
        old_runtime=next(node.value.value for node in before.body if isinstance(node,ast.Assign)
                         and any(isinstance(target,ast.Name)and target.id=='_STREAM'for target in node.targets))
        actual=replace(binding(),guest_python='/usr/local/libexec/vpn-tool-recovery-cont-control/python/bin/python3.12')
        for phase,runtime in (('before',old_runtime),('after',stream._STREAM)):
            with self.subTest(phase=phase),tempfile.TemporaryDirectory()as temporary:
                source=self.fixture(Path(temporary)).decode()
                source=source.replace(stream._STREAM,runtime).replace(' counter+=1\n',
                    " counter+=1\n if counter==2:\n  replacement=prefix/'replacement';replacement.write_bytes(probe.read_bytes());os.replace(replacement,probe)\n")
                with patch.object(stream,'guest_session_stream_source',return_value=source.encode()):
                    argv,payload=stream.session_stream_command(actual)
                process=subprocess.Popen([sys.executable,*argv[1:]],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    process.stdin.write(payload);process.stdin.flush();self.line(process)
                    process.stdin.write(b'check\n');process.stdin.flush()
                    if phase=='before':
                        self.assertEqual(self.line(process)['observation']['freshCounter'],2)
                    process.stdin.close();process.wait(timeout=3)
                    self.assertEqual(process.returncode,0 if phase=='before'else 73)
                    self.assertEqual(process.stdout.read(),b'');self.assertEqual(process.stderr.read(),b'')
                finally:
                    if process.poll()is None:process.kill();process.wait()
                    for pipe in (process.stdin,process.stdout,process.stderr):
                        if not pipe.closed:pipe.close()

    def test_exact_source_packet_wrong_account_refuses_before_native_observer(self):
        actual=replace(binding(),guest_python='/usr/local/libexec/vpn-tool-recovery-cont-control/python/bin/python3.12',
                       ordinary_uid=max(501,os.geteuid()+1))
        argv,payload=stream.session_stream_command(actual)
        result=subprocess.run([sys.executable,*argv[1:]],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(73,b'',b''))

    def fixture(self,directory):
        # Explicit controlled filesystem observer: this is no Mac qualification.
        return ("import json,os,pathlib,pwd\n"
                "os.getgrouplist=lambda *args:[20] # controlled nonadmin account fixture only\n"
                "prefix=pathlib.Path("+repr(str(directory))+ ")\nprobe=prefix/'probe';agent=prefix/'tart-guest-agent'\n"
                "probe.write_text('public');agent.write_text('public');before=probe.stat()\n"
                "p={'uid':os.geteuid(),'principal':pwd.getpwuid(os.geteuid()).pw_name,'home':pwd.getpwuid(os.geteuid()).pw_dir}\n"
                "def need(value):\n if not value:raise SystemExit(73)\n"
                "def protected(path):\n need(path.is_file())\n"
                "counter=0\ndef _observe():\n global counter\n counter+=1\n"
                " return {'agent':{'pid':os.getpid()},'boot':'controlled','rawBoot':'controlled','freshCounter':counter}\n"+
                stream._STREAM).encode()

    def line(self,process):
        with selectors.DefaultSelector()as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            self.assertTrue(selector.select(3),'finite observer reply deadline')
        return json.loads(process.stdout.readline())

    def test_complete_fixed_stream_framing_fresh_roundtrips_eof_and_malformed(self):
        actual=replace(binding(),guest_python='/usr/local/libexec/vpn-tool-recovery-cont-control/python/bin/python3.12')
        for malformed in (False,True):
            with self.subTest(malformed=malformed),tempfile.TemporaryDirectory()as temporary:
                source=self.fixture(Path(temporary))
                with patch.object(stream,'guest_session_stream_source',return_value=source):
                    argv,payload=stream.session_stream_command(actual)
                process=subprocess.Popen([sys.executable,*argv[1:]],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    process.stdin.write(payload);process.stdin.flush()
                    self.assertEqual(self.line(process)['observation']['freshCounter'],1)
                    for count in (2,3,4):
                        process.stdin.write(b'check\n');process.stdin.flush()
                        self.assertEqual(self.line(process)['observation']['freshCounter'],count)
                    if malformed:
                        process.stdin.write(b'PRIVATE-invalid\n');process.stdin.flush()
                    process.stdin.close();process.wait(timeout=3)
                    self.assertEqual(process.returncode,73 if malformed else 0)
                    self.assertEqual(process.stdout.read(),b'');self.assertEqual(process.stderr.read(),b'')
                finally:
                    if process.poll()is None:process.kill();process.wait()
                    for pipe in (process.stdin,process.stdout,process.stderr):
                        if not pipe.closed:pipe.close()


if __name__=='__main__':unittest.main()
