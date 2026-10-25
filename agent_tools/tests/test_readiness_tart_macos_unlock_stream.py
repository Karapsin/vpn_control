"""Actual framed subprocesses for the separate correlated unlock observer."""
from dataclasses import replace
import json
import hashlib
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest
import builtins
import ctypes
from types import ModuleType
from unittest.mock import patch

from agent_tools import readiness_tart_macos_unlock_stream as stream
from agent_tools.tests.test_readiness_tart_macos import binding


@unittest.skipUnless(os.name=='posix','controlled guest runtime requires POSIX')
class UnlockStreamTests(unittest.TestCase):
    def source(self,root,*,drift=False,layout='com.apple.keylayout.US',switch=False,runtime=None):
        # Keep the entire emitted protocol/generation runtime. Only the native
        # getter and private root become explicit public controlled fixtures.
        raw=("import json,os,pathlib,pwd\n"
             "os.getgrouplist=lambda *args:[20] # controlled fixture only\n"
             "prefix=pathlib.Path("+repr(str(root))+")\nprobe=prefix/'probe';agent=prefix/'tart-guest-agent'\n"
             "probe.write_text('public');agent.write_text('public');before=probe.stat()\n"
             "p={'uid':os.geteuid(),'principal':pwd.getpwuid(os.geteuid()).pw_name,'home':pwd.getpwuid(os.geteuid()).pw_dir}\n"
             "def need(value):\n if not value:raise SystemExit(73)\n"
             "def protected(path):\n need(path.is_file())\n"
             "_fixture_layout="+repr(layout)+"\n"
             "def _require_us_layout():\n need(_fixture_layout=='com.apple.keylayout.US')\n"
             "_fixture_observations=0\ndef _observe():\n global _fixture_observations,_fixture_layout\n _fixture_observations+=1\n"
             " return {'agent':{'pid':os.getpid()},'boot':'controlled','rawBoot':'controlled','freshCounter':_fixture_observations}\n"+
             (stream._STREAM if runtime is None else runtime))
        if drift:
            raw=raw.replace(' _fixture_observations+=1\n',
                " _fixture_observations+=1\n if _fixture_observations==2:\n  replacement=prefix/'replacement';replacement.write_bytes(probe.read_bytes());os.replace(replacement,probe)\n")
        if switch:
            raw=raw.replace(' _fixture_observations+=1\n',
                " _fixture_observations+=1\n if _fixture_observations==2:_fixture_layout='com.apple.keylayout.ABC'\n")
        return raw.encode()

    def line(self,process):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            self.assertTrue(selector.select(3),'bounded reply deadline')
        return json.loads(process.stdout.readline())

    def run_case(self,requests,*,drift=False):
        with tempfile.TemporaryDirectory() as temporary:
            selected=replace(binding(),guest_python='/usr/local/libexec/vpn-tool-recovery-control/python/bin/python3.12')
            with patch.object(stream,'guest_session_stream_source',return_value=self.source(Path(temporary),drift=drift)):
                argv,payload=stream.session_stream_command(selected)
            process=subprocess.Popen([sys.executable,*argv[1:]],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            replies=[]
            try:
                process.stdin.write(payload);process.stdin.flush();initial=self.line(process)
                self.assertEqual({'protocol','state','observation'},set(initial))
                self.assertEqual((stream.PROTOCOL,'observer_ready',1),
                    (initial['protocol'],initial['state'],initial['observation']['freshCounter']))
                for raw,expected in requests:
                    process.stdin.write(raw);process.stdin.flush()
                    if expected:
                        value=self.line(process);replies.append(value)
                        counter,nonce=expected
                        self.assertEqual({'protocol','state','counter','nonce','observation'},set(value))
                        self.assertEqual((stream.PROTOCOL,'observed',counter,nonce,counter+1),
                            (value['protocol'],value['state'],value['counter'],value['nonce'],value['observation']['freshCounter']))
                process.stdin.close();process.wait(timeout=3)
                self.assertEqual(b'',process.stdout.read());self.assertEqual(b'',process.stderr.read())
                return process.returncode,replies
            finally:
                if process.poll() is None:process.kill();process.wait()
                for pipe in (process.stdin,process.stdout,process.stderr):
                    if not pipe.closed:pipe.close()

    def test_emitted_gate_real_process_unique_roundtrips_after_fresh_native_getter(self):
        requests=[(('check '+str(i)+' '+format(i,'032x')+'\n').encode(),(i,format(i,'032x'))) for i in range(1,5)]
        code,replies=self.run_case(requests)
        self.assertEqual((0,4),(code,len(replies)))

    def test_whole_controlled_fixture_before_counter_collision_red_current_isolated(self):
        path=Path(__file__).parent/'fixtures/tart_macos_unlock_stream_fixture.before.source';raw=path.read_bytes()
        self.assertEqual('8a246293d67cdacf34bb97aca9d96fe08b4a16daee13a7bd5dd733d37f27dc0e',hashlib.sha256(raw).hexdigest())
        old=ModuleType('agent_tools.tests._old_unlock_stream_fixture');old.__file__=str(path)
        exec(compile(raw,str(path),'exec'),old.__dict__)
        producer=Path(__file__).parent/'fixtures/tart_macos_unlock_tis.before.source'
        producer_raw=producer.read_bytes()
        self.assertEqual('de5792eb08a015dccbe920be74d33fac22c66ea67e7984452d7dbc7a5fdcbf69',hashlib.sha256(producer_raw).hexdigest())
        historical=ModuleType('agent_tools._fixture_epoch_unlock_stream');historical.__file__=str(producer);historical.__package__='agent_tools'
        exec(compile(producer_raw,str(producer),'exec'),historical.__dict__)
        for fixture,expected_counter in ((old.UnlockStreamTests(),2),(self,1)):
            with tempfile.TemporaryDirectory() as temporary:
                if fixture is self:source=fixture.source(Path(temporary))
                else:
                    with patch.object(stream,'_STREAM',historical._STREAM):source=fixture.source(Path(temporary))
                selected=replace(binding(),guest_python='/usr/local/libexec/vpn-tool-recovery-control/python/bin/python3.12')
                with patch.object(stream,'guest_session_stream_source',return_value=source):
                    argv,payload=stream.session_stream_command(selected)
                result=subprocess.run([sys.executable,*argv[1:]],input=payload+b'check 1 '+b'1'*32+b'\n',
                                      stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
                self.assertEqual((0,b''),(result.returncode,result.stderr))
                replies=[json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual((expected_counter,2),(replies[1]['counter'],replies[1]['observation']['freshCounter']))

    def test_complete_before_accepts_wrong_or_switched_layout_current_never_authorizes_echo(self):
        path=Path(__file__).parent/'fixtures/tart_macos_unlock_tis.before.source';raw=path.read_bytes()
        self.assertEqual('de5792eb08a015dccbe920be74d33fac22c66ea67e7984452d7dbc7a5fdcbf69',hashlib.sha256(raw).hexdigest())
        before=ModuleType('agent_tools._unlock_tis_before');before.__file__=str(path);before.__package__='agent_tools'
        exec(compile(raw,str(path),'exec'),before.__dict__)
        selected=replace(binding(),guest_python='/usr/local/libexec/vpn-tool-recovery-control/python/bin/python3.12')
        for initial,switch in (('com.apple.keylayout.ABC',False),('com.apple.keylayout.US',True)):
            for producer in (before,stream):
                with self.subTest(initial=initial,switch=switch,before=producer is before),tempfile.TemporaryDirectory() as temporary:
                    source=self.source(Path(temporary),layout=initial,switch=switch,runtime=producer._STREAM)
                    with patch.object(producer,'guest_session_stream_source',return_value=source):argv,payload=producer.session_stream_command(selected)
                    result=subprocess.run([sys.executable,*argv[1:]],input=payload+b'check 1 '+b'1'*32+b'\n',
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
                    self.assertEqual(b'',result.stderr)
                    replies=[json.loads(line)for line in result.stdout.splitlines()]
                    if producer is before:
                        self.assertEqual((0,2),(result.returncode,len(replies)))
                        self.assertEqual('observed',replies[-1]['state'])
                    else:
                        self.assertEqual((73,0 if not switch else 1),(result.returncode,len(replies)))

    def test_duplicate_nonce_noncanonical_counter_old_protocol_and_private_malformed_no_echo(self):
        for raw in (b'check\n',b'check 01 '+b'0'*32+b'\n',b'check 2 '+b'0'*32+b'\n',
                    b'check 1 '+b'A'*32+b'\n',b'PRIVATE'+b'x'*140+b'\n'):
            with self.subTest(length=len(raw)):
                self.assertEqual((73,[]),self.run_case([(raw,None)]))
        self.assertEqual(73,self.run_case([(b'check 1 '+b'a'*32+b'\n',(1,'a'*32)),
                                           (b'check 2 '+b'a'*32+b'\n',None)])[0])

    def test_actual_postobservation_inode_replacement_never_echoes_pending_nonce(self):
        self.assertEqual((73,[]),self.run_case([(b'check 1 '+b'1'*32+b'\n',None)],drift=True))

    def test_production_command_rejects_wrong_account_before_any_observation(self):
        selected=replace(binding(),guest_python='/usr/local/libexec/vpn-tool-recovery-control/python/bin/python3.12',
                         ordinary_uid=max(501,os.geteuid()+1))
        argv,payload=stream.session_stream_command(selected)
        result=subprocess.run([sys.executable,*argv[1:]],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertEqual((73,b'',b''),(result.returncode,result.stdout,result.stderr))


class TisBoundaryTests(unittest.TestCase):
    def test_fixed_tis_api_source_returns_only_us_and_releases_owned_handle(self):
        class Function:
            def __init__(self,call):self.call=call
            def __call__(self,*args):return self.call(*args)
        for variant in ('us','different','null-source','null-property','wrong-type','empty','overflow','encoding'):
            released=[];opened=[]
            class Pointer:
                @staticmethod
                def in_dll(library,name):
                    self.assertEqual('kTISPropertyInputSourceID',name);return 10
            def cstring(value,buffer,size,encoding):
                self.assertEqual((2,513,0x08000100),(value,size,encoding))
                buffer.value=b'com.apple.keylayout.US' if variant=='us' else b'com.apple.keylayout.ABC'
                return variant!='encoding'
            hit=type('Hit',(),{})();cf=type('Cf',(),{})()
            hit.TISCopyCurrentKeyboardInputSource=Function(lambda:0 if variant=='null-source'else 1)
            hit.TISGetInputSourceProperty=Function(lambda *args:0 if variant=='null-property'else 2)
            cf.CFRelease=Function(lambda handle:released.append(handle))
            cf.CFGetTypeID=Function(lambda _:2 if variant=='wrong-type'else 1)
            cf.CFStringGetTypeID=Function(lambda:1)
            cf.CFStringGetLength=Function(lambda _:0 if variant=='empty'else 129 if variant=='overflow'else 22)
            cf.CFStringGetCString=Function(cstring)
            def library(path):
                opened.append(path)
                expected={'/System/Library/Frameworks/Carbon.framework/Frameworks/HIToolbox.framework/HIToolbox':hit,
                          '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation':cf}
                self.assertIn(path,expected);return expected[path]
            proxy=type('Ctypes',(),{'CDLL':staticmethod(library),'c_void_p':Pointer,'c_ulong':ctypes.c_ulong,
                'c_long':ctypes.c_long,'c_uint32':ctypes.c_uint32,'c_bool':ctypes.c_bool,
                'create_string_buffer':staticmethod(ctypes.create_string_buffer)})()
            def imported(name,*args,**kwargs):
                return proxy if name=='ctypes'else builtins.__import__(name,*args,**kwargs)
            def need(value):
                if not value:raise ValueError('layout_refused')
            scope={'need':need,'__builtins__':{**vars(builtins),'__import__':imported}}
            exec(compile(stream._LAYOUT,'<fixed-tis-guard>','exec'),scope)
            if variant=='us':scope['_require_us_layout']()
            else:
                with self.subTest(variant=variant),self.assertRaisesRegex(ValueError,'layout_refused'):
                    scope['_require_us_layout']()
            self.assertEqual([]if variant=='null-source'else[1],released)
            self.assertEqual(2,len(opened))


if __name__=='__main__':unittest.main()
