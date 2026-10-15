"""Measured API35 dump/bound regressions; pure helpers, no native calls."""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import random
import re
import time
import types
import unittest
from unittest.mock import patch
from agent_tools import ssh_transport
from agent_tools import android_original_host_wire as wire

ROOT=Path(__file__).resolve().parents[2]
TARGET=ROOT/'agent_tools/android_installer_failed_check_retirement.py'
BEFORE=Path(__file__).parent/'fixtures/api35_os_session_bound_before.source'
# Exact complete relevant sections from the retained API35 dump eb583dbf.
SECTION=b'Active install sessions:\n  \nFinalized install sessions:\n  \nHistorical install sessions:\nLegacy install sessions:\n'

def function(path,name):
    tree=ast.parse(path.read_bytes())
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name)
    namespace={'hashlib':hashlib}
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),namespace)
    return namespace,name

def receipt(raw):
    return {'returnCode':0,'timedOut':False,'stdoutEOF':True,'stderrEOF':True,'stderrBytes':0,
            'stdoutBytes':len(raw),'stdoutSha256':hashlib.sha256(raw).hexdigest()}

class OsSessionProjectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.namespace,cls.name=function(TARGET,'project_api35_os_session_dump')
        # Same measured 2,621,266-byte complete producer size, safe generated data.
        padding=''.join(random.Random(828431).choices('abcdefghijklmnopqrstuvwxyz0123456789',k=2621266-len(SECTION)-1)).encode()+b'\n'
        cls.raw=padding+SECTION
        cls.project=staticmethod(cls.namespace[cls.name])

    def test_actual_shaped_command_bound_red_then_projection_green(self):
        ns,name=function(BEFORE,'capture_command')
        raw=self.raw
        class Child:
            pid=1
            returncode=0
            def communicate(self,timeout=None):return raw,b''
        stored={}
        ns.update(deadline=time.monotonic()+55,time=time,real_subprocess=types.SimpleNamespace(Popen=lambda *a,**k:Child(),DEVNULL=-1,PIPE=-1),retain=lambda name,data:stored.setdefault(name,data),records=[],base64=base64)
        with self.assertRaisesRegex(ValueError,'read_command_timeout_or_bound'):
            ns[name]('os-installer-before',['inert-retained-output'])
        self.assertEqual(stored['os-installer-before.stdout.private'],raw)
        self.assertEqual(ns['records'][0]['stdoutBytes'],2621266)
        self.assertEqual(self.project(raw,receipt(raw))['sectionText'].encode(),SECTION)

    def test_finalized_header_before_parser_red_then_green(self):
        ns,name=function(BEFORE,'terminal_pass');ns.update(device=lambda *a:self.raw.decode(),re=re)
        with self.assertRaisesRegex(ValueError,'os_active_installer_not_empty_or_unknown'):ns[name]('before')
        value=self.project(self.raw,receipt(self.raw));self.assertTrue(value['activeEmpty']);self.assertTrue(value['finalizedEmpty'])

    def test_full_envelope_wire_red_then_bounded_green(self):
        original={'scope':'fixed_readonly_retirement_facts_only','records':[dict(receipt(self.raw),stdoutBase64=base64.b64encode(self.raw).decode())]}
        with self.assertRaisesRegex(ValueError,'wire_encoded_bounds'):wire.encode_payload(original)
        projected=self.project(self.raw,receipt(self.raw));encoded=wire.encode_payload(projected)
        self.assertLess(len(encoded),65536);self.assertEqual(wire.decode_payload_bytes(encoded),json.dumps(projected,sort_keys=True,separators=(',',':')).encode())

    def test_full_relevant_sections_and_terminators(self):
        v=self.project(self.raw,receipt(self.raw));self.assertEqual(v['sectionBytes'],113);self.assertEqual(v['headerCounts'],[1,1,1,1]);self.assertTrue(v['activeSectionComplete']);self.assertTrue(v['finalizedSectionComplete']);self.assertFalse(v['admissionAllowed']);self.assertEqual(v['producerStdoutSha256'],hashlib.sha256(self.raw).hexdigest())

    def test_nonempty_active_and_finalized_preserved(self):
        for marker,field in [(b'Active install sessions:\n', 'activeEmpty'),(b'Finalized install sessions:\n','finalizedEmpty')]:
            with self.subTest(field=field):
                raw=SECTION.replace(marker,marker+b'  Session 17\n');v=self.project(raw,receipt(raw));self.assertFalse(v[field]);self.assertIn('Session 17',v['sectionText'])

    def test_missing_duplicate_and_reordered_headers_refuse(self):
        for raw in [SECTION.replace(b'Finalized install sessions:\n',b''),SECTION+SECTION,SECTION.replace(b'Historical install sessions:',b'TEMP:').replace(b'Legacy install sessions:',b'Historical install sessions:').replace(b'TEMP:',b'Legacy install sessions:')]:
            with self.subTest(sha=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(ValueError):self.project(raw,receipt(raw))

    def test_complete_receipt_required(self):
        for key,value in [('returnCode',1),('returnCode',False),('timedOut',True),('stdoutEOF',False),('stderrEOF',False),('stderrBytes',1),('stderrBytes',False),('stdoutBytes',1),('stdoutSha256','0'*64)]:
            with self.subTest(key=key,value=value):
                row=receipt(SECTION);row[key]=value
                with self.assertRaises(ValueError):self.project(SECTION,row)

    def test_measured_bootstrap_command_red_then_fixed_green(self):
        path=Path(__file__).parent/'fixtures/api35_record_bootstrap.source'
        ns={};exec(path.read_bytes(),ns);ns['binary']=types.SimpleNamespace(sha=lambda raw:hashlib.sha256(raw).hexdigest())
        source=b'print("fixed owned record only")\n'
        before=ns['before_bootstrap'](source);fixed=ns['fixed_bootstrap'](source)
        config=types.SimpleNamespace(hosts={'archlinux':types.SimpleNamespace(alias='archlinux')},root=ROOT)
        with self.assertRaisesRegex(ssh_transport.SshConfigError,'safe strings'):
            ssh_transport.build_ssh_argv(config,'archlinux',30,command=before)
        seen=[]
        route=[config.hosts['archlinux']]
        selection=types.SimpleNamespace(selection_present=lambda root,alias:root==ROOT and alias=='archlinux')
        with patch.object(ssh_transport,'_route_hosts',return_value=route), \
             patch.object(ssh_transport.os.path,'lexists',return_value=True), \
             patch.object(ssh_transport,'_selection_module',return_value=selection), \
             patch.object(ssh_transport,'_build_selected_arch_argv',side_effect=lambda config,route,command,*rest:seen.append(command)or ['inert-no-process']):
            self.assertEqual(ssh_transport.build_ssh_argv(config,'archlinux',30,command=fixed),['inert-no-process'])
        self.assertEqual(seen,[fixed]);self.assertNotIn('\n',fixed[-1]);compile(fixed[-1],'<actual-fixed-bootstrap>','exec')

    def test_record_section_and_text_bounds(self):
        for raw in [b'x'*4194305,SECTION+b'\0',SECTION[:-1],b'\xff\n'+SECTION,SECTION.replace(b'  \nFinalized',b'x'*1048576+b'\nFinalized')]:
            with self.subTest(bytes=len(raw)):
                with self.assertRaises((ValueError,UnicodeDecodeError)):self.project(raw,receipt(raw))

if __name__=='__main__':unittest.main()
