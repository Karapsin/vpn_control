"""Canonical manager XML must remain selected before the sole start call."""
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest
from unittest import mock
from uuid import UUID,uuid5
from xml.etree import ElementTree as ET

from agent_tools import readiness_windows_managed_create as current
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding

FIXTURE=Path(__file__).parent/'fixtures/windows_creator_bootstrap_closure'


def subject():
    if os.environ.get('VPN_CONTROL_CREATOR_XML_BEFORE')!='1':return current
    raw=(FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._windows_creator_xml_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


class CanonicalXmlTests(unittest.TestCase):
    def setUp(self):
        self.binding,_=managed_binding();self.spec=self.binding['spec'];self.domain=self.binding['domain'];self.raw=current.domain_xml(self.spec,self.domain)

    def test_exact_public_canonical_graph_and_private_graph_rejected_before_hash(self):
        self.assertEqual(current.validate_canonical_xml(self.raw,self.spec,self.domain),hashlib.sha256(self.raw.encode()).hexdigest())
        for xpath,attribute,value in [('devices/disk/source','file','/other/VM.qcow2'),('devices/graphics','passwd','PRIVATE_TEST_ONLY'),('devices/tpm/backend/source','path','/other/tpm'),('devices/channel/source','path','/other/qga.sock')]:
            tree=ET.fromstring(self.raw);tree.find(xpath).set(attribute,value);raw=ET.tostring(tree,encoding='unicode')
            with mock.patch.object(hashlib,'sha256',wraps=hashlib.sha256)as hashed:
                with self.assertRaisesRegex(ValueError,'windows_managed_canonical_xml_unresolved'):current.validate_canonical_xml(raw,self.spec,self.domain)
                self.assertEqual(hashed.call_count,0)

    @unittest.skipUnless(os.name=='posix','controlled Unix mutation endpoint')
    def test_authentic_postdefine_prestart_caller_foreign_disk_has_zero_actual_effects(self):
        module=subject();rid='c'*64;op=str(uuid5(UUID(self.spec['deploymentId']),rid))
        plan=current.plan(self.spec,self.binding['setup'],self.binding['context'],self.binding['uri'],self.domain,op,rid)
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as directory:
            root=Path(directory);xml=root/'canonical.xml';tree=ET.fromstring(self.raw);tree.find('devices/disk/source').set('file','/other/VM.qcow2');xml.write_text(ET.tostring(tree,encoding='unicode'))
            endpoint=root/'effect.sock';server=socket.socket(socket.AF_UNIX);server.bind(str(endpoint));server.listen();server.settimeout(.2);self.addCleanup(server.close)
            probe=socket.socket(socket.AF_INET);probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
            # Preserve the authentic WHOLE beforeimage. Execute its exact
            # selected post-define→pre-start caller span, including all guards
            # present there; only native manager/files are controlled endpoints.
            raw=inspect.getsource(module._creator_main);start=raw.index('        actual_xml=');end=raw.index('        require(domain.isActive()',start);span=raw[start:end]
            code='import json,hashlib,socket,types\nfrom pathlib import Path\n'
            code+='PLAN='+repr(plan)+'\nSPEC='+repr(self.spec)+'\nspec=dict(SPEC);spec["vncPort"]='+repr(port)+'\nOPERATION='+repr(op)+'\n'
            code+='class Domain:\n def XMLDesc(self,flags):return Path('+repr(str(xml))+').read_text()\n def UUIDString(self):return SPEC["deploymentId"]\n def name(self):return PLAN["binding"]["domain"]\n def createWithFlags(self,flags):\n  with socket.socket(socket.AF_UNIX)as s:s.connect('+repr(str(endpoint))+');s.sendall(b"effect")\ndomain=Domain()\n'
            code+='libvirt=types.SimpleNamespace(VIR_DOMAIN_XML_INACTIVE=2)\noriginal_manager={}\nmanager_guard=lambda:None\nseed_guard=lambda:None\nsave=lambda *args:None\ndef require(value,reason):\n if not value:raise ValueError(reason)\n'
            if module is current:code+=inspect.getsource(current.validate_canonical_xml)+'\n'
            code+='def run():\n    try:\n'+span+'        print("controller-returned")\n    except Exception:print("blocked")\nrun()\n'
            result=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"authenticated-selected-manager-span","exec"))'],input=code.encode(),capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            try:client,_=server.accept();client.close();effect=True
            except TimeoutError:effect=False
            self.assertFalse(effect,'unvalidated canonical disk selected a foreign VM before domain start')


if __name__=='__main__':unittest.main()
