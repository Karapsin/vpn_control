"""Data-only setup arguments, ordinary autologon and a separate administrator."""
import os
import hashlib
import json
import types
from pathlib import Path
import subprocess
import sys
import unittest
from xml.etree import ElementTree as ET
from agent_tools import windows_vm_unattend as setup
from agent_tools import windows_vm_deploy_remote as producer
from agent_tools.native_vm_spec import FreshWindowsVmSpec
from agent_tools.tests import test_native_vm_spec as specs


class UnattendedTests(unittest.TestCase):
    def test_preserved_answer_omits_installed_locale_fixed_answer_automates_oobe_locale(self):
        folder=Path(__file__).parent/'fixtures/oobe_installed_locale'
        raw=(folder/'before.source').read_bytes();metadata=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(metadata['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('owned_setup_before');exec(compile(raw,str(folder/'before.source'),'exec'),before.__dict__)
        ns={'w':'urn:schemas-microsoft-com:unattend'}
        credentials={'user':'User8!'+'a'*24,'administrator':'Admin8!'+'b'*24}
        for locale in ('en-US','fr-FR'):
            data=self.settings(locale=locale)
            def installed(module):
                xml=ET.fromstring(module.answer_file(data,credentials))
                return xml.find("w:settings[@pass='oobeSystem']/w:component[@name='Microsoft-Windows-International-Core']",ns)
            self.assertIsNone(installed(before))
            current=installed(setup);self.assertIsNotNone(current)
            self.assertEqual({key:locale for key in ('InputLocale','SystemLocale','UILanguage','UserLocale')},
                             {node.tag.rsplit('}',1)[-1]:node.text for node in current})

    def settings(self,**extra):
        return {'imageName':'Windows 11 Pro','locale':'en-US','user':'ordinary','administrator':'fixtureAdmin',**extra}
    def test_two_account_layouts_change_only_arguments_and_keep_user_ordinary(self):
        credentials={'user':'User8!'+'a'*24,'administrator':'Admin8!'+'b'*24}
        ns={'w':'urn:schemas-microsoft-com:unattend'}
        for data in (self.settings(),self.settings(user='anotherUser',administrator='otherAdmin',locale='fr-FR')):
            xml=ET.fromstring(setup.answer_file(data,credentials))
            accounts={a.find('w:Name',ns).text:a.find('w:Group',ns).text for a in xml.findall('.//w:LocalAccount',ns)}
            self.assertEqual('Users',accounts[data['user']]);self.assertEqual('Administrators',accounts[data['administrator']])
            self.assertEqual(data['user'],xml.find('.//w:AutoLogon/w:Username',ns).text)
            self.assertEqual('0',xml.find('.//w:InstallTo/w:DiskID',ns).text)
            self.assertEqual(data['imageName'],xml.find('.//w:InstallFrom/w:MetaData/w:Value',ns).text)
    def test_invalid_account_or_command_data_fails_before_xml(self):
        for field,value in (('administrator','ordinary'),('user','Administrator'),('user','../actor'),('locale','x;command'),('imageName','x";command')):
            with self.subTest(field=field),self.assertRaises(ValueError):setup.parse_setup(self.settings(**{field:value}))
    @unittest.skipUnless(os.name=='posix' and os.geteuid()!=0,'Unprivileged whole-producer refusal')
    def test_complete_start_program_refuses_without_privilege_before_creating_root(self):
        spec=FreshWindowsVmSpec.parse(specs.request())
        source=producer.program(spec,'start',setup=self.settings(),context={'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[]})
        result=subprocess.run([sys.executable,'-I','-B','-c',source],capture_output=True,timeout=5)
        import json
        self.assertEqual(0,result.returncode,result.stderr.decode())
        self.assertEqual('unknown',json.loads(result.stdout)['state'])


if __name__=='__main__':unittest.main()
