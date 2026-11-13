"""Data-only setup arguments, ordinary autologon and a separate administrator."""
import os
import hashlib
import json
import types
from pathlib import Path
import subprocess
import sys
import tempfile
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
        with tempfile.TemporaryDirectory()as directory:
            saved=Path(directory)/'complete-start.py';saved.write_bytes(source);saved.chmod(0o600)
            argv=[sys.executable,'-I','-B',str(saved)]
            self.assertLessEqual(sum(len(os.fsencode(word))+1 for word in argv),60000)
            result=subprocess.run(argv,capture_output=True,timeout=5)
        import json
        self.assertEqual(0,result.returncode,result.stderr.decode())
        self.assertEqual('unknown',json.loads(result.stdout)['state'])


class SecondAdministratorTests(unittest.TestCase):
    """T6: a new clone may carry a second Administrators account, the different approving administrator of
    windows-public-update.different-admin. Until then a setup naming one was refused (setup_fields)."""
    ns={'w':'urn:schemas-microsoft-com:unattend'}
    one={'imageName':'Windows 11 Enterprise Evaluation','locale':'en-US','user':'fixtureuser','administrator':'fixtureadmin'}
    credentials={'user':'User8!'+'a'*24,'administrator':'Admin8!'+'b'*24}
    second='Second8!'+'c'*32

    def two(self,**changes):
        return {**self.one,'secondAdministrator':'fixtureapprover',**changes}

    def parsed(self,value):
        try:return setup.parse_setup(value)
        except ValueError as error:self.fail('the setup was refused: '+str(error))

    def answer(self,module,value,credentials):
        try:return ET.fromstring(module['answer_file'](value,credentials)if type(module)is dict else module.answer_file(value,credentials))
        except ValueError as error:self.fail('no answer file: '+str(error))

    def accounts(self,xml):
        return [(a.find('w:Name',self.ns).text,a.find('w:Group',self.ns).text,a.find('w:Password/w:Value',self.ns).text)
                for a in xml.findall('.//w:LocalAccount',self.ns)]

    def test_a_clone_setup_names_a_second_administrator_with_its_own_secret(self):
        self.assertEqual(self.two(),self.parsed(self.two()))
        xml=self.answer(setup,self.two(),{**self.credentials,'secondAdministrator':self.second})
        self.assertEqual([('fixtureuser','Users',self.credentials['user']),('fixtureapprover','Administrators',self.second),
                          ('fixtureadmin','Administrators',self.credentials['administrator'])],self.accounts(xml),
                         'the second administrator with its own secret, created before the fixture administrator')
        self.assertEqual('fixtureuser',xml.find('.//w:AutoLogon/w:Username',self.ns).text,'it never signs in: the ordinary user does')
        self.assertEqual(self.credentials['user'],xml.find('.//w:AutoLogon/w:Password/w:Value',self.ns).text)
        # A setup without one keeps its exact answer file: the three-account file less that account.
        plain=ET.tostring(self.answer(setup,self.one,self.credentials))
        accounts=xml.find('.//w:LocalAccounts',self.ns);accounts.remove(accounts.findall('w:LocalAccount',self.ns)[1])
        self.assertEqual(plain,ET.tostring(xml))

    def test_a_second_administrator_needs_its_own_name_and_secret_and_no_visual_purpose(self):
        for value in (self.two(secondAdministrator='FixtureAdmin'),self.two(secondAdministrator='FIXTUREUSER'),self.two(secondAdministrator='Administrator'),
                      self.two(secondAdministrator='Guest'),self.two(secondAdministrator='../x'),self.two(secondAdministrator=''),self.two(secondAdministrator=7)):
            with self.subTest(name=value['secondAdministrator']),self.assertRaisesRegex(ValueError,'^setup_accounts$'):setup.parse_setup(value)
        with self.assertRaisesRegex(ValueError,'^setup_fields$'):setup.parse_setup(self.two(purpose='windowsUacVisual'))
        with self.assertRaisesRegex(ValueError,'^setup_fields$'):setup.parse_setup({**self.one,'thirdAdministrator':'x'})
        for credentials in (self.credentials,{**self.credentials,'secondAdministrator':'short'},{**self.credentials,'secondAdministrator':self.second,'extra':self.second}):
            with self.subTest(credentials=sorted(credentials)),self.assertRaisesRegex(ValueError,'^setup_credentials$'):
                setup.answer_file(self.two(),credentials)
        with self.assertRaisesRegex(ValueError,'^setup_credentials$'):setup.answer_file(self.one,{**self.credentials,'secondAdministrator':self.second})

    def test_the_start_and_creator_programs_compile_the_same_answer_with_only_their_own_names(self):
        """Both programs compile parse_setup and answer_file from source beside FIELDS, re and ET alone: a second
        administrator must need no other module name there."""
        spec=FreshWindowsVmSpec.parse(specs.request())
        try:source=producer.program(spec,'start',setup=self.two(),context={'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[],
                                                                          'image':{'imageId':'0b0b0b0b-1c1c-4d4d-8e8e-2f2f2f2f2f2f','manifestSha256':'a'*64}})
        except ValueError as error:self.fail('no clone start program: '+str(error))
        import inspect,re
        for name in ('parse_setup','answer_file'):
            self.assertIn(inspect.getsource(getattr(setup,name)),source.decode())
        namespace={'FIELDS':set(setup.FIELDS),'re':re,'ET':ET}
        exec(compile(inspect.getsource(setup.parse_setup)+'\n'+inspect.getsource(setup.answer_file),'compiled setup','exec'),namespace)
        credentials={**self.credentials,'secondAdministrator':self.second}
        self.assertEqual(ET.tostring(self.answer(setup,self.two(),credentials)),ET.tostring(self.answer(namespace,self.two(),credentials)))
        self.assertEqual(ET.tostring(self.answer(setup,self.one,self.credentials)),ET.tostring(self.answer(namespace,self.one,self.credentials)))


if __name__=='__main__':unittest.main()
