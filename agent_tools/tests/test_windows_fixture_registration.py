"""Windows alias writer: immutable, source-bound, and refused on any changed proof."""
import base64,hashlib,json,os,stat,tempfile,unittest,uuid,zlib
from pathlib import Path
from unittest import mock
from agent_tools import readiness_fixture_registry as registry,readiness_windows as windows,readiness_windows_login as login,readiness_windows_registration as registration
from agent_tools.tests.test_native_vm_spec import request

SID='S-1-5-21-1-2-3-1004'


@unittest.skipUnless(os.name=='posix','POSIX private-file custody')
class RegistrationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700);self.machine=str(uuid.uuid4())
        spec=request();spec['deploymentId']=self.machine
        self.intent={'spec':spec,'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'fixtureuser','administrator':'fixtureadmin'},
                     'context':{'hostBootId':str(uuid.uuid4()),'pending':[]},'correlationId':'a'*32,'mode':'start','callerSha256':'b'*64}
        for path in (self.root/'.rag_index',self.root/'.rag_index/windows-vm-deploy-intents',self.root/'.runtime'):path.mkdir(mode=0o700)
        path=self.root/'.rag_index/windows-vm-deploy-intents'/(self.machine+'.intent.json');path.write_text(json.dumps(self.intent));path.chmod(0o600)
    def secret(self,name='host-sudo.secret',body=b'fixture-sudo-secret\n'):
        path=self.root/'.runtime'/name;path.write_bytes(body);path.chmod(0o600);return str(path)
    def test_zero_capability_alias_loads_with_no_recovery_and_is_immutable(self):
        fixture=registration.register(self.root,'windows-raw-test-v1',self.machine,SID)
        self.assertEqual(frozenset(),fixture.adapter.capabilities);self.assertEqual(self.machine,fixture.machine)
        path=self.root/'.rag_index/readiness-fixtures/windows-raw-test-v1.json';self.assertEqual(0o600,stat.S_IMODE(path.stat().st_mode))
        descriptor=json.loads(path.read_text());self.assertEqual({'path':None}['path'],descriptor['credential']);self.assertEqual(self.intent['setup'],descriptor['binding']['setup'])
        with self.assertRaises(FileExistsError):registration.register(self.root,'windows-raw-test-v1',self.machine,SID)
    def test_capability_alias_needs_a_qualification_written_under_the_same_sources(self):
        proof=registration.write_qualification(self.root,self.machine,'wake_display',evidence={'operationId':str(uuid.uuid4())})
        fixture=registration.register(self.root,'windows-raw-wake-v1',self.machine,SID,qualifications={'wake_display':proof})
        self.assertEqual(frozenset({'wake_display'}),fixture.adapter.capabilities)
    def test_reboot_needs_a_private_runtime_credential_and_refuses_one_elsewhere(self):
        proof=registration.write_qualification(self.root,self.machine,'reboot',evidence={'operationId':str(uuid.uuid4())})
        fixture=registration.register(self.root,'windows-raw-reboot-v1',self.machine,SID,qualifications={'reboot':proof},credential_file=self.secret())
        self.assertIn('reboot',fixture.adapter.capabilities)
        descriptor=json.loads((self.root/'.rag_index/readiness-fixtures/windows-raw-reboot-v1.json').read_text());self.assertNotIn('fixture-sudo-secret',json.dumps(descriptor))
        outside=self.root/'outside.secret';outside.write_bytes(b'x\n');outside.chmod(0o600)
        with self.assertRaises(ValueError):registration.register(self.root,'windows-raw-reboot-v2',self.machine,SID,qualifications={'reboot':proof},credential_file=str(outside))
        descriptor2=json.loads((self.root/'.rag_index/readiness-fixtures/windows-raw-reboot-v1.json').read_text())
        (self.root/'.runtime/host-sudo.secret').write_bytes(b'changed-secret\n')
        with self.assertRaises(ValueError):registry.registered_fixture(self.root,'windows-raw-reboot-v1')
        self.assertEqual(descriptor,descriptor2)
    def test_login_profile_is_public_and_validated_and_the_secret_is_fixture_scoped(self):
        crop={'width':320,'height':200,'crops':[{'rect':[0,0,10,10],'sha256':'a'*64}]};profile={'password':crop,'lockscreen':crop}
        with self.assertRaises(ValueError):registration.write_qualification(self.root,self.machine,'login',evidence={'operationId':str(uuid.uuid4())})
        with self.assertRaises(ValueError):registration.write_qualification(self.root,self.machine,'login',evidence={'operationId':str(uuid.uuid4())},profiles={'locked':{'password':crop}})
        proof=registration.write_qualification(self.root,self.machine,'login',evidence={'operationId':str(uuid.uuid4())},profiles={'locked':profile})
        directory=self.root/'.runtime/windows-vm-credentials'/self.machine
        with self.assertRaises(Exception):registration.register(self.root,'windows-raw-login-v0',self.machine,SID,qualifications={'login':proof})
        directory.mkdir(mode=0o700,parents=True);path=directory/'user.secret';path.write_bytes(b'fixture-user-secret\n');path.chmod(0o600)
        fixture=registration.register(self.root,'windows-raw-login-v1',self.machine,SID,qualifications={'login':proof})
        self.assertIn('login',fixture.adapter.capabilities);self.assertEqual({'locked':profile},fixture.adapter.backend.login_profiles)
        raw=(self.root/'.rag_index/readiness-fixtures/windows-raw-login-v1.json').read_text()+Path(proof['path']).read_text();self.assertNotIn('fixture-user-secret',raw)
    def test_changed_proof_or_source_makes_the_alias_stale(self):
        proof=registration.write_qualification(self.root,self.machine,'wake_display',evidence={'operationId':str(uuid.uuid4())})
        registration.register(self.root,'windows-raw-stale-v1',self.machine,SID,qualifications={'wake_display':proof})
        path=Path(proof['path']);body=json.loads(path.read_text());body['qualified']=False;path.write_text(json.dumps(body))
        with self.assertRaises(ValueError):registry.registered_fixture(self.root,'windows-raw-stale-v1')
    def test_a_proof_from_other_sources_is_refused(self):
        proof=registration.write_qualification(self.root,self.machine,'wake_display',evidence={'operationId':str(uuid.uuid4())})
        path=Path(proof['path']);body=json.loads(path.read_text());body['sourcePins']={};path.unlink();windows._save(path,body)
        fresh={'path':str(path),'pin':registry._json(path)[1]}
        with self.assertRaises(ValueError):registration.register(self.root,'windows-raw-foreign-v1',self.machine,SID,qualifications={'wake_display':fresh})
        self.assertFalse((self.root/'.rag_index/readiness-fixtures/windows-raw-foreign-v1.json').exists())
    def test_bad_inputs_refuse_before_anything_is_written(self):
        directory=self.root/'.rag_index/readiness-fixtures'
        for call in (lambda:registration.register(self.root,'Bad Id',self.machine,SID),lambda:registration.register(self.root,'ok-id',self.machine,'not-a-sid'),
                     lambda:registration.register(self.root,'ok-id',str(uuid.uuid4()),SID),
                     lambda:registration.write_qualification(self.root,self.machine,'start',evidence={'a':'b'}),
                     lambda:registration.write_qualification(self.root,self.machine,'reboot',evidence={}),
                     lambda:registration.write_qualification(self.root,self.machine,'reboot',evidence={'a':'with space'}),
                     lambda:registration.write_qualification(self.root,self.machine,'reboot',evidence={'a':'b'},profiles={})):
            with self.assertRaises(Exception):call()
        self.assertFalse(directory.exists() and any(directory.iterdir()))
    def test_there_is_no_public_route(self):
        catalog=(Path(windows.__file__).parent/'mcp_server.py').read_text()
        self.assertNotIn('readiness_windows_registration',catalog)


class EnrollmentPacketTests(unittest.TestCase):
    binding={'spec':{'host':'owned'}}
    def test_only_the_fixed_modes_that_type_nothing_are_admitted(self):
        for mode in ('login-submit','login-status','login-wake','login-dismiss','anything'):
            with self.subTest(mode=mode),mock.patch.object(login,'program',side_effect=AssertionError('generated')):
                with self.assertRaisesRegex(ValueError,'windows_registration_login_mode_invalid'):registration.login_enrollment_packet(Path('.'),self.binding,mode,'operation',expected_sid=SID)
    def test_one_packet_returns_its_reply_and_a_failed_transport_is_never_retried(self):
        def run(reply):
            admission=mock.MagicMock();admission.__enter__.return_value=admission
            with mock.patch.object(login,'program',return_value=b'source') as program,mock.patch.object(registration.transport,'admitted_transport',return_value=admission),\
                 mock.patch.object(registration.transport,'load_config'),mock.patch.object(registration.transport,'build_ssh_argv',return_value=['ssh']),\
                 mock.patch.object(registration.transport,'run_ssh',return_value=reply) as send:
                return registration.login_enrollment_packet(Path('.'),self.binding,'login-lock-fixture','operation',expected_sid=SID,expected={'boot':'b'}),send,program
        value,send,program=run(mock.Mock(returncode=0,stderr=b'',stdout=b'{"state":"observed"}'))
        self.assertEqual({'state':'observed'},value);send.assert_called_once();self.assertEqual({'boot':'b'},program.call_args.kwargs['expected'])
        with self.assertRaisesRegex(ValueError,'windows_registration_login_packet_failed'):run(mock.Mock(returncode=1,stderr=b'',stdout=b''))
        with self.assertRaisesRegex(ValueError,'windows_registration_login_packet_failed'):run(mock.Mock(returncode=0,stderr=b'noise',stdout=b'{}'))


class ReviewedProfileTests(unittest.TestCase):
    '''The real reviewed regions of one signed-out screen on two boots (sign-in b878ab46 refused, nothing typed).'''
    def frame(self,name):
        fixture=Path(__file__).parent/'fixtures/windows_native_tools_20261106'
        raw=(fixture/'signed-out-field-regions.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((fixture/'provenance.json').read_bytes())['sha256']['signed-out-field-regions.json'])
        value=json.loads(raw)[name];width,height=value['width'],value['height'];pixels=bytearray(width*height*3)
        for row in value['crops']:
            x0,y0,x1,y1=row['rect'];body=zlib.decompress(base64.b64decode(row['pixelsZlib']));size=(x1-x0)*3
            for index,y in enumerate(range(y0,y1)):pixels[(y*width+x0)*3:(y*width+x1)*3]=body[index*size:(index+1)*size]
        return b'P6\n%d %d\n255\n'%(width,height)+bytes(pixels)
    def crops(self,raw,regions):
        width,height,pixels=login.ppm(raw)
        return {'width':width,'height':height,'crops':[{'rect':list(r),'sha256':hashlib.sha256(b''.join(pixels[(y*width+r[0])*3:(y*width+r[2])*3] for y in range(r[1],r[3]))).hexdigest()} for r in regions]}
    def test_a_profile_with_the_avatar_refuses_the_same_screen_after_a_boot(self):
        before=self.crops(self.frame('reference'),((600,215,680,320),)+registration.FIELD_REGIONS)
        self.assertTrue(login.screen_gate(self.frame('reference'),before))
        with self.assertRaisesRegex(ValueError,'instance_login_screen_unrecognized'):login.screen_gate(self.frame('laterBoot'),before)
    def test_the_reviewed_profile_accepts_it_and_still_sees_the_account_name(self):
        profile=registration.reviewed_profile(self.frame('reference'),self.frame('reference'))
        self.assertTrue(login.screen_gate(self.frame('laterBoot'),profile['password']))
        self.assertNotIn([600,215,680,320],[row['rect'] for row in profile['password']['crops']])
        raw=bytearray(self.frame('laterBoot'));header=raw.index(b'255\n')+4
        raw[header+(390*1280+600)*3]^=1
        with self.assertRaisesRegex(ValueError,'instance_login_screen_unrecognized'):login.screen_gate(bytes(raw),profile['password'])


if __name__=='__main__':unittest.main()
