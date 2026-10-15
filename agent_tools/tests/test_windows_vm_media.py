"""Actual UDF/WIM bytes and complete start-admission before/fix boundaries."""
import hashlib,inspect,io,json,os,struct,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest import mock
import pycdlib
from agent_tools import windows_vm_media as media,windows_vm_deploy as deploy
from agent_tools.tests.test_native_vm_spec import request


def wim(*,flags=2,name='Windows 11 Enterprise Evaluation',count=1):
    raw=('<WIM><IMAGE INDEX="1"><NAME>'+name+'</NAME><WINDOWS><ARCH>9</ARCH><EDITIONID>EnterpriseEval</EDITIONID><LANGUAGES><LANGUAGE>en-US</LANGUAGE></LANGUAGES></WINDOWS></IMAGE></WIM>').encode('utf-16')
    header=bytearray(208);header[:8]=b'MSWIM\0\0\0';struct.pack_into('<I',header,8,208)
    struct.pack_into('<HHI',header,40,1,1,count);struct.pack_into('<QQQ',header,72,len(raw)|(flags<<56),208,len(raw))
    return bytes(header)+raw


class MediaTests(unittest.TestCase):
    def test_preserved_xml_flags_refuse_real_metadata_current_accepts_it(self):
        folder=Path(__file__).parent/'fixtures/media_xml_flags';raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before={};exec(compile(raw,str(folder/'before.source'),'exec'),before)
        with self.assertRaisesRegex(ValueError,'media_wim_xml_resource'):before['read_wim_images'](io.BytesIO(wim()))
        self.assertEqual('EnterpriseEval',media.read_wim_images(io.BytesIO(wim()))[0]['editionId'])
        for raw in (wim(flags=4),wim(count=2),wim()[:-2],b'INVALID',wim(name='bad\nname')):
            with self.subTest(bytes=len(raw)),self.assertRaises(ValueError):media.read_wim_images(io.BytesIO(raw))

    def test_actual_udf_only_payload_reads_in_isolated_process_and_removes_reader(self):
        capsule=media.dependency_capsule(media.dependency_sources())
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/'installer.iso'
            iso=pycdlib.PyCdlib();iso.new(udf='2.60');iso.add_directory('/SOURCES',udf_path='/sources')
            raw=wim();iso.add_fp(io.BytesIO(raw),len(raw),udf_path='/sources/install.wim')
            iso.write(str(path));iso.close()
            body=('import os,json,sys\nMEDIA_READER='+repr(capsule)+'\n'+inspect.getsource(media.read_wim_images)+'\n'+inspect.getsource(media.installer_images)+'''\nfd=os.open(sys.argv[1],os.O_RDONLY)
try:
 images=installer_images(fd)
 assert not any(n=='pycdlib' or n.startswith('pycdlib.') for n in sys.modules)
 assert not any('vpn-control-media-reader-' in p for p in sys.path)
 print(json.dumps(images))
finally:os.close(fd)
''')
            programme=root/'reader.py';programme.write_text(body)
            result=subprocess.run([sys.executable,'-I','-B',str(programme),str(path)],capture_output=True,timeout=15)
            self.assertEqual(0,result.returncode,result.stderr.decode())
            self.assertEqual('Windows 11 Enterprise Evaluation',json.loads(result.stdout)[0]['name'])

    @unittest.skipUnless(os.name=='posix','POSIX coordinator fixture')
    def test_missing_requested_image_before_would_submit_fixed_refuses_before_any_preparation(self):
        folder=Path(__file__).parent/'fixtures/media_image_admission';raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._media_admission_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        settings={'imageName':'Windows 11 Pro','locale':'en-US','user':'ordinary','administrator':'fixtureAdmin'}
        images=media.read_wim_images(io.BytesIO(wim()))
        for module,fixed in ((before,False),(deploy,True)):
            with self.subTest(fixed=fixed),tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
                root=Path(temporary).resolve();root.chmod(0o700);credential=root/'sudo.secret'
                credential.write_text('INERT_LOCAL_FIXTURE\n');credential.chmod(0o600)
                prepared={'request':{},'reservation':{},'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[]}
                def native(_root,_spec,mode,**kwargs):
                    return {'state':'media-observed','images':images} if mode=='media' else {'state':'unknown'}
                with mock.patch.object(module,'_prepare_reservation',return_value=prepared) as reserve,mock.patch.object(module,'_execute',side_effect=native) as effect:
                    result=module.start(root,request(),settings,str(credential))
                    if fixed:
                        self.assertEqual('media_requested_image_unavailable',result['reason']);self.assertFalse(result['vmSubmitted'])
                        reserve.assert_not_called();self.assertFalse((root/'.runtime/windows-vm-credentials').exists())
                        self.assertEqual(['media'],[c.args[2] for c in effect.call_args_list])
                    else:
                        self.assertEqual('unknown',result['state']);reserve.assert_called_once()
                        self.assertEqual(['start'],[c.args[2] for c in effect.call_args_list])

    def test_matching_name_and_language_both_required(self):
        images=media.read_wim_images(io.BytesIO(wim()))
        self.assertEqual(1,media.select_image(images,{'imageName':images[0]['name'],'locale':'en-US'})['index'])
        for args in ({'imageName':'Windows 11 Pro','locale':'en-US'},{'imageName':images[0]['name'],'locale':'fr-FR'}):
            with self.assertRaisesRegex(ValueError,'media_requested_image_unavailable'):media.select_image(images,args)


if __name__=='__main__':unittest.main()
