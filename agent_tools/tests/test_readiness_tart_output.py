"""Complete harmless child callers; private Tart output never reaches logs."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import readiness_tart_output as subject

_CHILD = '''import os,sys,time
secret=os.read(int(sys.argv[1]),128)
mode=sys.argv[2]
if mode=='timeout':time.sleep(2)
else:
 line=b'VNC server is running at vnc://:'+secret+b'@127.0.0.1:5999\\r\\n'
 os.write(1,b'private banner '+secret+b'\\n'+line)
 os.write(2,b'private stderr echo '+secret+b' vnc://:'+secret+b'@127.0.0.1:5999\\n')
'''


@unittest.skipUnless(os.name=='posix','protected Tart owner file/FD custody')
class TartOutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.secret=b'gentle-river-silver-moon'
    def child(self,mode='normal'):
        reader,writer=os.pipe();os.write(writer,self.secret);os.close(writer)
        try:
            child=subprocess.Popen([sys.executable,'-I','-c',_CHILD,str(reader),mode],pass_fds=(reader,),
                                   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        finally:os.close(reader)
        def close():
            if child.poll()is None:child.terminate()
            child.wait(timeout=3)
            child.stdout.close();child.stderr.close()
        self.addCleanup(close)
        return child
    def line(self,secret=None,port=b'5999',ending=b'\n'):
        return b'VNC server is running at vnc://:'+(secret or self.secret)+b'@127.0.0.1:'+port+ending

    def test_complete_real_child_stdout_stderr_are_redacted_before_any_owner_stream(self):
        child=self.child();public=[]
        with subject.ProtectedRunOutput(self.root)as output,mock.patch.object(hashlib,'sha256',side_effect=AssertionError('no secret/output hashes')):
            result=subject.consume(child.stdout,child.stderr,output,deadline=time.monotonic()+3,on_endpoint=public.append)
            self.assertEqual([{'port':5999}],public)
            self.assertEqual(5999,result['port'])
            metadata=output.credential_metadata();reader=output.credential_fd()
            try:self.assertEqual(self.secret,os.read(reader,128))
            finally:os.close(reader)
        self.assertEqual(0,child.wait(timeout=2))
        self.assertEqual(0o600,stat.S_IMODE((self.root/'vnc-auth.bin').stat().st_mode))
        self.assertEqual(1,(self.root/'vnc-auth.bin').stat().st_nlink)
        published=json.dumps({'result':result,'metadata':metadata,'public':public})
        self.assertNotIn(self.secret.decode(),published);self.assertNotIn('vnc://',published)
        self.assertEqual(['vnc-auth.bin'],[p.name for p in self.root.iterdir()])

    def test_every_byte_boundary_and_crlf_is_accepted_without_buffering_private_echo(self):
        with subject.ProtectedRunOutput(self.root)as output:
            for value in b'private echo '+self.secret+b'\r\n'+self.line(ending=b'\r\n'):
                output.feed('stdout',bytes([value]))
            output.feed('stderr',self.secret)
            self.assertEqual({'port':5999},output.endpoint())
            self.assertEqual(5999,output.finish()['port'])
            self.assertEqual(b'',output._buffer)

    def test_actual_standalone_generated_owner_needs_no_repository_import_and_retains_no_raw_streams(self):
        reader,writer=os.pipe();os.write(writer,self.secret);os.close(writer)
        program=subject.standalone_source()+'''import json,os,subprocess,sys,time
from pathlib import Path
child=subprocess.Popen([sys.executable,'-I','-c',CHILD,sys.argv[2],'normal'],pass_fds=(int(sys.argv[2]),),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
with _tart_output.ProtectedRunOutput(Path(sys.argv[1]))as output:
 result=_tart_output.consume(child.stdout,child.stderr,output,deadline=time.monotonic()+3)
print(json.dumps(result,sort_keys=True));child.wait(timeout=2)
'''
        program='CHILD='+repr(_CHILD)+'\n'+program
        try:
            result=subprocess.run([sys.executable,'-I','-c',program,str(self.root),str(reader)],pass_fds=(reader,),
                                  stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        finally:os.close(reader)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(5999,json.loads(result.stdout)['port'])
        self.assertEqual(b'',result.stderr);self.assertNotIn(self.secret,result.stdout)
        self.assertNotIn(self.secret,program.encode())
        self.assertEqual(self.secret,(self.root/'vnc-auth.bin').read_bytes())

    def test_malformed_known_line_overflow_and_timeout_emit_only_fixed_blockers(self):
        cases=[(self.line(port=b'65536'),'vnc_line_malformed'),(self.line(port=b'0001'),'vnc_line_malformed'),
               (self.line(secret=b'Gentle-river-silver-moon'),'vnc_line_malformed'),
               (self.line(secret=b'longwordxx-river-silver-moon'),'vnc_line_malformed'),
               (self.line().replace(b'127.0.0.1',b'localhost'),'vnc_line_malformed'),
               (b'x'*513,'line_overflow')]
        for index,(wire,reason)in enumerate(cases):
            directory=self.root/str(index);directory.mkdir(mode=0o700)
            with subject.ProtectedRunOutput(directory)as output:
                with self.assertRaisesRegex(subject.OutputBlocked,'tart_output_'+reason)as caught:output.feed('stdout',wire)
                self.assertNotIn(self.secret.decode(),str(caught.exception));self.assertEqual(b'',output._buffer)
            self.assertEqual([],list(directory.iterdir()))
        directory=self.root/'overflow';directory.mkdir(mode=0o700)
        with subject.ProtectedRunOutput(directory)as output:
            with self.assertRaisesRegex(subject.OutputBlocked,'stream_overflow'):output.feed('stderr',self.secret*3000)
        directory=self.root/'timeout';directory.mkdir(mode=0o700);child=self.child('timeout')
        with subject.ProtectedRunOutput(directory)as output:
            with self.assertRaisesRegex(subject.OutputBlocked,'^tart_output_deadline$'):
                subject.consume(child.stdout,child.stderr,output,deadline=time.monotonic()+.05)
        self.assertEqual([],list(directory.iterdir()))

    def test_lost_client_retains_once_credential_and_refuses_replacement_without_secret_logging(self):
        child=self.child()
        def lost(public):raise RuntimeError('private client exception '+self.secret.decode())
        with subject.ProtectedRunOutput(self.root)as output:
            with self.assertRaisesRegex(subject.OutputBlocked,'^tart_output_consumer_unknown$')as caught:
                subject.consume(child.stdout,child.stderr,output,deadline=time.monotonic()+3,on_endpoint=lost)
        self.assertNotIn(self.secret.decode(),str(caught.exception))
        self.assertTrue((self.root/'vnc-auth.bin').is_file())
        before=(self.root/'vnc-auth.bin').stat()
        with self.assertRaisesRegex(subject.OutputBlocked,'^tart_output_original_exists$'):
            subject.ProtectedRunOutput(self.root)
        self.assertEqual(before,(self.root/'vnc-auth.bin').stat())

    def test_duplicate_incomplete_line_and_metadata_replacement_never_authorize_reader(self):
        with subject.ProtectedRunOutput(self.root)as output:
            output.feed('stdout',self.line())
            with self.assertRaisesRegex(subject.OutputBlocked,'vnc_line_duplicate'):output.feed('stdout',self.line())
            with self.assertRaisesRegex(subject.OutputBlocked,'original_unavailable'):output.credential_fd()
        directory=self.root/'partial';directory.mkdir(mode=0o700)
        with subject.ProtectedRunOutput(directory)as output:
            output.feed('stdout',self.line(ending=b''))
            with self.assertRaisesRegex(subject.OutputBlocked,'vnc_line_incomplete'):output.finish()
        self.assertEqual([],list(directory.iterdir()))
        directory=self.root/'changed';directory.mkdir(mode=0o700)
        with subject.ProtectedRunOutput(directory)as output:
            output.feed('stdout',self.line());path=directory/'vnc-auth.bin';path.unlink();path.write_bytes(b'foreign');path.chmod(0o600)
            with self.assertRaisesRegex(subject.OutputBlocked,'credential_changed'):output.credential_fd()

    def test_arbitrary_unrecognized_lines_and_stderr_cannot_supply_endpoint(self):
        with subject.ProtectedRunOutput(self.root)as output:
            output.feed('stdout',b'Opening vnc://:'+self.secret+b'@127.0.0.1:5999...\n')
            output.feed('stderr',self.line())
            self.assertIsNone(output.endpoint())
            with self.assertRaisesRegex(subject.OutputBlocked,'endpoint_unavailable'):output.finish()
        self.assertEqual([],list(self.root.iterdir()))


if __name__=='__main__':unittest.main()
