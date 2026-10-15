"""Linux real-worker close ordering; no guest, VM, SSH or installer actions."""
import ast
import base64
import errno
import hashlib
import http.client
import inspect
import json
import os
from pathlib import Path
import socket
import sys
import time
import unittest
from urllib.parse import urlsplit

from agent_tools import windows_msi_http_transfer as transfer
from agent_tools.tests import test_windows_msi_http_transfer as fixtures


FIXTURE=Path(__file__).parent/'fixtures/msi_listener_close_order'
METHOD='test_one_use_listener_serves_exact_staged_bytes'


def source(before):
    provenance=json.loads((FIXTURE/'provenance.json').read_bytes())
    raw=(FIXTURE/'before.source').read_bytes()
    if len(raw)!=provenance['sourceBytes']or hashlib.sha256(raw).hexdigest()!=provenance['sourceSha256']:
        raise ValueError('listener_before_source_changed')
    if (hashlib.sha256(Path(transfer.__file__).read_bytes()).hexdigest()!=provenance['producerSha256']
            or hashlib.sha256(transfer._HTTP_WORKER.encode()).hexdigest()!=provenance['workerSha256']):
        raise ValueError('listener_actual_worker_source_changed')
    if before:return raw.decode()
    current=inspect.getsource(getattr(fixtures.TransferTests,METHOD))
    import textwrap
    current=textwrap.dedent(current)
    node=next(node for node in ast.parse(current).body if isinstance(node,ast.FunctionDef)and node.name==METHOD)
    return ast.get_source_segment(current,node)+'\n'


def tcp_rows(port):
    rows=[]
    for name in ('/proc/net/tcp','/proc/net/tcp6'):
        for line in Path(name).read_text().splitlines()[1:]:
            fields=line.split()
            if len(fields)>=10 and int(fields[1].split(':')[1],16)==port:
                rows.append({'table':name,'state':fields[3],'row':line})
    return rows


def actual_free_port(port):
    tree=ast.parse(transfer._REMOTE_COMMON)
    node=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='free_port')
    namespace={'socket':socket}
    exec(compile(ast.get_source_segment(transfer._REMOTE_COMMON,node),'<actual-free-port>','exec'),namespace)
    namespace['free_port'](port)


def native_case(before):
    class NativeCase(unittest.TestCase):
        request=fixtures.TransferTests.request
        args=fixtures.TransferTests.args

        def setUp(self):
            self.trace={'before':before,'python':sys.version,'remoteCalls':[],'receipts':{},'getCount':0}
            self.stage=None;self.started=None
            self.trace['sourceSha256']=hashlib.sha256(source(before).encode()).hexdigest()

        def snapshot(self):
            if self.stage is None:return
            for name in ('binding.json','download-intent.json','worker.json','listener-ready.json',
                         'listener-done.json','listener-stopped.json'):
                path=self.stage/name
                if path.is_file()and not path.is_symlink():
                    raw=path.read_bytes()
                    self.assertLessEqual(len(raw),65536)
                    self.trace['receipts'][name]={'rawBase64':base64.b64encode(raw).decode(),
                                                  'sha256':hashlib.sha256(raw).hexdigest()}

        def run_remote(self,program,args,payload=b''):
            self.stage=Path(args[0])/args[1]/'windows-msi-http-transfer'/args[2]
            argv=[sys.executable,'-c',program,*args]
            self.assertLessEqual(sum(len(os.fsencode(word))+1 for word in argv),60000)
            result=fixtures.TransferTests.run_remote(self,program,args,payload)
            kind=next((name for name in ('_REMOTE_STAGE','_REMOTE_LISTEN_START','_REMOTE_LISTEN_STATUS',
                                        '_REMOTE_CLEANUP','_REMOTE_LISTEN_STOP')if getattr(transfer,name)==program),'unexpected')
            self.trace['remoteCalls'].append({'kind':kind,'result':result})
            if kind=='_REMOTE_LISTEN_START':self.started=result
            self.snapshot()
            return result

        def server_first_urlopen(self,url,timeout):
            parsed=urlsplit(url)
            self.assertEqual(('http','127.0.0.1'),(parsed.scheme,parsed.hostname))
            self.assertEqual(self.started['port'],parsed.port)
            self.assertEqual(self.started['path'],parsed.path)
            owner=self
            class Response:
                def read(self):
                    owner.trace['getCount']+=1
                    owner.assertEqual(1,owner.trace['getCount'])
                    # Retain the raw socket after HTTPResponse closes its file
                    # at Content-Length. Only actual server EOF permits close.
                    with socket.create_connection(('127.0.0.1',parsed.port),timeout=timeout)as connection:
                        connection.sendall(('GET '+parsed.path+' HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n').encode())
                        response=http.client.HTTPResponse(connection);response.begin()
                        owner.assertEqual(200,response.status)
                        body=response.read(19)
                        owner.assertEqual(b'local-loopback-msi',body)
                        owner.assertGreaterEqual(connection.fileno(),0)
                        owner.assertEqual(b'',connection.recv(1),'must observe actual server FIN first')
                        owner.trace['beforeClientCloseTcp']=tcp_rows(parsed.port)
                    deadline=time.monotonic()+3;done=None;rows=[]
                    while time.monotonic()<deadline:
                        try:done=json.loads((owner.stage/'listener-done.json').read_bytes())
                        except (FileNotFoundError,ValueError):done=None
                        rows=tcp_rows(parsed.port)
                        if done=={'served':True}and any(row['state']=='06'for row in rows):break
                        time.sleep(.01)
                    owner.assertEqual({'served':True},done)
                    owner.assertTrue(any(row['state']=='06'for row in rows),'actual listener port must be TIME_WAIT')
                    owner.trace['afterClientCloseTcp']=rows
                    try:actual_free_port(parsed.port)
                    except OSError as error:
                        owner.assertEqual(errno.EADDRINUSE,error.errno)
                        owner.trace['freePortErrno']=error.errno
                    else:owner.fail('Linux original free_port must refuse actual server TIME_WAIT')
                    owner.snapshot()
                    return body
            return Response()

        def tearDown(self):
            try:
                starts=[row for row in self.trace['remoteCalls']if row['kind']=='_REMOTE_LISTEN_START']
                self.assertEqual(1,len(starts))
                self.assertEqual('listening',starts[0]['result']['state'])
                self.assertEqual('unknown'if before else'stopped',self.trace['remoteCalls'][-1]['result']['state'])
                self.assertEqual('_REMOTE_LISTEN_STOP',self.trace['remoteCalls'][-1]['kind'])
                ready=self.trace['receipts'].get('listener-ready.json')
                if ready:
                    value=json.loads(base64.b64decode(ready['rawBase64']))
                    entries=tcp_rows(value['port'])
                    self.assertFalse(any(row['state']=='0A'for row in entries),'owned one-use listener must close')
                    self.trace['closingTcp']=entries
                    deadline=time.monotonic()+3;terminal=False
                    while time.monotonic()<deadline:
                        try:fields=Path('/proc/'+str(value['pid'])+'/stat').read_bytes().rsplit(b') ',1)[1].split()
                        except FileNotFoundError:
                            terminal=True;self.trace['originalProcess']='absent';break
                        if fields[19].decode()!=value['startTicks']or fields[0]in(b'Z',b'X'):
                            terminal=True;self.trace['originalProcess']='original-birth-terminal';break
                        time.sleep(.01)
                    self.assertTrue(terminal,'exact owned listener process must become terminal')
            finally:
                print(json.dumps({'listenerCloseOrder':self.trace,'nativeLinux':True,'guestAction':False},sort_keys=True),flush=True)

    namespace=dict(vars(fixtures));namespace['urlopen']=lambda url,timeout:case.server_first_urlopen(url,timeout)
    exec(compile(source(before),str(FIXTURE/'before.source')if before else'<actual-current-positive-method>','exec'),namespace)
    setattr(NativeCase,METHOD,namespace[METHOD])
    if not sys.platform.startswith('linux'):
        NativeCase=unittest.skip('Actual Linux TCP TIME_WAIT and full listener status required')(NativeCase)
    case=NativeCase(METHOD)
    return case


@unittest.skipUnless(sys.platform.startswith('linux'),'Actual Linux TCP TIME_WAIT and full listener status required')
class ListenerCloseOrderTests(unittest.TestCase):
    def test_preserved_positive_method_is_sole_served_unknown_red(self):
        result=unittest.TestResult();case=native_case(True);case.run(result)
        trace=result.failures[0][1]if result.failures else''
        observed=[row['result'].get('state')for row in case.trace['remoteCalls']if row['kind']=='_REMOTE_LISTEN_STATUS']
        self.assertLessEqual(len(trace.encode()),8192)
        print(json.dumps({'listenerCounterfactual':{'testsRun':result.testsRun,'errors':len(result.errors),
              'skips':len(result.skipped),'failures':len(result.failures),'positiveExpected':'served',
              'originalObserved':observed[-1]if observed else None,'assertionTrace':trace,'python':sys.version}},sort_keys=True),flush=True)
        self.assertEqual(1,result.testsRun);self.assertEqual([],result.errors);self.assertEqual([],result.skipped)
        self.assertEqual(1,len(result.failures),result.failures)
        self.assertIn("'unknown' != 'served'",result.failures[0][1])
        self.assertEqual(errno.EADDRINUSE,case.trace['freePortErrno'])

    def test_actual_current_positive_method_is_strict_served_green(self):
        result=unittest.TestResult();case=native_case(False);case.run(result)
        self.assertEqual([],result.errors);self.assertEqual([],result.failures);self.assertEqual([],result.skipped)
        self.assertEqual(1,result.testsRun)
        statuses=[row['result']['state']for row in case.trace['remoteCalls']if row['kind']=='_REMOTE_LISTEN_STATUS']
        self.assertTrue(statuses);self.assertEqual('served',statuses[-1])
        self.assertEqual(1,sum(row['kind']=='_REMOTE_LISTEN_START'for row in case.trace['remoteCalls']))


if __name__=='__main__':
    if '--legacy-red'in sys.argv:
        result=unittest.TextTestRunner(verbosity=2).run(native_case(True))
        raise SystemExit(not result.wasSuccessful())
    unittest.main()
