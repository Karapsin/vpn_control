"""Real fixture CONNECT producer/client and owned TCP deadline regressions."""
import concurrent.futures,hashlib,json,os,re,shutil,socket,ssl,subprocess,tempfile,threading,time,unittest
from pathlib import Path
from agent_tools import windows_ordinary_https as subject
FIXTURES=Path(__file__).resolve().parent/'fixtures/windows_ordinary_https'

def specimen(name):
    provenance=json.loads((FIXTURES/'provenance.json').read_text())
    raw=(FIXTURES/name).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=provenance['files'][name]['sha256']:
        raise AssertionError('public specimen changed')
    return raw.decode()

def powershell(native=False):
    if os.name=='nt' or native:return shutil.which('powershell.exe')
    return shutil.which('pwsh') or os.environ.get('VPN_TEST_PWSH')

class ActualTlsFixture:
    """Only synthetic endpoint/certificate/body; actual six producer functions."""
    def run(self,sources,*,duration=350,interval=None,count=30,native=False,bad_response=False):
        pw=powershell(native)
        if not pw:raise unittest.SkipTest('PowerShell required to execute actual C# reader')
        openssl=shutil.which('openssl')
        if not openssl:raise unittest.SkipTest('OpenSSL required for ephemeral TLS certificate')
        ns={'json':json,'os':os,'MANIFEST_PATH':'/Karapsin/vpn_control/releases/latest/download/update-manifest.json'}
        exec(compile(specimen('actual-fixture-producer.source'),'public_fixture_producer','exec'),ns)
        with tempfile.TemporaryDirectory(prefix='https-causal-') as td:
            tmp=Path(td);key=tmp/'key.pem';cert=tmp/'cert.pem'
            subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=github.com','-addext','subjectAltName=DNS:github.com'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
            key.chmod(0o600);pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key)
            body=b'x'*count if interval else b'{"test":true}'
            class SlowWrite:
                def __init__(self,stream):self.stream=stream
                def recv(self,*args):return self.stream.recv(*args)
                def close(self):return self.stream.close()
                def sendall(self,data):
                    if interval and data.startswith(b'HTTP/1.1 200 OK'):
                        at=data.index(b'\r\n\r\n')+4;self.stream.sendall(data[:at])
                        for value in data[at:]:time.sleep(interval);self.stream.sendall(bytes([value]))
                    else:self.stream.sendall(data)
            class Context:
                def wrap_socket(self,*args,**kwargs):return SlowWrite(tls.wrap_socket(*args,**kwargs))
            def one(index):
                source=sources[index];listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
                port=listener.getsockname()[1];events=[];tls_entered=[]
                class ObservedContext(Context):
                    def wrap_socket(self,*args,**kwargs):tls_entered.append(True);return super().wrap_socket(*args,**kwargs)
                def serve():
                    try:
                        conn,_=listener.accept();conn.settimeout(7)
                        with conn:
                            if bad_response:
                                method,target,host=ns['read_request_header'](conn)
                                events.append({'connect':method=='CONNECT','target':target,'host':host})
                                conn.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                            else:ns['serve_connection'](conn,ObservedContext(),{'assets':[]},{},body,events.append)
                    except OSError as error:events.append({'localExceptionType':type(error).__name__})
                    finally:listener.close()
                thread=threading.Thread(target=serve,daemon=True);thread.start()
                emitted=re.sub(r'Hash\(cert.GetRawCertData\(\)\)=="[0-9a-f]{64}"','Hash(cert.GetRawCertData())=="'+pin+'"',source)
                if os.name!='nt' and not native:
                    # Identical declared synthetic certificate seam: macOS .NET
                    # selfsigned SAN name mismatch; production/native keeps policy.
                    emitted=emitted.replace('(errors&SslPolicyErrors.RemoteCertificateNameMismatch)==0&&','')
                emitted=emitted.replace('null,15000,System.Threading.Timeout.Infinite','null,'+str(duration)+',System.Threading.Timeout.Infinite')
                ps=tmp/('reader-'+str(index)+'.ps1')
                ps.write_text("Add-Type -TypeDefinition @'\n"+emitted+"\n'@\n$c=[Diagnostics.Stopwatch]::StartNew();try{$b=[Cp117FreshServerHttps]::Read("+str(port)+");$v=@{state='read';body=$b}}catch{$v=@{state='refused';message=$_.Exception.Message}};$c.Stop();$v.elapsedMs=$c.ElapsedMilliseconds;$v|ConvertTo-Json -Compress\n")
                try:
                    process=subprocess.run([pw,'-NoLogo','-NoProfile','-NonInteractive','-File',str(ps)],capture_output=True,timeout=35,env={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'})
                    if process.returncode:raise AssertionError(process.stderr.decode(errors='replace'))
                    value=json.loads(process.stdout);thread.join(timeout=2)
                    return {**value,'producerEvents':events,'producerTlsEntered':bool(tls_entered)}
                finally:listener.close();thread.join(timeout=1)
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as pool:
                return list(pool.map(one,range(len(sources))))

class DeadlineRoutineTests(unittest.TestCase):
    def test_actual_producer_direct_tls_refuses_corrected_connect_reads_manifest(self):
        old,new=ActualTlsFixture().run([specimen('prior-direct-tls.cs'),subject.https_source()],duration=15000)
        self.assertEqual('refused',old['state']);self.assertIn('HTTPS_TLS_BOUND',old['message'])
        self.assertFalse(old['producerTlsEntered']);self.assertEqual('connect-admission',old['producerEvents'][0]['stage'])
        self.assertEqual(('read','{"test":true}'),(new['state'],new.get('body')));self.assertTrue(new['producerTlsEntered']);self.assertEqual([],new['producerEvents'])
    def test_actual_non200_connect_refuses_before_tls(self):
        value,=ActualTlsFixture().run([subject.https_source()],bad_response=True)
        self.assertEqual('refused',value['state']);self.assertIn('HTTPS_CONNECT_STATUS',value['message'])
        self.assertFalse(value['producerTlsEntered']);self.assertEqual([{'connect':True,'target':'github.com:443','host':'github.com'}],value['producerEvents'])
    def test_actual_slow_trickle_untimed_reader_outlives_fixed_probe(self):
        old,new=ActualTlsFixture().run([specimen('before-total-deadline.cs'),subject.https_source()],interval=.06)
        self.assertEqual(('read','x'*30),(old['state'],old['body']));self.assertGreater(old['elapsedMs'],1500)
        self.assertEqual('refused',new['state']);self.assertGreaterEqual(new['elapsedMs'],300);self.assertLess(new['elapsedMs'],1500)
        self.assertTrue(old['producerTlsEntered']);self.assertTrue(new['producerTlsEntered'])
    def test_fixed_emitter_has_no_caller_endpoint_or_policy_overrides(self):
        self.assertEqual(subject.HTTPS_SOURCE_SHA256,hashlib.sha256(subject.https_source().encode()).hexdigest())
        for args in [('example.com',),('0'*64,),(1,)]:
            with self.assertRaises(TypeError):subject.https_source(*args)
        # Supplemental exact policy preservation, real compiled network cases above.
        fixed=subject.https_source().replace('using(var deadline=new System.Threading.Timer(_=>tcp.Close(),null,15000,System.Threading.Timeout.Infinite)){','').replace('return body;}}}}}','return body;}}}}')
        self.assertEqual(specimen('before-total-deadline.cs'),fixed)

@unittest.skipUnless(os.name=='nt','Native Windows PowerShell full deadline gate')
class NativeDeadlineTests(unittest.TestCase):
    def test_actual_full_15_second_deadline_with_native_windows_powershell(self):
        self.assertTrue(powershell(True),'Native powershell.exe required')
        self.assertTrue(shutil.which('openssl'),'Ephemeral OpenSSL TLS certificate producer required')
        old,new=ActualTlsFixture().run([specimen('before-total-deadline.cs'),subject.https_source()],duration=15000,interval=.6,count=40,native=True)
        self.assertEqual(('read','x'*40),(old['state'],old['body']));self.assertGreater(old['elapsedMs'],20000)
        self.assertEqual('refused',new['state']);self.assertGreaterEqual(new['elapsedMs'],14500);self.assertLess(new['elapsedMs'],18000)
        self.assertTrue(old['producerTlsEntered']);self.assertTrue(new['producerTlsEntered'])

if __name__=='__main__':unittest.main()
