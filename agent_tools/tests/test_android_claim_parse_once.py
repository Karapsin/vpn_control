"""Complete consumed postcollector ingress, real create-only evidence, inert data.

No native captures, credentials, SSH, ADB, .runtime source dependencies or mocked
success validators. The only I/O seams are a local pipe child and TempFS source
pin guard; real original terminal, guard projection and claim parser all execute.
"""
import base64,copy,hashlib,io,json,os,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from contextlib import redirect_stdout
from agent_tools import android_installer_component_bundle as bundle
from agent_tools import windows_diagnostic_authority_capture as authority
from agent_tools.tests.fixtures import android_claim_parse_once as fixture


def b64(raw):return base64.b64encode(raw).decode()

def parents(path):
    result={};p=Path(path)
    while True:
        result[str(p)]=[1,100,stat.S_IFDIR|0o700,1000,1000]
        if p==p.parent:return result
        p=p.parent


def proof_fixture():
    # Full source-shaped, explicitly synthetic evidence. Authority is checked by
    # the real projection; no production success callback is substituted.
    request={'expectedOwner':'22222222-2222-4222-8222-222222222222'}
    certificate_raw=b'{"fixture":"synthetic-certificate"}\n'
    certificate_pin={'sha256':fixture.digest(certificate_raw)}
    generation={'child':{'pid':10},'guest':{'pid':20},'device':{'boot':'inert'}}
    certificate={'facts':{'packagePath':'/inert-package/base.apk'},'stage':{'id':'inert'},'host':{'uid':1000},'appProcess':{'pid':30}}
    observations=[]
    words=[['shell','-T','getprop',prop]for _,prop in bundle._PROPERTIES]+[
        ['shell','-T','id','-u'],['shell','-T','cat','/proc/sys/kernel/random/boot_id'],
        ['shell','-T','sh -c '+__import__('shlex').quote(bundle._PROCESS_READ)],
        ['shell','-T','pm','path','com.kardinal.vpncontrol'],['shell','-T','sha256sum',certificate['facts']['packagePath']],
        ['shell','-T','pidof','com.kardinal.vpncontrol'],['shell','-T','ps','-A','-o','PID,UID,NAME'],['shell','-T','cat','/proc/30/stat']]
    for _ in range(2):
        observations.append({'certificatePath':'/inert-certificate','certificatePin':certificate_pin,'certificateSha256':certificate_pin['sha256'],'rawBase64':b64(certificate_raw)})
        observations.append({'originalGeneration':{'state':'guest-generation-admitted','guestAdmitted':True,**generation}})
        for command in words:
            observations.append({'words':command,'result':{'returncode':0,'stdoutRaw':'synthetic OS reply','stderrRaw':''},
                'captures':[{'failure':None,'returncode':0,'stdoutBase64':b64(b'synthetic OS reply'),'stderrBase64':''}]})
    records=[]
    admission={key:certificate[key]for key in ('facts','stage','host')}
    values=[('component-guard-current-admission.json',admission)]
    for i,command in enumerate([['status'],['operations','list'],['status']]):
        data={'operations':[]}if command==['operations','list']else{'runtimeRunning':False,'runtimeObservation':'stopped'}
        reply={'requestId':str(i),'ok':True,'final':True,'code':'OK','controllerId':request['expectedOwner'],'configurationRevision':0,'data':data}
        values.append(('component-guard-read-'+str(i).zfill(5)+'.json',{'phase':'baseline','words':command,'returncode':0,'stderrRaw':'','stdoutRaw':json.dumps(reply)}))
    for name,record in values:
        raw=fixture.encoded({'binding':request,'phase':'baseline-read-only','installerLeaseGranted':False,'record':record})
        records.append({'name':name,'bytes':len(raw),'sha256':fixture.digest(raw),'pin':{'sha256':fixture.digest(raw)},'rawBase64':b64(raw)})
    job=fixture.REMOTE_ROOT+'/android-installer-'+fixture.ORIGINAL
    row={'records':[{'path':p,'state':'absent','parents':parents(str(Path(p).parent))}for p in fixture.fixed_record_paths()],
        'inventories':[{'path':p,'generation':[1,100,stat.S_IFDIR|0o700,1000,1000,2,0,1,1],'parents':parents(p),'names':[]}for p in (job,job+'/output')], 'workers':[]}
    result={'state':'original-claim-observed','originalCorrelationId':fixture.ORIGINAL,'passes':[row,copy.deepcopy(row)],'claimGranted':False,'releaseGranted':False,'originalOutcomeChanged':False,'acceptanceComplete':False}
    fifo=[1,200,stat.S_IFIFO|0o600,1000,1000,1,0,1,1]
    proof={'schema':1,'kind':'api35-original-claim-census-proof','request':request,'failure':None,'failureDetail':None,
        'installedLauncherAccepted':False,'bundledRuntimeAccepted':False,'acceptanceComplete':False,'records':records,
        'carrierSourceStdinPin':fifo,'carrierInitialStdinPin':fifo,'originalFileLimit':[-1,-1],'admittedFileLimit':[8388608,8388608],
        'certificateObservations':observations,'certificatePin':certificate_pin,'certificateSha256':certificate_pin['sha256'],'backup':result}
    state={'source':b'fixed inert source; no guest effects','request':request,'certificate':certificate,'certificatePin':certificate_pin,
        'certificatePath':'/inert-certificate','certificateSha256':certificate_pin['sha256'],'getterGeneration':generation,'ledger':[]}
    return proof,state


def wrapped(proof,state,stderr=b''):
    raw=fixture.encoded(proof)
    header={'schema':1,'kind':'api29-component-baseline-terminal','returncode':0,'failure':None,
        'hostIdentity':{'uid':1000,'euid':1000,'gid':1000,'egid':1000,'groups':[1000]},
        'sourceBytes':len(state['source']),'sourceSha256':fixture.digest(state['source']),
        'stdoutBytes':len(raw),'stdoutSha256':fixture.digest(raw),'stderrBytes':len(stderr),'stderrSha256':fixture.digest(stderr)}
    result=fixture.encoded(header)
    for label,stream in [('out',raw),('err',stderr)]:
        for start in range(0,len(stream),fixture.CHUNK):result+=label.encode()+b':'+base64.b64encode(stream[start:start+fixture.CHUNK])+b'\n'
    return result


class ClaimParseOnceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.proof,self.state=proof_fixture()
        self.pin_path=self.root/'source';self.pin_path.write_bytes(self.state['source']);self.pin_path.chmod(0o600)
        self.pin=self.source_snapshot();self.collect_count=0;self.guard_count=0

    def source_snapshot(self):
        fd=os.open(self.pin_path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd);raw=os.read(fd,65536);after=os.fstat(fd);named=self.pin_path.lstat()
            pin=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            if pin(before)!=pin(after)or pin(after)!=pin(named):raise ValueError('source_changed')
            return pin(after),raw
        finally:os.close(fd)

    def guard(self,state):
        self.guard_count+=1
        if self.source_snapshot()!=self.pin:raise ValueError('source_changed')

    def setup_capture(self,leaf):
        (self.root/'.runtime/parity-evidence'/leaf).mkdir(parents=True,mode=0o700)
        cap=authority.AuthorityCapture(self.root,leaf);self.addCleanup(cap.close)
        state={**self.state,'capture':cap,'leaf':leaf}
        namespace=dict(vars(fixture))
        namespace.update(guard=self.guard,__authenticated_raw=fixture.PARENT_VALIDATE_SOURCE)
        return cap,state,namespace

    def collect(self,raw):
        self.collect_count+=1
        # Managed local child supplies actual complete PIPE EOF. It neither
        # executes source/state nor evaluates proof and has no native transport.
        child=subprocess.run([sys.executable,'-I','-B','-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],input=raw,capture_output=True,timeout=2)
        self.assertEqual(0,child.returncode);self.assertEqual(b'',child.stderr)
        return child.stdout

    def files(self,cap):return {p.name:p.read_bytes()for p in cap.path.iterdir()}

    def test_whole_original_ingress_collision_red_fixed_consume_once_green(self):
        raw=wrapped(self.proof,self.state);cap,state,ns=self.setup_capture('old')
        ns['collect']=lambda unused,credential:self.collect(raw)
        scope={**vars(fixture),'ns':ns,'state':state,'cap':cap,'credential':b''}
        with redirect_stdout(io.StringIO()),self.assertRaises(FileExistsError):
            exec(compile(fixture.ORIGINAL_TAIL,'<actual-original-postcollector-main>','exec'),scope)
        self.assertEqual(1,self.collect_count);self.assertEqual(1,self.guard_count)
        self.assertIn('remote-terminal.json',self.files(cap));self.assertNotIn('claim-summary.json',self.files(cap))
        before=self.files(cap)
        with self.assertRaises(FileExistsError):fixture.parse_terminal(raw,state)
        self.assertEqual(before,self.files(cap))
        cap,state,ns=self.setup_capture('fixed')
        actual=self.collect(raw)
        parsed,proof=fixture.consume_once(ns,vars(fixture),actual,state)
        # Execute the exact original final summary tail after full validation.
        scope={**vars(fixture),'ns':ns,'state':state,'cap':cap,'raw':actual,'proof':proof,'result':proof['backup']}
        with redirect_stdout(io.StringIO()):exec(compile(fixture.SUMMARY_TAIL,'<unchanged-summary-tail>','exec'),scope)
        self.assertEqual(fixture.encoded(self.proof),parsed);self.assertEqual(2,self.collect_count);self.assertEqual(2,self.guard_count)
        summary=json.loads((cap.path/'claim-summary.json').read_bytes())
        self.assertFalse(summary['claimGranted']);self.assertFalse(summary['releaseGranted']);self.assertFalse(summary['acceptanceComplete'])
        self.assertTrue(any(name.startswith('guard-record-')for name in self.files(cap)))
        self.assertTrue(any(name.startswith('certificate-observations')for name in self.files(cap)))

    def test_invalid_guard_evidence_never_publishes_summary(self):
        proof=copy.deepcopy(self.proof);proof['records'][0]['sha256']='0'*64
        cap,state,ns=self.setup_capture('bad-guard')
        with self.assertRaisesRegex(ValueError,'evidence_bytes_changed'):
            fixture.consume_once(ns,vars(fixture),self.collect(wrapped(proof,state)),state)
        self.assertIn('remote-terminal.json',self.files(cap));self.assertNotIn('claim-summary.json',self.files(cap))

    def test_hashed_foreign_public_owner_still_refused_by_actual_projection(self):
        proof=copy.deepcopy(self.proof);row=proof['records'][1]
        evidence=json.loads(base64.b64decode(row['rawBase64']));reply=json.loads(evidence['record']['stdoutRaw'])
        reply['controllerId']='44444444-4444-4444-8444-444444444444'
        evidence['record']['stdoutRaw']=json.dumps(reply);raw=fixture.encoded(evidence)
        row.update(bytes=len(raw),sha256=fixture.digest(raw),pin={'sha256':fixture.digest(raw)},rawBase64=b64(raw))
        cap,state,ns=self.setup_capture('foreign-owner')
        with self.assertRaisesRegex(ValueError,'public_owner_unknown'):
            fixture.consume_once(ns,vars(fixture),self.collect(wrapped(proof,state)),state)
        self.assertNotIn('claim-summary.json',self.files(cap))

    def test_claim_pass_drift_cannot_publish_summary(self):
        proof=copy.deepcopy(self.proof);proof['backup']['passes'][1]['workers']=[{'state':'absent'}]
        cap,state,ns=self.setup_capture('claim-drift')
        with self.assertRaisesRegex(ValueError,'claim_result_unstable'):
            fixture.consume_once(ns,vars(fixture),self.collect(wrapped(proof,state)),state)
        self.assertIn('remote-terminal.json',self.files(cap));self.assertNotIn('claim-summary.json',self.files(cap))

    def test_source_drift_after_collect_refuses_with_terminal_retained(self):
        cap,state,ns=self.setup_capture('source-drift');raw=self.collect(wrapped(self.proof,state))
        self.pin_path.write_bytes(b'changed source')
        with self.assertRaisesRegex(ValueError,'source_changed'):fixture.consume_once(ns,vars(fixture),raw,state)
        self.assertIn('remote-terminal.json',self.files(cap));self.assertNotIn('claim-summary.json',self.files(cap))

    def test_transport_stderr_unknown_retains_bounded_raw(self):
        cap,state,ns=self.setup_capture('stderr')
        with self.assertRaisesRegex(ValueError,'terminal_unknown_raw_retained'):
            fixture.consume_once(ns,vars(fixture),self.collect(wrapped(self.proof,state,b'inert error')),state)
        self.assertIn('remote-terminal.json',self.files(cap));self.assertEqual(b'inert error',(cap.path/'remote-stderr-0.private').read_bytes())
        self.assertNotIn('claim-summary.json',self.files(cap))

    def test_changed_frame_digest_cannot_become_proof(self):
        cap,state,ns=self.setup_capture('digest')
        raw=wrapped(self.proof,state);header,rest=raw.split(b'\n',1);value=json.loads(header);value['stdoutSha256']='0'*64
        with self.assertRaisesRegex(ValueError,'stream_changed'):
            fixture.consume_once(ns,vars(fixture),fixture.encoded(value)+rest,state)
        self.assertNotIn('claim-summary.json',self.files(cap))


if __name__=='__main__':unittest.main()
