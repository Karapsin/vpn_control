"""Real POSIX bounded PIPE transport + complete generated claim entry.

Explicit seams: TempFS app files, inherited host/ADB/privilege observations and
BaselineGuard. No Android/SSH/native execution. The exact consumed reader keeps
30s/1MiB limits, EOF handling and retained raw; complete original parsers execute.
"""
import base64,copy,hashlib,json,os,re,select,shlex,stat,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from agent_tools.tests.fixtures import android_install_session_dump_selector as fixture


def parser_scope():
    scope={'re':re,'hashlib':hashlib,'json':json,'BASELINE_BASE64':base64}
    exec(compile(fixture.FUNCTIONS,'<exact-session-functions>','exec'),scope)
    return scope


class SessionProjectionTests(unittest.TestCase):
    def setUp(self):self.scope=parser_scope()
    def test_official_source_metadata_is_android15_exact(self):
        self.assertEqual(2,len(fixture.OFFICIAL_ANDROID15_SOURCE))
        self.assertEqual(['DumpHelper.java','PackageInstallerService.java'],[r['name']for r in fixture.OFFICIAL_ANDROID15_SOURCE])
        for row in fixture.OFFICIAL_ANDROID15_SOURCE:
            self.assertIn('/android-15.0.0_r1/',row['url']);self.assertRegex(row['sha256'],r'^[0-9a-f]{64}$')
    def test_complete_headers_and_orphan_presence(self):
        parse=self.scope['session_os_inventory'];self.assertEqual('empty',parse(fixture.SELECTED)['state'])
        self.assertEqual('present',parse(fixture.SELECTED.replace('Finalized install sessions:','Orphaned install sessions:\n  Session 12\nFinalized install sessions:'))['state'])
    def test_missing_duplicate_malformed_and_truncated_headers_refused(self):
        parse=self.scope['session_os_inventory']
        for header in ('Active','Finalized','Historical','Legacy'):
            with self.subTest(header=header),self.assertRaises(ValueError):parse(fixture.SELECTED.replace(header+' install sessions:',header+' changed:'))
        for raw in (fixture.SELECTED+'Active install sessions:\n',fixture.SELECTED.split('Legacy')[0],'{malformed}',fixture.SELECTED.encode()):
            with self.subTest(raw=raw),self.assertRaises(ValueError):parse(raw)


@unittest.skipUnless(os.name=='posix','actual descriptor/subprocess PIPE wrapper requires POSIX')
class SessionSelectorTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve()
        self.original='11111111-1111-4111-8111-111111111111';job=self.root/('android-installer-'+self.original);(job/'output').mkdir(parents=True,mode=0o700)
        self.phase_path=job/'output/phase-check.json';self.intent_path=job/'output/intent.json'
        self.phase_path.write_text(json.dumps({'correlationId':self.original,'phase':'check'}));self.intent_path.write_text('{"fixture":"inert"}');self.phase_path.chmod(0o600);self.intent_path.chmod(0o600)
        self.phase=self.record(self.phase_path);self.intent=self.record(self.intent_path)
        entries=[];rows=''
        for index in range(3):
            name=str(index+2)+'2222222-2222-4222-8222-222222222222.json'
            value={'id':name[:-5],'nonce':'inert','sessionId':index+1,'version':'2.2.2','build':16840,'sha256':'a'*64,'byteCount':123,'phase':('INSTALLED','STAGED','UNKNOWN')[index],'createdAt':1,'confirmation':None,'signers':['b'*64]}
            raw=(json.dumps(value)+'\n').encode();generation='1|'+str(index+100)+'|'+str(len(raw))+'|1|1|600|1000|1000|1|regular file'
            entries.append({'name':name,'generation':generation})
            rows+='F\0'+name+'\0'+generation+'\0'+hashlib.sha256(raw).hexdigest()+'\0'+base64.b64encode(raw).decode()+'\0'
        self.receipts=rows+'DONE\0';self.metadata={'no_backup/control-install-sessions':{'kind':'directory','generation':'inert-private-parent','entries':entries},'files/control-installs':{'kind':'absent','generation':'','entries':[]}}
        self.selected=fixture.SELECTED;self.change_active=False;self.dump_calls=[];self.host_guards=0;self.baseline_guards=0
        class Process:
            DEVNULL=subprocess.DEVNULL;PIPE=subprocess.PIPE;TimeoutExpired=subprocess.TimeoutExpired
            @staticmethod
            def Popen(argv,**kwargs):
                # Only unavailable Linux FD executable spelling and privileged
                # UID transition are substituted; reader/select/read/cap/EOF and
                # bounded kill/reap retain exact consumed production code.
                kwargs['executable']=sys.executable;kwargs['preexec_fn']=None
                return subprocess.Popen(argv,**kwargs)
        self.scope={'os':os,'subprocess':Process,'time':time,'select':select,'json':json,'hashlib':hashlib,'re':re,'stat':stat,'Path':Path,
            'GETTER_RECORDS':{},'READINESS_OBSERVATIONS':[],'COMMAND_HOST':{'uid':os.getuid()},'command_host_guard':self.guard,
            'external_jdk_guard':self.guard,'getter_stage':lambda:{'stage':'inert'},'BASELINE_BASE64':base64,'ROOT':self.root,
            'CLAIM_ORIGINAL':self.original,'LAUNCH':{'adbPath':'/inert-adb','adbFacts':{'generation':'fixed'},'environment':dict(os.environ)},
            'BASELINE_REQUEST':{'fixture':'inert'},'COMPONENT_RECEIPT':{'fixture':'inert'},'READINESS_QUOTE':shlex,
            'SESSION_METADATA':self.metadata,'SESSION_PHASE_PIN':self.phase,'READINESS_ORIGINAL_RECORDS':{str(self.intent_path):self.intent},
            'SESSION_HELPER':{'fixture':'inert'},'SESSION_PHASES':('PREPARING','STAGED','COMMITTING','AWAITING_CONFIRMATION','HANDED_OFF','INSTALLED','FAILED','UNKNOWN','CANCELLED'),
            'SESSION_TERMINAL':('INSTALLED','FAILED','CANCELLED'),'READINESS_METADATA_SCRIPT':'metadata','SESSION_READ_SCRIPT':'receipts',
            'ReadinessSubprocess':Process,'claim_record':self.record}
        # Inherited privileged Android metadata I/O seam only. It runs actual
        # fixed_read/readiness/command_bounded child transport for both replies.
        self.scope['READINESS_RETIREMENT_SOURCE']="""def native():return None,'inert-shell'
def authenticated_privileged_read(shell,script):
 if shell!='inert-shell' or script not in ('metadata','receipts'):raise ValueError('inert_read_scope_unknown')
 return fixed_run(['/inert-adb','-s','emulator-5682',script],30,1048576)
def parse_installer_metadata_census(raw):return json.loads(raw)
"""
        self.scope['COMPONENT_BUNDLE']=types.SimpleNamespace(modules=lambda receipt:{'fixture':'inert'},BaselineGuard=lambda *args:self.baseline_guard)
        exec(compile(fixture.TRANSPORT,'<exact-consumed-transport>','exec'),self.scope)
        self.scope['command_binary']=self.command
        self.load(fixture.FUNCTIONS)

    def record(self,path,limit=4194304):
        raw=Path(path).read_bytes();s=Path(path).stat()
        return {'state':'present','generation':[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns],
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'rawBase64':base64.b64encode(raw).decode()}
    def guard(self):
        self.host_guards+=1
        if self.record(self.phase_path)!=self.phase or self.record(self.intent_path)!=self.intent:raise ValueError('inert_source_guard_changed')
    def baseline_guard(self):self.baseline_guards+=1;self.guard()
    def load(self,source):exec(compile(source,'<complete-generated-claim-entry>','exec'),self.scope)
    def command(self,path,expected,args,environment,limit,timeout):
        self.assertEqual((1048576,30),(limit,timeout))
        if args==['-s','emulator-5682','metadata']:raw=json.dumps(self.metadata).encode();full=False
        elif args==['-s','emulator-5682','receipts']:raw=self.receipts.encode();full=False
        elif args in (['-s','emulator-5682','shell','-T','dumpsys','package'],['-s','emulator-5682','shell','-T','dumpsys','package','installs']):
            self.dump_calls.append(args);full=args[-1]!='installs';raw=self.selected.encode()
            if self.change_active and len(self.dump_calls)==2:raw=raw.replace(b'Active install sessions:\n',b'Active install sessions:\n  Session 21: active\n')
        else:raise ValueError('inert_command_catalogue_unknown')
        script="import sys;sys.stdout.buffer.write((b'P'*(1048576+4096) if sys.argv[1]=='full' else b'')+bytes.fromhex(sys.argv[2]))"
        fd=os.open(sys.executable,os.O_RDONLY)
        try:return self.scope['command_bounded']([sys.executable,'-c',script,'full'if full else'selected',raw.hex()],fd,environment,timeout,limit)
        finally:os.close(fd)

    def test_complete_old_entry_cap_red_retains_exact_one_mib(self):
        self.load(fixture.OLD_FUNCTIONS)
        with self.assertRaisesRegex(ValueError,'permission_command_output_limit'):self.scope['claim_inventory']()
        capture=self.scope['GETTER_RECORDS']['captures'][-1]
        self.assertEqual('permission_command_output_limit',capture['failure']);self.assertEqual(1048576,capture['stdoutBytes'])
        raw=base64.b64decode(capture['stdoutBase64']);self.assertEqual(1048576,len(raw));self.assertNotIn(b'Active install sessions:',raw)
        self.assertIsNone(self.scope['READINESS_OBSERVATIONS'][-1]['adb']['result']);self.assertNotEqual('installs',self.dump_calls[0][-1])

    def test_complete_fixed_entry_two_complete_reads_same_limits_green(self):
        result=self.scope['claim_inventory']();self.assertEqual(2,len(self.dump_calls));self.assertTrue(all(a[-1]=='installs'for a in self.dump_calls))
        self.assertEqual(4,self.baseline_guards)
        for row in result['passes']:
            self.assertEqual('empty',row['osInventory']['state']);self.assertTrue(row['osInventory']['complete'])
            self.assertEqual(fixture.SELECTED.encode(),base64.b64decode(row['osInventory']['rawBase64']))
            self.assertEqual(['terminal','pending','outcome-unknown'],[r['classification']for r in row['rows']])
        self.assertFalse(result['acceptanceComplete']);self.assertFalse(result['reconciliationPerformed']);self.assertFalse(result['claimGranted'])
        self.assertTrue(all(c['failure']is None and c['returncode']==0 and c['stderrBytes']==0 for c in self.scope['GETTER_RECORDS']['captures']))

    def test_changed_active_session_second_read_rejected_with_both_retained(self):
        self.change_active=True
        with self.assertRaisesRegex(ValueError,'session_observation_changed'):self.scope['claim_inventory']()
        rows=[r['sessionPass']for r in self.scope['READINESS_OBSERVATIONS']if 'sessionPass'in r];self.assertEqual(2,len(rows))
        self.assertNotEqual(rows[0]['osInventory']['activeSectionSha256'],rows[1]['osInventory']['activeSectionSha256'])

    def test_malformed_truncated_header_raw_retained_before_parser(self):
        self.selected=fixture.SELECTED.split('Legacy install sessions:')[0]
        with self.assertRaisesRegex(ValueError,'session_os_inventory_unknown'):self.scope['claim_inventory']()
        self.assertTrue(any(base64.b64encode(self.selected.encode()).decode()==r.get('adb',{}).get('captures',[{}])[-1].get('stdoutBase64')for r in self.scope['READINESS_OBSERVATIONS']if 'adb'in r))


if __name__=='__main__':unittest.main()
