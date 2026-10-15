"""Standard-account policy counterfactuals and emitted guard integration."""
from dataclasses import asdict,replace
import ast,base64,hashlib,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from agent_tools import ssh_transport as transport,windows_guest_input as owner
from agent_tools.tests.test_windows_guest_input import context,binding,profile,CORRELATION,_configured_profile

FIXTURE=Path(__file__).parent/'fixtures/windows_standard_token'
STANDARD=transport.WindowsInputTokenPolicy('ordinaryStandardUser',0,1,False,False)

def before_module():
    raw=(FIXTURE/'transport.before.source').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_bytes())['sources']['transport.before.source']
    name='agent_tools._standard_token_before';module=types.ModuleType(name);sys.modules[name]=module
    try:exec(compile(raw,str(FIXTURE/'transport.before.source'),'exec'),module.__dict__)
    finally:sys.modules.pop(name,None)
    return module

def native_sources():
    # These are the entire original/fixed native classes, not hand-written token
    # simulations. The native harness binds only observed SID/session values.
    tree=ast.parse((FIXTURE/'input.before.source').read_bytes())
    before=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='CURRENT_GUEST_GUARD_TEMPLATE'for t in n.targets))
    def csharp(body,name):return body.split("Add-Type -TypeDefinition @'",1)[1].split("'@ -ReferencedAssemblies",1)[0].replace('Cp117OwnerToken',name)
    after=owner.CURRENT_GUEST_GUARD_TEMPLATE
    for k,v in owner._guard_token_values(STANDARD).items():after=after.replace('__CTX_'+k+'__',v)
    return csharp(before,'BeforeOwnerToken'),csharp(after,'AfterOwnerToken')

class StandardTokenTests(unittest.TestCase):
    def test_actual_preserved_parser_rejects_standard_account_fixed_parser_preserves_it(self):
        row=_configured_profile();row['tokenPolicy']={'kind':'ordinaryStandardUser','elevation':0,'elevationType':1,'adminMember':False,'adminEnabled':False}
        before=before_module()
        with self.assertRaises(before.SshConfigError):before._windows_input_profiles({'standard':row})
        selected=transport._windows_input_profiles({'standard':row})['standard']
        self.assertEqual(STANDARD,selected.token_policy)
        self.assertEqual(row['expectedSid'],selected.expected_sid)

    def test_invalid_elevated_or_mixed_policy_is_rejected_by_parser_and_renderer(self):
        valid=asdict(STANDARD)
        for field,bad in (('kind','administrator'),('elevation',1),('elevation',False),('elevation_type',3),('elevation_type',True),('admin_member',True),('admin_member',0),('admin_enabled',True)):
            values={**valid,field:bad};policy=transport.WindowsInputTokenPolicy(**values)
            with self.subTest(field=field,bad=bad):
                with self.assertRaises(ValueError):owner.render_unbound_current_guest_guard(context(),policy)
                row=_configured_profile();row['tokenPolicy']={'kind':policy.kind,'elevation':policy.elevation,'elevationType':policy.elevation_type,'adminMember':policy.admin_member,'adminEnabled':policy.admin_enabled}
                with self.assertRaises(transport.SshConfigError):transport._windows_input_profiles({'standard':row})

    def test_complete_emitted_runtime_requires_the_configured_token_type(self):
        c=context();p=replace(profile(Path('/not-opened'),'8'*64),token_policy=STANDARD)
        source=owner.build_remote_program(p,c,CORRELATION,'8'*64);runtime={'__name__':'controlled_no_native'};exec(compile(source,'complete standard-user input programme','exec'),runtime)
        runtime['validate_globals']();runtime['emit']=lambda _:None
        first={'state':'CURRENT_TYPED_GETPROCESS_BIRTHS','effects':False,'source':'GetProcess.StartTime.ToFileTimeUtc','explorer40':c.console_birth,'owner11':c.owner.birth,'launcher10':c.owner_wrapper.birth}
        last={'state':'CURRENT_BOUND_GUEST_GREEN','jobId':binding()['jobId'],'sid':c.ordinary_sid,'sessionId':c.session_id,'consolePid':c.console_pid,'ownerPid':c.owner.pid,'ownerBirth':c.owner.birth,'boot':c.boot_utc,'elevated':0,'elevationType':1,'effects':False,'helperActors':[]}
        def call(sock,command,args,**kwargs):
            if command=='guest-exec':return {'pid':7}
            if command=='guest-exec-status':return {'exited':True,'exitcode':0,'out-data':base64.b64encode(owner._json(first)+b'\n'+owner._json(last)).decode()}
            raise AssertionError(command)
        runtime['call']=call
        self.assertEqual(1,runtime['current_guest_guard'](binding())[0]['elevationType'])
        for field,bad in (('elevationType',3),('elevationType',True),('elevated',1),('elevated',False),('sid','S-1-5-21-9-9-9-9'),('sessionId',2)):
            original=last[field];last[field]=bad
            try:
                with self.subTest(field=field,bad=bad),self.assertRaises(ValueError):runtime['current_guest_guard'](binding())
            finally:last[field]=original
        runtime['PROFILE']['token_policy']['admin_member']=True
        with self.assertRaisesRegex(ValueError,'PROFILE_TOKEN_POLICY'):runtime['validate_globals']()

@unittest.skipUnless(os.name=='nt' and shutil.which('powershell.exe'),'Windows PowerShell5.1 native compiler/parser')
class NativeTokenSourceCompileTests(unittest.TestCase):
    def test_both_actual_native_classes_compile_and_complete_standard_guard_parses(self):
        before,after=native_sources()
        def bound(source):
            return source.replace('__CTX_SID__',context().ordinary_sid).replace('__CTX_SESSION_CSHARP__','Info(t,12)!=1')
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);guard=root/'standard.ps1'
            guard.write_text(owner.render_unbound_current_guest_guard(context(),STANDARD),encoding='utf-8',newline='\n')
            harness=root/'harness.ps1';harness.write_bytes((FIXTURE/'native_harness.ps1').read_bytes())
            source="$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\nAdd-Type -TypeDefinition @'\n"+bound(before)+"\n'@ -ReferencedAssemblies @('System','System.Core')\nAdd-Type -TypeDefinition @'\n"+bound(after)+"\n'@ -ReferencedAssemblies @('System','System.Core')\n"
            for path in (guard,harness):
                source+="$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile('"+str(path).replace("'","''")+"',[ref]$t,[ref]$e);if($e.Count){throw ($e|Out-String)}\n"
            source+="[Console]::Out.WriteLine('NATIVE_CLASSES_AND_GUARD_COMPILED')\n"
            script=root/'compile.ps1';script.write_text(source,encoding='utf-8',newline='\n')
            result=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script)],capture_output=True,timeout=30)
        self.assertEqual(0,result.returncode,result.stderr.decode('utf-8',errors='replace'))
        self.assertIn(b'NATIVE_CLASSES_AND_GUARD_COMPILED',result.stdout)

if __name__=='__main__':unittest.main()
