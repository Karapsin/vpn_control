"""Standalone Windows execution of actual child catch and parent failure tail.

Only a private temporary file and inert throw are exercised. No UIA/native
method, authentication, keyboard, or guest operation runs. The fixture replaces
SYSTEM ACL identity with its current test actor; production syntax is unchanged.
"""
import ast,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]


def fragments():
    tree=ast.parse((ROOT/'agent_tools/windows_cp117_secure_input_observe.py').read_text())
    catch=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_CHILD_FAILURE'for t in n.targets))
    fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='bodies')
    parent=next(ast.literal_eval(n.value)for n in ast.walk(fn)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='failure_read'for t in n.targets))
    head_tree=ast.parse((ROOT/'agent_tools/windows_cp117_secure_layout_observe.py').read_text())
    head=next(ast.literal_eval(n.value)for n in head_tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_CHILD_HEAD'for t in n.targets))
    write=next(line for line in head.splitlines()if line.startswith('function WritePrivate('))
    original_tree=ast.parse((ROOT/'agent_tools/windows_cp117_recovered_session_observe.py').read_text())
    original=next(ast.literal_eval(n.value)for n in original_tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='BODY'for t in n.targets))
    old=original[original.rfind('}catch{'):]
    return old,catch,parent,write


def managed_case_pass(value,marker):
    # HadErrors remains set by intentional caught negative cases. This inert
    # fixture requires the actual completion marker and no unhandled error.
    return (set(value)=={'exit','failed','stdout','error'} and type(value['exit'])is int
            and value['exit']==0 and type(value['failed'])is bool
            and value['error']=='' and value['stdout']==marker+'\r\n')


def persist_case(directory,index,result):
    # Inert case evidence survives a parser/assertion failure. No VM input or
    # credentials exist in this fixture; this is not a production command API.
    raw=json.dumps({'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr},sort_keys=True).encode()
    if len(raw)>32768:raise ValueError('inert-case-evidence-cap')
    path=Path(directory)/('case-result-%d.json'%index)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        offset=0
        while offset<len(raw):offset+=os.write(fd,raw[offset:])
        os.fsync(fd)
    finally:os.close(fd)
    return path


def role_prelude(directory):
    path=str(directory).replace("'","''")
    return "$ErrorActionPreference='Stop';$dir='"+path+"';$actor=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$group=[IO.Directory]::GetAccessControl($dir).GetGroup([Security.Principal.SecurityIdentifier]).Value;$role=[Security.AccessControl.FileSecurity]::new();$role.SetSecurityDescriptorSddlForm(('O:'+$actor+'G:'+$group+'D:P(A;;FA;;;'+$actor+')'));$roleAcl=$role.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All);\n"


def actor_fragment(source):
    return source.replace("'O:SYG:SYD:P(A;;FA;;;SY)'",'$roleAcl')


class SourceExtractionTests(unittest.TestCase):
    def test_actual_success_with_caught_negative_haderrors_is_not_failure(self):
        actual={'exit':0,'failed':True,'stdout':'ACL_CAUSAL_PASS\r\n','error':''}
        self.assertFalse(not actual['failed'] and 'ACL_CAUSAL_PASS' in actual['stdout'])
        self.assertTrue(managed_case_pass(actual,'ACL_CAUSAL_PASS'))
        for field,value in [('exit',1),('stdout',''),('error','unhandled'),('exit',True)]:
            bad=dict(actual);bad[field]=value
            self.assertFalse(managed_case_pass(bad,'ACL_CAUSAL_PASS'))
    def test_actual_parent_failure_is_retained_before_json_parsing(self):
        result=subprocess.CompletedProcess([],1,'','SEMANTIC_FAILURE_ACL')
        with tempfile.TemporaryDirectory()as directory:
            path=persist_case(directory,0,result)
            with self.assertRaises(json.JSONDecodeError):json.loads(result.stdout)
            self.assertEqual(json.loads(path.read_text()),{'exit':1,'stdout':'','stderr':'SEMANTIC_FAILURE_ACL'})
            with self.assertRaises(FileExistsError):persist_case(directory,0,result)
    def test_acl_equivalence_guard_is_actual_parent_source(self):
        _,_,parent,_=fragments()
        self.assertIn('function GuardFailureAcl',parent)
        self.assertIn('AreAccessRulesProtected',parent)
        self.assertIn('GetAccessRules($true,$true',parent)
        self.assertIn('$aclBefore',parent)
    def test_actual_catch_and_parent_tail_are_extracted_without_product_imports(self):
        old,new,parent,write=fragments()
        self.assertNotIn('failure.json',old);self.assertIn("WritePrivate 'failure.json'",new)
        self.assertIn('reader=$birth',new);self.assertIn("'SEMANTIC_FAILURE_BINDING'",parent)
        self.assertIn('CreateNew',write);self.assertIn('$f.Flush($true)',write)
        for source in(new,parent):
            self.assertNotIn('CP117InputRead]::Read',source)
            self.assertNotIn('SendMessageTimeout',source)
            self.assertNotIn('send-key',source)


@unittest.skipUnless(shutil.which('powershell.exe'),'Windows PowerShell is unavailable')
class ExecutableFailureTests(unittest.TestCase):
    def invoke(self,directory,script):
        path=Path(directory)/'case.ps1';path.write_text(script,encoding='utf-8')
        result=subprocess.run([shutil.which('powershell.exe'),'-NoProfile','-NonInteractive','-File',str(path)],capture_output=True,text=True,timeout=20)
        index=getattr(self,'caseIndex',0);persist_case(directory,index,result);self.caseIndex=index+1
        return result
    def run_child(self,directory,fixed):
        old,new,_,write=fragments()
        script=role_prelude(directory)+write+'\n'
        script+="$birth=@{nonce='inert-nonce';sourceSha256=('b'*64);pid=$PID;parentPid=456;creationFileTime=[Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc().ToString();sessionId=1;applicationSha256=('a'*64)};\n"
        script+="try{throw [InvalidOperationException]::new('SEMANTIC_LENGTH_UNAVAILABLE')"+actor_fragment(new if fixed else old)
        return self.invoke(directory,script)
    def run_parent(self,directory,expected):
        _,_,parent,_=fragments();literal=json.dumps(expected,separators=(',',':')).replace("'","''")
        script=role_prelude(directory)+"function GuardUI{};$exit=1;$resumed=$true;$record=('"+literal+"'|ConvertFrom-Json);\n"+actor_fragment(parent)
        return self.invoke(directory,script)
    def test_managed_powershell_caught_throw_keeps_haderrors_after_success(self):
        with tempfile.TemporaryDirectory()as directory:
            script=r"""$ErrorActionPreference='Stop';$p=[Management.Automation.PowerShell]::Create();try{$p.AddScript("try{throw 'expected-negative'}catch{};'ACL_CAUSAL_PASS'")|Out-Null;$output=$p.Invoke();[Console]::Out.WriteLine((@{hadErrors=$p.HadErrors;errors=$p.Streams.Error.Count;output=@($output|ForEach-Object {$_.ToString()})}|ConvertTo-Json -Compress))}finally{$p.Dispose()}"""
            result=self.invoke(directory,script);self.assertEqual(result.returncode,0,result.stderr)
            value=json.loads(result.stdout);self.assertEqual(value,{'hadErrors':True,'errors':0,'output':['ACL_CAUSAL_PASS']})
    def test_windows_canonical_ai_flag_keeps_only_exact_permissions(self):
        _,_,parent,_=fragments()
        guard=parent[:parent.index("if($exit -ne 0)")]
        with tempfile.TemporaryDirectory()as directory:
            script=role_prelude(directory)+actor_fragment(guard)+r"""
$p=Join-Path $dir 'acl.json';[IO.File]::WriteAllText($p,'{}');[IO.File]::SetAccessControl($p,$role)
$acl=[IO.File]::GetAccessControl($p);$actual=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
if($actual -ceq $roleAcl){throw 'CAUSAL_AI_NOT_REPRODUCED'}
GuardFailureAcl $acl
# FileSecurity canonicalizes CI away; its resulting effective ACL is safe.
$fileCi=[Security.AccessControl.FileSecurity]::new();$fileCi.SetSecurityDescriptorSddlForm(('O:'+$actor+'G:'+$group+'D:PAI(A;CI;FA;;;'+$actor+')'))
if($fileCi.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All) -cne $actual){throw 'FILE_CI_CANONICAL_DRIFT'}
GuardFailureAcl $fileCi
foreach($bad in @(
 ('O:'+$actor+'G:'+$group+'D:PAI(A;;FR;;;'+$actor+')'),
 ('O:'+$actor+'G:'+$group+'D:AI(A;;FA;;;'+$actor+')'),
 ('O:'+$actor+'G:'+$group+'D:PAI(D;;FA;;;'+$actor+')'),
 ('O:'+$actor+'G:'+$group+'D:PAI(A;CI;FA;;;'+$actor+')'),
 ('O:'+$actor+'G:'+$group+'D:PAI(A;ID;FA;;;'+$actor+')'),
 ('O:'+$actor+'G:'+$group+'D:PAI(A;;FA;;;'+$actor+')(A;;FR;;;WD)'),
 ('O:WDG:'+$group+'D:PAI(A;;FA;;;'+$actor+')'),
 ('O:'+$actor+'G:WDD:PAI(A;;FA;;;'+$actor+')'))){
 $changed=if($bad.Contains('(A;CI;')){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()};$changed.SetSecurityDescriptorSddlForm($bad);$rejected=$false
 try{GuardFailureAcl $changed}catch{$rejected=$true};if(-not $rejected){throw 'ACL_UNSAFE_ACCEPTED'}
}
[Console]::Out.WriteLine('ACL_CAUSAL_PASS')
"""
            result=self.invoke(directory,script)
            self.assertEqual(result.returncode,0,result.stderr);self.assertIn('ACL_CAUSAL_PASS',result.stdout)
    def test_actual_old_loses_error_fixed_creates_bound_failure_before_exit(self):
        with tempfile.TemporaryDirectory()as olddir,tempfile.TemporaryDirectory()as newdir:
            old=self.run_child(olddir,False);self.assertEqual(old.returncode,1);self.assertFalse((Path(olddir)/'failure.json').exists());self.assertIn('UNKNOWN',old.stdout)
            fixed=self.run_child(newdir,True);self.assertEqual(fixed.returncode,1,fixed.stderr)
            value=json.loads((Path(newdir)/'failure.json').read_text(encoding='utf-8-sig'));self.assertEqual(value['phase'],'SEMANTIC_LENGTH_UNAVAILABLE')
            # Full details stay private; only the finite category is returned.
            self.assertIn('SEMANTIC_LENGTH_UNAVAILABLE',value['details']);self.assertEqual(value['reader']['nonce'],'inert-nonce');self.assertGreater(value['reader']['pid'],0);self.assertTrue(value['reader']['creationFileTime'].isdigit())
            parent=self.run_parent(newdir,value['reader']);self.assertEqual(parent.returncode,1,parent.stderr)
            self.assertTrue(parent.stdout,parent.stderr)
            answer=json.loads(parent.stdout);self.assertEqual(answer['diagnosticFailure'],value);self.assertEqual(len(answer['failureRecord']['sha256']),64);self.assertEqual(len(answer['failureRecord']['generation']),4)
    def test_actual_parent_rejects_child_source_nonce_birth_and_schema_drift(self):
        with tempfile.TemporaryDirectory()as directory:
            child=self.run_child(directory,True);self.assertEqual(child.returncode,1,child.stderr)
            p=Path(directory)/'failure.json';value=json.loads(p.read_text(encoding='utf-8-sig'));expected=dict(value['reader'])
            for key,replacement in [('nonce','other'),('sourceSha256','0'*64),('pid',999),('creationFileTime','0'),('sessionId',0),('parentPid',789)]:
                changed=json.loads(json.dumps(value));changed['reader'][key]=replacement;p.write_text(json.dumps(changed),encoding='utf-8')
                failed=self.run_parent(directory,expected);self.assertEqual(failed.returncode,1);self.assertNotIn('diagnosticFailure',failed.stdout);self.assertIn('SEMANTIC_FAILURE_BINDING',failed.stderr)
            changed=dict(value);changed['phase']='unbounded foreign phase';p.write_text(json.dumps(changed),encoding='utf-8');failed=self.run_parent(directory,expected);self.assertIn('SEMANTIC_FAILURE_SCHEMA',failed.stderr)
