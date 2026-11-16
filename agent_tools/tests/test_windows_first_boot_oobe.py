"""Clone first-boot OOBE stuck (db6df990 2026-11-08, 23824f97 2026-11-16): whole-before RED, current GREEN.

Both clones of image 637199a5 ended with OOBEInProgress 1, IMAGE_STATE_UNDEPLOYABLE, nobody signed in, the
guest agent running without ready.json and VpnControlFixtureInitialize ending 73. The agent is installed only
after the setup task's gate, and that task is registered only by SetupComplete.cmd, which Windows runs after the
machine OOBE set IMAGE_STATE_COMPLETE. So both clones had completed the machine OOBE, the agent install was
in flight, and Windows then put the machine back into OOBE (a reseal) and restarted it; the restarted OOBE never
completed by itself.

The tooling decision behind it is install-agent.ps1's gate. Windows sets OOBEInProgress 0 and
IMAGE_STATE_COMPLETE at the end of the machine OOBE, before the user OOBE runs in the temporary defaultuserN
session; that phase can still fail and reseal (the preserved ee0d45b1 disk logs). The preserved gate therefore
started Windows Installer during the user OOBE: clone 07831787 wrote ready.json while defaultuser0 owned the
console. Each test runs one behavioural check on the preserved module the stuck clones executed (its
INSTALL_AGENT sha256 equals the one in both start programs) and the same check on CURRENT:

* the installer starts only once an account that is not a temporary OOBE account owns the console;
* a machine OOBE still incomplete when the wait ends is made observable (agent installed, ready.json
  setup-incomplete, exit 75), never reported ready;
* qualification names the stopped OOBE (setupFailure first_boot_oobe_stuck) with a replace-fixture next
  action, from the clones' own preserved replies.

The gate is evaluated by a strict interpreter for exactly the PowerShell statements it uses (anything else
refuses) against registry and console values taken from the preserved native replies. When Windows fails the
user OOBE, which page the resealed OOBE then waits on, and the fixed gate end to end stay native evidence.
"""
import ast
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_vm_unattend as unattended

FIXTURES=Path(__file__).parent/'fixtures/windows_first_boot_oobe'
SETUP_KEY='HKLM:\\SYSTEM\\Setup'
STATE_KEY='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State'
# The fixed module under test. The private RED record points this slot at the beforeimage.
CURRENT=unattended.INSTALL_AGENT


def provenance():
    return json.loads((FIXTURES/'provenance.json').read_bytes())


def before_install_agent():
    """The preserved INSTALL_AGENT, authenticated against what both stuck clones executed."""
    record=provenance()['beforeimage'];raw=(FIXTURES/record['file']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('before_source_changed')
    value=[ast.literal_eval(n.value)for n in ast.parse(raw).body if isinstance(n,ast.Assign)
           and len(n.targets)==1 and getattr(n.targets[0],'id',None)=='INSTALL_AGENT']
    if len(value)!=1 or hashlib.sha256(value[0].encode()).hexdigest()!=record['installAgentSha256']:raise ValueError('before_install_agent')
    return value[0]


def replies():
    return {row['reply']:row for row in json.loads((FIXTURES/'qualify-replies.json').read_bytes())['replies']}


def phase(name,setup,console):
    """Guest facts the gate reads: HKLM Setup, Setup\\State and Win32_ComputerSystem.UserName."""
    return {'name':name,'registry':{SETUP_KEY:{'SystemSetupInProgress':setup['systemSetupInProgress'],'OOBEInProgress':setup['oobeInProgress']},
                                    STATE_KEY:{'ImageState':setup['imageState']}},'console':console}


def native_phases():
    rows=replies();found={}
    for row in rows.values():
        result=row['response']['result'];found.setdefault(row['role'],phase(row['role'],result['setup'],result['computer']['loggedOn']))
    order=provenance()['phaseOrder']['lines']
    # ee0d45b1 setupact: oobeldr ...SPECIALIZE_RESEAL_TO_OOBE --> UNDEPLOYABLE, then UNDEPLOYABLE --> COMPLETE and
    # SetupComplete.cmd at 07:29:30, before the user OOBE logs defaultuser0 on (OOBE Monitor 101 at 07:29:38).
    assert '[IMAGE_STATE_UNDEPLOYABLE] --> [IMAGE_STATE_COMPLE' in order['237'] and 'SetupComplete.cmd' in order['238'] and ': 101' in order['244']
    machine={'systemSetupInProgress':0,'oobeInProgress':1,'imageState':'IMAGE_STATE_UNDEPLOYABLE'}
    done={'systemSetupInProgress':0,'oobeInProgress':0,'imageState':'IMAGE_STATE_COMPLETE'}
    return [phase('machine-oobe',machine,None),phase('machine-complete-before-user-oobe',done,None),
            found['user-oobe-temporary-console'],found['fixture-user-console'],found['visual-administrator-console'],
            found['stuck-task-ended']]


# ---- a strict interpreter for the PowerShell statements of the install gate ----

class PsError(ValueError):
    pass


TOKEN=re.compile(r"\s*(?:(?P<s>'(?:[^']|'')*')|(?P<n>\d+)\b|(?P<v>\$[A-Za-z_]\w*)|(?P<o>-(?:and|or|not|eq|ne|match|notmatch)\b)"
                 r"|(?P<a>-[A-Za-z]\w*)|(?P<m>\.[A-Za-z_]\w*)|(?P<p>[()])|(?P<w>[A-Za-z][\w-]*))",re.I)


def tokens(text):
    out,k=[],0
    while k<len(text):
        if text[k:].strip()=='':break
        m=TOKEN.match(text,k)
        if not m:raise PsError('token at %r'%text[k:k+20])
        kind=m.lastgroup;value=m.group(kind);k=m.end()
        out.append((kind,value[1:-1].replace("''","'")if kind=='s' else int(value)if kind=='n' else value.lower()if kind in ('o','v')else value))
    return out


class Gate:
    """Evaluate the gate's assignments and decisions against one guest phase; unknown statements refuse."""

    def __init__(self,guest):
        self.guest,self.vars=guest,{'$null':None,'$true':True,'$false':False}

    def truth(self,value):
        if value is None:return False
        if type(value)in (bool,int,str):return bool(value)
        raise PsError('truth')

    def expression(self,items):
        value,rest=self.disjunction(items)
        if rest:raise PsError('trailing %r'%(rest[:3],))
        return value

    def disjunction(self,items):
        value,items=self.conjunction(items)
        while items and items[0]==('o','-or'):
            right,items=self.conjunction(items[1:]);value=self.truth(value)or self.truth(right)
        return value,items

    def conjunction(self,items):
        value,items=self.comparison(items)
        while items and items[0]==('o','-and'):
            right,items=self.comparison(items[1:]);value=self.truth(value)and self.truth(right)
        return value,items

    def comparison(self,items):
        left,items=self.unary(items)
        if items and items[0][0]=='o' and items[0][1]in ('-eq','-ne','-match','-notmatch'):
            operator=items[0][1];right,items=self.unary(items[1:])
            if operator in ('-eq','-ne'):
                same=left.lower()==right.lower()if type(left)is str and type(right)is str else left==right
                return (same if operator=='-eq' else not same),items
            if type(right)is not str:raise PsError('pattern')
            # PowerShell matches $null as an empty string, case-insensitively.
            found=re.search(right,'' if left is None else str(left),re.I)is not None
            return (found if operator=='-match' else not found),items
        return left,items

    def unary(self,items):
        if items and items[0]==('o','-not'):
            value,rest=self.unary(items[1:]);return not self.truth(value),rest
        return self.primary(items)

    def primary(self,items):
        if not items:raise PsError('empty')
        kind,value=items[0]
        if kind=='p' and value=='(':
            depth,end=0,0
            for end,item in enumerate(items):
                depth+=item==('p','(');depth-=item==('p',')')
                if depth==0:break
            inner=items[1:end];rest=items[end+1:]
            if inner and inner[0]==('w','Get-CimInstance'):result=self.cim(inner)
            else:result=self.expression(inner)
            while rest and rest[0][0]=='m':result=self.member(result,rest[0][1][1:]);rest=rest[1:]
            return result,rest
        if kind=='w' and value=='Get-ItemProperty':
            if len(items)<3 or items[1]!=('a','-LiteralPath')or items[2][0]!='s' or items[2][1]not in self.guest['registry']:
                raise PsError('registry read %r'%(items[1:3],))
            return dict(self.guest['registry'][items[2][1]]),items[3:]
        if kind in ('s','n'):return value,items[1:]
        if kind=='v':
            if value not in self.vars:raise PsError('variable '+value)
            result,rest=self.vars[value],items[1:]
            while rest and rest[0][0]=='m':result=self.member(result,rest[0][1][1:]);rest=rest[1:]
            return result,rest
        raise PsError('primary %r'%(items[0],))

    def cim(self,items):
        if items!=[('w','Get-CimInstance'),('a','-ClassName'),('w','Win32_ComputerSystem')]:raise PsError('CIM read %r'%(items,))
        return {'UserName':self.guest['console']}

    def member(self,value,name):
        if type(value)is not dict:raise PsError('member of %r'%(value,))
        found=[v for k,v in value.items()if k.lower()==name.lower()]
        if len(found)!=1:raise PsError('member '+name)
        return found[0]

    def statement(self,line):
        """Run one statement; returns an exit code, or None to continue."""
        line=line.strip()
        if line=='if(-not $ready){Start-Sleep -Seconds 2}':return None
        guarded=re.fullmatch(r'if\((.*)\)\{(.*)\}',line)
        if guarded:
            return self.statement(guarded.group(2))if self.truth(self.expression(tokens(guarded.group(1))))else None
        exit=re.fullmatch(r'exit (\d+)',line)
        if exit:return int(exit.group(1))
        assignment=re.fullmatch(r'(\$[A-Za-z_]\w*)=(.*)',line)
        if assignment:
            items=tokens(assignment.group(2))
            if items and items[0]==('w','Get-ItemProperty'):
                self.vars[assignment.group(1).lower()]=self.primary(items)[0]
            else:self.vars[assignment.group(1).lower()]=self.expression(items)
            return None
        raise PsError('statement %r'%line)


def sections(script):
    """The wait-loop body, the decision statements before the install intent, and the reporting tail."""
    lines=script.splitlines()
    start=lines.index('do {');end=next(k for k in range(start,len(lines))if lines[k].startswith('} until('))
    intent=next(k for k in range(end,len(lines))if lines[k].startswith('$intent='))
    tail=[line for line in lines[intent:]if line.startswith('$outcome=')or line.startswith('if($observeOnly)')]
    return lines[start+1:end],lines[end+1:intent],tail


def decide(script,guest):
    """Evaluate one wait iteration and, as at the deadline, the decisions that follow it.

    Returns (installerAdmittedNow, exitBeforeInstall or None, observeOnly, reportedState, finalExit).
    """
    body,decisions,tail=sections(script);gate=Gate(guest)
    for line in body:
        if gate.statement(line)is not None:raise PsError('exit inside the wait')
    admitted=gate.truth(gate.vars['$ready'])
    for line in decisions:
        code=gate.statement(line)
        if code is not None:return admitted,code,None,None,code
    reported,final='ready',0
    for line in tail:
        code=gate.statement(line)
        if code is not None:final=code
    if '$outcome' in gate.vars:reported=gate.vars['$outcome']
    return admitted,None,gate.vars.get('$observeonly',False),reported,final


class InstallerGateTests(unittest.TestCase):
    def test_the_beforeimage_is_the_install_gate_both_stuck_clones_executed(self):
        record=provenance()
        self.assertEqual(2,len(record['stuckStarts']))
        for start in record['stuckStarts']:
            self.assertEqual(record['beforeimage']['installAgentSha256'],start['executedInstallAgentSha256'])
        self.assertEqual(record['beforeimage']['installAgentSha256'],hashlib.sha256(before_install_agent().encode()).hexdigest())
        for row in replies().values():
            self.assertRegex(row['replySha256'],'^[0-9a-f]{64}$')

    def test_windows_installer_starts_only_once_a_non_temporary_account_owns_the_console(self):
        before=before_install_agent()
        expected={'machine-oobe':False,'machine-complete-before-user-oobe':False,'user-oobe-temporary-console':False,
                  'fixture-user-console':True,'visual-administrator-console':True,'stuck-task-ended':False}
        observed_before={p['name']:decide(before,p)[0]for p in native_phases()}
        # RED as observed natively: the preserved gate admits the installer while the user OOBE may still fail
        # and reseal (07831787 wrote ready.json while defaultuser0 owned the console).
        self.assertTrue(observed_before['user-oobe-temporary-console'])
        self.assertTrue(observed_before['machine-complete-before-user-oobe'])
        for p in native_phases():
            with self.subTest(phase=p['name']):
                self.assertEqual(expected[p['name']],decide(CURRENT,p)[0])

    def test_a_stopped_machine_oobe_is_made_observable_and_never_reported_ready(self):
        stuck=next(p for p in native_phases()if p['name']=='stuck-task-ended')
        # The preserved gate ends 73 without an agent: had the reseal not interrupted an agent install already in
        # flight, the stopped OOBE would have had no guest agent at all.
        self.assertEqual(73,decide(before_install_agent(),stuck)[1])
        admitted,early,observe,reported,final=decide(CURRENT,stuck)
        self.assertFalse(admitted);self.assertIsNone(early)
        self.assertTrue(observe);self.assertEqual('setup-incomplete',reported);self.assertEqual(75,final)
        # A completed machine OOBE whose user OOBE outlives the wait never installs; the next logon retries.
        user=next(p for p in native_phases()if p['name']=='user-oobe-temporary-console')
        self.assertEqual(73,decide(CURRENT,user)[1])
        fixture=next(p for p in native_phases()if p['name']=='fixture-user-console')
        self.assertEqual((True,None,False,'ready',0),decide(CURRENT,fixture))

    def test_the_interpreter_refuses_statements_it_does_not_know(self):
        guest=native_phases()[0]
        for line in ('$x=(Get-Process explorer).Name','$x=$unknown','Restart-Computer','if($x -gt 1){exit 1}'):
            with self.subTest(line=line),self.assertRaises(PsError):Gate(guest).statement(line)


class QualifyNamedFailureTests(unittest.TestCase):
    def setUp(self):
        from contextlib import nullcontext
        from agent_tools import mcp_server,readiness_vm_dispatch
        from agent_tools.tests.route_adapter import bind_cached_routes
        # Schema and adapter routing only, as in test_windows_vm_deploy: the readiness boundary has its own suites.
        admission=mock.patch.object(readiness_vm_dispatch,'admitted_dispatch',return_value=nullcontext())
        admission.start();self.addCleanup(admission.stop)
        bind_cached_routes(self,mcp_server,'readiness_vm_dispatch','windows_vm_deploy','windows_vm_guest')

    def outcome(self,response,action='windows-vm-deploy-qualify-status'):
        from agent_tools import mcp_server,windows_vm_deploy
        inputs={'deploymentId':response['deploymentId'],'operationId':response['operationId'],'credentialFile':'/INERT_PRIVATE_PATH'}
        reply={**response,'schemaVersion':1,'mode':action.replace('windows-vm-deploy-',''),'nativeActionAllowed':False,'replayAllowed':False}
        with tempfile.TemporaryDirectory()as temporary,mock.patch.object(mcp_server,'REPO_ROOT',Path(temporary)),\
                mock.patch.object(windows_vm_deploy,'qualify',return_value=reply)as qualify:
            value=mcp_server.vm_workflow(action,inputs)
        qualify.assert_called_once()
        return value

    def test_the_stuck_clones_last_replies_name_the_stopped_oobe_and_say_replace(self):
        for name,row in replies().items():
            if row['role']!='stuck-task-ended':continue
            with self.subTest(reply=name):
                value=self.outcome(row['response'])
                self.assertTrue(value['ok']);self.assertFalse(value['setupReady'])
                self.assertEqual('first_boot_oobe_stuck',value.get('setupFailure'))
                self.assertEqual('replace-fixture',value['nextAction']['kind'])
                self.assertFalse(value['nextAction']['replayAllowed']);self.assertNotIn('action',value['nextAction'])

    def test_waiting_and_ready_replies_name_no_failure(self):
        for name,row in replies().items():
            if row['role']=='stuck-task-ended':continue
            with self.subTest(reply=name):
                value=self.outcome(row['response'])
                self.assertIn('setupFailure',value);self.assertIsNone(value['setupFailure'])
                self.assertNotEqual('replace-fixture',value['nextAction']['kind'])

    def test_the_fixed_observation_install_is_named_the_same_way(self):
        # Constructed from the 23824f97 reply: the fixed gate's own record of a stopped OOBE (exit 75).
        row=next(r for r in replies().values()if r['role']=='stuck-task-ended')
        response=json.loads(json.dumps(row['response']));setup=response['result']['setup']
        setup.update(taskResult=75,ready={'state':'setup-incomplete','installerExit':0,'principal':'NT AUTHORITY\\SYSTEM','time':'2026-11-16T17:52:00Z'})
        self.assertEqual('first_boot_oobe_stuck',self.outcome(response)['setupFailure'])
        # A task still waiting, or one that ended for another reason, is never named.
        for state,result in (('Running',75),('Ready',74),('Ready',0)):
            setup.update(taskState=state,taskResult=result)
            with self.subTest(state=state,result=result):self.assertIsNone(self.outcome(response)['setupFailure'])


if __name__=='__main__':unittest.main()
