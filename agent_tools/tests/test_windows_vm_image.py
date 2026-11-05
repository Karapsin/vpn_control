"""Generalized Windows images: one-shot guest effects, read-only publication, reuse."""
import base64,builtins,contextlib,copy,hashlib,inspect,io,json,os,shutil,stat,subprocess,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import windows_vm_image as image
from agent_tools import windows_vm_deploy_remote as remote
from agent_tools.native_vm_spec import FreshWindowsVmSpec

SETUP={'imageName':'Windows 11 Enterprise Evaluation','locale':'en-US','user':'fixtureuser','administrator':'fixtureadmin'}
BOOT='6c0f5d1e-2a4b-4c8d-9e7f-0a1b2c3d4e5f'


def spec_dict(root='/home/fixture/vc-rw-1',deployment=None):
    deployment=deployment or str(uuid.uuid4())
    asset=lambda name,size:{'path':'/home/fixture/media/'+name,'sha256':hashlib.sha256(name.encode()).hexdigest(),'bytes':size}
    return {'deploymentId':deployment,'host':'archlinux','root':root,'cpus':4,'memoryMiB':4096,'diskGiB':64,'headroomMiB':8192,'vncPort':5963,
            'assets':{'installer':asset('windows-x64.iso',7092807680),'drivers':asset('virtio-win.iso',789645312),
                      'firmwareCode':{'path':'/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd','sha256':'c'*64,'bytes':3653632},
                      'firmwareVars':{'path':'/usr/share/edk2/x64/OVMF_VARS.4m.fd','sha256':'d'*64,'bytes':540672}}}


def manifest_for(spec,image_id,created,selected=None):
    return {'schemaVersion':1,'kind':'windows-generalized-image','imageId':image_id,'createdAtUnixMs':created,'hostBootId':BOOT,
            'source':{'deploymentId':spec['deploymentId'],'generalizeOperationId':str(uuid.uuid4()),'captureOperationId':image_id},
            'assets':{n:{'sha256':a['sha256'],'bytes':a['bytes']} for n,a in spec['assets'].items()},'diskGiB':spec['diskGiB'],
            'setup':{'imageName':SETUP['imageName'],'locale':SETUP['locale']},
            'installerImage':{'installerSha256':spec['assets']['installer']['sha256'],'image':selected or {'name':SETUP['imageName']}},
            'os':{'build':'26200'},'templateNetwork':'restricted','sysprepPrincipal':'builtin-administrator-interactive',
            'files':{'disk.qcow2':{'identity':[1]},'uefi-vars.fd':{'identity':[2],'sha256':'e'*64},'tpm2-00.permall':{'identity':[3],'sha256':'f'*64}}}


def setup_result(operation,**changes):
    """The schema-6 setup step's one-line result (SYSTEM, before the restart)."""
    value={'nonce':operation,'sysprepPrincipal':'builtin-administrator-interactive','accountsRemoved':['fixtureuser','fixtureadmin'],
           'temporaryAccountsRemoved':['defaultuser0'],'temporaryAccountsDeferred':[],'sessionsSignedOut':True,'fixtureAutomaticLogonRemoved':True,
           'setupStateRemoved':True,'setupCachesRemoved':True,'volumeDecryptionStarted':True,'finalSha256':image.GENERALIZE_FINAL_SHA256,
           'finalScheduled':True,'restartScheduled':True}
    value.update(changes);return value


def try_body(script):
    """Statements of a script's top-level try block, without comments or blank lines."""
    body=script[script.index('try {')+len('try {'):script.index('} catch {')]
    return [line.strip() for line in body.splitlines() if line.strip() and not line.strip().startswith('#')]


class ScriptTests(unittest.TestCase):
    def test_setup_binds_names_nonce_and_exact_final_digest_without_credentials(self):
        operation=str(uuid.uuid4());source=image.generalize_source(SETUP,operation)
        self.assertIn("$ExpectedUser='fixtureuser'",source);self.assertIn("$ExpectedAdministrator='fixtureadmin'",source)
        self.assertIn('$OperationId='+repr(operation),source);self.assertIn('$FinalSha256='+repr(image.GENERALIZE_FINAL_SHA256),source)
        self.assertEqual(hashlib.sha256(image.GENERALIZE_FINAL.encode()).hexdigest(),image.GENERALIZE_FINAL_SHA256)
        # The host binds no credential: the Administrator's one-shot logon password
        # is generated in the guest and never reaches the result line.
        for script in (source,image.GENERALIZE_FINAL):
            self.assertNotRegex(script,r"-Password\s*['\"]");self.assertNotRegex(script,r"DefaultPassword\s+-PropertyType\s+String\s+-Value\s*['\"]")
            self.assertIn('[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)',script)
        result=[line for line in source.splitlines() if line.startswith('[Console]::WriteLine(')]
        self.assertEqual(1,len(result));self.assertNotIn('$secret',result[0]);self.assertNotIn('$bytes',result[0])
        for line in source.splitlines():
            if '$secret' in line:self.assertNotRegex(line,r'Write-|Console|Out-File|Set-Content|Add-Content|Tee-|Transcript')
        # The whole encoded command stays below the Windows command-line bound.
        self.assertLess(len(base64.b64encode(source.encode('utf-16le')))+120,32767)
        with self.assertRaises(ValueError):image.generalize_source(SETUP,'not-a-uuid')
        with self.assertRaises(ValueError):image.generalize_source(dict(SETUP,user='administrator'),operation)

    def test_template_removes_every_secure_cache_and_accounts_before_scheduling(self):
        from agent_tools import windows_vm_guest as guest
        for cache in ("Panther\\unattend.xml","Panther\\autounattend.xml","Panther\\Unattend\\unattend.xml","System32\\Sysprep\\unattend.xml"):
            self.assertIn(cache,guest.SECURE_SETUP);self.assertIn(cache,image.GENERALIZE_SETUP)
        body=image.GENERALIZE_SETUP
        order=[body.index(x) for x in ("AutoAdminLogon -Value '0'",'WTSLogoffSession','Remove-LocalUser',"Unregister-ScheduledTask -TaskName 'VpnControlFixtureInitialize'",'Register-ScheduledTask')]
        self.assertEqual(order,sorted(order))
        self.assertTrue(all(ord(c)<128 for c in body+image.GENERALIZE_FINAL+image.GENERALIZE_PROBE))

    def test_final_step_generalizes_last_and_restores_the_agent_only_on_failure(self):
        final=image.GENERALIZE_FINAL
        self.assertIn("@('/generalize','/oobe','/shutdown','/quiet','/mode:vm',('/unattend:'+(Join-Path $work 'image-unattend.xml')))",final)
        self.assertEqual(1,final.count('/unattend'))
        self.assertLess(final.index("'/x'"),final.index('/delete-driver'));self.assertLess(final.index('/delete-driver'),final.index('sysprep.exe'))
        self.assertLess(final.index('sysprep.exe'),final.index('} catch {'));self.assertGreater(final.index("'/i'"),final.index('} catch {'))
        self.assertIn("throw 'TEMPLATE_SYSPREP_REFUSED'",final)

    def test_device_encryption_is_prevented_and_decrypted_before_the_agent_is_removed(self):
        setup=image.GENERALIZE_SETUP;final=image.GENERALIZE_FINAL
        self.assertLess(setup.index('PreventDeviceEncryption'),setup.index("-MethodName Decrypt"))
        self.assertLess(final.index('ConversionStatus -eq 0'),final.index("'/x'"))
        self.assertIn("throw 'TEMPLATE_DECRYPTION_TIMEOUT'",final)
        self.assertNotIn('TEMPLATE_VOLUME_ENCRYPTED',setup)
    def test_image_answer_file_copies_the_clone_answer_and_holds_no_account(self):
        from xml.etree import ElementTree as ET
        raw=image.image_answer_file(SETUP);root=ET.fromstring(raw.encode());ns={'u':'urn:schemas-microsoft-com:unattend'}
        self.assertEqual(['specialize','oobeSystem'],[s.get('pass') for s in root.findall('u:settings',ns)])
        path=root.find('.//u:RunSynchronousCommand/u:Path',ns).text
        # The image hook only runs the clone's own script from its VCSETUP volume.
        self.assertEqual(image.IMAGE_HOOK,path);self.assertIn('VCSETUP',path);self.assertTrue(path.endswith("':\\clone-specialize.ps1')\""))
        clone=image.CLONE_SPECIALIZE
        self.assertIn("Join-Path $env:WINDIR 'Panther\\Unattend'",clone)
        self.assertIn("Copy-Item -LiteralPath (Join-Path $seed 'Autounattend.xml') -Destination (Join-Path $answer 'Unattend.xml') -Force",clone)
        # Never the Setup-annotated cached answer file or the registry pointer (F3b).
        for text in (path,clone):self.assertNotIn('Panther\\unattend.xml',text);self.assertNotIn('UnattendFile',text)
        self.assertTrue(all(ord(c)<128 for c in clone))
        for forbidden in ('LocalAccount','AutoLogon','Password','windowsPE'):self.assertNotIn(forbidden,raw)
        source=image.generalize_source(SETUP,str(uuid.uuid4()))
        self.assertIn('$AnswerSha256='+repr(hashlib.sha256(raw.encode()).hexdigest()),source)
        self.assertLess(image.GENERALIZE_SETUP.index("'TEMPLATE_ANSWER_SOURCE'"),image.GENERALIZE_SETUP.index('AutoAdminLogon'))
        self.assertIn("('/unattend:'+(Join-Path $work 'image-unattend.xml'))",image.GENERALIZE_FINAL)
        self.assertIn('TEMPLATE_ANSWER_SOURCE',image.PRE_EFFECT_REFUSALS)
    def test_clone_specialize_never_needs_task_scheduler(self):
        # F3e: Task Scheduler is not running in the specialize pass after
        # generalization (0x80041315), so the hook may not run initialize.ps1,
        # which registers a task. SetupComplete.cmd runs it after Setup instead.
        # The hook is what Windows runs in that pass (schema 4 ran initialize.ps1 here).
        # Source-text guard, not a reproducer: the causal RED/GREEN runs the preserved
        # schema-4 module in agent_tools.tests.test_windows_vm_image_failures.
        hook=image.IMAGE_HOOK
        self.assertNotIn('initialize.ps1',hook);self.assertNotIn('Register-ScheduledTask',hook);self.assertNotIn('schtasks',hook.lower())
        clone=image.CLONE_SPECIALIZE
        self.assertNotIn('Register-ScheduledTask',clone);self.assertNotIn('schtasks',clone.lower())
        self.assertNotRegex(clone,r"&\s*\(?[^\n]*initialize\.ps1");self.assertNotIn('-File (Join-Path $seed',clone)
        self.assertIn("foreach($name in @('initialize.ps1','install-agent.ps1'))",clone);self.assertIn("Join-Path $env:WINDIR 'Setup\\Scripts'",clone)
        command=clone[clone.index('$command='):clone.index('[IO.File]::WriteAllText')]
        self.assertIn('-File ""%~dp0initialize.ps1""',command)
        # The clone answer, which holds the account passwords, leaves the disk only after initialize.
        self.assertLess(command.index('initialize.ps1'),command.index('del /f /q ""%WINDIR%\\Panther\\Unattend\\Unattend.xml""'))
        self.assertLess(clone.index("'Autounattend.xml'"),clone.index('SetupComplete.cmd'))
    def test_every_run_synchronous_path_fits_the_windows_limit(self):
        # Setup refuses the whole answer file when a RunSynchronous Path exceeds
        # 259 characters (F3c: schemas 2 and 3 used 705 and 417 characters). The
        # causal RED/GREEN is in agent_tools.tests.test_windows_vm_image_failures.
        from xml.etree import ElementTree as ET
        from agent_tools import windows_vm_unattend as unattended
        ns={'u':'urn:schemas-microsoft-com:unattend'}
        blank=unattended.answer_file(SETUP,{'user':'A'*24,'administrator':'B'*24})
        for raw in (image.image_answer_file(SETUP).encode(),blank):
            paths=[node.text for node in ET.fromstring(raw).findall('.//u:RunSynchronousCommand/u:Path',ns)]
            self.assertTrue(paths)
            for path in paths:self.assertLessEqual(len(path),image.RUN_SYNCHRONOUS_PATH_LIMIT,path)
        self.assertEqual(259,image.RUN_SYNCHRONOUS_PATH_LIMIT)
    def test_probe_template_binds_only_a_placeholder_nonce(self):
        self.assertIn("$OperationId='__PROBE_ID__'",image.probe_template())


class SysprepContextTests(unittest.TestCase):
    """F3d: clones crash-looped Explorer at their first sign-in (defaultuser0 OOBE).

    Sysprep ran as LocalSystem from a scheduled task, which Microsoft does not
    support (on 24H2/25H2 it skips XAML AppX registration), minutes after the
    template's own OOBE without a restart, so the template's defaultuser0 was
    captured. These are source-text guards of the guest scripts, not
    reproducers. The causal RED/GREEN of the host gates (generalize, capture,
    listing, selection, clone start) runs the preserved schema-4/5 modules in
    agent_tools.tests.test_windows_vm_image_failures. The guest-side decision
    (the Administrator's interactive logon task and the final step's
    TEMPLATE_SYSPREP_CONTEXT guard) has native evidence only (round 6).
    """
    def at(self,text,part,start=0):
        """Position of part in text; asserts presence so an old source fails by assertion."""
        self.assertIn(part,text[start:]);return text.index(part,start)
    def test_sysprep_never_runs_as_system_but_in_the_builtin_administrators_interactive_session(self):
        setup=image.GENERALIZE_SETUP;final=image.GENERALIZE_FINAL
        self.assertNotIn("-UserId 'S-1-5-18'",setup);self.assertNotIn('ServiceAccount',setup)
        self.assertIn("$admin=@(Get-LocalUser | Where-Object {$_.SID.Value -match '^S-1-5-21-\\d+-\\d+-\\d+-500$'})",setup)
        self.assertIn('New-ScheduledTaskPrincipal -UserId $admin.SID.Value -LogonType Interactive -RunLevel Highest',setup)
        self.assertIn('-Trigger (New-ScheduledTaskTrigger -AtLogOn)',setup)
        # The final step proves its own context before any other statement.
        steps=try_body(final)
        self.assertTrue(steps[0].startswith('$identity=[Security.Principal.WindowsIdentity]::GetCurrent()'),steps[:3])
        self.assertTrue(steps[1].startswith('$session=(Get-Process -Id $PID).SessionId'),steps[:3])
        check=steps[2]
        for part in ("-notmatch '^S-1-5-21-\\d+-\\d+-\\d+-500$'",'$session -eq 0','IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',"throw 'TEMPLATE_SYSPREP_CONTEXT'"):
            self.assertIn(part,check)
        self.assertLess(self.at(final,"throw 'TEMPLATE_SYSPREP_CONTEXT'"),self.at(final,'sysprep.exe'))
        self.assertEqual('builtin-administrator-interactive',image.SYSPREP_PRINCIPAL)
        for function in (image.generalize_instance,image.capture_image_instance,image.clone_manifest_matches):
            self.assertIn("'builtin-administrator-interactive'",inspect.getsource(function))
    def test_temporary_oobe_accounts_are_removed_and_only_builtin_accounts_are_captured(self):
        setup=image.GENERALIZE_SETUP;final=image.GENERALIZE_FINAL
        # Refused before the first guest modification when an unknown account exists.
        first_effect=self.at(setup,'PreventDeviceEncryption -PropertyType')
        for refusal in ('TEMPLATE_ADMIN_ACCOUNT','TEMPLATE_ACCOUNT_UNEXPECTED'):
            self.assertLess(self.at(setup,"throw '"+refusal+"'"),first_effect);self.assertIn(refusal,image.PRE_EFFECT_REFUSALS)
        self.assertLess(self.at(setup,"$_.Name -match '^defaultuser\\d+$'"),first_effect)
        removal=self.at(setup,'foreach($name in $temporary){')
        self.assertLess(self.at(setup,'Remove-LocalUser -SID $account.SID;$temporaryRemoved+=$name',removal),self.at(setup,"throw 'TEMPLATE_ACCOUNT_REMAINS'"))
        # After the restart a still-present temporary account is removed, then the baseline is asserted.
        self.assertLess(self.at(final,"Get-LocalUser | Where-Object {$_.Name -match '^defaultuser\\d+$'}"),self.at(final,'sysprep.exe'))
        for part in ("'^S-1-5-21-\\d+-\\d+-\\d+-(500|501|503|504)$'","throw 'TEMPLATE_ACCOUNT_REMAINS'","'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'",
                     "@('All Users','Default','Default User','Public','desktop.ini',","throw 'TEMPLATE_PROFILE_REMAINS'"):
            self.assertLess(self.at(final,part),self.at(final,'sysprep.exe'),part)
    def test_template_restarts_between_cleanup_and_sysprep(self):
        setup=image.GENERALIZE_SETUP;final=image.GENERALIZE_FINAL
        restart=self.at(setup,'& shutdown.exe /r /t $FinalDelaySeconds')
        for earlier in ("Join-Path $work 'setup.json'",'Register-ScheduledTask','Remove-LocalUser','WTSLogoffSession'):self.assertLess(self.at(setup,earlier),restart,earlier)
        self.assertLess(restart,self.at(setup,'restartScheduled=$true'));self.assertNotIn('New-ScheduledTaskTrigger -Once',setup)
        self.assertIn('setupUnixMs=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()',setup)
        boot=self.at(final,'(Get-CimInstance Win32_OperatingSystem).LastBootUpTime')
        self.assertLess(boot,self.at(final,"throw 'TEMPLATE_NOT_REBOOTED'"));self.assertLess(self.at(final,"throw 'TEMPLATE_NOT_REBOOTED'"),self.at(final,'sysprep.exe'))
        self.assertIn('if($bootMs -le [int64]$setup.setupUnixMs)',final)
    def test_one_shot_administrator_logon_is_cleared_and_rotated_before_sysprep(self):
        setup=image.GENERALIZE_SETUP;final=image.GENERALIZE_FINAL
        for part in ('Enable-LocalUser -SID $admin.SID','-Name AutoLogonCount -PropertyType DWord -Value 1',"-Name AutoAdminLogon -Value '1'",'$secret=$null'):
            self.assertIn(part,setup)
        self.assertLess(self.at(setup,"-Name DefaultPassword -PropertyType String -Value $secret"),self.at(setup,'$secret=$null'))
        sysprep=self.at(final,'sysprep.exe')
        for part in ("Set-ItemProperty -LiteralPath $key -Name AutoAdminLogon -Value '0'","foreach($name in @('DefaultPassword','AutoLogonCount','DefaultUserName','AutoLogonSID'))",
                     'Set-LocalUser -SID $identity.User -Password',"throw 'FIXTURE_AUTOLOGON_REMAINS'"):
            self.assertLess(self.at(final,part),sysprep,part)
        # Cleared before anything that can fail later, and again on every failure.
        self.assertLess(self.at(final,"-Name AutoAdminLogon -Value '0'"),self.at(final,"throw 'TEMPLATE_NOT_REBOOTED'"))
        catch=final[self.at(final,'} catch {'):]
        self.assertIn("Set-ItemProperty -LiteralPath $key -Name AutoAdminLogon -Value '0' -ErrorAction SilentlyContinue",catch)
        self.assertIn('Remove-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue',catch)
    def test_answer_file_logon_secret_cannot_override_or_outlive_the_administrator_logon(self):
        # Setup stores an answer-file AutoLogon password as the LSA secret
        # DefaultPassword ("AutoLogon Password saved"); Winlogon would try the
        # fixture's password for the Administrator, and the image would keep it.
        setup=image.GENERALIZE_SETUP;final=image.GENERALIZE_FINAL
        lsa=self.at(setup,"$lsa='HKLM:\\SECURITY\\Policy\\Secrets\\DefaultPassword'")
        removed=self.at(setup,'if(Test-Path -LiteralPath $lsa){Remove-Item -LiteralPath $lsa -Recurse -Force}')
        asserted=self.at(setup,"-or (Test-Path -LiteralPath $lsa)){throw 'FIXTURE_AUTOLOGON_REMAINS'}")
        armed=self.at(setup,"-Name AutoAdminLogon -Value '1'")
        self.assertLess(lsa,removed);self.assertLess(removed,asserted);self.assertLess(asserted,armed)
        self.assertLess(self.at(setup,'WTSLogoffSession'),armed)
        for part in ('LsaStorePrivateData(policy,ref key,IntPtr.Zero)','LsaRetrievePrivateData(policy,ref key,out data)','return status==0xC0000034;'):self.assertIn(part,final)
        clear="if(-not [VcLogonSecret]::Clear()){throw 'FIXTURE_AUTOLOGON_REMAINS'}"
        self.assertLess(self.at(final,clear),self.at(final,"throw 'TEMPLATE_NOT_REBOOTED'"))
        self.assertLess(self.at(final,"-or -not [VcLogonSecret]::Clear()){throw 'FIXTURE_AUTOLOGON_REMAINS'}"),self.at(final,'sysprep.exe'))
    def test_xaml_packages_are_registered_for_the_sysprep_user_before_sysprep(self):
        final=image.GENERALIZE_FINAL
        self.assertIn("$xaml=@('MicrosoftWindows.Client.CBS','Microsoft.UI.Xaml.CBS','MicrosoftWindows.Client.Core')",final)
        self.assertIn("Get-AppxPackage -Name $name | Where-Object {[string]$_.Status -eq 'Ok'}",final)
        self.assertLess(self.at(final,"throw 'TEMPLATE_XAML_UNREGISTERED'"),self.at(final,'sysprep.exe'))


class GeneralizeTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.operation=str(uuid.uuid4());(self.root/'qga.sock').write_bytes(b'')
        self.records={'qemu-started.json':{'pid':11,'startTicks':5},'swtpm-started.json':{'pid':12,'startTicks':4}}
        self.alive={11:True,12:True};self.calls=[];self.exited=True;self.qualify_calls=[];self.agent_ready=False
        self.result=setup_result(self.operation)
        self.signals=[]
        namespace={'CONTEXT':{'hostBootId':'FIXTURE_BOOT'},'call':self.call,'qualify_instance':self.qualify,
                   'GENERALIZE_SCRIPT':'FIXED_GENERALIZE','GENERALIZE_CHECK_SCRIPT':'FIXED_CHECK','GENERALIZE_FINAL':image.GENERALIZE_FINAL,
                   'GENERALIZE_FINAL_SHA256':image.GENERALIZE_FINAL_SHA256,'GENERALIZE_PROBE_TEMPLATE':image.probe_template(),
                   'PROBE_AFTER_SECONDS':image.PROBE_AFTER_SECONDS,'PRE_EFFECT_REFUSALS':image.PRE_EFFECT_REFUSALS,'IMAGE_ANSWER':image.image_answer_file(SETUP),
                   '_actor_absent':lambda row,process,birth:not self.alive[row['pid']]}
        exec(compile(inspect.getsource(image.refusal_token)+'\n'+inspect.getsource(image.generalize_instance),'actual generalize','exec'),namespace)
        self.subject=namespace['generalize_instance']
    def qualify(self,*args):
        self.qualify_calls.append(args[2]);self.assertEqual('FIXED_CHECK',args[-1])
        return {'state':'setup-observed','setupReady':True,'result':{'os':{'build':'26200'}}}
    def read(self,name):
        if name not in self.records:raise FileNotFoundError(name)
        return copy.deepcopy(self.records[name])
    def save(self,name,value):
        with (self.root/name).open('xb')as stream:stream.write(value if type(value)is bytes else json.dumps(value).encode())
        if type(value)is not bytes:self.records[name]=copy.deepcopy(value)
    def call(self,path,command,arguments,**kwargs):
        self.calls.append(command)
        if command=='guest-exec':
            if arguments.get('input-data'):
                payload=json.loads(base64.b64decode(arguments['input-data']))
                self.assertEqual({'operationId':self.operation,'finalScript':image.GENERALIZE_FINAL,'imageAnswer':image.image_answer_file(SETUP)},payload)
            return {'pid':4242}
        if not self.exited:return {'exited':False}
        if arguments=={'pid':4242}:return {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(self.result).encode()).decode()}
        return {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(self.probe_report).encode()).decode()}
    def invoke(self,status_only=False):
        real=builtins.open
        def opened(path,*args,**kwargs):return io.StringIO('FIXTURE_BOOT')if str(path)=='/proc/sys/kernel/random/boot_id'else real(path,*args,**kwargs)
        clock=iter(range(0,10**6,7))
        with mock.patch.object(builtins,'open',side_effect=opened),mock.patch('time.sleep'),mock.patch('time.monotonic',side_effect=lambda:next(clock)):
            return self.subject({},SETUP,self.operation,status_only,self.root,self.read,self.save,lambda row:None,lambda *a:None,lambda:None,lambda:None,
                                lambda:{'guestAgentReady':self.agent_ready},lambda pid:0)
    def test_one_submission_then_status_observes_guest_power_off_without_replay(self):
        self.assertEqual('generalize-submitted',self.invoke()['state']);self.assertEqual(['guest-exec','guest-exec-status'],self.calls)
        self.assertEqual(1,len(self.qualify_calls));self.calls.clear()
        self.assertEqual('generalize-running',self.invoke(True)['state']);self.assertEqual([],self.calls)
        self.alive={11:False,12:False}
        stopped=self.invoke(True);self.assertEqual('generalized-stopped',stopped['state']);self.assertTrue(stopped['positiveAbsence'])
        self.assertEqual(stopped,self.invoke(True));self.assertEqual([],self.calls)
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(1,len(self.qualify_calls))
    def test_pending_terminal_is_collected_by_status_and_status_never_submits(self):
        self.exited=False;self.assertEqual('generalize-pending',self.invoke()['state'])
        self.exited=True;self.calls.clear();self.assertEqual('generalize-running',self.invoke(True)['state'])
        self.assertEqual(['guest-exec-status'],self.calls)
    def test_status_without_original_acknowledgement_refuses(self):
        self.save('generalize-intent.json',{'operationId':self.operation})
        with self.assertRaisesRegex(ValueError,'instance_guest_exec_ack'):self.invoke(True)
        self.assertEqual([],self.calls)
    def test_power_off_before_the_guest_result_is_unknown_not_success(self):
        self.exited=False;self.invoke();self.alive={11:False,12:False}
        with self.assertRaisesRegex(ValueError,'instance_generalize_result_unknown'):self.invoke(True)
    def test_changed_guest_result_refuses_and_is_retained(self):
        self.result['accountsRemoved']=['fixtureuser']
        with self.assertRaisesRegex(ValueError,'instance_generalize_result'):self.invoke()
        self.assertTrue((self.root/'generalize.terminal.json').exists())
    def test_system_context_setup_result_is_refused(self):
        # F3d: the schema-5 setup armed sysprep as SYSTEM; such a result never counts.
        self.result={'nonce':self.operation,'principal':'S-1-5-18','accountsRemoved':['fixtureuser','fixtureadmin'],'sessionsSignedOut':True,
                     'automaticLogonDisabled':True,'setupStateRemoved':True,'setupCachesRemoved':True,'volumeDecryptionStarted':True,
                     'finalSha256':image.GENERALIZE_FINAL_SHA256,'finalScheduled':True}
        with self.assertRaisesRegex(ValueError,'instance_generalize_result'):self.invoke()
    def test_temporary_account_lists_are_exact(self):
        for name,changes in {'deferred':{'temporaryAccountsRemoved':[],'temporaryAccountsDeferred':['defaultuser0']},
                             'none':{'temporaryAccountsRemoved':[]},'two':{'temporaryAccountsRemoved':['defaultuser0','defaultuser1']},
                             'six-digit':{'temporaryAccountsRemoved':['defaultuser100000']}}.items():
            with self.subTest(name):
                self.setUp();self.result=setup_result(self.operation,**changes)
                self.assertEqual('generalize-submitted',self.invoke()['state'])
        for name,changes in {'stranger':{'temporaryAccountsRemoved':['fixtureuser']},'duplicate':{'temporaryAccountsDeferred':['DefaultUser0']},
                             'missing':{'temporaryAccountsDeferred':None},'no-restart':{'restartScheduled':False},
                             'system':{'sysprepPrincipal':'S-1-5-18'}}.items():
            with self.subTest(name):
                self.setUp();self.result=setup_result(self.operation,**changes)
                if changes.get('temporaryAccountsDeferred',1)is None:del self.result['temporaryAccountsDeferred']
                with self.assertRaisesRegex(ValueError,'instance_generalize_result'):self.invoke()
    def refuse_first(self,message):
        terminal={'exited':True,'exitcode':1,'err-data':base64.b64encode(message).decode()}
        first=self.operation;self.result_terminal=terminal
        def call(path,command,arguments,**kwargs):
            self.calls.append(command)
            return {'pid':4242} if command=='guest-exec' else terminal
        self.subject.__globals__['call']=call
        with self.assertRaises(ValueError)as raised:self.invoke()
        self.subject.__globals__['call']=self.call;self.operation=str(uuid.uuid4());self.result['nonce']=self.operation
        return first,str(raised.exception)
    def test_pre_effect_refusal_is_retired_by_a_new_operation_and_kept(self):
        first,reason=self.refuse_first(b"TEMPLATE_VOLUME_ENCRYPTED\r\nAt line:20 char:3\r\n+ throw 'TEMPLATE_PROFILE_REMAINS'\r\n")
        self.assertEqual('instance_generalize_template_volume_encrypted',reason)
        with self.assertRaisesRegex(ValueError,'instance_generalize_original_exists'):
            saved=self.operation;self.operation=first;self.invoke()
        self.operation=saved;self.result['nonce']=saved;self.calls.clear()
        self.assertEqual('generalize-submitted',self.invoke()['state'])
        retired=self.root/('generalize-refused-'+first)
        self.assertEqual(sorted(['generalize-intent.json','generalize.ps1','generalize.ack.json','generalize.terminal.json','generalize-submitted.json']),sorted(os.listdir(retired)))
    def test_refusals_after_a_guest_modification_stay_final(self):
        for message in (b'TEMPLATE_PROFILE_REMAINS\r\n',b'Access denied\r\n+ {throw \'TEMPLATE_REBOOT_PENDING\'}\r\n',
                        b'#< CLIXML\r\n<Objs><S S="Error">TEMPLATE_SESSIONS_REMAIN_x000D__x000A_</S><S S="Error">TEMPLATE_INPUT</S></Objs>'):
            with self.subTest(message=message):
                self.setUp();self.refuse_first(message)
                with self.assertRaisesRegex(ValueError,'instance_generalize_original_exists'):self.invoke()
    def test_refusal_token_reads_only_the_first_error_message(self):
        token=lambda raw:image.refusal_token({'exited':True,'exitcode':1,'err-data':base64.b64encode(raw).decode()})
        self.assertEqual('TEMPLATE_REBOOT_PENDING',token(b'TEMPLATE_REBOOT_PENDING\r\nAt line:1'))
        self.assertEqual('TEMPLATE_INPUT',token(b'#< CLIXML\r\n<Objs><S S="Error">TEMPLATE_INPUT_x000D__x000A_</S></Objs>'))
        self.assertIsNone(token(b'Exception\r\n+ throw \'TEMPLATE_INPUT\''))
        self.assertIsNone(image.refusal_token({'exited':True,'exitcode':0,'err-data':''}))
    def test_restored_agent_after_final_window_reports_failure_from_read_only_probe(self):
        self.invoke();self.calls.clear();self.agent_ready=True
        self.records['generalize-submitted.json']['collectedAtUnixMs']-=(image.PROBE_AFTER_SECONDS+5)*1000
        self.probe_report=None
        def capture(path,command,arguments,**kwargs):
            self.calls.append(command)
            if command=='guest-exec':
                self.assertNotIn('input-data',arguments)
                script=base64.b64decode(arguments['arg'][-1]).decode('utf-16le');nonce=script.split("$OperationId='",1)[1].split("'",1)[0]
                self.probe_report={'nonce':nonce,'failure':{'state':'failed','reason':'TEMPLATE_SYSPREP_REFUSED'},'sysprepErrors':['line']}
                return {'pid':5151}
            return {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(self.probe_report).encode()).decode()}
        self.subject.__globals__['call']=capture
        value=self.invoke(True);self.assertEqual('generalize-failed',value['state']);self.assertEqual('TEMPLATE_SYSPREP_REFUSED',value['failure']['reason'])
        self.assertEqual(['guest-exec','guest-exec-status'],self.calls)
        # A reported failure is final; a fresh template whose probe finds none keeps running.
        self.setUp();self.invoke();self.calls.clear();self.agent_ready=True
        self.records['generalize-submitted.json']['collectedAtUnixMs']-=(image.PROBE_AFTER_SECONDS+5)*1000
        self.probe_report=None;original=capture
        def no_failure(path,command,arguments,**kwargs):
            value=original(path,command,arguments,**kwargs)
            if command=='guest-exec':self.probe_report['failure']=None
            return value if command=='guest-exec' else {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(self.probe_report).encode()).decode()}
        self.subject.__globals__['call']=no_failure
        self.assertEqual('generalize-running',self.invoke(True)['state'])
    def test_reported_failure_stays_final_after_power_off(self):
        self.invoke();self.agent_ready=True
        self.records['generalize-submitted.json']['collectedAtUnixMs']-=(image.PROBE_AFTER_SECONDS+5)*1000
        def failing(path,command,arguments,**kwargs):
            if command=='guest-exec':
                script=base64.b64decode(arguments['arg'][-1]).decode('utf-16le');self.nonce=script.split("$OperationId='",1)[1].split("'",1)[0]
                return {'pid':5151}
            report={'nonce':self.nonce,'failure':{'state':'failed','reason':'TEMPLATE_XAML_UNREGISTERED'},'sysprepErrors':[]}
            return {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(report).encode()).decode()}
        self.subject.__globals__['call']=failing
        self.assertEqual('generalize-failed',self.invoke(True)['state']);self.assertTrue((self.root/'generalize-failed.json').exists())
        self.subject.__globals__['call']=self.call;self.calls.clear();self.alive={11:False,12:False}
        value=self.invoke(True);self.assertEqual('generalize-failed',value['state']);self.assertEqual('TEMPLATE_XAML_UNREGISTERED',value['failure']['reason'])
        self.assertFalse((self.root/'generalize-stopped.json').exists());self.assertEqual([],self.calls)
    def test_host_stop_after_setup_is_never_a_generalized_template(self):
        # The stop's intent is saved before its QMP quit; QEMU absence then is not sysprep's power-off.
        self.assertEqual('generalize-submitted',self.invoke()['state'])
        (self.root/'stop-intent.json').write_text('{}');self.alive={11:False,12:False}
        with self.assertRaisesRegex(ValueError,'instance_generalize_host_stopped'):self.invoke(True)
        self.assertFalse((self.root/'generalize-stopped.json').exists())


def template_logs(**changes):
    """A read-only disk-logs observation of a template stopped by its own sysprep."""
    work='Windows/Temp/VpnControlGeneralize/'
    context={'sid':'S-1-5-21-1-2-3-500','elevated':True,'sessionId':1,'bootUnixMs':2000,'setupUnixMs':1000,
             'temporaryAccountsRemoved':['defaultuser0'],'usersFolder':['Administrator','Public']}
    context.update(changes.pop('context',{}))
    files={work+'final-context.json':{'bytes':1,'tail':json.dumps(context,indent=4).splitlines(),'errors':[]},
           work+'final.log':{'bytes':1,'tail':['\ufeff**********************','Windows PowerShell transcript start','Username: DESKTOP-1\\Administrator',
                                                'RunAs User: DESKTOP-1\\Administrator','Machine: DESKTOP-1 (Microsoft Windows NT 10.0.26200.0)'],'errors':[]},
           work+'failure.json':None,'listings':{'Users':['Administrator/','All Users@','Default User@','Default/','Public/','desktop.ini']}}
    files.update(changes.pop('files',{}))
    presence={'Windows/Panther/Unattend/Unattend.xml':None,'Windows/Panther/unattend.xml':3703,'Windows/System32/Sysprep/Sysprep_succeeded.tag':0}
    presence.update(changes.pop('presence',{}))
    value={'schemaVersion':1,'mode':'disk-logs','state':'disk-logs-observed','logs':{'files':files,'presence':presence}}
    value.update(changes);return value


class TemplateEvidenceTests(unittest.TestCase):
    def test_only_a_successful_administrator_session_sysprep_is_evidence(self):
        # F3d: captured only after the stopped disk shows sysprep ran in that session.
        self.assertTrue(image.template_evidence_ok(template_logs(),SETUP))
        work='Windows/Temp/VpnControlGeneralize/'
        system={'bytes':1,'tail':['Username: WORKGROUP\\SYSTEM','RunAs User: WORKGROUP\\SYSTEM'],'errors':[]}
        users=['Administrator/','Public/','desktop.ini']
        bad={'refused':{'state':'disk-logs-refused'},'no-tag':{'presence':{'Windows/System32/Sysprep/Sysprep_succeeded.tag':None}},
             'failure':{'files':{work+'failure.json':{'bytes':80,'tail':['{}'],'errors':[]}}},'system-transcript':{'files':{work+'final.log':system}},
             'no-transcript':{'files':{work+'final.log':None}},'system-sid':{'context':{'sid':'S-1-5-18'}},'other-rid':{'context':{'sid':'S-1-5-21-1-2-3-1500'}},
             'not-elevated':{'context':{'elevated':False}},'session-0':{'context':{'sessionId':0}},'not-rebooted':{'context':{'bootUnixMs':900}},
             'no-context':{'files':{work+'final-context.json':None}},'bad-context':{'files':{work+'final-context.json':{'bytes':1,'tail':['{'],'errors':[]}}},
             'temporary-profile':{'files':{'listings':{'Users':users+['defaultuser0/']}}},'fixture-profile':{'files':{'listings':{'Users':users+['FixtureUser/']}}},
             'no-users':{'files':{'listings':{'Users':None}}}}
        for name,change in bad.items():
            with self.subTest(name):self.assertFalse(image.template_evidence_ok(template_logs(**copy.deepcopy(change)),SETUP))
    def test_stopped_template_logs_carry_the_whole_transcript_and_context(self):
        self.assertIn('Windows/Temp/VpnControlGeneralize/final.log',image.DISK_LOG_FULL)
        for name in ('Windows/Temp/VpnControlGeneralize/final-context.json','Windows/Temp/VpnControlGeneralize/setup.json'):self.assertIn(name,image.DISK_LOG_FILES)
        self.assertIn('Windows/System32/Sysprep/Sysprep_succeeded.tag',image.DISK_LOG_PRESENCE)


@unittest.skipUnless(os.name=='posix','POSIX image fixture')
class CaptureAndListTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        self.home=Path(temporary.name).resolve();self.root=self.home/'vc-rw-1';self.root.mkdir(mode=0o700)
        self.spec=spec_dict(str(self.root));self.operation=str(uuid.uuid4());self.records={}
        (self.root/'tpm').mkdir(mode=0o700)
        for name,raw in (('disk.qcow2',b'QFI\xfb'+b'\0'*60),('uefi-vars.fd',b'VARS'*16),('tpm/tpm2-00.permall',b'TPM2'*32)):
            path=self.root/name;path.write_bytes(raw);path.chmod(0o600)
        s=lambda n:list((lambda v:[v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid])(os.lstat(self.root/n)))
        self.records.update({'generalize-stopped.json':{'operationId':'g'},'generalize-intent.json':{'operationId':'g','os':{'build':'26200'}},
                             'generalize.terminal.json':{'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(setup_result('g')).encode()).decode()},
                             'qemu-started.json':{'pid':11,'argv':['/proc/self/fd/9','-netdev','user,id=net0,restrict=on','-device','virtio-net-pci,netdev=net0']},'swtpm-started.json':{'pid':12},'mutable-artifacts.json':{n:s(n) for n in ('disk.qcow2','uefi-vars.fd')},
                             'installer-image.json':{'installerSha256':self.spec['assets']['installer']['sha256'],'image':{'name':SETUP['imageName']}}})
        self.alive=False
        namespace={'CONTEXT':{'hostBootId':BOOT,'pending':[]},'SPEC':self.spec,'SETUP':SETUP,'STORE_NAME':image.STORE_NAME,'IMAGE_SCHEMA_VERSION':image.IMAGE_SCHEMA_VERSION,
                   '_actor_absent':lambda row,process,birth:not self.alive}
        exec(compile(inspect.getsource(image.capture_image_instance),'actual capture','exec'),namespace)
        self.capture=namespace['capture_image_instance']
        listing={'SPEC':self.spec,'STORE_NAME':image.STORE_NAME,'MAX_IMAGES':image.MAX_IMAGES,'IMAGE_SCHEMA_VERSION':image.IMAGE_SCHEMA_VERSION,'IMAGE_FILES':image.IMAGE_FILES}
        exec(compile(inspect.getsource(image.read_image)+'\n'+inspect.getsource(image.images_main),'actual listing','exec'),listing)
        self.listing=listing
    def read(self,name):return copy.deepcopy(self.records[name])
    def save(self,name,value):
        with (self.root/name).open('xb')as stream:stream.write(json.dumps(value).encode())
        self.records[name]=value
    def qemu_img(self,argv,**kwargs):
        self.assertEqual((5,),kwargs['pass_fds'])
        if argv[1]=='check':return subprocess.CompletedProcess(argv,0,json.dumps({'check-errors':0}).encode(),b'')
        return subprocess.CompletedProcess(argv,0,json.dumps({'format':'qcow2','virtual-size':64*1024**3}).encode(),b'')
    def invoke(self):
        with mock.patch('subprocess.run',side_effect=self.qemu_img):
            return self.capture(self.spec,SETUP,self.operation,self.root,self.read,self.save,lambda r:None,lambda p:0,{'qemu-img':5})
    def listed(self):
        out=io.StringIO()
        with mock.patch('sys.stdout',out):self.listing['images_main']()
        return json.loads(out.getvalue())
    def test_capture_publishes_one_read_only_image_and_listing_proves_identity(self):
        value=self.invoke();self.assertEqual('image-captured',value['state'])
        published=self.home/image.STORE_NAME/self.operation
        self.assertEqual(0o500,stat.S_IMODE(published.stat().st_mode));self.assertFalse((self.root/'disk.qcow2').exists())
        self.assertEqual(sorted(image.IMAGE_FILES),sorted(os.listdir(published)))
        for name in image.IMAGE_FILES:self.assertEqual(0o400,stat.S_IMODE((published/name).stat().st_mode))
        # Clones receive the template's exact TPM state, bound by digest.
        self.assertEqual(b'TPM2'*32,(published/'tpm2-00.permall').read_bytes())
        self.assertEqual(value['manifestSha256'],hashlib.sha256((published/'manifest.json').read_bytes()).hexdigest())
        rows=self.listed();self.assertEqual([self.operation],[r['imageId'] for r in rows['images']]);self.assertEqual(0,rows['refusedImages'])
        self.assertEqual(value['manifestSha256'],rows['images'][0]['manifestSha256'])
        manifest=rows['images'][0]['manifest']
        self.assertEqual((6,'panther-unattend-embedded','restricted','builtin-administrator-interactive'),
                         (manifest['schemaVersion'],manifest['answerHook'],manifest['templateNetwork'],manifest['sysprepPrincipal']))
        self.assertEqual(hashlib.sha256(b'TPM2'*32).hexdigest(),manifest['files']['tpm2-00.permall']['sha256'])
        with self.assertRaisesRegex(ValueError,'instance_capture_original_exists'):self.invoke()
    def test_capture_refuses_a_template_that_had_open_network(self):
        # F3d: a template that reached update and store services is never published.
        for argv in (['/q','-netdev','user,id=net0'],['/q'],['/q','-netdev','user,id=net0,restrict=on','-netdev','user,id=net1']):
            with self.subTest(argv=argv):
                self.records['qemu-started.json']['argv']=argv
                with self.assertRaisesRegex(ValueError,'instance_capture_template_network'):self.invoke()
                self.assertTrue((self.root/'disk.qcow2').exists());self.assertFalse((self.root/'capture-intent.json').exists())
                self.assertFalse((self.home/image.STORE_NAME).exists())
    def test_capture_refuses_a_template_generalized_as_system(self):
        # F3d: only a template whose recorded setup armed the Administrator-session sysprep is published.
        old={'nonce':'g','principal':'S-1-5-18','accountsRemoved':['fixtureuser','fixtureadmin'],'finalScheduled':True}
        for name,result in (('system',old),('other-nonce',setup_result('other')),('no-restart',setup_result('g',restartScheduled=False))):
            with self.subTest(name):
                self.records['generalize.terminal.json']['out-data']=base64.b64encode(json.dumps(result).encode()).decode()
                with self.assertRaisesRegex(ValueError,'instance_capture_sysprep_context'):self.invoke()
                self.assertTrue((self.root/'disk.qcow2').exists());self.assertFalse((self.root/'capture-intent.json').exists())
                self.assertFalse((self.home/image.STORE_NAME).exists())
    def test_capture_refuses_after_a_host_stop_or_a_reported_failure(self):
        for name in ('stop-intent.json','generalize-failed.json'):
            with self.subTest(name):
                self.setUp();(self.root/name).write_text('{}')
                with self.assertRaisesRegex(ValueError,'instance_capture_generalize'):self.invoke()
                self.assertTrue((self.root/'disk.qcow2').exists());self.assertFalse((self.home/image.STORE_NAME).exists())
    def test_capture_refuses_a_running_template_or_missing_stop(self):
        self.alive=True
        with self.assertRaisesRegex(ValueError,'instance_capture_actor_alive'):self.invoke()
        self.alive=False;del self.records['generalize-stopped.json']
        with self.assertRaises(KeyError):self.invoke()
        self.assertFalse((self.home/image.STORE_NAME).exists())
    def test_older_image_schemas_are_never_listed(self):
        # Schema 1 had no answer hook (F3); schemas 2 and 3 exceeded the Path limit (F3c);
        # schema 4 clones failed in OOBE and agent setup (F3d, F3e); schema 5 was
        # still generalized as SYSTEM with the template's defaultuser0 (F3d).
        for schema in (1,2,3,4,5):
            with self.subTest(schema=schema):
                self.setUp();self.invoke();published=self.home/image.STORE_NAME/self.operation;manifest=published/'manifest.json'
                value=json.loads(manifest.read_bytes());value['schemaVersion']=schema
                if schema==1:value.pop('answerHook')
                elif schema==2:value['answerHook']='panther-unattend-copy'
                published.chmod(0o700);manifest.chmod(0o600);manifest.write_bytes(json.dumps(value).encode());manifest.chmod(0o400);published.chmod(0o500)
                rows=self.listed();self.assertEqual([],rows['images']);self.assertEqual(1,rows['refusedImages'])
                published.chmod(0o700)
    def test_listing_refuses_changed_files_and_ignores_partial_captures(self):
        self.invoke();published=self.home/image.STORE_NAME/self.operation
        (self.home/image.STORE_NAME/('.'+str(uuid.uuid4())+'.partial')).mkdir(mode=0o700)
        published.chmod(0o700);(published/'uefi-vars.fd').chmod(0o600);(published/'uefi-vars.fd').write_bytes(b'changed')
        (published/'uefi-vars.fd').chmod(0o400);published.chmod(0o500)
        rows=self.listed();self.assertEqual([],rows['images']);self.assertEqual(1,rows['refusedImages'])
        published.chmod(0o700)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.spec=spec_dict();self.now=2_000_000_000_000
    def listing(self,*manifests):
        return {'state':'images-observed','images':[{'imageId':m['imageId'],'manifestSha256':hashlib.sha256(m['imageId'].encode()).hexdigest(),'manifest':m} for m in manifests]}
    def test_newest_matching_unexpired_image_is_reused(self):
        older=manifest_for(self.spec,str(uuid.uuid4()),self.now-3600_000);newer=manifest_for(self.spec,str(uuid.uuid4()),self.now-60_000)
        chosen=image.choose_image(self.listing(older,newer),self.spec,SETUP,self.now)
        self.assertEqual(newer['imageId'],chosen['imageId'])
    def test_any_mismatch_or_expiry_installs_from_scratch(self):
        cases={'expired':lambda m:m.update(createdAtUnixMs=self.now-image.MAX_IMAGE_AGE_MS-1),
               'future':lambda m:m.update(createdAtUnixMs=self.now+1),
               'installer':lambda m:m['assets']['installer'].update(sha256='0'*64),
               'disk':lambda m:m.update(diskGiB=128),'locale':lambda m:m['setup'].update(locale='de-DE'),
               'edition':lambda m:m['setup'].update(imageName='Windows 11 Pro'),
               'online-template':lambda m:m.update(templateNetwork=None),'unknown-network':lambda m:m.pop('templateNetwork'),
               'system-sysprep':lambda m:m.update(sysprepPrincipal='S-1-5-18'),'unknown-principal':lambda m:m.pop('sysprepPrincipal')}
        for name,change in cases.items():
            with self.subTest(name):
                manifest=manifest_for(self.spec,str(uuid.uuid4()),self.now-60_000);change(manifest)
                self.assertIsNone(image.choose_image(self.listing(manifest),self.spec,SETUP,self.now))
        self.assertIsNone(image.choose_image(self.listing(),self.spec,SETUP,self.now))
    def test_account_names_do_not_bind_an_image(self):
        manifest=manifest_for(self.spec,str(uuid.uuid4()),self.now-60_000)
        self.assertIsNotNone(image.choose_image(self.listing(manifest),self.spec,dict(SETUP,user='otheruser'),self.now))


class ProgramTests(unittest.TestCase):
    def setUp(self):
        self.spec=FreshWindowsVmSpec.parse(spec_dict());self.context={'hostBootId':BOOT,'pending':[]};self.operation=str(uuid.uuid4())
    def test_every_new_mode_compiles_and_clone_context_is_exact(self):
        for mode in ('generalize','generalize-status','capture-image','status'):
            remote.program(self.spec,mode,setup=SETUP,context=self.context,operation_id=self.operation)
        image_context={**self.context,'image':{'imageId':self.operation,'manifestSha256':'a'*64}}
        body=remote.program(self.spec,'status',setup=SETUP,context=image_context,operation_id=self.operation).decode()
        self.assertIn('instance_clone_disk',body);self.assertIn("BOOT_CLONE='order=c,menu=off'",body)
        for bad in ({**self.context,'image':{'imageId':'x','manifestSha256':'a'*64}},{**self.context,'image':{'imageId':self.operation}},
                    {**self.context,'other':1}):
            with self.subTest(bad=bad),self.assertRaises(ValueError):remote.program(self.spec,'status',setup=SETUP,context=bad,operation_id=self.operation)
        self.assertIn(b'images_main()',remote.program(self.spec,'images'))
    def test_template_network_is_restricted_and_never_combined_with_a_clone(self):
        restricted={**self.context,'network':'restricted'}
        body=remote.program(self.spec,'start',setup=SETUP,context=restricted,operation_id=self.operation).decode()
        self.assertIn("'user,id=net0,restrict=on'",body);self.assertIn('instance_network_mode',body)
        remote.program(self.spec,'status',setup=SETUP,context=restricted,operation_id=self.operation)
        for bad in ({**self.context,'network':'open'},{**self.context,'network':None},
                    {**restricted,'image':{'imageId':self.operation,'manifestSha256':'a'*64}}):
            with self.subTest(bad=bad),self.assertRaises(ValueError):remote.program(self.spec,'status',setup=SETUP,context=bad,operation_id=self.operation)
    def test_clone_start_installs_the_image_tpm_state_before_the_tpm_starts(self):
        image_context={**self.context,'image':{'imageId':self.operation,'manifestSha256':'a'*64}}
        body=remote.program(self.spec,'start',setup=SETUP,context=image_context,operation_id=self.operation).decode()
        self.assertIn('CLONE_SPECIALIZE='+repr(image.CLONE_SPECIALIZE),body);self.assertIn('IMAGE_FILES='+repr(image.IMAGE_FILES),body)
        start=body.index("phase='image'")
        order=[body.index(x,start) for x in ("manifest['files']['tpm2-00.permall']['sha256']","save('seed/clone-specialize.ps1'","save('tpm/tpm2-00.permall',tpm_raw)",
                                             "phase='seed'","phase='tpm'","phase='qemu'")]
        self.assertEqual(order,sorted(order))
    def test_blank_topology_still_boots_installer_once(self):
        from agent_tools import windows_vm_hardware as hardware
        argv=hardware.qemu_argv(self.spec.as_dict(),'/qemu',{'firmwareCode':1,'installer':2,'drivers':3})
        self.assertEqual(image.BOOT_BLANK,argv[argv.index('-boot')+1])
    def response(self,mode,state,**extra):
        return {'schemaVersion':1,'deploymentId':self.spec.deployment_id,'mode':mode,'state':state,'reason':None,'nativeActionAllowed':False,'replayAllowed':False,**extra}
    def test_results_are_exact(self):
        good=[('generalize',self.response('generalize','generalize-submitted',operationId=self.operation,productReady=False)),
              ('generalize-status',self.response('generalize-status','generalized-stopped',operationId=self.operation,productReady=False,positiveAbsence=True,
                                                 qemu={'pid':1,'startTicks':2},swtpm={'pid':3,'startTicks':4})),
              ('generalize-status',self.response('generalize-status','generalize-running',operationId=self.operation,productReady=False,guestAgentReady=False)),
              ('capture-image',self.response('capture-image','image-captured',operationId=self.operation,imageId=self.operation,manifestSha256='a'*64,productReady=False)),
              ('images',self.response('images','images-observed',images=[],refusedImages=0))]
        for mode,value in good:
            with self.subTest(mode=mode,state=value['state']):self.assertEqual(value,remote.validate_result(self.spec,mode,value))
        bad=[('generalize-status',self.response('generalize-status','generalized-stopped',operationId=self.operation,productReady=False,positiveAbsence=False,
                                                qemu={'pid':1,'startTicks':2},swtpm={'pid':3,'startTicks':4})),
             ('capture-image',self.response('capture-image','image-captured',operationId=self.operation,imageId=str(uuid.uuid4()),manifestSha256='a'*64,productReady=False)),
             ('images',self.response('images','images-observed',images=[{'imageId':'x','manifestSha256':'a'*64,'manifest':{'imageId':'x'}}],refusedImages=0)),
             ('status',self.response('status','generalized-stopped',operationId=self.operation,productReady=False,positiveAbsence=True,
                                     qemu={'pid':1,'startTicks':2},swtpm={'pid':3,'startTicks':4}))]
        for mode,value in bad:
            with self.subTest(mode=mode,state=value['state']),self.assertRaises(ValueError):remote.validate_result(self.spec,mode,value)


@unittest.skipUnless(os.name=='posix','POSIX directory fixture')
class DiskLogTests(unittest.TestCase):
    def test_listing_names_entries_without_following_links(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        users=Path(temporary.name)/'Users'
        for name in ('defaultuser0','defaultuser0.DESKTOP-1','Public'):(users/name).mkdir(parents=True)
        (users/'desktop.ini').write_text('x');(users/'All Users').symlink_to(users/'Public')
        self.assertEqual(['All Users@','Public/','defaultuser0.DESKTOP-1/','defaultuser0/','desktop.ini'],image.list_entries(users))
        self.assertIsNone(image.list_entries(users/'All Users'));self.assertIsNone(image.list_entries(users/'missing'))
        self.assertEqual(2,len(image.list_entries(users,limit=2)))
    def test_event_records_carry_utc_time_and_number(self):
        import struct
        def record(number,unix,*strings):
            body=b''.join(s.encode('utf-16-le')+b'\0\0' for s in strings);size=24+len(body)+4
            return b'**\0\0'+struct.pack('<IQQ',size,number,int(unix*1e7)+116444736000000000)+body+struct.pack('<I',size)
        raw=(b'junk**\0\0'+record(7,1793863784,'explorer.exe','0xc0000005')+record(8,1793863790,'harmless','value')
             +record(9,1793863804,'C:\\Users\\defaultuser0')+b'**\0\0\xff\xff\xff\xff')
        self.assertEqual(['2026-11-05 07:29:44 #7 explorer.exe | 0xc0000005','2026-11-05 07:30:04 #9 C:\\Users\\defaultuser0'],image.evtx_records(raw))
    def test_program_reads_profile_evidence_and_never_answer_contents(self):
        spec=FreshWindowsVmSpec.parse(spec_dict())
        body=remote.program(spec,'disk-logs').decode();compile(body,'disk-logs','exec')
        for name in ('User Profile Service%4Operational.evtx','AppReadiness%4Admin.evtx','Logs/System.evtx'):self.assertIn(name,body)
        self.assertIn("DISK_LOG_LISTINGS=('Users',)",body);self.assertIn('def list_entries(',body)
        # Answer files (which may hold credentials) are only checked for presence and size.
        for answer in image.DISK_LOG_PRESENCE:self.assertNotIn(answer,image.DISK_LOG_FILES)


class DeployTests(unittest.TestCase):
    def test_create_reuses_a_chosen_image_or_installs_blank(self):
        from agent_tools import windows_vm_deploy as deploy
        spec=spec_dict();chosen={'imageId':str(uuid.uuid4()),'manifestSha256':'b'*64}
        for selected in (chosen,None):
            with self.subTest(selected=selected),mock.patch.object(deploy,'images',return_value={'state':'images-observed','images':[]}),\
                    mock.patch('agent_tools.windows_vm_image.choose_image',return_value=selected),\
                    mock.patch.object(deploy,'start',return_value={'state':'booted-observed'})as start:
                value=deploy.create('/repo',spec,SETUP,'/credential',now_ms=1)
                self.assertEqual(selected,start.call_args.kwargs['image']);self.assertEqual(selected,value['image'])
                # Only a blank install, the next image template, is built offline.
                self.assertEqual(None if selected else 'restricted',start.call_args.kwargs['network'])
                self.assertEqual(None if selected else 'generalize-and-capture-after-qualification',value['nextAction'])
    def test_identity_validation_happens_before_any_operation(self):
        from agent_tools import windows_vm_deploy as deploy
        with mock.patch.object(deploy,'_original_operation')as original:
            for call in (lambda:deploy.generalize('/r',str(uuid.uuid4()),'bad','/c'),lambda:deploy.capture_image('/r',str(uuid.uuid4()),'bad','/c'),
                         lambda:deploy.generalize('/r',str(uuid.uuid4()),str(uuid.uuid4()),'/c',status_only=1)):
                with self.assertRaises(ValueError):call()
            original.assert_not_called()


class HostMaintenanceFixture:
    """Run the shipped vm-inventory and vm-cleanup programs over a fake /proc tree.

    windows_vm_deploy_remote.program composes each program from the preserved
    whole module (loaded only when its provenance digests match) or from the
    current one. The shipped functions reach /proc only through builtins.open,
    os.listdir, os.readlink and os.stat with exact str paths, and only those are
    rebased into the tree. Any other API, path type or spelling that names /proc
    fails the test, so the real /proc is never read.
    """
    BEFORE=Path(__file__).parent/'fixtures/windows_vm_host_maintenance/windows_vm_image.py.before.source'
    PROVENANCE=Path(__file__).parent/'fixtures/windows_vm_host_maintenance/provenance.json'
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        raw=cls.BEFORE.read_bytes();record=json.loads(cls.PROVENANCE.read_bytes())['files']['windows_vm_image.py.before.source']
        if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('before_source_changed')
        before=types.ModuleType('agent_tools._windows_vm_image_before');before.__file__=str(cls.BEFORE);before.__package__='agent_tools'
        exec(compile(raw,str(cls.BEFORE),'exec',dont_inherit=True),before.__dict__)
        for name,key in (('vm_processes','vmProcessesSha256'),('vm_cleanup_main','vmCleanupMainSha256')):
            if hashlib.sha256(inspect.getsource(getattr(before,name)).encode()).hexdigest()!=record[key]:raise ValueError('before_source_changed')
        cls.before=before
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name).resolve();self.home=self.base/'fx';self.root=self.home/'vc-rw-1';(self.root/'tpm').mkdir(parents=True,mode=0o700)
        self.disk=self.root/'disk.qcow2';self.disk.write_bytes(b'QFI\xfb');self.state=self.root/'tpm/tpm2-00.permall';self.state.write_bytes(b'TPM2')
        self.spec=FreshWindowsVmSpec.parse(spec_dict(str(self.root)));self.proc=self.base/'proc';(self.proc/'self').mkdir(parents=True)
        self.add(1,['/usr/lib/systemd/systemd','--system'],'/usr/lib/systemd/systemd');self.add(2,[])
    def add(self,pid,argv,exe=None,fds=()):
        """One /proc/<pid>: cmdline, an exe link unless exe is None (kernel thread or exited), fd links."""
        entry=self.proc/str(pid);(entry/'fd').mkdir(parents=True)
        (entry/'cmdline').write_bytes(b''.join(os.fsencode(word)+b'\0' for word in argv))
        if exe is not None:os.symlink(exe,entry/'exe')
        for number,target in fds:os.symlink(target,entry/'fd'/str(number))
    @contextlib.contextmanager
    def proc_rebased(self,denied=()):
        """Exact str paths under /proc land in the tree; a denied exe link raises the kernel's EACCES."""
        base=str(self.proc);real_open,real_io_open=builtins.open,io.open
        real={name:getattr(os,name) for name in ('listdir','readlink','stat','scandir','lstat','open','access','statvfs')}
        def names_proc(path):
            try:name=os.fsdecode(os.fspath(path))
            except TypeError:return False
            return os.path.normpath(os.path.join(os.getcwd(),name)).lstrip('/').split('/')[0]=='proc'
        def moved(path):
            if type(path)is str and (path=='/proc' or path.startswith('/proc/')):return base+path[5:]
            if names_proc(path):raise AssertionError('unrebased /proc access: '+repr(path))
            return path
        def guarded(name,function):
            def call(*args,**kwargs):
                path=args[0] if args else kwargs.get('file',kwargs.get('path'))
                if names_proc(path):raise AssertionError(name+' reached /proc: '+repr(path))
                return function(*args,**kwargs)
            return call
        def rebased_open(file,*args,**kwargs):return real_open(moved(file),*args,**kwargs)
        def listdir(path=None):return real['listdir'](moved(path))
        def stat_(path,*args,**kwargs):return real['stat'](moved(path),*args,**kwargs)
        def readlink(path,*args,**kwargs):
            if path in denied:raise PermissionError(13,'Permission denied',path)
            return real['readlink'](moved(path),*args,**kwargs)
        with contextlib.ExitStack()as stack:
            stack.enter_context(mock.patch('builtins.open',rebased_open));stack.enter_context(mock.patch.object(io,'open',guarded('io.open',real_io_open)))
            for name,function in (('listdir',listdir),('readlink',readlink),('stat',stat_)):stack.enter_context(mock.patch.object(os,name,function))
            for name in ('scandir','lstat','open','access','statvfs'):stack.enter_context(mock.patch.object(os,name,guarded('os.'+name,real[name])))
            yield
    def shipped(self,module,mode,paths=None,denied=()):
        """The host's view: run the program windows_vm_deploy_remote.program composes from module."""
        context={'paths':[str(path) for path in (paths or (self.disk,self.state))],'keep':[str(self.home/image.STORE_NAME)]}if mode=='vm-cleanup'else None
        with mock.patch('agent_tools.windows_vm_image',module):program=remote.program(self.spec,mode,context=context)
        for function in (module.vm_processes,module.vm_cleanup_main if mode=='vm-cleanup' else module.vm_inventory_main):
            self.assertIn(inspect.getsource(function).encode(),program)
        out=io.StringIO()
        with self.proc_rebased(denied),mock.patch('sys.stdout',out):exec(compile(program,'shipped '+mode,'exec',dont_inherit=True),{'__name__':'shipped'})
        return remote.validate_result(self.spec,mode,json.loads(out.getvalue()))
    def processes(self,module,denied=()):
        return sorted(self.shipped(module,'vm-inventory',denied=denied)['inventory']['processes'],key=lambda row:row['pid'])
    @staticmethod
    def outcomes(value):return [row.get('reason',row['state']) for row in value['results']]


@unittest.skipUnless(os.name=='posix','POSIX /proc fixture')
class VmProcessDetectionTests(HostMaintenanceFixture,unittest.TestCase):
    """F6b: the instance execs QEMU and swtpm through a pinned /proc/self/fd/N.

    Native evidence (private, never committed): while clone 246a3304 reported
    QEMU 3063661 and swtpm 3063660 running, vm-inventory reported processes=[]
    and vm-cleanup's whole-run refusal could not trigger. Here argv[0] names the
    descriptor and /proc/<pid>/exe the binary, as for that run; the before
    module is RED, the current one GREEN.
    """
    QEMU,SWTPM=3063661,3063660
    def setUp(self):
        super().setUp()
        self.add(self.SWTPM,['/proc/self/fd/7','socket','--tpm2','--tpmstate','dir='+str(self.root/'tpm')],'/usr/bin/swtpm')
        self.add(self.QEMU,['/proc/self/fd/9','-name','vpn-control-'+self.spec.deployment_id,'-uuid',self.spec.deployment_id],'/usr/bin/qemu-system-x86_64',((14,self.disk),))
    def test_descriptor_executed_vm_is_inventoried(self):
        self.assertEqual([],self.processes(self.before))
        self.assertEqual([{'pid':self.SWTPM,'name':'swtpm'},{'pid':self.QEMU,'name':'qemu-system-x86_64'}],self.processes(image))
    def test_cleanup_refuses_everything_while_the_vm_runs(self):
        # Before, only the per-file check guarded: the unheld TPM state of the running VM was deleted.
        value=self.shipped(self.before,'vm-cleanup')
        self.assertEqual(('vm-cleanup-done',['instance_cleanup_in_use','deleted']),(value['state'],self.outcomes(value)))
        self.assertTrue(self.disk.exists());self.assertFalse(self.state.exists());self.state.write_bytes(b'TPM2')
        value=self.shipped(image,'vm-cleanup')
        self.assertEqual(('vm-cleanup-refused',[]),(value['state'],value['results']))
        self.assertEqual([self.SWTPM,self.QEMU],sorted(row['pid'] for row in value['processes']))
        self.assertTrue(self.disk.exists() and self.state.exists())
    def test_unreadable_descriptor_executable_is_an_unverified_vm(self):
        denied=('/proc/%d/exe'%self.QEMU,'/proc/%d/exe'%self.SWTPM)
        self.assertEqual([],self.processes(self.before,denied))
        self.assertEqual([{'pid':self.SWTPM,'name':'7','unverified':True},{'pid':self.QEMU,'name':'9','unverified':True}],self.processes(image,denied))
        value=self.shipped(image,'vm-cleanup',denied=denied)
        self.assertEqual(('vm-cleanup-refused',[]),(value['state'],value['results']));self.assertTrue(self.disk.exists() and self.state.exists())
    def test_argv_names_and_replaced_binaries_still_count(self):
        # Another principal's QEMU (exe unreadable) still matches by argv[0]; a replaced binary by its exe.
        self.add(402,['/usr/bin/qemu-system-x86_64','-name','other-principal']);self.add(403,['/opt/vm/runner'],'/usr/bin/qemu-system-x86_64 (deleted)')
        self.assertEqual([{'pid':402,'name':'qemu-system-x86_64'},{'pid':403,'name':'qemu-system-x86_64 (deleted)'}],
                         [row for row in self.processes(image,('/proc/402/exe',)) if row['pid']in(402,403)])
        # The proc root parameter reads a fixture tree directly; the shipped default stays '/proc'.
        self.assertIn({'pid':403,'name':'qemu-system-x86_64 (deleted)'},image.vm_processes(str(self.proc)))
    def test_unreadable_daemons_libvirt_and_descriptor_run_tools_keep_cleanup_usable(self):
        # Usability guard, not causal: no row for daemons whose exe is unreadable and whose
        # argv[0] is a path, for a descriptor-run tool whose exe is readable (the instance's
        # xorriso) or one that exited (no exe link); libvirtd is listed but never blocks.
        for pid in (self.QEMU,self.SWTPM):shutil.rmtree(self.proc/str(pid))
        self.add(400,['/usr/bin/sshd','-D'],'/usr/bin/sshd');self.add(401,['/usr/bin/libvirtd','--timeout','120'],'/usr/bin/libvirtd')
        self.add(404,['/proc/self/fd/5','-as','mkisofs'],'/usr/bin/xorriso');self.add(405,['/proc/self/fd/9','-name','exited'])
        denied=('/proc/1/exe','/proc/400/exe')
        self.assertEqual([{'pid':401,'name':'libvirtd'}],self.processes(image,denied))
        value=self.shipped(image,'vm-cleanup',denied=denied)
        self.assertEqual(('vm-cleanup-done',['deleted','deleted']),(value['state'],self.outcomes(value)))
        self.assertFalse(self.disk.exists() or self.state.exists())
    def test_a_guest_argv_blocks_cleanup_under_a_daemon_executable(self):
        # Found in review of the fix: rows named the executable first and vm-cleanup blocks
        # on the reported name alone, so a QEMU argv[0] under a libvirtd executable stopped
        # blocking although the before module blocked on it. A guest name now wins.
        for pid in (self.QEMU,self.SWTPM):shutil.rmtree(self.proc/str(pid))
        self.add(406,['/usr/bin/qemu-system-x86_64','-name','under-a-daemon-executable'],'/usr/bin/libvirtd')
        for module in (self.before,image):
            with self.subTest(module=module.__name__):
                value=self.shipped(module,'vm-cleanup')
                self.assertEqual(('vm-cleanup-refused',[],[406]),(value['state'],value['results'],[row['pid'] for row in value.get('processes',[])]))
                self.assertTrue(self.disk.exists() and self.state.exists())
        self.assertEqual([{'pid':406,'name':'qemu-system-x86_64'}],self.processes(image))
    def test_every_descriptor_spelling_is_unverified_and_near_misses_are_not(self):
        # Coverage guard from review: every descriptor form a process can be executed
        # through counts when its executable is unreadable; near misses never do.
        for pid in (self.QEMU,self.SWTPM):shutil.rmtree(self.proc/str(pid))
        forms={410:'/dev/fd/3',411:'/proc/thread-self/fd/4',412:'/proc/123/fd/5',413:'/proc/self/fd/6'}
        misses={414:'/proc/self/fd/3/x',415:'proc/self/fd/3',416:'/proc/self/fd/x',417:'/dev/fd/'}
        for pid,command in {**forms,**misses}.items():self.add(pid,[command,'-name','fixture'],'/usr/bin/unknown')
        denied=tuple('/proc/%d/exe'%pid for pid in (*forms,*misses))
        self.assertEqual([],[row for row in self.processes(self.before,denied) if row['pid']>=410])
        self.assertEqual([{'pid':pid,'name':os.path.basename(command),'unverified':True} for pid,command in forms.items()],
                         [row for row in self.processes(image,denied) if row['pid']>=410])
    def test_fake_proc_fails_closed(self):
        # Harness check, not causal: only the shipped call forms are rebased; every other
        # API, path type or spelling naming /proc fails instead of reading the real /proc.
        with self.proc_rebased():
            with open('/proc/1/cmdline','rb')as stream:self.assertEqual(b'/usr/lib/systemd/systemd\0--system\0',stream.read())
            self.assertEqual('/usr/bin/swtpm',os.readlink('/proc/%d/exe'%self.SWTPM));self.assertEqual(self.disk.stat().st_ino,os.stat('/proc/%d/fd/14'%self.QEMU).st_ino)
            calls=(lambda:os.scandir('/proc'),lambda:os.lstat('/proc/1'),lambda:os.open('/proc/1/cmdline',os.O_RDONLY),lambda:io.open('/proc/1/cmdline','rb'),
                   lambda:Path('/proc/1/cmdline').read_bytes(),lambda:list(Path('/proc').iterdir()),lambda:os.listdir(b'/proc'),lambda:os.stat(Path('/proc/1')),
                   lambda:open('//proc/1/cmdline','rb'),lambda:os.readlink(Path('/proc/1/exe')),lambda:os.statvfs('/proc'),lambda:os.access('/proc',os.R_OK),
                   lambda:list(os.walk('/proc')),lambda:os.path.realpath('/proc/self'))
            for index,call in enumerate(calls):
                with self.subTest(index=index),self.assertRaises(AssertionError):call()


@unittest.skipUnless(os.name=='posix','POSIX /proc fixture')
class VmCleanupContainmentTests(HostMaintenanceFixture,unittest.TestCase):
    """vm-cleanup deletes only below the fixture home (found in review; no native failure).

    The before guard tested os.path.dirname(path).startswith(home) without a
    separator: with home <tmp>/fx, a same-uid file in the sibling directory
    <tmp>/fx-old passed and was deleted. No VM runs in the fake /proc, so only
    the path guard decides.
    """
    def test_sibling_sharing_the_home_name_prefix_is_never_deleted(self):
        sibling=self.base/'fx-old';sibling.mkdir(mode=0o700);victim=sibling/'disk.qcow2'
        stale=self.home/'vc-rw-0';stale.mkdir(mode=0o700);inside=stale/'disk.qcow2';paths=(victim,inside,self.home)
        victim.write_bytes(b'QFI\xfb');inside.write_bytes(b'QFI\xfb')
        value=self.shipped(self.before,'vm-cleanup',paths)
        self.assertEqual(('vm-cleanup-done',['deleted','deleted','instance_cleanup_path']),(value['state'],self.outcomes(value)))
        self.assertFalse(victim.exists() or inside.exists())
        victim.write_bytes(b'QFI\xfb');inside.write_bytes(b'QFI\xfb')
        value=self.shipped(image,'vm-cleanup',paths)
        self.assertEqual(('vm-cleanup-done',['instance_cleanup_path','deleted','instance_cleanup_path']),(value['state'],self.outcomes(value)))
        self.assertTrue(victim.exists() and self.home.is_dir());self.assertFalse(inside.exists())


if __name__=='__main__':unittest.main()
