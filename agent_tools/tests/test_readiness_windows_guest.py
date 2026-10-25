"""Actual WTS buffer/class regression and strict session identity admission."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from agent_tools import readiness_windows_guest as guest

FIXTURE=Path(__file__).parent/'fixtures/windows_wts_info_class'
SID='S-1-5-21-1-2-3-1000'
MACHINE='6e848ad1-8078-4435-9abc-e3a24c6556cd'


def before_native():
    raw=(FIXTURE/'observe.before.source').read_bytes()
    expected=json.loads((FIXTURE/'provenance.json').read_text())['sources']['observe.before.source']
    if hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('wts_beforeimage_changed')
    return raw.decode().split("Add-Type -TypeDefinition @'\n",1)[1].split("\n'@",1)[0]


def facts():
    session={k:0 for k in ['State','Logon','Connect','Disconnect','LastInput','Current','InBytes','OutBytes','InFrames','OutFrames','InCompressed','OutCompressed']}
    session.update(SessionId=2,Flags=1,Station='Console',User='recovery',Domain='FIXTURE',Logon=123)
    return {'machine':MACHINE.upper(),'boot':'2026-10-20T09:37:35.5000000Z','console':2,'infoLevel':1,
            'session':session,'expectedSid':SID,'tokenSid':SID,'ordinary':True,
            'sessions':[{'Id':0,'Name':'Services','State':4},{'Id':2,'Name':'Console','State':0}],
            'explorers':[{'Id':12,'SessionId':2}]}


def native_harness(source):
    # Bind only the native API boundary to controlled unmanaged buffers. The
    # complete captured/current Read implementation and struct layout execute.
    declaration='[DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool WTSQuerySessionInformationW(IntPtr server,UInt32 session,int info,out IntPtr buffer,out int bytes);'
    replacement='''static bool WTSQuerySessionInformationW(IntPtr server,UInt32 session,int info,out IntPtr buffer,out int bytes){
 bytes=Marshal.SizeOf(typeof(Info));buffer=Marshal.AllocHGlobal(bytes);for(int i=0;i<bytes;i++)Marshal.WriteByte(buffer,i,0);
 Marshal.WriteInt32(buffer,0,1);if(info==25){Marshal.WriteInt32(buffer,8,(int)session);Marshal.WriteInt32(buffer,16,1);}return true;
 }'''
    free='[DllImport("wtsapi32.dll")]static extern void WTSFreeMemory(IntPtr ptr);'
    if source.count(declaration)!=1 or source.count(free)!=1:
        raise ValueError('wts_native_boundary_changed')
    source=source.replace(declaration,replacement).replace(free,'static void WTSFreeMemory(IntPtr ptr){Marshal.FreeHGlobal(ptr);}')
    return "$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n"+source+"\n'@\n$result=[SessionFacts]::Read(2)\nif($result.Level -ne 1 -or $result.Data.SessionId -ne 2 -or $result.Data.Flags -ne 1){throw 'WTS_CAUSAL_SESSION_IDENTITY'}\n[Console]::WriteLine('WTS_CAUSAL_GREEN')\n"


class WindowsSessionTests(unittest.TestCase):
    def validate(self,value):
        return guest.validate_session(value,SID,'recovery',MACHINE)

    def test_actual_session_states_and_original_account_identity(self):
        value=facts();self.assertEqual('ready',self.validate(value)['ordinary_session'])
        value['session']['Flags']=0;self.assertEqual('locked',self.validate(value)['ordinary_session'])
        value['session']['User']='other';self.assertEqual('wrong_account',self.validate(value)['ordinary_session'])
        value['session']['User']='';value['tokenSid']=None;self.assertEqual('signed_out',self.validate(value)['ordinary_session'])

    def test_zeroed_unrelated_WTS_payload_is_never_a_lock(self):
        value=facts();value['session'].update(SessionId=0,Flags=0,Station='',User='',Domain='',Logon=0)
        with self.assertRaisesRegex(ValueError,'windows_session_unrecognized'):self.validate(value)

    def test_boolean_integer_and_foreign_boot_account_or_machine_are_refused(self):
        for field,bad in [('console',True),('infoLevel',True),('ordinary',False),('expectedSid','S-1-5-18'),('machine','wrong'),('boot','yesterday')]:
            value=facts();value[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(value)
        for field,bad in [('SessionId',True),('Flags',True),('State',True),('Logon',True)]:
            value=facts();value['session'][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(value)

    def test_shell_and_competing_operator_visibility(self):
        value=facts();value['explorers']=[]
        with self.assertRaisesRegex(ValueError,'windows_desktop_shell_unrecognized'):self.validate(value)
        value=facts();value['sessions'].append({'Id':3,'Name':'RDP-Tcp#0','State':0})
        self.assertTrue(self.validate(value)['competingSessions'])

    def test_source_has_no_input_power_or_user_supplied_program(self):
        emitted=guest.powershell_source('recovery')
        for forbidden in ['Set-LocalUser','SendInput','SendKeys','guest-shutdown','LockWorkStation','AutoAdminLogon']:
            self.assertNotIn(forbidden,emitted)
        for account in ["recovery';throw 'injected",'ADMIN\\recovery','',None]:
            with self.assertRaises(ValueError):guest.powershell_source(account)
        self.assertIn('WTS_CAUSAL_SESSION_IDENTITY',native_harness(before_native()))
        self.assertIn('WTS_CAUSAL_SESSION_IDENTITY',native_harness(guest.WTS_NATIVE))


@unittest.skipUnless(os.name=='nt' and shutil.which('powershell.exe'),'Windows PowerShell native C# boundary execution')
class NativeWindowsWtsTests(unittest.TestCase):
    def test_actual_before_wrong_information_class_RED_and_fixed_GREEN(self):
        for label,source,code in [('before',before_native(),1),('fixed',guest.WTS_NATIVE,0)]:
            with self.subTest(label=label),tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/'native.ps1';path.write_text(native_harness(source),encoding='utf-8')
                result=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],capture_output=True,timeout=30)
                self.assertEqual(code,result.returncode,(result.stdout+result.stderr).decode(errors='replace'))
                self.assertEqual(label=='fixed',b'WTS_CAUSAL_GREEN' in result.stdout)


if __name__=='__main__':unittest.main()
