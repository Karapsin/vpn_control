"""Fixed Windows session facts; no credential, login, lock or power actions."""
import json
import re
import sys

_EXECUTING_CODE=sys._getframe().f_code

WTS_NATIVE = 'using System;\nusing System.ComponentModel;\nusing System.Runtime.InteropServices;\nusing System.Security.Principal;\npublic static class SessionFacts {\n [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]public struct Level1 {\n public UInt32 SessionId;public Int32 State;public Int32 Flags;\n [MarshalAs(UnmanagedType.ByValTStr,SizeConst=33)]public string Station;\n [MarshalAs(UnmanagedType.ByValTStr,SizeConst=21)]public string User;\n [MarshalAs(UnmanagedType.ByValTStr,SizeConst=18)]public string Domain;\n public Int64 Logon;public Int64 Connect;public Int64 Disconnect;public Int64 LastInput;public Int64 Current;\n public UInt32 InBytes;public UInt32 OutBytes;public UInt32 InFrames;public UInt32 OutFrames;public UInt32 InCompressed;public UInt32 OutCompressed;\n }\n [StructLayout(LayoutKind.Sequential)]public struct Info {public UInt32 Level;public Level1 Data;}\n [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]public struct Session {public Int32 Id;public string Name;public Int32 State;}\n [DllImport("kernel32.dll")]public static extern UInt32 WTSGetActiveConsoleSessionId();\n [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool WTSQuerySessionInformationW(IntPtr server,UInt32 session,int info,out IntPtr buffer,out int bytes);\n [DllImport("wtsapi32.dll")]static extern void WTSFreeMemory(IntPtr ptr);\n [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool WTSEnumerateSessionsW(IntPtr server,int reserved,int version,out IntPtr buffer,out int count);\n [DllImport("wtsapi32.dll",SetLastError=true)]static extern bool WTSQueryUserToken(UInt32 session,out IntPtr token);\n [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);\n public static Info Read(UInt32 id){IntPtr p;int bytes;if(!WTSQuerySessionInformationW(IntPtr.Zero,id,25,out p,out bytes))throw new Win32Exception();try{if(bytes<Marshal.SizeOf(typeof(Info)))throw new Exception("WTS_SIZE");Info result=(Info)Marshal.PtrToStructure(p,typeof(Info));if(result.Level!=1||result.Data.SessionId!=id)throw new Exception("WTS_IDENTITY");return result;}finally{WTSFreeMemory(p);}}\n public static Session[] All(){IntPtr p;int count;if(!WTSEnumerateSessionsW(IntPtr.Zero,0,1,out p,out count))throw new Win32Exception();try{if(count<0||count>128)throw new Exception("WTS_COUNT");var result=new Session[count];int size=Marshal.SizeOf(typeof(Session));for(int i=0;i<count;i++)result[i]=(Session)Marshal.PtrToStructure(IntPtr.Add(p,i*size),typeof(Session));return result;}finally{WTSFreeMemory(p);}}\n public static string Sid(UInt32 id){IntPtr token;if(!WTSQueryUserToken(id,out token))throw new Win32Exception();try{using(var identity=new WindowsIdentity(token)){return identity.User.Value;}}finally{CloseHandle(token);}}\n}'

def powershell_source(user):
    if type(user) is not str or re.fullmatch('[a-z][a-z0-9-]{0,31}', user) is None:
        raise ValueError('windows_account_invalid')
    prefix = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
    prefix += "if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'SYSTEM_REQUIRED'}\n"
    prefix += "Add-Type -TypeDefinition @'\n" + WTS_NATIVE + "\n'@\n"
    return prefix + "$ExpectedUser=" + repr(user) + "\n" + OBSERVE


OBSERVE = r"""
$id=[SessionFacts]::WTSGetActiveConsoleSessionId()
if($id -eq [UInt32]::MaxValue){throw 'CONSOLE_TRANSITION'}
$info=[SessionFacts]::Read($id);$user=Get-LocalUser -Name $ExpectedUser
$admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {$_.SID.Value})
$users=@(Get-LocalGroupMember -SID 'S-1-5-32-545' | ForEach-Object {$_.SID.Value})
$os=Get-CimInstance Win32_OperatingSystem
$tokenSid=$null
if(-not [String]::IsNullOrEmpty($info.Data.User)){$tokenSid=[SessionFacts]::Sid($id)}
$result=[ordered]@{machine=(Get-CimInstance Win32_ComputerSystemProduct).UUID;boot=$os.LastBootUpTime.ToUniversalTime().ToString('o');console=$id;infoLevel=$info.Level;session=$info.Data;tokenSid=$tokenSid;expectedSid=$user.SID.Value;ordinary=($admins -notcontains $user.SID.Value -and $users -contains $user.SID.Value -and $user.Enabled);sessions=@([SessionFacts]::All());explorers=@(Get-Process explorer -ErrorAction SilentlyContinue | Select-Object Id,SessionId)}
[Console]::WriteLine(($result|ConvertTo-Json -Depth 6 -Compress))
"""


def validate_session(value, expected_sid, user, expected_machine):
    """Refuse unrecognized WTS identity instead of interpreting zeroes as lock."""
    def need(condition, reason):
        if not condition:
            raise ValueError(reason)
    need(type(value) is dict and set(value) == {'machine','boot','console','infoLevel','session','tokenSid','expectedSid','ordinary','sessions','explorers'}, 'windows_session_fields')
    need(type(expected_sid) is str and re.fullmatch('S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+',expected_sid) is not None, 'windows_expected_sid')
    need(value['expectedSid'] == expected_sid and value['ordinary'] is True, 'windows_account_mismatch')
    need(type(value['boot']) is str and re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z',value['boot']) is not None, 'windows_boot_unrecognized')
    need(type(value['machine']) is str and value['machine'].lower() == expected_machine, 'windows_machine_mismatch')
    session = value['session']
    need(type(value['console']) is int and 0 <= value['console'] < 2**32-1 and value['infoLevel'] == 1 and type(value['infoLevel']) is int, 'windows_session_unrecognized')
    need(type(session) is dict and set(session) == {'SessionId','State','Flags','Station','User','Domain','Logon','Connect','Disconnect','LastInput','Current','InBytes','OutBytes','InFrames','OutFrames','InCompressed','OutCompressed'}, 'windows_session_unrecognized')
    need(type(session['SessionId']) is int and session['SessionId'] == value['console'] and type(session['State']) is int and 0 <= session['State'] <= 9 and type(session['Flags']) is int and session['Flags'] in {0,1}, 'windows_session_unrecognized')
    need(session['Station'] == 'Console' and type(session['User']) is str and type(session['Domain']) is str, 'windows_session_unrecognized')
    need(type(session['Logon']) is int and session['Logon'] >= 0, 'windows_session_unrecognized')
    need(type(value['sessions']) is list and 1 <= len(value['sessions']) <= 128 and type(value['explorers']) is list and len(value['explorers']) <= 128, 'windows_session_unrecognized')
    for row in value['sessions']:
        need(type(row) is dict and set(row)=={'Id','Name','State'} and type(row['Id']) is int and type(row['Name']) is str and type(row['State']) is int, 'windows_session_unrecognized')
    for row in value['explorers']:
        need(type(row) is dict and set(row)=={'Id','SessionId'} and type(row['Id']) is int and row['Id']>0 and type(row['SessionId']) is int, 'windows_session_unrecognized')
    need(len(json.dumps(value)) <= 65536, 'windows_session_bound')
    if not session['User']:
        need(value['tokenSid'] is None, 'windows_session_unrecognized')
        state = 'signed_out'
    elif session['User'].casefold() != user.casefold() or value['tokenSid'] != expected_sid:
        state = 'wrong_account'
    elif session['State'] != 0:
        state = 'unknown'
    elif session['Flags'] == 0:
        state = 'locked'
    else:
        need(sum(row['SessionId']==value['console'] for row in value['explorers']) == 1, 'windows_desktop_shell_unrecognized')
        state = 'ready'
    return {'ordinary_session':state,'boot':value['boot'],'account':expected_sid,'session':str(value['console'])+':'+str(session['Logon']),
            'competingSessions':any(row['Id'] not in {0,value['console']} for row in value['sessions'])}
