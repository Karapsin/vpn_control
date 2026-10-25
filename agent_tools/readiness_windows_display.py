"""Fixed read-only console-display power notification, including initial state.

No window/input/setting/power operation is exposed. A current-value callback is
required; registration success alone never means the display is awake.
"""
import json
import re
import sys
from uuid import UUID

_EXECUTING_CODE = sys._getframe().f_code


def powershell_source(machine, boot):
    if type(machine) is not str or str(UUID(machine)) != machine:
        raise ValueError('windows_display_machine_invalid')
    if type(boot) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z', boot):
        raise ValueError('windows_display_boot_invalid')
    return ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n"
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
            "function Guard {\n"
            " if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'SYSTEM_REQUIRED'}\n"
            " $m=([Guid](Get-CimInstance Win32_ComputerSystemProduct).UUID).ToString('D')\n"
            " $b=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')\n"
            " if($m -ne '" + machine + "' -or $b -ne '" + boot + "'){throw 'GUEST_IDENTITY_CHANGED'}\n}\n"
            "Guard\nAdd-Type -TypeDefinition @'\n" + NATIVE + "\n'@\n"
            "$state=[ConsoleDisplayFacts]::Read();Guard\n"
            "[Console]::WriteLine((@{schemaVersion=1;machine='" + machine + "';boot='" + boot +
            "';displayState=$state}|ConvertTo-Json -Compress))\n")


def validate(value, machine, boot):
    if (type(value) is not dict or set(value) != {'schemaVersion','machine','boot','displayState'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['machine'] != machine or value['boot'] != boot
            or type(value['displayState']) is not int or value['displayState'] not in {0,1,2}):
        raise ValueError('windows_display_observation_invalid')
    return {0: 'asleep', 1: 'awake', 2: 'dimmed'}[value['displayState']]


NATIVE = r'''
using System;
using System.Runtime.InteropServices;
using System.Threading;
public static class ConsoleDisplayFacts {
 static readonly Guid Setting=new Guid("6fe69556-704a-47a0-8f24-c28d936fda47");
 [UnmanagedFunctionPointer(CallingConvention.Winapi)]delegate UInt32 Callback(IntPtr context,UInt32 type,IntPtr value);
 [StructLayout(LayoutKind.Sequential)]struct Subscriber {public IntPtr Callback;public IntPtr Context;}
 [DllImport("powrprof.dll")]static extern UInt32 PowerSettingRegisterNotification(ref Guid setting,UInt32 flags,ref Subscriber subscriber,out IntPtr handle);
 [DllImport("powrprof.dll")]static extern UInt32 PowerSettingUnregisterNotification(IntPtr handle);
 sealed class State {public readonly object Gate=new object();public readonly ManualResetEvent Ready=new ManualResetEvent(false);public int Value=-1;public bool Invalid=false;}
 public static int Read(){
  var state=new State();Callback callback=delegate(IntPtr context,UInt32 type,IntPtr value){
   try{if(type!=0x8013||value==IntPtr.Zero)return 0;
    Guid guid=(Guid)Marshal.PtrToStructure(value,typeof(Guid));if(guid!=Setting)return 0;
    int length=Marshal.ReadInt32(value,16);int current=length==4?Marshal.ReadInt32(value,20):-1;
    lock(state.Gate){if(current<0||current>2)state.Invalid=true;else state.Value=current;}state.Ready.Set();
   }catch{lock(state.Gate){state.Invalid=true;}state.Ready.Set();}return 0;
  };
  var subscriber=new Subscriber{Callback=Marshal.GetFunctionPointerForDelegate(callback),Context=IntPtr.Zero};
  Guid setting=Setting;IntPtr registration;UInt32 code=PowerSettingRegisterNotification(ref setting,2,ref subscriber,out registration);
  if(code!=0)throw new Exception("DISPLAY_NOTIFICATION_UNAVAILABLE");
  try{
   if(!state.Ready.WaitOne(2000))throw new Exception("DISPLAY_INITIAL_VALUE_UNAVAILABLE");
   Thread.Sleep(100);lock(state.Gate){if(state.Invalid||state.Value<0)throw new Exception("DISPLAY_VALUE_UNRECOGNIZED");return state.Value;}
  }finally{UInt32 removed=PowerSettingUnregisterNotification(registration);GC.KeepAlive(callback);state.Ready.Dispose();if(removed!=0)throw new Exception("DISPLAY_NOTIFICATION_RELEASE_UNVERIFIED");}
 }
}
'''
