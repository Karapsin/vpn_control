"""Fixed API35-measured readonly utility ABI profile.

Original direct component receipt SHA256:
 a29bb4e8a30f72d34dc9b98552d7eeed05e67982e03cba5a5c816bff5a902cf1.
This module generates and validates only the fixed probe. Callers must bind its
source, transport, device and opening/closing physical authority. It performs
no transport, owner admission, sink creation, batching or product operation.
"""
import base64
import re
import shlex
import uuid

_PROGRAM = 'set -eu\nprintf \'PHYSICAL-READONLY-4\\n\'\nuid=$(id -u);printf \'UID %s\\n\' "$uid"\nshellmap=$(/system/bin/toybox readlink /proc/$$/exe)\nutilitymap=$(/system/bin/toybox readlink /proc/self/exe)\nprintf \'SHELL %s\\nUTILITY %s\\n\' "$shellmap" "$utilitymap"\nng=$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/sh)\nprintf \'NAMED-SH-GENERATION %s\\n\' "$ng"\nif test -L /system/bin/sh; then\n link=$(/system/bin/toybox readlink /system/bin/sh);kind=symlink\nelse\n link=NONE;kind=regular\nfi\nprintf \'SH-KIND %s\\nSH-TARGET %s\\n\' "$kind" "$link"\nprintf \'KSH-VERSION \'\nprintf \'%s\' "${KSH_VERSION-}" | /system/bin/toybox base64 -w 0\nprintf \'\\n\'\nprintf \'PRINCIPAL \'; /system/bin/toybox id\nboot=$(cat /proc/sys/kernel/random/boot_id);printf \'BOOT %s\\n\' "$boot"\nprintf \'INHERITED-LIMITS \'; /system/bin/toybox base64 -w 0 /proc/$$/limits;printf \'\\n\'\ntest "$uid" = 2000\ntest "$utilitymap" = /system/bin/toybox\ncase "$shellmap" in /system/bin/sh|/system/bin/mksh) ;; *) exit 91;; esac\ncase "$kind:$link:$shellmap" in regular:NONE:/system/bin/sh|symlink:mksh:/system/bin/mksh|symlink:/system/bin/mksh:/system/bin/mksh) ;; *) exit 92;; esac\ncase "${KSH_VERSION-}" in \'@(#)MIRBSD KSH R\'[0-9]*\' \'*) ;; *) exit 93;; esac\ntest -f "$shellmap" && test ! -L "$shellmap"\ntest -f /system/bin/toybox && test ! -L /system/bin/toybox\nfor binary in "$shellmap" /system/bin/toybox; do\n principal=$(/system/bin/toybox stat -c \'%u:%g:%a:%h\' "$binary")\n case "$principal" in 0:0:755:1|0:2000:755:1) ;; *) exit 94;; esac\ndone\nsg=$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' "$shellmap")\ntg=$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/toybox)\nshellhash=$(/system/bin/toybox sha256sum "$shellmap");toyhash=$(/system/bin/toybox sha256sum /system/bin/toybox)\nprintf \'SHELL-GENERATION %s\\nTOYBOX-GENERATION %s\\nSHELL-HASH %s\\nTOYBOX-HASH %s\\n\' "$sg" "$tg" "$shellhash" "$toyhash"\ntest "$(printf \'a\\nb\\n\' | /system/bin/toybox base64 -w 0)" = \'YQpiCg==\'\nexec 4</system/bin/toybox\nexec 5</system/bin/toybox\nbg=$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/toybox)\ntest "$bg" = "$tg"\nexpected=$(/system/bin/toybox sha256sum /system/bin/toybox);expected=${expected%% *}\ntest "$expected" = "${toyhash%% *}"\nfor fd in 4 5; do\n test "$(/system/bin/toybox stat -L -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /proc/$$/fd/$fd)" = "$bg"\ndone\nh4=$(/system/bin/toybox sha256sum /proc/self/fd/4 4>&4);h4=${h4%% *}\nh5=$(/system/bin/toybox sha256sum /proc/self/fd/5 5>&5);h5=${h5%% *}\nexec 4<&-;exec 5<&-\nprintf \'FD4 %s\\nFD5 %s\\n\' "$h4" "$h5"\ntest "$h4" = "$expected" && test "$h5" = "$expected"\ntest "$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/toybox)" = "$bg"\nbefore=$(/system/bin/toybox cat /proc/uptime);set -- $before;before=$1\nset +e\nwd=$(/system/bin/toybox timeout -s KILL 1 "$shellmap" -c __WD_CHILD__)\nrc=$?\nset -e\nafter=$(/system/bin/toybox cat /proc/uptime);set -- $after;after=$1\nprintf \'%s\\nWATCHDOG %s\\nWATCHDOG-TIME %s %s\\n\' "$wd" "$rc" "$before" "$after"\ntest "$rc" = 137 || exit 95\nset -- $wd;test "$#" = 5;test "$1" = WATCHDOG-CHILD;test "$2" = __WD_CORR__;pid=$3;ticks=$4;test "$5" = 2000\ncase "$pid:$ticks" in *[!0-9:]*|:*|*:) exit 96;; esac;test "$pid" -gt 0;test "$ticks" -gt 0\nset +e\npost=$(/system/bin/toybox stat -L -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /proc/$pid 2>&1);postrc=$?\nset -e\nprintf \'WATCHDOG-POST %s \' "$postrc";printf \'%s\' "$post" | /system/bin/toybox base64 -w 0;printf \'\\n\'\ntest "$postrc" = 1\ntest "$post" = "stat: \'/proc/$pid\': No such file or directory"\nlimit=$( (ulimit -f 32; /system/bin/toybox cat /proc/self/limits) )\nprintf \'LIMIT-PROOF \';printf \'%s\' "$limit" | /system/bin/toybox base64 -w 0;printf \'\\n\'\ntest "$(printf \'%s\\n\' "$limit" | /system/bin/toybox grep -E \'^Max file size[[:space:]]+16384[[:space:]]+16384[[:space:]]+bytes[[:space:]]*$\')" != \'\'\ntest "$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' "$shellmap")" = "$sg"\ntest "$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/toybox)" = "$tg"\ntest "$(/system/bin/toybox stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' /system/bin/sh)" = "$ng"\ntest "$(/system/bin/toybox sha256sum "$shellmap")" = "$shellhash"\ntest "$(/system/bin/toybox sha256sum /system/bin/toybox)" = "$toyhash"\ntest "$(/system/bin/toybox readlink /proc/$$/exe)" = "$shellmap"\ntest "$(cat /proc/sys/kernel/random/boot_id)" = "$boot"\nprintf \'EOF READONLY-4 COMPLETE\\n\'\n'

_CHILD = 'set -eu\nuid=$(/system/bin/toybox id -u);test "$uid" = 2000\nline=$(/system/bin/toybox cat /proc/$$/stat)\ncase "$line" in "$$ ("*") "*) ;; *) exit 96;; esac\nrest=${line##*) };set -- $rest;test "$#" -ge 20;shift 19;ticks=$1\ncase "$ticks" in \'\'|*[!0-9]*) exit 96;; esac;test "$ticks" -gt 0\nprintf \'WATCHDOG-CHILD __WD_CORR__ %s %s %s\\n\' "$$" "$ticks" "$uid"\nexec /system/bin/toybox sleep 2\n'

def source(correlation):
    """One fixed readonly command, positively bound to a canonical UUID."""
    if type(correlation) is not str or str(uuid.UUID(correlation)) != correlation:
        raise ValueError('abi_packet_identity_changed')
    child = _CHILD.replace('__WD_CORR__', correlation)
    return _PROGRAM.replace('__WD_CHILD__', shlex.quote(child)).replace('__WD_CORR__', correlation)


def parse(raw, correlation, expected_boot):
    """Strict bounded ABI facts only, with no native/product authority."""
    if (type(correlation) is not str or type(expected_boot) is not str or
        re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', correlation) is None or
        re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', expected_boot) is None):
        raise ValueError('abi_packet_identity_changed')
    if type(raw)is not str or len(raw.encode())>16384 or not raw.endswith('\n'):raise ValueError('abi_packet_reply_unknown')
    lines=raw.splitlines()
    keys=('PHYSICAL-READONLY-4','UID','SHELL','UTILITY','NAMED-SH-GENERATION','SH-KIND','SH-TARGET','KSH-VERSION','PRINCIPAL','BOOT','INHERITED-LIMITS','SHELL-GENERATION','TOYBOX-GENERATION','SHELL-HASH','TOYBOX-HASH','FD4','FD5','WATCHDOG-CHILD','WATCHDOG','WATCHDOG-TIME','WATCHDOG-POST','LIMIT-PROOF','EOF')
    if len(lines)!=len(keys)or lines[0]!=keys[0]or lines[-1]!='EOF READONLY-4 COMPLETE':raise ValueError('abi_packet_reply_unknown')
    values={}
    for line,key in zip(lines[1:],keys[1:]):
     if not line.startswith(key+' '):raise ValueError('abi_packet_reply_unknown')
     values[key]=line[len(key)+1:]
    shell=values['SHELL']
    if values['UID']!='2000'or shell not in('/system/bin/sh','/system/bin/mksh')or values['UTILITY']!='/system/bin/toybox':raise ValueError('abi_packet_mapping_unknown')
    if (values['SH-KIND'],values['SH-TARGET'],shell)not in(('regular','NONE','/system/bin/sh'),('symlink','mksh','/system/bin/mksh'),('symlink','/system/bin/mksh','/system/bin/mksh')):raise ValueError('abi_packet_mapping_unknown')
    import stat
    for key in ('NAMED-SH-GENERATION','SHELL-GENERATION','TOYBOX-GENERATION'):
     generation=values[key]
     if re.fullmatch(r'[0-9]+:[1-9][0-9]*:[0-9a-f]+:0:(?:0|2000):1:[0-9]+:[^\n]+:[^\n]+',generation)is None:raise ValueError('abi_packet_generation_unknown')
     mode=int(generation.split(':')[2],16)
     link=key=='NAMED-SH-GENERATION'and values['SH-KIND']=='symlink'
     if (not stat.S_ISLNK(mode)if link else not stat.S_ISREG(mode))or(not link and stat.S_IMODE(mode)!=0o755):raise ValueError('abi_packet_generation_unknown')
    def decode(key,limit):
     try:value=base64.b64decode(values[key],validate=True)
     except Exception:raise ValueError('abi_packet_reply_unknown')from None
     if len(value)>limit or base64.b64encode(value).decode()!=values[key]:raise ValueError('abi_packet_reply_unknown')
     return value
    version=decode('KSH-VERSION',512)
    if re.fullmatch(rb'@\(#\)MIRBSD KSH R[0-9]+ [ -~]{1,256}',version)is None:raise ValueError('abi_packet_shell_family_unknown')
    if re.fullmatch(r'uid=2000\([^\n()]+\) gid=2000\([^\n()]+\)(?: groups=[^\n]+)?',values['PRINCIPAL'])is None:raise ValueError('abi_packet_principal_unknown')
    if re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',values['BOOT'])is None or values['BOOT']!=expected_boot:raise ValueError('abi_packet_boot_unknown')
    inherited=decode('INHERITED-LIMITS',8192);limit_proof=decode('LIMIT-PROOF',8192)
    if len(re.findall(rb'^Max file size\s+(?:[0-9]+|unlimited)\s+(?:[0-9]+|unlimited)\s+bytes\s*$',inherited,re.M))!=1 or len(re.findall(rb'^Max file size\s+16384\s+16384\s+bytes\s*$',limit_proof,re.M))!=1:raise ValueError('abi_packet_limits_unknown')
    for key,path in (('SHELL-HASH',shell),('TOYBOX-HASH','/system/bin/toybox')):
     if re.fullmatch('[0-9a-f]{64}  '+re.escape(path),values[key])is None:raise ValueError('abi_packet_hash_unknown')
    if values['WATCHDOG']!='137'or re.fullmatch('[0-9a-f]{64}',values['FD4'])is None or values['FD5']!=values['FD4']or values['FD4']!=values['TOYBOX-HASH'][:64]:raise ValueError('abi_packet_capability_unknown')
    child=re.fullmatch(re.escape(correlation)+r' ([1-9][0-9]*) ([1-9][0-9]*) 2000',values['WATCHDOG-CHILD'])
    if child is None:raise ValueError('abi_packet_watchdog_child_unknown')
    times=re.fullmatch(r'([0-9]+\.[0-9]+) ([0-9]+\.[0-9]+)',values['WATCHDOG-TIME'])
    if times is None:raise ValueError('abi_packet_watchdog_time_unknown')
    from decimal import Decimal
    elapsed=Decimal(times[2])-Decimal(times[1])
    if not Decimal('0.75')<=elapsed<=Decimal('1.75'):raise ValueError('abi_packet_watchdog_time_unknown')
    post=values['WATCHDOG-POST'].split(' ')
    if len(post)!=2 or post[0]!='1':raise ValueError('abi_packet_watchdog_child_unknown')
    try:absence=base64.b64decode(post[1],validate=True)
    except Exception:raise ValueError('abi_packet_watchdog_child_unknown')from None
    if base64.b64encode(absence).decode()!=post[1]or absence!=("stat: '/proc/"+child[1]+"': No such file or directory").encode():raise ValueError('abi_packet_watchdog_child_unknown')
    return {'kind':'utility-abi-only','profileVersion':4,'shellPath':shell,'shellSha256':values['SHELL-HASH'][:64],'toyboxSha256':values['TOYBOX-HASH'][:64],'fdSha256':values['FD4'],'utilityGenerations':{k:values[k]for k in('NAMED-SH-GENERATION','SHELL-GENERATION','TOYBOX-GENERATION')},'guestBootId':values['BOOT'],'family':'mksh-capability-checked','shellVersion':version.decode(),'fileLimit':16384,'watchdogExit':137,'watchdogChildPid':int(child[1]),'watchdogChildStartTicks':int(child[2]),'watchdogElapsedSeconds':str(elapsed),'watchdogChildAbsent':True,'ownerAdmission':False,'runtimeAdmission':False,'batchEnabled':False,'overflowWriteProven':False,'nativeAcceptance':False}
