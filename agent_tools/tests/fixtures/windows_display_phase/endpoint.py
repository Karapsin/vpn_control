"""Finite QMP/QGA fixture, with real Linux process/file/socket ownership."""
import base64
import hashlib
import json
import re
from pathlib import Path
import socket
import sys
import threading
import time

root=Path(sys.argv[1]);mode=sys.argv[2]
config=json.loads((root/'fixture.json').read_text())
mutex=threading.Lock();current={'status':'running','display':0,'execCount':0,'inputCount':0,'statusCount':0}
jobs={};files=[]
if mode=='qemu':
    files=[(root/name).open('rb')for name in ('disk.qcow2','uefi-vars.fd')]

def save():
    (root/'counters.json').write_text(json.dumps(current))

def project_guest(source,session,display,expected_sources):
    matches=re.findall(r"^\$VcFrame=\('([^']+)'\|ConvertFrom-Json\)$",source,re.M)
    if len(matches)!=1:raise ValueError('fixture_source_frame')
    frame=json.loads(matches[0])
    if set(frame)!={'schemaVersion','operationId','label','sourceSha256'}or type(frame['schemaVersion'])is not int or frame['schemaVersion']!=1:raise ValueError('fixture_source_frame')
    roles=[role for role,body in expected_sources.items()if hashlib.sha256(body.encode()).hexdigest()==frame['sourceSha256']]
    if len(roles)!=1:raise ValueError('fixture_source_unknown')
    role=roles[0];lines=expected_sources[role].rstrip().splitlines();last=lines[-1]
    if not last.startswith('[Console]::WriteLine(')or not last.endswith(')'):raise ValueError('fixture_source_output')
    lines[-1]='$VcRaw='+last[len('[Console]::WriteLine('):-1]
    wanted='\n'.join(lines)+"\n$VcBody=($VcRaw|ConvertFrom-Json)\n$VcOwner=Get-Process -Id $PID\n"
    wanted+="$VcFrame=('"+json.dumps(frame,separators=(',',':'))+"'|ConvertFrom-Json)\n"
    wanted+="$VcFrame|Add-Member -NotePropertyName owner -NotePropertyValue (@{pid=$PID;birth=$VcOwner.StartTime.ToFileTimeUtc().ToString()})\n$VcFrame|Add-Member -NotePropertyName result -NotePropertyValue $VcBody\n[Console]::WriteLine(($VcFrame|ConvertTo-Json -Depth 24 -Compress))\n"
    if source!=wanted:raise ValueError('fixture_source_body_changed')
    account={'name':'recovery','fullName':'recovery','sid':session['expectedSid'],'enabled':True,'loginKeyboard':'00000409'}
    if role=='combined':return {'sessionFacts':session,'displayFacts':display,'accountFacts':account}
    if role=='account':return account
    if role=='session':return session
    raise ValueError('fixture_source_unknown')

def handle(channel,family):
    with channel:
        stream=channel.makefile('rwb',buffering=0)
        if family=='qmp':stream.write(b'{"QMP":{"version":{},"capabilities":[]}}\n')
        while True:
            line=stream.readline(262145)
            if not line or len(line)>262144:return
            request=json.loads(line.lstrip(b'\xff'));command=request['execute'];args=request.get('arguments',{})
            marker=b'';error=None
            with mutex:
                if command=='qmp_capabilities':value={}
                elif command=='query-uuid':value={'UUID':config['machine']}
                elif command=='query-status':
                    if (root/'intentional-paused').exists():current['status']='paused'
                    value={'status':current['status']}
                elif command in {'cont','system_wakeup'}:
                    (root/'intentional-paused').unlink(missing_ok=True);current['status']='running';value={}
                elif command=='query-mice':value=[{'current':True,'absolute':True}]
                elif command=='input-send-event':
                    if args!={'events':[{'type':'rel','data':{'axis':'x','value':1}}]}:raise ValueError('fixture_fixed_relative_pointer')
                    current['display']=1;current['inputCount']+=1;value={}
                elif command=='screendump':
                    path=Path(args['filename'])
                    if path.parent!=root or args.get('format')!='ppm':raise ValueError('fixture_screen_path')
                    path.write_bytes(b'P6\n320 200\n255\n'+b'\0'*(320*200*3));path.chmod(0o600);value={}
                elif command=='guest-sync-delimited':marker=b'\xff';value=args['id']
                elif command=='guest-ping':value={}
                elif command=='guest-exec':
                    # Windows is the controlled native boundary. The complete
                    # generated caller and kernel/QMP/QGA guards remain real.
                    source=base64.b64decode(args['input-data']).decode()
                    if args['path']!='powershell.exe'or '-EncodedCommand'in args['arg']:raise ValueError('fixture_guest_invocation')
                    current['execCount']+=1;pid=1000+current['execCount']
                    session=config['sessionFacts']
                    display={'schemaVersion':1,'machine':config['machine'],'boot':session['boot'],'displayState':current['display']}
                    result=project_guest(source,session,display,json.loads((root/'getter-sources.json').read_text()))
                    if (root/'oversized-controller').exists():result={**result,'padding':'x'*66000}
                    frame=re.search(r"\$VcFrame=\('([^']+)'\|ConvertFrom-Json\)",source)
                    if frame:
                        identity=json.loads(frame.group(1))
                        if (root/'wrong-controller').exists():identity['operationId']='00000000-0000-0000-0000-000000000000'
                        if (root/'malformed-controller').exists():identity['schemaVersion']=True
                        result={**identity,'owner':{'pid':pid,'birth':'134369607007458666'},'result':result}
                    jobs[pid]={'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(result).encode()).decode()}
                    value={'pid':pid}
                elif command=='guest-exec-status':current['statusCount']+=1;value=jobs[args['pid']]
                else:error={'class':'UnsupportedCommand','desc':'finite fixture'};value=None
                save()
            reply={'error':error}if error else{'return':value}
            if 'id'in request:reply['id']=request['id']
            stream.write(marker+(json.dumps(reply)+'\n').encode())

def serve(path,family):
    with socket.socket(socket.AF_UNIX)as listener:
        listener.bind(str(root/path));listener.listen(16)
        (root/(path+'.ready')).write_text('ready')
        while True:
            channel,_=listener.accept()
            threading.Thread(target=handle,args=(channel,family),daemon=True).start()

for name in (('qmp.sock','qga.sock')if mode=='qemu'else('swtpm.sock',)):
    threading.Thread(target=serve,args=(name,'qmp'if name=='qmp.sock'else'qga'),daemon=True).start()
while True:time.sleep(1)
