"""Finite QMP/QGA fixture, with real Linux process/file/socket ownership."""
import base64
import json
import re
from pathlib import Path
import socket
import sys
import threading
import time

root=Path(sys.argv[1]);mode=sys.argv[2]
config=json.loads((root/'fixture.json').read_text())
mutex=threading.Lock();current={'status':'running','display':0,'execCount':0,'inputCount':0,'statusCount':0,'jobStartCount':0}
jobs={};files=[]
if mode=='qemu':
    files=[(root/name).open('rb')for name in ('disk.qcow2','uefi-vars.fd')]

def save():
    (root/'counters.json').write_text(json.dumps(current))

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
                elif command=='input-send-event':current['display']=1;current['inputCount']+=1;value={}
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
                    if '[NativeJob]::Control(' in source:
                        result=json.loads((root/'fixture.json').read_text())['jobResult']
                        if "[NativeJob]::Control('start'," in source:current['jobStartCount']+=1
                    elif 'sessionFacts=$sessionFacts;displayFacts=$displayFacts'in source:
                        result={'sessionFacts':session,'displayFacts':display}
                    elif 'ConsoleDisplayFacts'in source:result=display
                    else:result=session
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
            if command=='guest-exec' and (root/'drop-guest-ack-once').exists():
                (root/'drop-guest-ack-once').unlink();return
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
