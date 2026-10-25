import json,pathlib,os,subprocess,re
rows=[]; units={};errors=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  status=dict(line.split(':',1) for line in (p/'status').read_text().splitlines());tail=(p/'stat').read_text().rsplit(')',1)[1].split();cgroup=(p/'cgroup').read_text()
  if status.get('Kthread','').strip()=='1' or tail[0]=='Z':continue
  unit=next((x for x in cgroup.split('/') if x.endswith('.service')),None)
  row={'pid':int(p.name),'uid':int(status['Uid'].split()[1]),'birth':'linux:'+tail[19],'parent':int(tail[1]),'comm':status['Name'].strip(),'unit':unit,'self':int(p.name)==os.getpid()}
  rows.append(row)
  if unit and unit not in units:
   x=subprocess.run(['systemctl','show',unit,'-p','MainPID','-p','FragmentPath','-p','ActiveState','-p','SubState'],capture_output=True,text=True,timeout=5);units[unit]={'exitCode':x.returncode,'fields':dict(t.split('=',1) for t in x.stdout.splitlines() if '=' in t)}
 except FileNotFoundError:continue
 except Exception as e:errors.append(type(e).__name__)
print(json.dumps({'rows':rows,'units':units,'errors':errors}))
