v=json.loads(p.stdout);worker=v['recovery']['recoveryWorker'];assert worker['uid']==1000 and not Path('/proc/%d'%worker['pid']).exists()
v['recoveryWorkerTerminal']={**worker,'terminalExitCode':p.returncode,'physicallyAbsent':True};print(json.dumps(v,separators=(',',':')))
