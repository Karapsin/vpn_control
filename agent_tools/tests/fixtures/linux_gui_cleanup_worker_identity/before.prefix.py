p=subprocess.Popen(['sudo','-n','-u','vpnfixture','python3','-I','-'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
deadline=time.monotonic()+10
while Path('/proc/%d'%p.pid).stat().st_uid!=1000:
 assert p.poll()is None and time.monotonic()<deadline;time.sleep(.01)
ticks=int(Path('/proc/%d/stat'%p.pid).read_text().rsplit(')',1)[1].split()[19])
