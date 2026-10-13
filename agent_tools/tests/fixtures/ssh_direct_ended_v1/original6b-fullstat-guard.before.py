def _pin_source(name):
 f=os.open(_STAGE+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(f)
 if not stat.S_ISREG(s.st_mode)or s.st_uid!=1000 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or not 0<s.st_size<=65536:os.close(f);raise ValueError('original_remote_source_shape')
 raw=b''
 while v:=os.read(f,65536):raw+=v
 if len(raw)!=s.st_size or os.fstat(f)!=s or os.stat(_STAGE+'/'+name,follow_symlinks=False)!=s:os.close(f);raise ValueError('original_remote_source_changed')
 _holders.append((name,f,s,raw));return json.loads(raw,object_pairs_hook=_fixed_pairs)
