from pathlib import Path
import ast,base64,contextlib,hashlib,io,json,os,tempfile,types
def control(source):
    with tempfile.TemporaryDirectory(prefix='owned-census-inert-') as td:
        t=ast.parse(source);namespace={};calls=[];holds=[];output=io.StringIO()
        real_import=__import__;real_os=os;real_read=Path.read_text
        fake_sub=types.SimpleNamespace(PIPE=-1,run=lambda argv,**kw: types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'') if argv==['ss','-H','-ltn','sport = :53895'] else (_ for _ in ()).throw(AssertionError('FOREIGN_SUBPROCESS')))
        fake_os=types.SimpleNamespace(**{n:getattr(os,n) for n in dir(os) if not n.startswith('__')});fake_os.getuid=lambda:1000;fake_os.statvfs=lambda path:types.SimpleNamespace(f_bavail=100000,f_frsize=4096) if path=='/synthetic/owner-home' else real_os.statvfs(path)
        def importer(name,*args,**kw):
            if name=='os':return fake_os
            if name=='subprocess':return fake_sub
            return real_import(name,*args,**kw)
        builtins_dict=dict(vars(__import__('builtins')));builtins_dict['__import__']=importer;namespace['__builtins__']=builtins_dict
        directory_assignment=next(n for n in t.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='directory' for x in n.targets));original_dir=ast.literal_eval(directory_assignment.value.args[0]);directory_assignment.value.args[0]=ast.Constant(str(Path(td)/'records'))
        main_index=t.body.index(directory_assignment)
        prefix=ast.Module(t.body[:main_index],type_ignores=[]);tail=ast.Module(t.body[main_index:],type_ignores=[])
        def read_text(p,*a,**kw):
            if str(p)=='/proc/meminfo':return 'MemAvailable: 12345678 kB\n'
            if str(p)=='/proc/sys/kernel/random/boot_id':return '11111111-2222-3333-4444-555555555555\n'
            return real_read(p,*a,**kw)
        Path.read_text=read_text
        try:
            exec(compile(ast.fix_missing_locations(prefix),'<actual-census-prefix>','exec'),namespace)
            q=namespace['_EXPECTED_QEMU'];namespace['identity']=lambda:[q[0],'(qemu)',q[1],q[2],q[3],q[4],q[5]]
            def qga(sock,command,args,**kw):
                calls.append(command)
                if command=='guest-exec':
                    assert set(args)=={'path','arg','input-data','capture-output'} and args['capture-output'] is True
                    raw=base64.b64decode(args['input-data'],validate=True);assert hashlib.sha256(raw).hexdigest()=='217445cfcd6199390c3d859e7a5c6b60e43fd5c587c2f3dcf90e7611fe3d360d'
                    return {'pid':1234}
                assert command=='guest-exec-status' and args=={'pid':1234}
                return {'exited':True,'exitcode':0,'out-data':base64.b64encode(b'{"inertGuest":true}').decode(),'err-data':''}
            namespace['call']=qga
            with contextlib.redirect_stdout(output):exec(compile(ast.fix_missing_locations(tail),'<actual-census-main>','exec'),namespace)
            result={'state':'PASS','calls':calls,'stdoutJson':json.loads(output.getvalue())}
        except NameError as e:
            result={'state':'RED','errorClass':'NameError','identifier':e.name,'calls':calls}
        finally:
            Path.read_text=real_read
            for name in ('wirefd','rawfd'):
                if name in namespace:os.close(namespace[name])
        return result
