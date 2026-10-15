"""Exact argv custody is independent of an old QEMU chardev label."""
import ast,hashlib,json,os,socket,tempfile,types,unittest
from pathlib import Path
from agent_tools import windows_guest_input as subject


def definitions(source):
    tree=ast.parse(source)
    return '\n'.join(ast.get_source_segment(source,n)for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom)) or isinstance(n,ast.FunctionDef)and n.name in ('live','identity'))+'\n'


@unittest.skipUnless(os.name=='posix','POSIX kernel-record file fixture')
class ChardevLabelTests(unittest.TestCase):
    def test_preserved_label_rejects_same_owned_actor_fixed_checks_full_argv_and_epoch(self):
        folder=Path(__file__).parent/'fixtures/windows_input_chardev_label';before=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['fragmentSha256'],hashlib.sha256(before).hexdigest())
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            root=Path(temporary).resolve();proc=root/'proc';actor=proc/'7';(actor/'fd').mkdir(parents=True)
            (actor/'stat').write_text(' '.join(['7','(qemu)','S','1']+['0']*17+['77']))
            (actor/'exe').symlink_to('/usr/bin/qemu-system-x86_64')
            boot=root/'boot';boot.write_text('CURRENT_EPOCH\n');paths={};lines=[]
            for index,name in enumerate(('qmp','qga'),555):
                path=root/(name+'.sock');server=socket.socket(socket.AF_UNIX);self.addCleanup(server.close);server.bind(str(path));paths[name]=str(path)
                (actor/'fd'/str(index)).symlink_to('socket:['+str(index)+']')
                lines.append('000: 00000002 00000000 00010000 0001 01 '+str(index)+' '+str(path))
            unix=root/'unix';unix.write_text('\n'.join(lines)+'\n')
            argv=b'/usr/bin/qemu-system-x86_64\0-qmp\0unix:'+os.fsencode(paths['qmp'])+b',server=on\0-chardev\0socket,path='+os.fsencode(paths['qga'])+b',server=on,id=qga\0'
            (actor/'cmdline').write_bytes(argv)
            profile={'qemu_parent_pid':1,'qemu_uid':os.geteuid(),'qemu_argv_sha256':hashlib.sha256(argv).hexdigest(),'host_boot_id':'CURRENT_EPOCH'}
            def mapped(path):
                value=os.fspath(path)
                if value=='/proc/sys/kernel/random/boot_id':return boot
                if value=='/proc/net/unix':return unix
                if value.startswith('/proc/'):return proc/value.removeprefix('/proc/')
                return path
            native=types.SimpleNamespace(**vars(os))
            native.stat=lambda path,*a,**kw:os.stat(mapped(path),*a,**kw)
            native.listdir=lambda path:os.listdir(mapped(path))
            native.readlink=lambda path:os.readlink(mapped(path))
            namespace={};exec(compile(definitions(subject._REMOTE_RUNTIME),'complete input identity definitions','exec'),namespace)
            namespace.update(os=native,open=lambda path,*a,**kw:open(mapped(path),*a,**kw),PROFILE=profile,QEMU_PID='7',QEMU_TICKS='77',QMP_SOCKET=paths['qmp'],QGA_SOCKET=paths['qga'])
            old=dict(namespace);exec(compile(before,'preserved exact identity','exec'),old)
            with self.assertRaisesRegex(ValueError,'QEMU_SOCKET_IDENTITY'):old['identity']()
            self.assertEqual(['7','1','77',os.geteuid(),'/usr/bin/qemu-system-x86_64',profile['qemu_argv_sha256'],'CURRENT_EPOCH'],namespace['identity']())
            for key,value in (('qemu_argv_sha256','0'*64),('host_boot_id','OLD_EPOCH'),('qemu_uid',os.geteuid()+1),('qemu_parent_pid',2)):
                current=profile[key];profile[key]=value
                try:
                    with self.assertRaisesRegex(ValueError,'QEMU_SOCKET_IDENTITY'):namespace['identity']()
                finally:profile[key]=current


if __name__=='__main__':unittest.main()
