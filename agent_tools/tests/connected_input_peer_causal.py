"""Real Linux connected-peer credentials; no VM, QEMU or guest execution."""


def prove(before_source,current_source):
    import ast,json,os,socket,tempfile,threading
    from pathlib import Path
    tree=ast.parse(current_source)
    definitions='\n'.join(ast.get_source_segment(current_source,n)for n in tree.body
                          if isinstance(n,(ast.Import,ast.ImportFrom))or isinstance(n,ast.FunctionDef)and n.name in ('call','verify_peer'))+'\n'
    def run(before=False,wrong_pid=False,wrong_uid=False):
        with tempfile.TemporaryDirectory(prefix='vc-peer-',dir='/tmp')as temporary:
            root=Path(temporary);path=root/'qga.sock';server=socket.socket(socket.AF_UNIX);server.bind(str(path));server.listen(1);server.settimeout(3)
            queries=[];errors=[]
            def serve():
                try:
                    client,_=server.accept()
                    with client,client.makefile('rb')as stream:
                        for raw in stream:
                            value=json.loads(raw.lstrip(b'\xff'));queries.append(value['execute'])
                            reply=value['arguments']['id']if value['execute']=='guest-sync-delimited'else {}
                            prefix=b'\xff'if value['execute']=='guest-sync-delimited'else b''
                            client.sendall(prefix+(json.dumps({'return':reply})+'\n').encode())
                except (OSError,ValueError)as error:errors.append(type(error).__name__)
            thread=threading.Thread(target=serve);thread.start()
            namespace={};exec(compile(definitions,'actual connected-peer RPC','exec'),namespace)
            if before:exec(compile(before_source,'preserved RPC without peer check','exec'),namespace)
            guards=[]
            namespace.update(QEMU_PID=str(os.getpid()+int(wrong_pid)),PROFILE={'qemu_uid':os.geteuid()+int(wrong_uid)},identity=lambda:guards.append(True))
            wire=os.open(root/'wire',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            partial=os.open(root/'partial',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            namespace.update(wire=wire,partial_wire=partial)
            try:
                try:value=namespace['call'](str(path),'guest-ping',{})
                except ValueError as error:value=str(error)
            finally:
                os.close(wire);os.close(partial);thread.join(4);server.close()
            if thread.is_alive():raise AssertionError('owned peer server did not close')
            if errors:raise AssertionError(errors)
            return value,queries,guards
    old,queries,_=run(before=True,wrong_pid=True)
    if old!={}or len(queries)!=2:raise AssertionError('preserved wrong peer did not expose original defect')
    for flags in ({'wrong_pid':True},{'wrong_uid':True}):
        value,queries,guards=run(**flags)
        if value!='QEMU_CONNECTED_PEER'or queries or guards:raise AssertionError('foreign peer received protocol data')
    value,queries,guards=run()
    if value!={}or len(queries)!=2 or guards!=[True]:raise AssertionError('matching kernel peer failed')
    return {'before':'RED','after':'GREEN','wrongPidRejectedBeforeSend':True,'wrongUidRejectedBeforeSend':True,'matchingPeerAccepted':True}
