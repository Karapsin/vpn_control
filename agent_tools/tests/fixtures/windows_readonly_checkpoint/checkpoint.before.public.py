def checkpoint():
    from agent_tools.mcp_server import _snapshot_fingerprint
    commands=(("rev-parse","HEAD"),("rev-parse","origin/dev"),("symbolic-ref","--short","HEAD"),("status","--porcelain=v1","-z","--untracked-files=normal"))
    values=[]
    for args in commands:
        result=subprocess.run(["git",*args],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        if result.returncode!=0 or result.stderr or len(result.stdout)>4096:raise ValueError("checkpoint_query")
        values.append(result.stdout.decode("utf-8","strict").strip())
    if values!=[HEAD,HEAD,"dev",""] or _snapshot_fingerprint()!=FP:raise ValueError("checkpoint_tuple")
