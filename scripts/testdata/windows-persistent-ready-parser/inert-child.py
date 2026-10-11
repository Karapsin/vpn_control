import sys,json,pathlib
raw=sys.stdin.buffer.read()
pathlib.Path(sys.argv[1]).write_text(json.dumps({'invoked':True,'argv':sys.argv[2:],'stdinBytes':len(raw),'nativeGuestEffects':0})+'\n')
print(json.dumps({'inertChildInvoked':True,'nativeGuestEffects':0}))
