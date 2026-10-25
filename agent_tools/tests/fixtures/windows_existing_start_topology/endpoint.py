"""Owned Linux actors holding the exact fixture files and Unix listeners."""
import json
from pathlib import Path
import selectors
import socket
import sys

root=Path(sys.argv[1]);role=sys.argv[2]
config=json.loads((root/'fixture.json').read_text())
held=[]
if role=='qemu':
    held=[open(path,'rb') for path in (root/'disk.qcow2',root/'uefi-vars.fd',Path(config['firmwarePath']))]
else:
    held=[(root/'tpm'/'state').open('rb')]
selector=selectors.DefaultSelector();listeners=[]
for name in (('qmp.sock','qga.sock') if role=='qemu' else ('swtpm.sock',)):
    channel=socket.socket(socket.AF_UNIX);channel.bind(str(root/name));channel.listen(4)
    listeners.append(channel);selector.register(channel,selectors.EVENT_READ)
(root/(role+'.ready')).write_text('ready')
while True:
    for key,_ in selector.select():
        channel,_=key.fileobj.accept()
        (root/(role+'.contact')).write_text('unexpected host or guest RPC')
        channel.close()
