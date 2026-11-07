"""Finite read-only scoped-TUN actor custody in an admitted SYSTEM observer.

No launch/stop/elevation/repair API. The current source/runtime-bound SYSTEM
collection Owner is a real prerequisite, not minted by this module. Original
helper/runtime handles remain retained between ready and explicit OFF stages.
"""
from __future__ import annotations
import ctypes
import hashlib
from pathlib import Path, PureWindowsPath
from ctypes import wintypes as W
import re


def require(value, code):
    if not value:raise ValueError(code)


def source_guard(owner, request):
    require(owner.native.token()['sid']=='S-1-5-18' and owner.native.token()['elevation']==1,
            'tun-read-only-system-collection-owner-required')
    require(request['context']['bootIdentifier']==owner.native.boot_identifier(), 'tun-current-native-boot')
    key=str(Path(__file__)).casefold()
    require(key in owner.by_path and owner.by_path[key].record['sha256']==request['collectorSourceSha256'],
            'tun-actual-current-collector-source-pin')
    owner.guard()


def validate(request, receipts):
    required={'schemaVersion','ordinaryTaskOperationId','productOperationId','originRequestId','controllerId',
        'collectorSourceSha256','sourceSha','context','ownerActor','guiActor','helperActor','runtimeActor',
        'helperImagePath','helperImageSha256','runtimeImagePath','runtimeImageSha256','configuration'}
    require(type(request) is dict and set(request)==required and request['schemaVersion']==1
            and all(request[key] is not None for key in required-{'guiActor'}), 'tun-native-request-pending')
    for key in ('ordinaryTaskOperationId','productOperationId','originRequestId','controllerId'):
        receipts.canonical_uuid(request[key])
    require(re.fullmatch('[a-f0-9]{40}',request['sourceSha']) and all(re.fullmatch('[a-f0-9]{64}',request[key])
        for key in ('collectorSourceSha256','helperImageSha256','runtimeImageSha256')),
        'tun-native-source-artifact-pins')
    cf={'ordinarySid','ordinarySessionId','approvingAdminSid','bootIdentifier','programData','workspace'}
    require(type(request['context']) is dict and set(request['context'])==cf
            and request['context']['ordinarySid']!=request['context']['approvingAdminSid'],
            'tun-native-ordinary-approving-context')
    config=request['configuration']
    require(type(config) is dict and set(config)=={'path','sha256','sizeBytes'}
            and receipts.canonical_path(config['path'])==receipts.canonical_path(request['context']['workspace'])/'runtime-config.json'
            and re.fullmatch('[a-f0-9]{64}',config['sha256'])
            and type(config['sizeBytes']) is int and 0<config['sizeBytes']<=32*1024*1024,
            'tun-actual-product-runtime-config-role')
    return request


class TunCustody:
    def __init__(self, request, collection_owner, receipts, observer):
        self.request=validate(request,receipts);self.owner=collection_owner
        self.receipts,self.observer=receipts,observer
        self.handles=[];self.ready=None;self.off=None;self.closed=False;self.publish_attempted=set()
        if not hasattr(collection_owner,'tun_custodies'):collection_owner.tun_custodies=[]
        collection_owner.tun_custodies.append(self)  # Before original native opens.
        source_guard(collection_owner,request)
        self.native=observer.WindowsNative()
        self.open_ready()

    def open_ready(self):
        r=self.request;c=r['context'];observations={}
        for role,elevated,sid in (('ownerActor',0,c['ordinarySid']),('guiActor',0,c['ordinarySid']),
            ('helperActor',1,c['approvingAdminSid']),('runtimeActor',1,c['approvingAdminSid'])):
            expected=r[role]
            if role=='guiActor' and expected is None:continue
            require(type(expected) is dict and set(expected)=={'pid','creationFileTime','image','sha256','sid','sessionId'}
                    and expected['sid']==sid and expected['sessionId']==c['ordinarySessionId'], 'tun-exact-'+role+'-role')
            process=self.native.open_process(expected['pid'],0x101410 if role=='helperActor' else 0x101000)
            self.handles.append((role,expected,process))
            value=process.describe();self.observer.require_identity(value,expected)
            require(process.wait()==258 and value['token']['elevated']==elevated
                    and value['token']['sessionId']==c['ordinarySessionId'], 'tun-current-'+role+'-token')
            if role in {'helperActor','runtimeActor'}:
                key='helper' if role=='helperActor' else 'runtime'
                require(self.receipts.canonical_path(expected['image'])==self.receipts.canonical_path(r[key+'ImagePath'])
                        and expected['sha256']==r[key+'ImageSha256'], 'tun-admitted-'+key+'-artifact')
            observations[role]={'pid':expected['pid'],**value}
        parents={row['pid']:row['parentPid'] for row in self.native.processes()}
        require(parents.get(r['runtimeActor']['pid'])==r['helperActor']['pid'], 'tun-runtime-not-exact-helper-child')
        helper=[item[2] for item in self.handles if item[0]=='helperActor'][0]
        modules=helper.modules()
        require(modules==helper.modules(), 'tun-helper-module-generation-changed')
        for module in modules:module.update(self.native.file_identity(module['path']))
        config=self.receipts.FileObservation(self.owner,r['configuration']['path'])
        try:
            raw=config.read(32*1024*1024)
            require(len(raw)==r['configuration']['sizeBytes'] and hashlib.sha256(raw).hexdigest()==r['configuration']['sha256'],
                    'tun-actual-runtime-config-digest')
            require(config.opening['security']['ownerSid']==c['ordinarySid'], 'tun-config-original-ordinary-owner')
            observations['configuration']={'sha256':hashlib.sha256(raw).hexdigest(),'sizeBytes':len(raw),
                'nativeFile':config.opening}
        finally:config.close()
        self.current_live()
        self.ready={**self.identity('ready'),'observations':observations,'helperModules':modules,
            'runtimeParentPid':parents[r['runtimeActor']['pid']],'readOnly':True,
            'trafficAndPublicOperationCorrelationStillRequired':True}

    def identity(self,stage):
        return {key:self.request[key] for key in ('schemaVersion','ordinaryTaskOperationId','productOperationId',
            'originRequestId','controllerId','collectorSourceSha256','sourceSha','context')}|{'stage':stage}

    def current_live(self):
        require(not self.closed, 'tun-original-custody-closed')
        source_guard(self.owner,self.request)
        for role,expected,process in self.handles:
            actual=process.describe();self.observer.require_identity(actual,expected)
            require(process.wait()==258, 'tun-original-'+role+'-not-live')

    def after_off(self):
        """Only observes retained original handles after explicit public OFF."""
        require(not self.closed and self.ready is not None,'tun-original-ready-custody-required')
        source_guard(self.owner,self.request)
        results=[]
        for role,expected,process in self.handles:
            if role in {'helperActor','runtimeActor'}:
                times=process.times()
                require(times['creationFileTime']==expected['creationFileTime'] and process.wait()==0,
                        'tun-original-helper-runtime-not-signaled-after-off')
                results.append({'role':role,'pid':expected['pid'],'creationFileTime':expected['creationFileTime'],
                    'originalHandleSignaled':True,'times':times})
            else:
                self.observer.require_identity(process.describe(),expected)
                require(process.wait()==258,'tun-off-closed-ordinary-owner-or-gui')
        value={**self.identity('off'),'originalProcesses':results,'readOnly':True,
            'publicOffIntentAndTrafficClosureStillRequired':True}
        self.off=value  # Keep proof reachable even if later file publication fails.
        for _,_,process in reversed(self.handles):process.__exit__(None,None,None)
        self.closed=True
        source_guard(self.owner,self.request)
        return value


def collect_ready(request,collection_owner,receipts,observer):
    return TunCustody(request,collection_owner,receipts,observer)


def publish(custody,stage):
    """Create only fixed machine-protected TUN evidence under current ProgramData."""
    require(stage in {'ready','off'} and custody in custody.owner.tun_custodies,'finite-tun-collector-stage')
    source_guard(custody.owner,custody.request)
    require(stage not in custody.publish_attempted,'tun-original-stage-publication-already-attempted')
    custody.publish_attempted.add(stage) # Consume before any CreateDirectory/CreateFile.
    custody.owner.event('tun-native-publication-intent',{'stage':stage,
        'ordinaryTaskOperationId':custody.request['ordinaryTaskOperationId'],
        'productOperationId':custody.request['productOperationId'],'replayAllowed':False})
    value=custody.ready if stage=='ready' else custody.after_off()
    if stage=='ready':custody.current_live()
    owner,receipts=custody.owner,custody.receipts
    root=str(receipts.canonical_path(custody.request['context']['programData']) / ('tun-evidence-'+custody.request['ordinaryTaskOperationId']))
    return publish_machine_record(owner,receipts,root,stage,value)


def publish_machine_record(owner, receipts, root, stage, value):
    """Create only this operation's machine evidence directory and phase file."""
    require(stage in {"ready", "off"} and PureWindowsPath(root).name == "tun-evidence-" + value["ordinaryTaskOperationId"],
            "one-fixed-machine-evidence-destination")
    native = owner.native
    require(native.token()["sid"] == "S-1-5-18", "machine-evidence-system-writer")
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", W.DWORD), ("descriptor", W.LPVOID), ("inherit", W.BOOL)]
    convert = native.a.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes, convert.restype = (W.LPCWSTR, W.DWORD, ctypes.POINTER(W.LPVOID), ctypes.POINTER(W.DWORD)), W.BOOL
    descriptor = W.LPVOID()
    require(convert("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
                    1, ctypes.byref(descriptor), None), "machine-directory-security-descriptor")
    create_dir = native.k.CreateDirectoryW
    create_dir.argtypes, create_dir.restype = (W.LPCWSTR, ctypes.POINTER(SecurityAttributes)), W.BOOL
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        if not create_dir(root, ctypes.byref(attributes)):
            require(ctypes.get_last_error() == 183, "machine-evidence-directory-create")
    finally:
        native.k.LocalFree(descriptor)
    directory = receipts.FileObservation(owner, root, directory=True)
    try:
        receipts.machine_security(directory.opening["security"], True)
        descriptor = W.LPVOID()
        require(convert("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)",
                        1, ctypes.byref(descriptor), None), "machine-file-security-descriptor")
        try:
            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            path = str(PureWindowsPath(root) / (stage + ".json"))
            handle = native.k.CreateFileW(path, 0xC0020000, 0, ctypes.byref(attributes), 1, 0x02200000, None)
            require(handle != ctypes.c_void_p(-1).value, "machine-phase-evidence-create-only")
        finally:
            native.k.LocalFree(descriptor)
        try:
            raw = receipts.encoded(value)
            require(len(raw) <= 256 * 1024, "machine-phase-evidence-byte-bound")
            written = W.DWORD()
            write = native.k.WriteFile
            write.argtypes = (W.HANDLE, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD), W.LPVOID)
            buffer = ctypes.create_string_buffer(raw)
            require(write(W.HANDLE(handle), buffer, len(raw), ctypes.byref(written), None)
                    and written.value == len(raw), "machine-phase-evidence-full-write")
            flush = native.k.FlushFileBuffers
            flush.argtypes, flush.restype = (W.HANDLE,), W.BOOL
            require(flush(W.HANDLE(handle)), "machine-phase-evidence-flush")
        finally:
            require(native.k.CloseHandle(W.HANDLE(handle)), "machine-phase-evidence-close")
        require(directory.describe() == directory.opening, "machine-phase-directory-closing")
        owner.guard()
        return {"path": path, "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "createOnly": True, "readOnlyProductObservation": True}
    finally:
        directory.close()
