"""Finite ordinary active-A/pending-B TUN stages on the Windows scenario route.

The product's original async job stays retained. This module cannot press UAC keys:
the closed windows-uac-decision action answers the vpn-broker prompt, and every input
here comes from the row's own job plan and context stage, never from a caller. The
decision it waits for is that action's one decision for this operation. A grant also
needs the TUN SYSTEM collector's ready and off records, which the dedicated driver hands
over (finish asks for ready only once the product's own operation ended OK); the direct
sampler runs only between them. The closing census shows the row left no broker, scoped
runtime, private stage or TUN route behind. From the request until the operation settles
(a denial, a known end or a grant's exact off) a failure parks the owner; a final refusal
of the request itself, with nothing changed, is a known end, and so is a reserved row's
request refused before the product wrote its correlation journal, with nothing changed.

The configuration and fault variants first add their own location from the documents the proxy rows' branch cases
make (windows_runtime_branch_cases), so each is the TUN half of a proxy row. A configuration grant compares the runtime
config the ordinary user reads in its ready window with the bytes SYSTEM read for its ready record. A preparation
failure in VPN mode raises no prompt and must leave A, pending B and the census as they were; a commit-readiness
failure after an approval must bring A back as a new unelevated runtime with nothing scoped left. Neither asks a
collector: no TUN comes up. A commit-failure row whose approved start ended RUNTIME_FAILED before its commit (A never
stopped, so nothing to recover) is a known end once A, pending B and the census are as before.

While finish waits for the terminal, a read-only preparation watch records how far the product's VPN start got (the
approved broker, its private stage, the sing-box it started, the launch's VPN config, redacted). On a terminal the
variant does not expect, the stages publish the product's own diagnostics (scoped-tun-product-diagnostics: the
operation's ledger record, its log, its diagnostics report, the workspace runtime log and folder, that watch) before any
check of the end, and the known end names the diagnosis: a failed row shows why. Every other unexpected end does the
same: a final refusal of the request itself, a final code no step expects (finish_operation's, a reserved case's), a
reserved row's end before its correlation journal (watched while the case waits), and a reserved case's park while its
operation's outcome is open, which reads them through the case's ``diagnose`` because a park never returns.

Before any change, a row that expects a prompt reads who holds the ordinary desktop's foreground: the Start menu, search
or another shell surface, or a console that is not of this owner's chain, refuses the row (a known failure, nothing
requested), and any other holder is recorded on the prompt event.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import threading
import time
import uuid

# The reserved cases (windows_tun_reserved_cases) restart into their own pending location: resources-grant and ssh-grant
# are grants with the collector and sampler; stage-squat is approved but its broker refuses, so no TUN comes up.
RESERVED_VARIANTS = frozenset({'resources-grant','ssh-grant','stage-squat'})
VARIANTS = frozenset({'restart-grant','restart-deny','find-best-grant','find-best-deny',
    'generated-grant','custom-grant','large-grant','vpn-prepare-failure','vpn-commit-failure'})|RESERVED_VARIANTS
# Approved variants whose TUN SYSTEM collector proves the broker and its runtime from the ready record to the off record.
GRANTS = frozenset({'restart-grant','find-best-grant','generated-grant','custom-grant','large-grant','resources-grant','ssh-grant'})
# Grants whose runtime config is the product's generated VPN config, with its TUN inbound: only through that TUN may the
# direct sampler run. A CUSTOM document in VPN mode keeps its own inbounds and these define no TUN, so the sampler's
# benchmark address would leave the guest: custom-grant and large-grant never sample.
SAMPLED = frozenset({'restart-grant','find-best-grant','generated-grant','resources-grant','ssh-grant'})
# Each configuration or fault variant's own location, added from a document before it is selected.
CONFIGS = {'generated-grant':'Owned generated','custom-grant':'Owned CUSTOM','large-grant':'Owned large CUSTOM'}
FAULTS = {'vpn-prepare-failure':'Owned prepare failure','vpn-commit-failure':'Owned commit failure'}
PENDING = {**dict.fromkeys(('restart-grant','restart-deny','find-best-grant','find-best-deny','ssh-grant'),'Owned B'),
    **dict.fromkeys(('resources-grant','stage-squat'),'Owned resources'),**CONFIGS,**FAULTS}
# windows_runtime_branch_cases.custom_config's kind for each CUSTOM document.
DOCUMENT_KIND = {'custom-grant':'custom','large-grant':'large','vpn-prepare-failure':'prepare-failure',
    'vpn-commit-failure':'commit-readiness-failure'}
# The product checks a config before it asks for the broker (DesktopProxyRuntimeManager.buildLaunch, sing-box check):
# a preparation failure raises no prompt, so nothing is answered and no decision awaits it.
PROMPTLESS = frozenset({'vpn-prepare-failure'})
CONFIG_BYTES = 8*1024*1024  # windows_runtime_branch_cases.MAX_CONFIG
INLINE_LIMIT = 60000  # The large document must exceed the inline limit, as the proxy row's does.
FIELDS = frozenset({'schemaVersion','variant','pendingLocation','runtimeConfigPath','guiPath',
    'installedAdmissionArtifactId','ordinaryContextArtifactId','expectedApprovingAdminSid',
    'uacDecisionId','programData','collectorSourceSha256'})
SAMPLER_FIELDS = frozenset({'samplerPath','samplerInputPath'})  # A grant's direct sampler and its input
BROKER_LEAF = 'vpn-control-vpn-broker.exe'  # DesktopWindowsVpnHelperAdmission's packaged helper
STAGE_PREFIX = 'vpn-control-vpn-'  # The broker's private stage under ProgramData
TUN_SUBNET = ('172.19.250.0', 30)  # DesktopProxyConfigFactory's generated TUN address
# ControlCode's final refusals and their exits: the owner admitted no operation, or ended it before it replied.
# Its transport codes (exit 2) and an answer from no or another controller leave the request's outcome open.
REFUSED_EXITS = {**dict.fromkeys(('INVALID_ARGUMENT','NOT_FOUND','AMBIGUOUS_LOCATION','READ_ONLY_SOURCE','BUSY','CONFLICT',
    'UNSUPPORTED','INTERACTION_REQUIRED','PERMISSION_DENIED','PERSISTENCE_FAILED','RUNTIME_FAILED'),1),'CANCELLED':130}
# The preparation watch: what the ordinary user can see of the product's VPN start while the row's operation runs. The
# approved broker writes no log of its own (its stderr goes to its hidden console) and runs as the approving administrator,
# so its exit code is not readable here; how far it got is: its process, the private stage it creates once its pipe, peer,
# job and runtime digest are admitted, and the suspended sing-box it starts there (DesktopWindowsVpnBroker, VpnRuntimeBroker.Run).
WATCH_INTERVAL = 0.01  # The product's own pipe poll is 25 ms; a broker refused at admission lives a few tens of ms.
WATCH_SECONDS = 330  # finish waits 300 s for the terminal.
WATCH_ITEMS = 32  # Distinct processes, stages or candidate folders kept per kind.
CANDIDATE_PREFIX = 'candidate-'  # DesktopProxyRuntimeManager: one folder per launch under the workspace runtime folder.
# The product's own diagnostics on an unexpected terminal, each bounded so the one event stays under the owner's 256 KiB.
LOG_ENTRIES = 200
LOG_MESSAGE_CHARS = 1000
TEXT_CHARS = 48*1024
DIAGNOSTICS_EVENT_BYTES = 200*1024
# agent_docs/runtime-troubleshooting.md: redact endpoints, subscription URLs, UUIDs, credentials and tokens. Loopback, the
# generated TUN subnet and the sampler's benchmark address are the row's own and stay readable.
SECRET_KEYS = frozenset({'password','uuid','private_key','pre_shared_key','psk','token','auth','auth_str','secret','short_id',
    'public_key','obfs_password','username','user','key','key_path','private_key_path','certificate','certificate_path'})
ENDPOINT_KEYS = frozenset({'server','domain','server_name','host','hostname','sni'})
URL = re.compile(r'\b([A-Za-z][A-Za-z0-9+.-]{0,15})://[^\s"\'<>]+')
UUID_TEXT = re.compile(r'\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b')
IPV4 = re.compile(r'(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])')
CREDENTIAL = re.compile(r'(?i)\b(password|passwd|token|secret|private[_-]?key|psk|auth|uuid)(\s*[=:]\s*"?)[^\s",}]+')
LOCAL_HOSTS = frozenset({'localhost','127.0.0.1','::1','0.0.0.0'})


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def decision_id(operation):
    """windows_uac_decision.decision_id: the one decision a scenario operation may have."""
    return str(uuid.uuid5(uuid.UUID(operation),'windows-uac-decision'))


def settled(lease):
    """The row's own operation is final and nothing of it can still run elevated: a denial, a known end, or a grant
    after its exact off. Until then any failure parks the owner; once settled, a failure closes as a known one."""
    return lease['finished'] is True and (lease['inputs']['variant'].endswith('deny') or 'knownEnd' in lease
                                          or 'faultRecovered' in lease or 'conflictEnd' in lease or lease.get('offFinished') is True)


def guest_filetime():
    """The guest's UTC system time as a FILETIME (100 ns since 1601): the clock GetProcessTimes stamps an exit with."""
    import ctypes
    value=ctypes.c_ulonglong(0)
    ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(value))
    require(value.value>0,'scoped-tun-guest-clock')
    return value.value


def tun_routes(subnet=TUN_SUBNET):
    """IPv4 routes and addresses on the generated TUN subnet, from the IP helper tables a standard user reads."""
    import ctypes
    network,bits=subnet;base=int.from_bytes(socket.inet_aton(network),'big');mask=(0xffffffff<<(32-bits))&0xffffffff
    found=set()
    # MIB_IPFORWARDROW: destination at 0, next hop at 12, 56 bytes; MIB_IPADDRROW: address at 0, 24 bytes.
    for name,width,columns in (('GetIpForwardTable',56,(0,12)),('GetIpAddrTable',24,(0,))):
        function=getattr(ctypes.windll.iphlpapi,name);size=ctypes.c_ulong(0)
        require(function(None,ctypes.byref(size),False) in (0,122),'tun-route-table-size')
        for _ in range(4):  # The table may grow between two calls.
            buffer=ctypes.create_string_buffer(size.value+4096);size=ctypes.c_ulong(len(buffer))
            code=function(buffer,ctypes.byref(size),False)
            if code!=122:break
        require(code==0,'tun-route-table-read')
        raw=buffer.raw;count=int.from_bytes(raw[:4],'little')
        require(4+count*width<=len(raw),'tun-route-table-bound')
        for row in range(count):
            for column in columns:
                at=4+row*width+column
                if int.from_bytes(raw[at:at+4],'big')&mask==base:found.add((name,socket.inet_ntoa(raw[at:at+4])))
    return sorted(found)


def interactive_desktop(owner, observer):
    """Who holds the ordinary desktop's foreground, read once before a prompting row changes anything (a75acf02).

    The owner's one guard (windows_ordinary_process_owner.interactive_desktop): the Start menu, search, another shell
    surface or a console outside the owner's chain refuses the row before any change; any other holder is recorded."""
    return owner.interactive_desktop(observer.WindowsNative().processes,'scoped-tun-interactive-desktop-unsettled')


def census(inputs, observer, exclude=()):
    """What a TUN row could leave behind, as the ordinary user sees it. Reads only."""
    rows=observer.WindowsNative().processes()
    return {'brokers':sorted(row['pid'] for row in rows if row['name'].casefold()==BROKER_LEAF),
            'runtimes':sorted(row['pid'] for row in rows if row['name'].casefold()=='sing-box.exe' and row['pid'] not in exclude),
            'stages':sorted(name for name in os.listdir(inputs['programData']) if name.casefold().startswith(STAGE_PREFIX)),
            'routes':[list(row) for row in tun_routes()]}


def kept(state, inputs, before, pending, initial, status, cases, observer):
    """Active A and its config bytes as before, pending B still selected in VPN mode, owner and runtime unelevated."""
    require(all(status['data'][key]==before['data'][key] for key in
        ('runtimeRunning','activeLocationId','activeMode','runtimeId','runtimeStartedAt'))
        and status['restartRequired'] is True and status['data']['configuredMode']=='vpn'
        and status['data']['selectedLocationId']==pending['data']['selectedLocationId']
        and cases.config_bytes(inputs['runtimeConfigPath'])=={key:initial[key] for key in ('sizeBytes','sha256')},
        'uac-denial-lost-active-a-or-pending-b')
    native=observer.WindowsNative()
    cases.exact_actor(native,state['actors']['owner'],elevated=False)
    cases.exact_actor(native,state['actors']['runtime'],elevated=False)


def unscoped(inputs, observer, state, baseline):
    """Nothing scoped started: no broker, no TUN route, and no runtime or private stage the baseline did not hold."""
    found=census(inputs,observer,exclude=(state['actors']['runtime']['pid'],))
    require(found['brokers']==[] and found['routes']==[] and set(found['runtimes'])<=set(baseline['runtimes'])
            and found['stages']==baseline['stages'],'scoped-tun-unexpected-terminal-scoped-state')
    return found


def local_ipv4(text):
    """Loopback, the unspecified address, the generated TUN subnet or the sampler's benchmark address: the row's own."""
    match=IPV4.fullmatch(text.split('/')[0]) if type(text) is str else None
    if match is None or any(int(part)>255 for part in match.groups()):
        return False
    value=int.from_bytes(bytes(int(part) for part in match.groups()),'big')
    network,bits=TUN_SUBNET;mask=(0xffffffff<<(32-bits))&0xffffffff
    return (value>>24==127 or value==0 or match.group(0)=='198.18.0.1'
            or value&mask==int.from_bytes(socket.inet_aton(network),'big'))


def redact_text(text):
    """URLs, UUIDs, credential assignments and endpoints that are not the row's own: runtime-troubleshooting.md."""
    text=URL.sub(lambda match:match.group(1)+'://<redacted>',text)
    text=UUID_TEXT.sub('<uuid>',text)
    text=CREDENTIAL.sub(lambda match:match.group(1)+match.group(2)+'<redacted>',text)
    return IPV4.sub(lambda match:match.group(0) if local_ipv4(match.group(0)) else '<ipv4>',text)


def redact_config(value, key=None):
    """A sing-box config with every secret and foreign endpoint replaced; its structure, tags and TUN fields stay."""
    name=key.casefold() if type(key) is str else None
    if type(value) is dict:
        return {item:redact_config(child,item) for item,child in value.items()}
    if type(value) is list:
        return [redact_config(child,key) for child in value]
    if name in SECRET_KEYS and value not in (None,True,False,''):
        return '<redacted>'
    if type(value) is str:
        if name in ENDPOINT_KEYS and value.casefold() not in LOCAL_HOSTS and not local_ipv4(value):
            return '<endpoint>'
        return redact_text(value)
    return value


def tun_summary(value):
    """What decides a VPN start on Windows, without the redacted body: the TUN inbound, the outbounds and the route's end."""
    if type(value) is not dict:
        return None
    inbounds=[row for row in value.get('inbounds') or [] if type(row) is dict]
    return {'tun':[{key:row.get(key) for key in ('tag','interface_name','address','auto_route','strict_route','stack','mtu')}
                   for row in inbounds if row.get('type')=='tun'],
            'inbounds':[[row.get('type'),row.get('tag')] for row in inbounds],
            'outbounds':[[row.get('type'),row.get('tag')] for row in value.get('outbounds') or [] if type(row) is dict],
            'route':{key:(value.get('route') or {}).get(key) for key in ('final','auto_detect_interface')}}


def clip(text, limit=TEXT_CHARS):
    """The last limit characters of a redacted text: a failure is at its end."""
    text=redact_text(text)
    return text if len(text)<=limit else '<clipped '+str(len(text)-limit)+' chars>'+text[-limit:]


def read_shared(owner, path, limit):
    """A product file's bytes, opened with read, write and delete sharing so the product can still replace or remove it;
    None when it does not exist or cannot be opened. Never writes, never holds the handle past the read."""
    import ctypes
    native=owner.native
    handle=native.k.CreateFileW(str(path),0x80000000,7,None,3,0x00200000,None)
    if handle==ctypes.c_void_p(-1).value:
        return None
    try:
        raw=bytearray()
        for block in native.read_blocks(handle):
            raw+=block
            require(len(raw)<=limit,'scoped-tun-diagnostic-file-bound')
        return bytes(raw)
    finally:
        native.k.CloseHandle(handle)


def runtime_folder(state):
    return Path(state['workspace'])/'runtime'


def candidates(state):
    """The product's launch folders now in the workspace runtime folder."""
    return sorted(name for name in os.listdir(str(runtime_folder(state))) if name.startswith(CANDIDATE_PREFIX))


class PrepareWatch:
    """How far the product's VPN start got, as the ordinary user sees it, while finish waits for the row's terminal.

    Read only, on its own thread: the approved broker process and its parent, the private ProgramData stage it creates,
    the sing-box it starts there, any other new sing-box, and the product's new launch folder, whose config.json (the VPN
    config the broker is sent) is read once, shared, and kept only redacted. A broker refused at admission or before its
    pipe lives tens of milliseconds and creates no stage; one that failed on its inputs has created its stage; one that
    started its suspended child has reached READY. Nothing here can fail the row: each read error is counted and kept.
    """

    def __init__(self, owner, lease, observer, clock=time.monotonic):
        state=lease['state']
        self.owner,self.observer,self.clock,self.state=owner,observer,clock,state
        self.program_data=lease['inputs']['programData']
        self.known_runtimes=set(lease['baseline']['runtimes'])|{state['actors']['runtime']['pid']}
        self.known_stages=set(lease['baseline']['stages'])
        self.known_candidates=set(lease.get('candidateBaseline') or ())
        self.items={'brokers':{},'runtimes':{},'stages':{},'candidates':{}}
        self.configs,self.attempts,self.errors={},{},{}
        self.samples,self.started,self.native,self.thread=0,None,None,None
        self.halt,self.lock=threading.Event(),threading.Lock()

    def note(self, kind, error):
        entry=self.errors.setdefault(kind,{'count':0,'first':type(error).__name__+': '+str(error)[:200]})
        entry['count']+=1

    def capture(self, name):
        """The launch folder's config.json, once it parses: a launch writes it before its preflight and keeps it until retired."""
        if name in self.configs or self.attempts.get(name,0)>=200:
            return
        self.attempts[name]=self.attempts.get(name,0)+1
        try:
            raw=read_shared(self.owner,runtime_folder(self.state)/name/'config.json',CONFIG_BYTES)
            if raw is None:
                return
            value=json.loads(raw)
        except Exception as error:
            self.note('candidate-config',error)
            return
        redacted=json.dumps(redact_config(value),sort_keys=True,separators=(',',':'))
        self.configs[name]={'sizeBytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'summary':tun_summary(value),
                            'redacted':redacted if len(redacted)<=TEXT_CHARS else None}

    def step(self):
        with self.lock:
            now=round(self.clock()-self.started,3);self.samples+=1;seen={}
            try:
                if self.native is None:
                    self.native=self.observer.WindowsNative()
                rows=self.native.processes()
                brokers={row['pid']:{'pid':row['pid'],'parentPid':row.get('parentPid')} for row in rows
                         if row['name'].casefold()==BROKER_LEAF}
                parents=set(self.items['brokers'])|set(brokers)
                seen['brokers']=brokers
                seen['runtimes']={row['pid']:{'pid':row['pid'],'parentPid':row.get('parentPid'),
                                              'brokerChild':row.get('parentPid') in parents}
                                  for row in rows if row['name'].casefold()=='sing-box.exe' and row['pid'] not in self.known_runtimes}
            except Exception as error:
                self.note('processes',error)
            try:
                seen['stages']={name:{'name':name} for name in os.listdir(self.program_data)
                                if name.casefold().startswith(STAGE_PREFIX) and name not in self.known_stages}
            except Exception as error:
                self.note('stages',error)
            try:
                seen['candidates']={name:{'name':name} for name in candidates(self.state) if name not in self.known_candidates}
                for name in seen['candidates']:
                    self.capture(name)
            except Exception as error:
                self.note('candidates',error)
            for kind,found in seen.items():  # A kind whose read failed keeps its last presence.
                table=self.items[kind]
                for key,value in found.items():
                    if key not in table and len(table)<WATCH_ITEMS:
                        table[key]={**value,'firstSeen':now}
                    if key not in table:
                        continue
                    table[key]['lastSeen']=now
                    if kind=='runtimes':
                        table[key]['brokerChild']=table[key]['brokerChild'] or value['brokerChild']
                for key,item in table.items():
                    item['present']=key in found

    def run(self):
        while not self.halt.wait(WATCH_INTERVAL) and self.clock()-self.started<WATCH_SECONDS:
            self.step()

    def start(self):
        self.started=self.clock()
        self.step()
        self.thread=threading.Thread(target=self.run,name='scoped-tun-prepare-watch',daemon=True)
        self.thread.start()
        return self

    def stop(self):
        """The last sample is taken here, after the terminal, so a broker still present then is reported present."""
        self.halt.set()
        if self.thread is not None:
            self.thread.join(5)
        self.step()
        with self.lock:
            return {'intervalSeconds':WATCH_INTERVAL,'samples':self.samples,
                    'durationSeconds':round(self.clock()-self.started,3),
                    **{kind:list(table.values()) for kind,table in self.items.items()},
                    'candidateConfigs':dict(self.configs),'errors':dict(self.errors)}


def diagnosis(timeline, logs=None):
    """How far the VPN start got, from the watch, and the product's own last log lines: the why of a failed grant row."""
    if type(timeline) is not dict or timeline.get('samples',0)<1:
        reach='unobserved'
    elif any(row.get('brokerChild') for row in timeline['runtimes']):
        reach='broker-child-created'  # The broker created its suspended sing-box: preparation reached READY or later.
    elif timeline['stages']:
        reach='broker-stage-created'  # Admitted pipe, peer, job and runtime digest; failed on its files, config or child.
    elif timeline['brokers']:
        # Before its stage: the broker's own admission, the owner process, the pipe, the peer, the job or the runtime digest.
        reach='broker-running-without-stage' if any(row['present'] for row in timeline['brokers']) else 'broker-ended-before-stage'
    else:
        reach='no-broker-observed'
    brokers=(timeline or {}).get('brokers') or []
    return {'reach':reach,'brokers':len(brokers),
            'brokerObservedSeconds':None if not brokers else round(brokers[0]['lastSeen']-brokers[0]['firstSeen'],3),
            'watchErrors':sorted((timeline or {}).get('errors') or {}),
            'lastProductLog':[row.get('message') for row in (logs or [])[-3:] if type(row) is dict]}


def fit(value, limit=None):
    """The diagnostics event under its bound: the bulkiest texts give way to their digests, the largest first."""
    limit=DIAGNOSTICS_EVENT_BYTES if limit is None else limit
    def size():
        return len(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
    for path in (('diagnosticsExport','text'),('runtimeLog','tail'),('watch','candidateConfigs'),('logs',)):
        if size()<=limit:
            break
        holder=value
        for step in path[:-1]:
            holder=holder.get(step) if type(holder) is dict else None
        if type(holder) is dict and path[-1] in holder:
            raw=json.dumps(holder[path[-1]],sort_keys=True).encode()
            holder[path[-1]]={'dropped':True,'sizeBytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    require(size()<=limit,'scoped-tun-diagnostics-bound')
    return value


def product_diagnostics(owner, lease, runtime, terminal, timeline):
    """On a terminal the variant does not expect: the product's own account of it, before any check of the end runs.

    The operation's ledger record, the product's log (logs, its own redaction), its diagnostics report (diagnostics export,
    its own redaction: preflight, VPN capability, connection log, runtime log tail), the workspace runtime log and runtime
    folder, the VPN config the launch held (from the watch, redacted), a reserved job's correlation journals, and the watch.
    Each read is best effort: a failed one is recorded, never raised, and nothing is written to the product.
    """
    state=lease['state'];workspace,identity=state['workspace'],state['identity']
    operation=(lease.get('accepted') or {}).get('operationId')  # None for a request refused before any operation.
    found={'variant':lease['inputs']['variant'],'terminal':terminal,'watch':timeline,'replayAllowed':False}

    def part(name, read):
        try:
            found[name]=read()
        except Exception as error:
            found[name]={'error':type(error).__name__+': '+str(error)[:200]}

    def ledger():
        if operation is None:
            return None
        rows=[row for row in runtime.result(owner,workspace,identity,'operations','list')['data']['operations']
              if type(row) is dict and row.get('id')==operation]
        return rows[0] if len(rows)==1 else {'matches':len(rows)}

    def logs():
        entries=runtime.result(owner,workspace,identity,'logs','--limit',str(LOG_ENTRIES))['data']['entries']
        return [{key:(clip(item,LOG_MESSAGE_CHARS) if type(item) is str else item) for key,item in row.items()}
                for row in entries[-LOG_ENTRIES:] if type(row) is dict]

    def report():
        # Raw stdout and no --json: ControlCliParser refuses "JSON output cannot be combined with a raw stdout export"
        # with a local INVALID_ARGUMENT envelope (b90ccd68). Raw, the report is all of stdout and a failure's code is on stderr.
        reply=owner.invoke(workspace,'--controller-id',identity,'diagnostics','export','--output','-')
        raw=reply.stdout.encode()
        return {'exitCode':reply.returncode,'stderr':clip(reply.stderr,2000),'sizeBytes':len(raw),
                'sha256':hashlib.sha256(raw).hexdigest(),'text':clip(reply.stdout)}

    def runtime_log():
        raw=read_shared(owner,runtime_folder(state)/'runtime-sing-box.log',CONFIG_BYTES)
        if raw is None:
            return {'absent':True}
        return {'sizeBytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                'tail':clip(raw[-4*TEXT_CHARS:].decode('utf-8','replace'))}

    part('operation',ledger)
    part('logs',logs)
    part('diagnosticsExport',report)
    part('runtimeLog',runtime_log)
    part('runtimeFolder',lambda:sorted(os.listdir(str(runtime_folder(state))))[:64])
    if 'reserved' in lease:
        part('journals',lambda:sorted(lease['reserved'].journals(workspace)))
    found['diagnosis']=diagnosis(timeline,found['logs'] if type(found['logs']) is list else None)
    owner.event('scoped-tun-product-diagnostics',fit(found))
    return found['diagnosis']


def unexpected_terminal(error):
    """A step's own check found a final code it does not expect: the case's, or finish_operation's."""
    return str(error) in ('reserved-operation-unexpected-terminal','original-operation-unexpected-terminal')


def watching(owner, lease, observer):
    """A started preparation watch, or the error that kept it from starting: a watch never fails the row."""
    try:
        return PrepareWatch(owner,lease,observer).start()
    except Exception as error:
        return error


def watched(watch):
    """The watch's timeline once stopped; a watch that could not start or stop is an unobserved one, with its error."""
    if isinstance(watch,PrepareWatch):
        try:
            return watch.stop()
        except Exception as error:
            watch=error
    return {'samples':0,'errors':{'watch':{'count':1,'first':type(watch).__name__+': '+str(watch)[:200]}}}


def refused(owner, state, inputs, runtime, cases, observer, operation, children, known):
    """The request's own reply, when a failed check found a final refusal from this controller.

    A refusal is a known end only with A, pending B and the census as before: no operation is open, so the row
    closes like any known failure. Any other reply (lost, partial, transport, another controller's) returns, and
    the original failure parks the owner.
    """
    if len(children)!=1 or tuple(children[0].argv[-5:])!=('--json','--controller-id',state['identity'],'--async',operation):
        return
    reply=children[0].completed()
    try:
        body=json.loads(reply.stdout)
    except ValueError:
        return
    if not (reply.stderr=='' and type(body) is dict and body.get('schemaVersion')==1 and body.get('controllerId')==state['identity']
            and body.get('final') is True and body.get('ok') is False and type(body.get('code')) is str
            and reply.returncode==REFUSED_EXITS.get(body['code'])):
        return
    # The product's own account of the refusal first, so a row that parks on the checks below keeps it too.
    product_diagnostics(owner,{'state':state,'inputs':inputs,'accepted':body},runtime,body,None)
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    kept(state,inputs,known['before'],known['pending'],known['initial'],status,cases,observer)
    found=unscoped(inputs,observer,state,known['baseline'])
    owner.event('scoped-tun-request-refused-known',{'variant':inputs['variant'],'reply':body,'status':status,
        'census':found,'knownFailure':True,'replayAllowed':False})
    owner.tun_operation_requested=False  # No operation is open: the driver closes the row as a known failure.
    raise AssertionError('scoped-tun-request-refused')


def ended_before_journal(owner, state, inputs, runtime, cases, observer, reserved, terminal, known):
    """A reserved row's own request ended in a definite refusal before the product wrote its correlation journal.

    The product writes that journal before UAC and every native input of a mutable job, so no prompt, broker or stage
    of this row exists. With A, pending B and the census as before and still no journal, nothing is open: the row closes
    like any known failure, with the product's own terminal in the evidence. Any other finding keeps the owner parking.
    """
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    kept(state,inputs,known['before'],known['pending'],known['initial'],status,cases,observer)
    found=unscoped(inputs,observer,state,known['baseline'])
    require(reserved.journals(state['workspace'])=={},'scoped-tun-reserved-journal-after-terminal')
    owner.event('scoped-tun-reserved-ended-before-journal',{'variant':inputs['variant'],'terminal':terminal,'status':status,
        'census':found,'journals':0,'knownFailure':True,'replayAllowed':False})
    owner.tun_operation_requested=False  # No operation is open: the driver closes the row as a known failure.
    raise AssertionError('scoped-tun-reserved-ended-before-journal')


def document(owner, state, variant, branches):
    """A configuration or fault variant's own location document, published as the proxy rows' branch cases publish
    theirs: the same generated SOCKS document or CUSTOM config, held open read-only until the row's off."""
    port=state['ready']['advertisedSocksPort'];name=PENDING[variant];original=None
    if variant=='generated-grant':
        value={'type':'socks','remarks':name,'server':'127.0.0.1','server_port':port}
    else:
        original=branches.custom_config(port,DOCUMENT_KIND[variant]);value=branches.profile_document(original,name)
    raw=branches.encoded(value)
    require(variant!='large-grant' or len(raw)>INLINE_LIMIT,'large-fixture-must-exceed-inline-limit')
    path,_=branches.publish_fixture(owner,'owned-tun-profile-'+variant+'.json',raw)
    return {'name':name,'path':str(path),'original':original,'sizeBytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def capture_refused(owner, state, inputs, runtime, cases, observer, reserved, known):
    """resources-grant, before its own request: a config the ordinary capture refuses ends in the product's UNSUPPORTED
    with A as before, the refused location pending, and no broker, stage, route or correlation journal: before any prompt.

    From this request until that is shown a failure parks, as for the row's own request; then nothing is open."""
    for tail in (('locations','select',reserved.REFUSED),('settings','set','mode','vpn')):
        status=runtime.result(owner,state['workspace'],state['identity'],'status')
        runtime.result(owner,state['workspace'],state['identity'],'--if-revision',str(status['configurationRevision']),*tail)
    pending=runtime.result(owner,state['workspace'],state['identity'],'status')
    require(pending['restartRequired'] is True and pending['data']['configuredMode']=='vpn'
            and pending['data']['selectedLocationId']!=known['before']['data']['activeLocationId'],
            'scoped-tun-refused-pending-not-established')
    owner.tun_operation_requested=True
    accepted=runtime.result(owner,state['workspace'],state['identity'],'--async','restart',final=False,codes=('ACCEPTED',))
    # This request's own account, for an end it does not expect or a park while it is still pending.
    lease={'state':state,'inputs':inputs,'accepted':accepted,'reserved':reserved}
    reserved.diagnose=lambda last:product_diagnostics(owner,lease,runtime,last,None)
    try:
        body=reserved.terminal(state,accepted,{'UNSUPPORTED'})
    except AssertionError as error:
        if unexpected_terminal(error):
            product_diagnostics(owner,lease,runtime,getattr(error,'terminal',None),None)
        raise
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    kept(state,inputs,known['before'],pending,known['initial'],status,cases,observer)
    found=unscoped(inputs,observer,state,known['baseline'])
    require(reserved.journals(state['workspace'])=={},'scoped-tun-refused-capture-left-a-journal')
    owner.tun_operation_requested=False  # Nothing is open: the refusal ended before any prompt or broker.
    owner.event('scoped-tun-capture-refused-before-prompt',{'variant':inputs['variant'],'terminal':body,'status':status,
        'census':found,'journals':0,'replayAllowed':False})
    return body


def begin(owner, state, inputs, runtime, cases, observer, branches=None, reserved=None):
    variant=inputs.get('variant') if type(inputs) is dict else None
    sampled=variant in SAMPLED
    require(type(inputs) is dict and set(inputs)==FIELDS|(SAMPLER_FIELDS if sampled else set()) and inputs['schemaVersion']==1
            and inputs['variant'] in VARIANTS and all(inputs[key] is not None for key in inputs),
            'scoped-tun-native-inputs-pending')
    require((branches is not None)==(variant in CONFIGS or variant in FAULTS),'scoped-tun-variant-document-cases')
    require(not sampled or all(str(Path(inputs[key])).casefold() in owner.by_path for key in SAMPLER_FIELDS),
            'scoped-tun-held-sampler')
    require(inputs['pendingLocation']==PENDING[variant] and str(Path(inputs['guiPath'])).casefold() in owner.by_path
            and inputs['expectedApprovingAdminSid']!=owner.request['context']['ordinarySid'],
            'scoped-tun-fixed-pending-location-admin-role')
    require(inputs['uacDecisionId']==decision_id(owner.request['operationId']),'scoped-tun-route-decision')
    require((reserved is not None)==(inputs['variant'] in RESERVED_VARIANTS)
            and (reserved is None or reserved.variant==inputs['variant'] and reserved.pending==inputs['pendingLocation']),
            'scoped-tun-reserved-case-binding')
    require(os.name=='nt' and Path(inputs['programData'])==Path(os.environ['ProgramData']),
            'scoped-tun-current-programdata-context')
    # Before any change: no broker and no TUN route exist, and these are the stages and runtimes not of this row.
    baseline=census(inputs,observer,exclude=(state['actors']['runtime']['pid'],))
    require(baseline['brokers']==[] and baseline['routes']==[],'scoped-tun-clean-before-row')
    # A prompt raised behind the Start menu cannot be answered (a75acf02): refuse while the desktop is not settled.
    desktop=None if variant in PROMPTLESS else interactive_desktop(owner,observer)
    before = runtime.result(owner,state['workspace'],state['identity'],'status')
    require(before['data']['runtimeRunning'] is True and before['data']['activeMode']=='proxy-only'
            and before['restartRequired'] is False, 'scoped-tun-active-proxy-a')
    config=cases.LiveConfig(owner,state['workspace'],inputs['runtimeConfigPath'])
    actual={k:before['data'][k] for k in ('activeLocationId','activeMode','runtimeId','runtimeStartedAt')}
    if reserved is not None:
        # The reserved case's own pending location (and SSH route); nothing restarts here.
        require(reserved.prepare(state,runtime)==inputs['pendingLocation'],'scoped-tun-reserved-pending-location')
        require(config.snapshot()==config.initial,'pending-b-mutated-active-a')
        if inputs['variant']=='resources-grant':
            capture_refused(owner,state,inputs,runtime,cases,observer,reserved,
                            {'before':before,'initial':config.initial,'baseline':baseline})
    added=None if branches is None else document(owner,state,variant,branches)
    tails=(('locations','select',PENDING[variant]),('settings','set','mode','vpn'))
    if added is not None:
        tails=(('locations','add','--input',added['path']),)+tails
    for tail in tails:
        status=runtime.result(owner,state['workspace'],state['identity'],'status')
        runtime.result(owner,state['workspace'],state['identity'],'--if-revision',str(status['configurationRevision']),*tail)
        pending=runtime.result(owner,state['workspace'],state['identity'],'status')
        require(all(pending['data'][key]==value for key,value in actual.items()) and config.snapshot()==config.initial,
                'pending-b-mutated-active-a')
    require(pending['restartRequired'] is True and pending['data']['configuredMode']=='vpn'
            and pending['data']['selectedLocationId']!=before['data']['activeLocationId'],
            'scoped-tun-pending-b-not-established')
    if variant in CONFIGS:
        # The location reads back as the document that made it, before anything is asked of the broker.
        shown=json.loads(runtime.result(owner,state['workspace'],state['identity'],'locations','show',PENDING[variant])['data']['configuration'])
        require(shown==added['original'] if added['original'] is not None else
                shown.get('server')=='127.0.0.1' and shown.get('server_port')==state['ready']['advertisedSocksPort'],
                'scoped-tun-configuration-public-readback')
    # Intentional product restart may replace its config. Preserve the actual
    # beforeimage and release this stable-window observer BEFORE mutation.
    raw=Path(inputs['runtimeConfigPath']).read_bytes()
    require(len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==config.initial['sha256'],
            'owned-small-proxy-config-beforeimage')
    runtime.publish(owner,owner.root/'tun-active-a-beforeimage.json',raw)
    config.close()
    # The launch folders before the request (active A's): the preparation watch reads only the ones the request adds.
    try:
        candidate_baseline=candidates(state)
    except OSError:
        candidate_baseline=None
    # From here on the product may hold an open operation, a prompt or a broker: any failure parks the owner,
    # unless the request's own reply proves it final and nothing changed.
    owner.tun_operation_requested=True
    operation='find-best' if inputs['variant'].startswith('find-best') else 'restart'
    asked=len(owner.children)
    try:
        accepted=runtime.result(owner,state['workspace'],state['identity'],'--async',operation,
                                final=False,codes=('ACCEPTED',))
    except AssertionError:
        refused(owner,state,inputs,runtime,cases,observer,operation,owner.children[asked:],
                {'before':before,'pending':pending,'initial':config.initial,'baseline':baseline})
        raise
    require(type(accepted['operationId']) is str and str(uuid.UUID(accepted['operationId']))==accepted['operationId']
            and str(uuid.UUID(accepted['requestId']))==accepted['requestId'], 'scoped-tun-original-accepted-job')
    lease={'state':state,'inputs':inputs,'before':before,'pending':pending,'accepted':accepted,
           'activeConfig':config,'baseline':baseline,'candidateBaseline':candidate_baseline,'finished':False,
           **({} if added is None else {'document':added})}
    if not hasattr(owner,'tun_operation_leases'):owner.tun_operation_leases=[]
    owner.tun_operation_leases.append(lease)
    if variant in PROMPTLESS:
        # No prompt follows: windows-uac-decision has no row for it and nothing waits on one.
        owner.event('scoped-tun-request-accepted',{'accepted':accepted,'variant':variant,'document':added,
            'promptExpected':False,'replayAllowed':False})
        return lease
    if reserved is not None:
        # Before the decision may answer: a mutable job's correlation journal, and a squat row's folder at its stage.
        # The preparation watch runs while the case waits: a start that ends before its journal leaves only what the
        # product shows, and the case reads the product's diagnostics through the stages before any park of its own.
        lease['reserved']=reserved
        watch=watching(owner,lease,observer);timeline=[]

        def stopped():
            if not timeline:
                timeline.append(watched(watch))
            return timeline[0]
        reserved.diagnose=lambda last:product_diagnostics(owner,lease,runtime,last,stopped())
        try:
            lease['beforeDecision']=reserved.before_prompt(state,accepted)
        except reserved.EndedBeforeJournal as ended:
            # 3260bc21: resources-grant's restart ended RUNTIME_FAILED before its journal, and the evidence held no
            # product log or report. The product's own account comes first, so a row that parks below keeps it too.
            product_diagnostics(owner,lease,runtime,ended.terminal,stopped())
            try:
                ended_before_journal(owner,state,inputs,runtime,cases,observer,reserved,ended.terminal,
                                     {'before':before,'pending':pending,'initial':config.initial,'baseline':baseline})
            finally:
                if owner.tun_operation_requested is False:
                    lease.update(finished=True,knownEnd='ended-before-journal')
        finally:
            stopped()
    # windows-uac-decision's census reads this event's variant and expectedApprovingAdminSid; it is published once.
    owner.event('scoped-tun-awaiting-current-input', {'accepted':accepted,'variant':inputs['variant'],
        'ordinarySid':owner.request['context']['ordinarySid'],
        'ordinarySessionId':owner.request['context']['ordinarySessionId'],
        'expectedApprovingAdminSid':inputs['expectedApprovingAdminSid'],
        'uacDecisionId':inputs['uacDecisionId'],
        'ownerActor':state['actors']['owner'],'originalServeChild':state['serve'].ordinal,'interactiveDesktop':desktop,
        'inputNotPerformedByThisAdapter':True,'replayAllowed':False,**({} if added is None else {'document':added})})
    return lease


def read_native_record(owner, lease, file_record, receipts, expected_stage):
    """Read a create-only machine-protected record from the actual SYS collector.

    Its source is the product source the row runs: the lifecycle inputs' own, which the dedicated driver keeps on the
    lease. The ordinary worker request carries none; an owner request that does binds the same way.
    """
    require(type(file_record) is dict and set(file_record)=={'path','sha256','sizeBytes'}
            and type(file_record['sizeBytes']) is int and 0<file_record['sizeBytes']<=262144,
            'scoped-tun-native-record-bound')
    source=lease['sourceSha'] if 'sourceSha' in lease else owner.request['sourceSha']
    expected=receipts.canonical_path(lease['inputs']['programData']) / ('tun-evidence-'+owner.request['operationId']) / (expected_stage+'.json')
    require(receipts.canonical_path(file_record['path'])==expected, 'scoped-tun-exact-machine-record-destination')
    observation=receipts.FileObservation(owner,file_record['path'])
    try:
        receipts.machine_security(observation.opening['security'],False)
        raw=observation.read(262144)
        require(len(raw)==file_record['sizeBytes'] and hashlib.sha256(raw).hexdigest()==file_record['sha256'],
                'scoped-tun-native-record-generation')
        value=json.loads(raw)
    finally:observation.close()
    require(value['schemaVersion']==1 and value['stage']==expected_stage
            and value['ordinaryTaskOperationId']==owner.request['operationId']
            and value['productOperationId']==lease['accepted']['operationId']
            and value['originRequestId']==lease['accepted']['requestId']
            and value['controllerId']==lease['state']['identity']
            and value['context']['bootIdentifier']==owner.request['context']['bootIdentifier']
            and value['context']['ordinarySid']==owner.request['context']['ordinarySid']
            and value['context']['approvingAdminSid']==lease['inputs']['expectedApprovingAdminSid']
            and type(value['context']['ordinarySessionId']) is int
            and value['context']['ordinarySessionId']==owner.request['context']['ordinarySessionId']
            and receipts.canonical_path(value['context']['workspace'])
                ==receipts.canonical_path(owner.request['workspace'])
                ==receipts.canonical_path(str(lease['state']['workspace']))
            and receipts.canonical_path(value['context']['programData'])
                ==receipts.canonical_path(lease['inputs']['programData'])
            and value['collectorSourceSha256']==lease['inputs']['collectorSourceSha256']
            and value['sourceSha']==source,
            'scoped-tun-protected-native-operation-join')
    return value


def denials(variant):
    """The public codes a denial of this variant's prompt ends its operation with.

    Esc ends the prompt with ERROR_CANCELLED (DesktopWindowsVpnBroker: 1223 is CANCELLED), and a restart that ends it
    otherwise unelevated may say PERMISSION_DENIED. Find Best ends at its first CANCELLED start, restoring A
    (DesktopFindBestService); any other failed start makes it try its next candidate, which raises a prompt of its own,
    so for Find Best no other code is the denial of this prompt.
    """
    return {'CANCELLED'} if variant.startswith('find-best') else {'CANCELLED','PERMISSION_DENIED'}


def find_best_selection(lease, status):
    """Which location a granted Find Best leaves selected: its winner, the active one, never a third.

    DesktopFindBestService starts candidates with commitSelectionOnSuccessOnly, so the selection moves only once the
    elevated start succeeded, and then to that candidate. The candidates are the owned locations, A and B, ordered by
    their measured connect time; both reach the one owned endpoint, so either may win. A winner A replaces the pending
    selection of B: the restart's rule (selection kept) is not Find Best's.
    """
    a=lease['before']['data']['activeLocationId'];b=lease['pending']['data']['selectedLocationId']
    selected=status['data']['selectedLocationId']
    require(a!=b and selected==status['data']['activeLocationId'] and selected in (a,b),'scoped-tun-find-best-winner-not-an-owned-candidate')
    return {'locationId':selected,'winner':'active-a' if selected==a else 'pending-b','pendingSelectionKept':selected==b}


def finish(owner, lease, runtime, cases, observer, handoff=None, receipts=None):
    """The public terminal of the row's own request. A grant whose TUN came up asks handoff(lease, 'ready') for its
    SYSTEM collector's ready record only now: the collector finds the broker and its runtime only once they run."""
    require(lease in owner.tun_operation_leases and not lease['finished'],'scoped-tun-finish-once')
    state=lease['state'];variant=lease['inputs']['variant'];denied=variant.endswith('deny');native_record=None
    if variant=='stage-squat':
        return squat_finish(owner,lease,runtime,cases,observer)
    # The default wait parks at 120 s, about as long as a prompt lives, so it must outlast the prompt.
    # Every final code the stages know is read; one this variant does not expect is known only as checked below.
    # The preparation watch runs exactly while the wait does: the prompt is answered only after begin published it.
    watch=watching(owner,lease,observer);timeline=None
    try:
        terminal=runtime.finish_operation(owner,state,lease['accepted'],
            {'OK','RUNTIME_FAILED','CANCELLED','PERMISSION_DENIED'},seconds=300)
    except AssertionError as error:
        # A final code no variant here knows (CONFLICT, UNSUPPORTED, BUSY, ...): its account before the failure parks.
        timeline=watched(watch)
        if unexpected_terminal(error):
            product_diagnostics(owner,lease,runtime,None,timeline)
        raise
    finally:
        if timeline is None:
            timeline=watched(watch)
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    # A fault variant's own end: RUNTIME_FAILED with A kept (preparation) or A back as a new runtime (commit).
    if variant in FAULTS and terminal['code']=='RUNTIME_FAILED':
        try:
            found=(prepared_failure if variant in PROMPTLESS else commit_failure)(owner,lease,status,runtime,cases,observer)
        except AssertionError as mismatch:
            if variant in PROMPTLESS:
                raise  # Its oracle already is the known-end check: A kept and nothing scoped.
            # The approved start ended before its commit: A was never stopped, so nothing was recovered. A definite
            # RUNTIME_FAILED with A, pending B and the census as before is a known end, closed by the row's own steps;
            # anything else (A replaced, something scoped left) keeps parking with the oracle's own reason.
            diagnosed=product_diagnostics(owner,lease,runtime,terminal,timeline)
            try:
                kept(state,lease['inputs'],lease['before'],lease['pending'],lease['activeConfig'].initial,status,cases,observer)
                found=unscoped(lease['inputs'],observer,state,lease['baseline'])
            except AssertionError:
                raise mismatch from None
            lease.update(finished=True,knownEnd=terminal['code'])
            owner.event('scoped-tun-unexpected-terminal-known',{'variant':variant,'terminal':terminal,'status':status,
                'census':found,'diagnosis':diagnosed,'oracle':str(mismatch),'commitReached':False,
                'knownFailure':True,'replayAllowed':False})
            return {'terminal':terminal,'status':status,'nativeRecord':None,'knownFailure':terminal['code']}
        lease.update(finished=True,faultRecovered=terminal['code'])
        owner.event('scoped-tun-fault-recovered',{'variant':variant,'terminal':terminal,'status':status,'census':found,
            'actors':state['actors'],'promptExpected':variant not in PROMPTLESS,'replayAllowed':False})
        return {'terminal':terminal,'status':status,'nativeRecord':None,'faultRecovered':True}
    # An expired prompt reaches a grant as the product's own CANCELLED: the same unchanged A, a known failure.
    cancelled=not denied and variant not in PROMPTLESS and terminal['code']=='CANCELLED'
    unexpected=terminal['code'] not in (denials(variant) if denied else set() if variant in PROMPTLESS
                                        else {'CANCELLED'} if variant in FAULTS else {'OK','CANCELLED'})
    if denied or cancelled or unexpected:
        # The product's own account first, so a row that parks on the checks below keeps it too.
        diagnosed=product_diagnostics(owner,lease,runtime,terminal,timeline) if unexpected else None
        kept(state,lease['inputs'],lease['before'],lease['pending'],lease['activeConfig'].initial,status,cases,observer)
        if unexpected:
            # A refused preparation, say, before any prompt: known only with A intact and nothing scoped started.
            found=unscoped(lease['inputs'],observer,state,lease['baseline'])
            lease.update(finished=True,knownEnd=terminal['code'])
            owner.event('scoped-tun-unexpected-terminal-known',{'variant':lease['inputs']['variant'],'terminal':terminal,
                'status':status,'census':found,'diagnosis':diagnosed,'knownFailure':True,'replayAllowed':False})
            return {'terminal':terminal,'status':status,'nativeRecord':None,'knownFailure':terminal['code']}
    else:
        require(variant in GRANTS and handoff is not None and receipts is not None,'actual-tun-native-file-required')
        native_record=read_native_record(owner,lease,handoff(lease,'ready'),receipts,'ready')
        require(native_record['stage']=='ready'
                and native_record['productOperationId']==lease['accepted']['operationId'],
                'actual-machine-protected-tun-ready-observation-required')
        require(status['data']['runtimeRunning'] is True and status['data']['activeMode']=='vpn'
                and status['data']['activeLocationId']==status['data']['selectedLocationId']
                and status['restartRequired'] is False
                and native_record['observations']['configuration']['sha256']!=lease['activeConfig'].initial['sha256'],
                'scoped-tun-actual-commit-result')
        if lease['inputs']['variant'].startswith('find-best'):
            lease['findBestSelection']=find_best_selection(lease,status)
        lease['nativeReady']=native_record  # The TUN is up: only now may the direct sampler run.
    lease['finished']=True
    if cancelled:
        lease['knownEnd']=terminal['code']  # No TUN came up: the grant closes by its census, with no off of its own.
        owner.event('scoped-tun-grant-cancelled-known',{'variant':lease['inputs']['variant'],'terminal':terminal,
            'status':status,'knownFailure':True,'replayAllowed':False})
        return {'terminal':terminal,'status':status,'nativeRecord':None,'cancelled':True}
    owner.event('scoped-tun-public-outcome',{'variant':lease['inputs']['variant'],'terminal':terminal,
        'status':status,'nativeRecord':native_record,'findBestSelection':lease.get('findBestSelection'),
        'uacInputOriginStillRequired':True,
        'trafficAndExactOffStillRequired':not denied,'privilegedFaultRecoveryProven':False})
    return {'terminal':terminal,'status':status,'nativeRecord':native_record}


def prepared_failure(owner, lease, status, runtime, cases, observer):
    """A preparation failure in VPN mode: the product refused the document before any prompt, so active A, pending B,
    their config bytes and the census are exactly as before the request."""
    kept(lease['state'],lease['inputs'],lease['before'],lease['pending'],lease['activeConfig'].initial,status,cases,observer)
    return unscoped(lease['inputs'],observer,lease['state'],lease['baseline'])


def commit_failure(owner, lease, status, runtime, cases, observer):
    """A commit-readiness failure after the approval: the product stopped A, the approved runtime could not bind its
    owned-conflict listener, and the product brought A back from its own descriptor (DesktopRuntimeTransition.recover).

    A is the same location and mode with a new runtime, its config bytes as before, pending B still selected in VPN mode;
    the original A runtime is gone and the new one runs unelevated; the runtime log names the conflict the elevated
    runtime hit; and no broker, TUN route, private stage or runtime beyond the baseline and the new A is left.
    """
    state,inputs,before,pending=lease['state'],lease['inputs'],lease['before'],lease['pending']
    initial=lease['activeConfig'].initial
    require(status['data']['runtimeRunning'] is True and status['data']['activeMode']=='proxy-only'
            and status['data']['activeLocationId']==before['data']['activeLocationId']
            and status['data']['runtimeId']!=before['data']['runtimeId']
            and status['restartRequired'] is True and status['data']['configuredMode']=='vpn'
            and status['data']['selectedLocationId']==pending['data']['selectedLocationId']
            and cases.config_bytes(inputs['runtimeConfigPath'])=={key:initial[key] for key in ('sizeBytes','sha256')},
            'scoped-tun-commit-failure-did-not-recover-active-a')
    native=observer.WindowsNative()
    old=state['actors']['runtime']
    gone=observer.observe_exit([old],native)
    require(len(gone)==1 and gone[0].get('originalAbsent') is True,'scoped-tun-commit-failure-original-a-not-retired')
    actors=runtime.capture_proxy_actors(owner,state['serve'],native,state['inputs']['runtimeImagePath'],state['inputs']['runtimeSha256'])
    require((actors['runtime']['pid'],actors['runtime']['creationFileTime'])!=(old['pid'],old['creationFileTime']),
            'scoped-tun-commit-failure-original-a-not-retired')
    cases.exact_actor(native,actors['owner'],elevated=False)
    cases.exact_actor(native,actors['runtime'],elevated=False)
    log=Path(state['workspace'])/'runtime'/'runtime-sing-box.log'
    with log.open('rb') as stream:raw=stream.read(CONFIG_BYTES+1)
    require(len(raw)<=CONFIG_BYTES and b'owned-conflict' in raw.lower() and b'bind' in raw.lower()
            and str(state['ready']['advertisedSocksPort']).encode() in raw,
            'scoped-tun-commit-failure-conflict-log-required')
    state['actors']=actors  # The row's own off and its census take the recovered A.
    return unscoped(inputs,observer,state,lease['baseline'])


def configuration(owner, lease, branches):
    """A configuration grant's runtime config inside its ready window: the bytes the ordinary user reads are the
    ones SYSTEM read for the ready record, and they are the product's VPN config of this variant's own document."""
    variant=lease['inputs']['variant']
    require(lease in owner.tun_operation_leases and lease['finished'] and lease.get('nativeReady') is not None
            and not lease.get('offRequested') and variant in CONFIGS and 'document' in lease
            and not lease.get('configurationObserved'),'scoped-tun-configuration-window')
    observed=lease['nativeReady']['observations']['configuration']
    with Path(lease['inputs']['runtimeConfigPath']).open('rb') as stream:raw=stream.read(CONFIG_BYTES+1)
    require(0<len(raw)<=CONFIG_BYTES and len(raw)==observed['sizeBytes'] and hashlib.sha256(raw).hexdigest()==observed['sha256'],
            'scoped-tun-configuration-not-the-ready-record')
    actual=json.loads(raw);state=lease['state'];port=state['ready']['advertisedSocksPort']
    tun=[row for row in actual['inbounds'] if row.get('type')=='tun']
    if variant=='generated-grant':
        # DesktopProxyConfigFactory.buildVpnConfig: one TUN on the generated address, the location's SOCKS server out.
        require(len(tun)==1 and tun[0].get('address')==['172.19.250.1/30']
                and any(row.get('type')=='socks' and row.get('server')=='127.0.0.1' and row.get('server_port')==port
                        for row in actual['outbounds']),'scoped-tun-generated-configuration')
    else:
        original=lease['document']['original']
        branches.custom_semantics(original,actual)  # Only the product's management and direct-probe transformations.
        probe=[{'process_name':['vpn-control-probe-sing-box','vpn-control-probe-sing-box.exe'],'action':'route',
                'outbound':'vpn-control-direct-probe'},
               {'process_path':[str(Path(state['workspace'])/'validation'/'vpn-control-probe-sing-box.exe')],
                'action':'route','outbound':'vpn-control-direct-probe'}]
        require(tun==[] and actual['route']['rules'][2:-len(original['route']['rules'])]==probe,
                'scoped-tun-custom-configuration')
        require(variant!='large-grant' or lease['document']['sizeBytes']>INLINE_LIMIT,'large-fixture-must-exceed-inline-limit')
    lease['configurationObserved']=True
    owner.event('scoped-tun-configuration-observed',{'variant':variant,'document':lease['document'],
        'runtimeConfig':{'sizeBytes':len(raw),'sha256':observed['sha256']},'tunInbound':bool(tun),
        'directSamplerAllowed':variant in SAMPLED,'replayAllowed':False})
    return actual


def squat_finish(owner, lease, runtime, cases, observer):
    """stage-squat: the approved broker finds its stage already there and refuses with CONFLICT. A and pending B stay,
    the squat folder is exactly as created, and nothing scoped is left once the case removed its own folder. An expired
    prompt is the grant's own known CANCELLED, with the same checks."""
    state,reserved=lease['state'],lease['reserved']
    try:
        terminal=reserved.terminal(state,lease['accepted'],{'CONFLICT','CANCELLED'})
    except AssertionError as error:
        if unexpected_terminal(error):
            product_diagnostics(owner,lease,runtime,getattr(error,'terminal',None),None)
        raise
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    kept(state,lease['inputs'],lease['before'],lease['pending'],lease['activeConfig'].initial,status,cases,observer)
    reserved.squat_kept_and_removed()
    found=unscoped(lease['inputs'],observer,state,lease['baseline'])
    if terminal['code']=='CANCELLED':
        lease.update(finished=True,knownEnd='CANCELLED')
        owner.event('scoped-tun-grant-cancelled-known',{'variant':'stage-squat','terminal':terminal,'status':status,
            'census':found,'knownFailure':True,'replayAllowed':False})
        return {'terminal':terminal,'status':status,'nativeRecord':None,'cancelled':True}
    lease.update(finished=True,conflictEnd='CONFLICT')
    owner.event('scoped-tun-stage-squat-refused',{'terminal':terminal,'status':status,'census':found,
        'jobId':reserved.job,'activeAKept':True,'pendingBKept':True,'replayAllowed':False})
    return {'terminal':terminal,'status':status,'nativeRecord':None}


def begin_off(owner,lease,runtime):
    require(lease in owner.tun_operation_leases and lease['finished'] and lease.get('nativeReady') is not None
            and lease['inputs']['variant'] in GRANTS and not lease.get('offRequested'),
            'scoped-tun-explicit-off-once')
    state=lease['state']
    # The product's own view right before its off: the TUN runtime it started still runs. A runtime that ended by itself
    # (a crash after the last sample, say) leaves an off that stops nothing of the product's: no exact stop to prove.
    before=runtime.result(owner,state['workspace'],state['identity'],'status')
    require(before['data']['runtimeRunning'] is True and before['data']['activeMode']=='vpn',
            'scoped-tun-runtime-ended-before-off')
    # The guest clock just before the off goes out: finish_off takes only originals that exited after it.
    lease.update(offRequested=True,offRequestedFileTime=guest_filetime())
    # Product owns retirement of the exact elevated child; no process kill.
    terminal=runtime.result(owner,state['workspace'],state['identity'],'off')
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    require(status['data']['runtimeRunning'] is False,'scoped-tun-public-off-runtime-still-running')
    lease['offTerminal']=terminal
    owner.event('scoped-tun-awaiting-exact-off-observation',{'accepted':lease['accepted'],'statusBeforeOff':before,
        'offRequestedFileTime':lease['offRequestedFileTime'],'offTerminal':terminal,'status':status,
        'originalNativeCustodyMustBeRetained':True})
    return terminal


def finish_off(owner,lease,file_record,receipts):
    require(lease.get('offRequested') and not lease.get('offFinished') and type(lease.get('offRequestedFileTime')) is int,
            'scoped-tun-original-off-stage')
    record=read_native_record(owner,lease,file_record,receipts,'off')
    rows=record['originalProcesses']
    require(len(rows)==2 and {row['role'] for row in rows}=={'helperActor','runtimeActor'}
            and all(row['originalHandleSignaled'] is True and row['times']['creationFileTime']==row['creationFileTime']
                    for row in rows), 'scoped-tun-original-process-handles-not-proven-terminal')
    # The collector publishes off once both original handles signal, for whatever reason: only an exit after the
    # product's own off was asked for is that off's. One that ended before it (a crash) is no exact stop.
    requested=lease['offRequestedFileTime']
    require(all(type(row['times'].get('exitFileTime')) is int and row['times']['exitFileTime']>requested for row in rows),
            'scoped-tun-original-ended-before-the-off')
    lease['offFinished']=True
    # This proves the off ended exactly these two originals after it was asked for. It cannot show the elevated stop
    # spared an unrelated runtime: none runs beside the grant (exact-child-stop stays unmapped for TUN).
    owner.event('scoped-tun-exact-off-observed',{'offTerminal':lease['offTerminal'],'offRequestedFileTime':requested,
        'record':record,'exitedAfterOffRequest':True,'siblingSurvivalObserved':False,'originalOwnerCleanupStillRequired':True})
    return record


def traffic(owner, lease):
    """The direct sampler through this row's own TUN: after its ready record proved the TUN up, before its off.

    Outside that window the benchmark address would leave the guest, so nothing else starts it.
    """
    require(lease in owner.tun_operation_leases and lease['finished'] and lease.get('nativeReady') is not None
            and not lease.get('offRequested') and lease['inputs']['variant'] in SAMPLED,
            'scoped-tun-direct-traffic-window')
    inputs=lease['inputs']
    raw=owner.by_path[str(Path(inputs['samplerInputPath'])).casefold()].digest(True,4096)
    require(json.loads(raw)['expectedBodyHex']==lease['state']['inputs']['fixtureBody'].encode().hex(),
            'scoped-tun-sampler-owned-upstream-body')
    child=owner.child('scoped-tun-direct-traffic',[owner.request['pythonRuntime']['interpreterPath'],'-I','-B',
        inputs['samplerPath'],'--input',inputs['samplerInputPath']])
    output=child.completed()
    rows=[json.loads(line) for line in output.stdout.splitlines()]
    require(output.returncode==0 and output.stderr=='' and len(rows)>=2
            and rows[-1]=={'kind':'terminal','sampleCount':len(rows)-1,'allSamplesSucceeded':True}
            and all(row.get('kind')=='sample' and row.get('succeeded') is True for row in rows[:-1]),
            'scoped-tun-direct-traffic')
    owner.event('scoped-tun-direct-traffic-observed',{'child':child.ordinal,'samples':len(rows)-1,
        'target':'198.18.0.1:80','socksStep':False,'replayAllowed':False})
    return rows


def closing(owner, lease, observer):
    """Read after the public off: no broker, no runtime this row started, no new private stage, no TUN route.

    Once per settled lease: a denial, a known end such as a cancelled grant, a fault variant's own recovery, or a
    grant after its exact off.
    """
    require(lease in owner.tun_operation_leases and settled(lease) and not lease.get('closed'),'scoped-tun-closing-once')
    found=census(lease['inputs'],observer)
    baseline=lease['baseline']
    require(found['brokers']==[] and found['routes']==[] and set(found['runtimes'])<=set(baseline['runtimes'])
            and found['stages']==baseline['stages'],'scoped-tun-scoped-state-left-behind')
    lease['closed']=True
    owner.event('scoped-tun-closing-census',{'baseline':baseline,'closing':found,'replayAllowed':False})
    return found
