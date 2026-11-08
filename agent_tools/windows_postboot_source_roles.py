"""Closed reboot-action inputs and original Owner source/module mapping.

No action, transport or native API is constructed at import. Initial native pins
and the original normal runner supply authority; a decoded schema is data only.
Each role's digest comes from the request's own pins and the planner's table.
"""
from pathlib import Path, PureWindowsPath
import hashlib
import json
import re

MODULE_ROLES={'autostart','lifecycle','runtime','runtimeStages','observer'}
SOURCE_ROLES=MODULE_ROLES|{'sourceRoles','postbootAction','prebootAction','startupCollector','trafficWorker','listenerScript','upstreamFixture'}
FILE_ROLES={'gui','powerShell','runtimeAuthority','snapshotScript','migrationScript','startScript'}
# The package ships its runtime only inside an app jar, extracted per workspace to runtime\tools.
# The installed native-helpers.json beside the GUI is the product's own record of that runtime's digest.
RUNTIME_AUTHORITY=('app','native','windows-amd64','native-helpers.json')
ROLES=SOURCE_ROLES|FILE_ROLES
PHASES={'preboot-reboot','postboot-final'}
# query-first needs no reboot: it runs in the preboot action's fresh workspace and starts nothing that outlives it.
SCENARIOS={'preboot-reboot':{'reconnect','explicit-off','autostart-migration','query-first'},
           'postboot-final':{'reconnect','explicit-off','autostart-migration'}}
# The in-guest SOCKS upstream listens here before and after the reboot, so the remembered profile still names it.
UPSTREAM_PORT=41081
UPSTREAM_TOKEN='vpn-control-reboot-upstream'
POWERSHELL=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'


def need(ok,code):
    if not ok:raise ValueError(code)
def wire(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def unique(pairs):
    result={}
    for key,value in pairs:
        need(key not in result,'duplicate-postboot-json-key');result[key]=value
    return result
def decoded(raw):return json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique)
def windows_path(value):
    need(type(value)is str and PureWindowsPath(value).is_absolute() and str(PureWindowsPath(value))==value
         and not any(c in value for c in '\0\r\n'),'canonical-postboot-windows-path')
    return value.casefold()


def validate_config(value):
    base={'schemaVersion','phase','scenario','sourceRoles','autostartInputs','trafficInputPath'}
    need(type(value)is dict and value.get('phase') in PHASES,'closed-postboot-phase')
    extra=set() if value['phase']=='preboot-reboot' else {'checkpointPath'}
    need(set(value)==base|extra and value['schemaVersion']==1 and value['scenario'] in SCENARIOS[value['phase']]
         and all(v is not None for v in value.values()),'closed-postboot-config-schema')
    roles=value['sourceRoles'];need(type(roles)is dict and set(roles)==ROLES,'closed-postboot-source-role-map')
    for path in roles.values():windows_path(path)
    for key in {'trafficInputPath'}|extra:windows_path(value[key])
    auto=value['autostartInputs']
    need(type(auto)is dict and set(auto)=={'schemaVersion','snapshotScriptPath','powerShellPath','migrationScriptPath','startScriptPath','guiPath','workspace'}
         and auto['schemaVersion']==1,'frozen-autostart-input-schema')
    for key,role in [('snapshotScriptPath','snapshotScript'),('powerShellPath','powerShell'),('migrationScriptPath','migrationScript'),('startScriptPath','startScript'),('guiPath','gui')]:
        need(windows_path(auto[key])==windows_path(roles[role]),'same-autostart-source-role')
    windows_path(auto['workspace'])
    need(roles['powerShell']==POWERSHELL,'fixed-existing-os-command-roles')
    need(PureWindowsPath(roles['runtimeAuthority'])==PureWindowsPath(roles['gui']).parent.joinpath(*RUNTIME_AUTHORITY),
         'installed-runtime-authority-beside-gui')
    return value


class SourceLease:
    def __init__(self,owner,config):
        self.owner,self.config=owner,validate_config(config)
        need(owner.request['workspace']==config['autostartInputs']['workspace'],'same-native-postboot-request-context')
        self.paths=dict(config['sourceRoles']);self.pins={};self.modules={}
        for role,path in self.paths.items():
            key=str(Path(path)).casefold();need(key in owner.by_path,'postboot-role-missing-initial-native-pin')
            pin=owner.by_path[key];pin.current()
            self.pins[role]=pin
        need(windows_path(self.paths['sourceRoles'])==windows_path(str(Path(__file__))),
             'same-source-role-validator-loaded-from-original-pin')
        self.config_bytes=wire(config)
        self.guard()
    def guard(self):
        self.owner.guard();need(wire(self.config)==self.config_bytes,'postboot-config-mutated')
        for role,pin in self.pins.items():
            need(self.owner.by_path[str(Path(self.paths[role])).casefold()] is pin,'original-postboot-role-pin-object')
            pin.current()
    def read(self,path,maximum=2*1024*1024):
        self.guard();key=str(Path(path)).casefold();need(key in self.owner.by_path,'postboot-initial-data-pin')
        pin=self.owner.by_path[key];raw=pin.digest(True,maximum=maximum);pin.current()
        need(type(raw)is bytes and len(raw)<=maximum and sha(raw)==pin.record['sha256'],'postboot-exact-held-data-bytes')
        return raw
    def runtime_sha256(self):
        """The bundled runtime's digest, from the held installed record the product's own helper admission reads."""
        value=decoded(self.read(self.paths['runtimeAuthority'],maximum=65536))
        need(type(value)is dict and set(value)=={'schemaVersion','policySha256','artifacts','runtimeAuthority'}
             and type(value['schemaVersion'])is int and value['schemaVersion']==1,'installed-runtime-authority-schema')
        authority=value['runtimeAuthority']
        need(type(authority)is dict and set(authority)=={'runtimeSha256','runtimeSizeBytes','authoritySourceSha256'}
             and type(authority['runtimeSha256'])is str and re.fullmatch('[0-9a-f]{64}',authority['runtimeSha256']) is not None
             and type(authority['runtimeSizeBytes'])is int and 64<=authority['runtimeSizeBytes']<=192*1024*1024,
             'installed-runtime-authority')
        return authority['runtimeSha256']
    def module(self,role):
        need(role in MODULE_ROLES or role in {'postbootAction','prebootAction'},'finite-postboot-module-role')
        self.guard()
        if role not in self.modules:
            self.modules[role]=self.owner.module(self.paths[role],'_postboot_fixed_'+role)
        return self.modules[role]
    def persistent_workspace(self):
        self.guard();target=windows_path(self.owner.request['workspace'])
        pins=[p for p in self.owner.pins if getattr(p,'directory',False) and windows_path(str(p.path))==target]
        need(len(pins)==1,'initial-pinned-persistent-workspace-directory-required')
        pins[0].current();return pins[0]
