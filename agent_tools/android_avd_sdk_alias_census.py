"""Complete read-only census through one positively authenticated SDK alias.

Consumed census/diagnostic/alias-observation sources remain unchanged. Every
other symlink still rejects. This companion grants no AVD launch authority.
"""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
from . import android_avd_census_diagnostic as diagnostic
from . import android_avd_sdk_alias_observation as alias_observation
from . import android_avd_launch_recovery as census
from . import android_device_availability as availability

ALIAS_ID='0ce9c4e4-8e3c-441f-82dd-a0549194f6f5'
ALIAS_SHA='9e67129652f4e6f3ee5e7122db86c20fc3bf7ff66076be014ede987b4ee8a11d'
DIAGNOSTIC_SOURCE='89aa607d9f3571b9dd3ae854285a6ea37b678b2182fbbbd0669381c36e7773ae'
ALIAS_SOURCE='f41658d9b919f076615e4c4d9603e87410e580f1194e9d8dda3adbe3048522c5'
_SAFE=r'''
KNOWN_ALIAS=__KNOWN__
_original_fixed_reader=read_fixed
REASONS.update({'alias_link_changed','alias_target_changed','alias_leaf_changed','alias_history_changed','alias_read_limit_changed','alias_ancestor_changed'})
def alias_history_guard():
 path=ROOT/('android-avd-privileged-census-'+KNOWN_ALIAS['correlationId']+'.json')
 observed=_original_fixed_reader(path,524288);observed.pop('raw')
 if observed!=KNOWN_ALIAS['capturePin']:raise ValueError('alias_history_changed')
def admitted_alias_read(path,limit):
 path=pathlib.Path(path);entry=KNOWN_ALIAS['files'].get(str(path))
 if entry is None:return _original_fixed_reader(path,limit)
 if limit!=16777216:raise ValueError('alias_read_limit_changed')
 alias_history_guard()
 chain,name=parent_fds(pathlib.Path(KNOWN_ALIAS['path']));target_chain=None
 try:
  if len(chain)-1!=len(KNOWN_ALIAS['ancestors']) or any(item['pin']!=wanted for item,wanted in zip(chain[1:],KNOWN_ALIAS['ancestors'])):raise ValueError('alias_ancestor_changed')
  link=os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False)
  if not stat.S_ISLNK(link.st_mode) or fp(link)!=KNOWN_ALIAS['linkGeneration'] or os.readlink(name,dir_fd=chain[-1]['fd'])!=KNOWN_ALIAS['linkText']:raise ValueError('alias_link_changed')
  target_chain,unused=parent_fds(pathlib.Path(KNOWN_ALIAS['target'])/'__admitted_sdk_target__')
  if target_chain[-1]['pin']!=KNOWN_ALIAS['targetDirectoryGeneration']:raise ValueError('alias_target_changed')
  current=_original_fixed_reader(pathlib.Path(entry['canonical']),limit)
  comparable={k:v for k,v in entry['facts'].items() if k not in {'text','present','kind'}}
  if {k:v for k,v in current.items() if k!='raw'}!=comparable:raise ValueError('alias_leaf_changed')
  guard_parents(target_chain)
  if fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=KNOWN_ALIAS['linkGeneration'] or os.readlink(name,dir_fd=chain[-1]['fd'])!=KNOWN_ALIAS['linkText']:raise ValueError('alias_link_changed')
  guard_parents(chain);alias_history_guard()
  return current
 finally:
  if target_chain is not None:close_parents(target_chain)
  close_parents(chain)
read_fixed=admitted_alias_read
alias_history_guard()
'''

def prepare_census(root: Path,correlation: str) -> dict:
    root=Path(root).absolute()
    prepared=diagnostic.prepare_diagnostic(root,correlation)
    alias_prepared=alias_observation.prepare_observation(root,correlation)
    for path,value in alias_prepared['snapshots'].items():
        if path in prepared['snapshots'] and prepared['snapshots'][path]!=value:raise ValueError('alias_census_local_snapshot_changed')
        prepared['snapshots'][path]=value
    for module,wanted in ((diagnostic,DIAGNOSTIC_SOURCE),(alias_observation,ALIAS_SOURCE)):
        path=Path(module.__file__).absolute();pin,raw=availability._snapshot(path)
        if hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError('alias_census_consumed_source_changed')
        prepared['snapshots'][path]=(pin,raw)
    base=root/'.runtime/parity-evidence'/('android-avd-sdk-alias-'+ALIAS_ID);saved={}
    for name in ('remote-full.json','result.json'):
        path=base/name;pin,raw=availability._snapshot(path);prepared['snapshots'][path]=(pin,raw);saved[name]=json.loads(raw)
        if name=='remote-full.json' and hashlib.sha256(raw).hexdigest()!=ALIAS_SHA:raise ValueError('alias_census_native_proof_changed')
    proof=saved['remote-full.json'];observations=proof['observations']
    if proof['correlationId']!=ALIAS_ID or len(observations)!=2 or observations[0]!=observations[1] or not all(proof['summary'].get(k) is True for k in ('stable','knownTargetMatched','historicalLeafFactsMatched')) or proof.get('lifecycleAllowed') is not False:raise ValueError('alias_census_native_proof_unadmitted')
    actual=observations[0]
    alias=ast.literal_eval(next(n.value for n in ast.parse(alias_prepared['program']).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ALIAS' for t in n.targets)))
    if actual['linkGeneration']!=alias['generation'] or actual['normalizedTarget']!=alias['target'] or not actual['allLeavesMatchHistorical'] or not actual['targetMatchesKnownSDK']:raise ValueError('alias_census_native_binding_changed')
    files={}
    for relative,old in alias['leaves'].items():
        observed=actual['leaves'].get(relative)
        if observed is None or observed['matchesHistorical'] is not True or observed['facts']!=old:raise ValueError('alias_census_native_leaf_changed')
        files[str(Path(alias['path'])/relative)]={'canonical':str(Path(alias['target'])/relative),'facts':old}
    pin=saved['result.json']['pin']
    if pin['sha256']!=ALIAS_SHA or pin['generation'][2]!=45643:raise ValueError('alias_census_capture_pin_changed')
    known={'path':alias['path'],'ancestors':alias['ancestors'],'linkGeneration':actual['linkGeneration'],'linkText':actual['linkText'],'target':actual['normalizedTarget'],'targetDirectoryGeneration':actual['targetDirectoryGeneration'],'files':files,'correlationId':ALIAS_ID,'capturePin':pin}
    own=Path(__file__).absolute();own_pin,own_raw=availability._snapshot(own);prepared['snapshots'][own]=(own_pin,own_raw)
    cfg=prepared['binding'];cfg['source'].update(alias_prepared['binding']['source']);cfg['source'][str(own.relative_to(root))]=hashlib.sha256(own_raw).hexdigest()
    # Rebind only CFG metadata in the exact reviewed diagnostic composition.
    program=prepared['program'];tree=ast.parse(program);assign=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CFG' for t in n.targets))
    lines=program.splitlines(keepends=True);lines[assign.lineno-1:assign.end_lineno]=['CFG='+repr(cfg)+'\n'];program=''.join(lines)
    template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_SAFE' for t in n.targets)))
    if not program.endswith('capture()\n'):raise ValueError('alias_census_dispatch_changed')
    program=program[:-len('capture()\n')]+template.replace('__KNOWN__',repr(known))+'\ncapture()\n'
    compile(program,'<admitted-sdk-alias-census>','exec');prepared['program']=program;census.guard_prepared(prepared);return prepared

def guard_prepared(prepared: dict) -> None:
    census.guard_prepared(prepared)
