"""Finite diagnosis of an unusable original route, never renewed authority.

Only retained public remote intent records are compared. A positive result
permits preparing a separately owned connection; it never admits the old master
or modifies its immutable intent, source, ready receipt or application jobs.
"""
from __future__ import annotations
import hashlib
import json
import stat
import sys

_EXECUTING_CODE=sys._getframe().f_code

# Exact emitted source families independently retained before this fix. Other
# original sources retain their precise UNKNOWN state rather than being edited.
_REVIEWED=frozenset({'6a67cbde6e7c34ce4745801fa58e666557225cc1f6dca803d2a1528d1f047139',
                    '1c3fc06655015f94485bab27e7bbac02dd9715c9b91e17a2c319e70a36031218'})

_COMPARATOR=r'''def membership_only(original,current):
 changed=False
 def directory_path(path):
  return (len(path)==4 and path[:2]==('configPin','parents') and type(path[2])is int and path[3]=='generation'
   or len(path)==6 and path[:2]==('effectiveRoute','keyMetadata') and type(path[2])is str and path[3]=='parents' and type(path[4])is int and path[5]=='generation'
   or len(path)==3 and path[:2]==('effectiveRoute','ownedHomePins') and type(path[2])is str)
 def same(a,b,path=()):
  nonlocal changed
  if type(a)is not type(b):return False
  if directory_path(path):
   if (type(a)is not list or len(a)!=9 or len(b)!=9 or any(type(v)is not int or v<0 for v in a+b)
       or not stat.S_ISDIR(a[2])or not stat.S_ISDIR(b[2])):return False
   if any(a[i]!=b[i]for i in (0,1,2,3,4,6)):return False
   changed=changed or a!=b
   return True
  if type(a)is dict:
   return set(a)==set(b)and all(same(a[k],b[k],path+(k,))for k in a)
  if type(a)is list:
   return len(a)==len(b)and all(same(x,y,path+(i,))for i,(x,y)in enumerate(zip(a,b)))
  return a==b
 return same(original,current)and changed
'''
exec(compile(_COMPARATOR,__file__+':comparator','exec'))


def diagnostic_source(remote):
    """Read-only exact-source diagnostic; never executes the original action."""
    if hashlib.sha256(remote.encode()).hexdigest()not in _REVIEWED:
        raise ValueError('membership_original_source_unsupported')
    needle="if json.loads(pin(stage+'/intent.json')[0],object_pairs_hook=reject_pairs)!=intent_value:raise ValueError('remote_intent_changed')"
    if remote.count(needle)!=1:raise ValueError('membership_original_source_unsupported')
    replacement="""original_raw,original_generation=pin(stage+'/intent.json')
  original_value=json.loads(original_raw,object_pairs_hook=reject_pairs)
  if action!='status' or request!={} or not membership_only(original_value,intent_value):raise ValueError('remote_intent_changed')
  remote_guard()
  if pin(stage+'/intent.json')!=(original_raw,original_generation):raise ValueError('remote_intent_changed')
  evidence={'state':'directory_membership_changed','correlationId':corr,'gatewayBoot':boot,'sourceSha256':source_sha,'originalIntentSha256':hashlib.sha256(original_raw).hexdigest(),'currentIntentSha256':hashlib.sha256(json.dumps(intent_value,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
  remote_guard()
  print(json.dumps(evidence,sort_keys=True));raise SystemExit(0)"""
    return _COMPARATOR+'\n'+remote.replace(needle,replacement)
