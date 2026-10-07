"""Retain one fixed historical read's evidence before its unchanged parser."""
from __future__ import annotations
import base64
import gzip
import hashlib
import json
import uuid
from . import windows_cp117_historical_base_archives as history
_CORRELATION='45e4514a-c629-4f3b-99bc-aad599640d29'
_PROOF_SHA='9d54ecb36ee1e7d4850fa7f985302b76a6c118cb3f2dfee96eb2a117c9d82ae8'
_PARSER_TEMPLATE_SHA='6c3a25621135a2077d42d46fc9776c9c5c80986b93c55c0f3b94c770f84f5842'
_HISTORY_SOURCE_SHA='84984c088a55aaa088f68a2a698ea502cd908dc0e2a499fb3a2902641263ba3a'
_REMOTE_SHA='e5caa51cf9fd0d1c94854b281d9123624abf28eedf1460489b49f10a60839ce3'

def catalog():
    proof=history._PS.replace('@CORR@',_CORRELATION).replace('@SID@',history._GENERATION[4])
    actual=proof.encode('utf-16le')
    if hashlib.sha256(actual).hexdigest()!=_PROOF_SHA:raise ValueError('proof-source')
    if hashlib.sha256(history._PARSER.encode('utf-16le')).hexdigest()!=_PARSER_TEMPLATE_SHA:raise ValueError('parser-source')
    parser=history._PARSER.replace('@PACKED@',base64.b64encode(gzip.compress(actual,mtime=0)).decode())
    return [base64.b64encode(parser.encode('utf-16le')).decode(),base64.b64encode(actual).decode()]

def trace_support(request):
    if request.get('catalog')!=catalog() or request.get('generation')!=list(history._GENERATION):raise ValueError('trace-authority')
    prefix="\nimport time,gzip\n_legacy_request="+repr(request)+"\n_legacy_parser_template="+repr(history._PARSER)+"\n"
    prefix+="_legacy_proof=base64.b64decode(_legacy_request['catalog'][1],validate=True)\n"
    prefix+="if hashlib.sha256(_legacy_proof).hexdigest()!="+repr(_PROOF_SHA)+":raise ValueError('proof-source')\n"
    prefix+="if hashlib.sha256(_legacy_parser_template.encode('utf-16le')).hexdigest()!="+repr(_PARSER_TEMPLATE_SHA)+":raise ValueError('parser-source')\n"
    # Match the original unchanged remote factory on its own Python runtime;
    # gzip OS-header differences cannot create a new PowerShell template/body.
    prefix+="_legacy_packed=base64.b64encode(gzip.compress(_legacy_proof,mtime=0)).decode('ascii')\n"
    prefix+="_legacy_parser=_legacy_parser_template.replace('@PACKED@',_legacy_packed)\n"
    prefix+="_legacy_catalog=[base64.b64encode(_legacy_parser.encode('utf-16le')).decode('ascii'),_legacy_request['catalog'][1]]\n"
    return prefix+_TRACE

_TRACE=r"""
_legacy_delegate=call
_legacy_index=0
_legacy_child=None
_legacy_sock=None
_legacy_polls=0
_legacy_source=None
_legacy_request_sha=hashlib.sha256(json.dumps(_legacy_request,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def _legacy_emit(event):
 _legacy_save({'diagnosticId':_legacy_request['diagnosticId'],'requestSha256':_legacy_request_sha,**event})
def _legacy_blob(value):
 if not isinstance(value,str):return {'type':'missing' if value is None else type(value).__name__}
 return {'chars':len(value),'sha256':hashlib.sha256(value.encode()).hexdigest(),'prefix':value[:4096],'complete':len(value)<=4096}
def _legacy_call(sock,operation,args):
 global _legacy_index,_legacy_child,_legacy_sock,_legacy_polls,_legacy_source
 begin=time.monotonic()
 if operation=='guest-exec':
  if _legacy_index>=2 or args!={'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',_legacy_catalog[_legacy_index]],'capture-output':True}:raise ValueError('fixed-legacy-source')
  _legacy_source=hashlib.sha256(base64.b64decode(_legacy_catalog[_legacy_index],validate=True)).hexdigest()
  try:result=_legacy_delegate(sock,operation,args)
  except Exception as error:
   _legacy_emit({'kind':'submit-exception','query':_legacy_index,'sourceSha256':_legacy_source,'exception':type(error).__name__});raise
  if not isinstance(result,dict)or type(result.get('pid'))is not int or result['pid']<=0:raise ValueError('legacy-child')
  _legacy_child=result['pid'];_legacy_sock=sock;_legacy_polls=0;_legacy_index+=1
  _legacy_emit({'kind':'submitted','query':_legacy_index-1,'childPid':_legacy_child,'sourceSha256':_legacy_source})
  return result
 if operation!='guest-exec-status' or _legacy_child is None or sock!=_legacy_sock or args!={'pid':_legacy_child} or _legacy_polls>=40:raise ValueError('fixed-legacy-status')
 _legacy_polls+=1
 try:result=_legacy_delegate(sock,operation,args)
 except Exception as error:
  _legacy_emit({'kind':'poll-exception','childPid':_legacy_child,'poll':_legacy_polls,'exception':type(error).__name__});raise
 exited=result.get('exited')if isinstance(result,dict)else None
 _legacy_emit({'kind':'poll','childPid':_legacy_child,'poll':_legacy_polls,'exited':exited if type(exited)is bool else None,'elapsedMs':max(0,round((time.monotonic()-begin)*1000))})
 if isinstance(result,dict)and result.get('exited')is True:
  _legacy_emit({'kind':'terminal','childPid':_legacy_child,'poll':_legacy_polls,'sourceSha256':_legacy_source,'exitcode':result.get('exitcode')if type(result.get('exitcode'))is int else None,'outTruncated':result.get('out-truncated'),'errTruncated':result.get('err-truncated'),'output':{k:_legacy_blob(result.get(k))for k in ('out-data','err-data')}})
 return result
call=_legacy_call
"""

def program(args,diagnostic):
    if hashlib.sha256(history._REMOTE.encode()).hexdigest()!=_REMOTE_SHA:raise ValueError('historical-source')
    if str(uuid.UUID(diagnostic))!=diagnostic:raise ValueError('diagnostic-correlation')
    if len(args)!=9 or tuple(args[1:7])!=(history._GENERATION[0],_CORRELATION,*map(str,history._GENERATION[1:4]),history._GENERATION[4]) or args[-1]!=catalog()[1]:raise ValueError('fixed-inputs')
    request={'version':1,'diagnosticId':diagnostic,'correlationId':_CORRELATION,'historicalSourceSha256':_REMOTE_SHA,'parserTemplateSha256':_PARSER_TEMPLATE_SHA,'proofSourceSha256':_PROOF_SHA,'historyFileSha256':_HISTORY_SOURCE_SHA,'inputsSha256':hashlib.sha256(json.dumps(list(args),separators=(',',':')).encode()).hexdigest(),'generation':list(history._GENERATION),'catalog':catalog()}
    setup="\ndef _legacy_save(event):\n print('LEGACY-QGA '+json.dumps(event,sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)\n"
    return history.base._QGA+setup+trace_support(request)+history._REMOTE[len(history.base._QGA):],request
