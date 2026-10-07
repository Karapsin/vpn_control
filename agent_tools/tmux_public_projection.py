"""Finite public packaging observations; no filesystem or native operations.

Private remote receipts and absolute spool paths are validated then projected to
bounded identifiers/digests. This grants no replay, release or product authority.
"""
from pathlib import PurePosixPath
import re
import stat
from uuid import UUID

_SHA40=re.compile(r'[0-9a-f]{40}')
_SHA64=re.compile(r'[0-9a-f]{64}')
_FILE=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,159}')
_FULL={'sourceSha','baseVersion','targetVersion','correlationId'}
_START_REASONS={'already-journaled','submission-response-lost','submission-response-uncertain'}
_STATUS_REASONS={'missing-journal','build-host-claim-differs','build-status-unavailable','build-status-identity-differs'}
_DRIVER_REASONS={'prepared-not-released','tmux-status-unavailable'}


def need(condition):
    if not condition:raise ValueError('tmux_public_result_invalid')


def fields(value,keys):
    need(type(value)is dict and set(value)==set(keys))


def digest(value,pattern=_SHA64):
    need(type(value)is str and pattern.fullmatch(value)is not None)
    return value


def correlation(value):
    need(type(value)is str)
    try:need(str(UUID(value))==value)
    except (ValueError,AttributeError):raise ValueError('tmux_public_result_invalid') from None
    return value


def request_for(operation,request):
    if operation=='availability':fields(request,set());return request
    keys=_FULL if operation in ('preflight','start') else {'correlationId'}
    fields(request,keys);correlation(request['correlationId'])
    if keys==_FULL:
        digest(request['sourceSha'],_SHA40)
        from scripts.version_metadata import parse_version
        need(type(request['baseVersion'])is str and type(request['targetVersion'])is str)
        try:need(parse_version(request['baseVersion'])<parse_version(request['targetVersion']))
        except (ValueError,TypeError):raise ValueError('tmux_public_result_invalid') from None
    return request


def bound(value,request,source=False):
    need(value['correlationId']==request['correlationId'] and type(value['correlationId'])is str)
    if 'replayAllowed' in value:need(value['replayAllowed']is False)
    if source:
        digest(value['sourceSha'],_SHA40)
        if 'sourceSha' in request:need(value['sourceSha']==request['sourceSha'])


def terminal(value,request):
    fields(value,{'state','correlationId','exitCode','terminalPin','artifactVerification','replayAllowed'})
    bound(value,request)
    need(value['artifactVerification']=='required' and type(value['artifactVerification'])is str)
    need(type(value['state'])is str and value['state'] in ('terminal','unknown'))
    need((value['state']=='terminal' and type(value['exitCode'])is int and -2147483648<=value['exitCode']<=2147483647) or (value['state']=='unknown' and value['exitCode']is None))
    pin=value['terminalPin'];fields(pin,{'generation','sha256'});digest(pin['sha256'])
    gen=pin['generation'];need(type(gen)is list and len(gen)==9 and all(type(x)is int and x>=0 for x in gen) and 0<gen[5]<=16384 and stat.S_ISREG(gen[2]) and stat.S_IMODE(gen[2])==0o600 and gen[8]==1)
    # Full private pin remains in the journal, not the public projection.
    return {'state':value['state'],'correlationId':value['correlationId'],'exitCode':value['exitCode'],
            'receiptSha256':pin['sha256'],'artifactVerification':'required','replayAllowed':False}


def collected(value,request):
    fields(value,{'state','correlationId','sourceSha','sourceFingerprint','artifacts','timingReceipts','timingReferences','replayAllowed'})
    bound(value,request,True);need(value['state']=='ready' and type(value['state'])is str);digest(value['sourceFingerprint'])
    artifacts=value['artifacts'];need(type(artifacts)is list and len(artifacts)==10)
    seen=set();counts={};public=[]
    for item in artifacts:
        fields(item,{'family','relativePath','artifactId','sha256','size'})
        need(type(item['family'])is str and item['family'] in ('default','arch'))
        digest(item['sha256']);need(type(item['artifactId'])is str and item['artifactId']=='sha256-'+item['sha256'])
        need(type(item['size'])is int and 0<item['size']<=1024**3)
        path=item['relativePath'];need(type(path)is str and len(path)<=512 and path not in seen)
        parts=path.split('/');need(parts[0]==item['family'])
        if parts==[item['family'],'fixture-receipt.json']:kind='fixture-receipt';stage=None
        else:
            need(len(parts)==4 and parts[1]=='packages' and parts[2] in ('base','target') and _FILE.fullmatch(parts[3])is not None and parts[3] not in ('.','..'))
            kind='package';stage=parts[2]
        seen.add(path);key=(item['family'],stage);counts[key]=counts.get(key,0)+1
        public.append({'family':item['family'],'artifactKind':kind,'stage':stage,'artifactId':item['artifactId'],'sha256':item['sha256'],'size':item['size']})
    need(counts=={('default',None):1,('arch',None):1,('default','base'):3,('default','target'):3,('arch','base'):1,('arch','target'):1})
    corr=request['correlationId'];expected={f'linux-package-{family}-{corr}-{phase}-{stage}.json':(family,stage,phase) for family in ('default','arch') for stage in ('base','target') for phase in ('runtime-prep','gradle','packaging')}
    receipts=value['timingReceipts'];references=value['timingReferences'];need(type(receipts)is list and len(receipts)==12 and type(references)is list and len(references)==12)
    timing={};public_timing=[]
    for item in receipts:
        fields(item,{'phase','pipelineId','sha256','path'});digest(item['sha256'])
        path=item['path'];need(type(path)is str and 0<len(path)<=4096 and not any(ord(x)<32 for x in path))
        p=PurePosixPath(path);need(p.is_absolute() and '..' not in p.parts and p.name in expected and p.name not in timing)
        family,stage,phase=expected[p.name]
        need(p.as_posix().endswith('/.rag_index/linux-package-fixture-build/'+corr+'/output/.rag_index/build-timings/'+p.name) and item['phase']==phase and type(item['phase'])is str and item['pipelineId']=='linux-package-'+family and type(item['pipelineId'])is str)
        timing[p.name]=item['sha256'];public_timing.append({'family':family,'stage':stage,'phase':phase,'sha256':item['sha256']})
    ref_names=set()
    for item in references:
        fields(item,{'path','sha256'});digest(item['sha256']);path=item['path']
        need(type(path)is str and path.startswith('.rag_index/build-timings/'))
        name=path.removeprefix('.rag_index/build-timings/')
        need(name in expected and name not in ref_names and path=='.rag_index/build-timings/'+name and item['sha256']==timing[name]);ref_names.add(name)
    need(ref_names==set(expected))
    return {'state':'ready','correlationId':corr,'sourceSha':value['sourceSha'],'sourceFingerprint':value['sourceFingerprint'],
            'artifacts':public,'timingReceipts':public_timing,'replayAllowed':False}


def project(operation,result,request):
    """Validate the exact frozen helper schema or raise a finite ValueError.

    request is the helper's request after the route removes trusted sourceRoot.
    No private paths, full receipt generations or unvalidated fields are returned.
    """
    need(type(operation)is str and operation in ('availability','preflight','start','status','collect'))
    request_for(operation,request);need(type(result)is dict)
    if operation!='availability':need(type(result.get('state'))is str)
    if operation=='availability':
        fields(result,{'available','reason','nativeActionAllowed'})
        need(type(result['available'])is bool and result['nativeActionAllowed']is False and type(result['reason'])is str and result['reason']==('available' if result['available'] else 'tmux_unavailable'))
        return dict(result)
    if operation=='preflight':
        fields(result,{'state','sourceSha','baseVersion','targetVersion','host','packageFamilies','nativeActionAllowed','reason'})
        need(type(result['state'])is str and result['state'] in ('ready','blocked') and result['reason']==('available' if result['state']=='ready' else 'tmux_unavailable') and type(result['reason'])is str)
        need(result['nativeActionAllowed']is False and result['host']=='archlinux' and type(result['host'])is str and type(result['packageFamilies'])is list and result['packageFamilies']==['default','arch'])
        need(all(type(result[k])is str and result[k]==request[k] for k in ('sourceSha','baseVersion','targetVersion')))
        return dict(result)
    if operation=='start':
        if result.get('state')=='submitted':fields(result,{'state','correlationId','replayAllowed'});bound(result,request);return dict(result)
        fields(result,{'state','correlationId','reason','replayAllowed'});bound(result,request)
        need(type(result['state'])is str and type(result['reason'])is str and ((result['state']=='blocked' and result['reason']=='build-host-already-claimed') or (result['state']=='unknown' and result['reason'] in _START_REASONS)))
        return dict(result)
    if operation=='collect':return collected(result,request)
    state=result.get('state')
    if state=='ready':fields(result,{'state','correlationId','sourceSha','replayAllowed'});bound(result,request,True);return dict(result)
    if 'remoteTerminal' in result:
        fields(result,{'state','correlationId','sourceSha','reason','remoteTerminal','replayAllowed'});bound(result,request,True)
        need(state=='unknown' and result['reason']=='explicit-collection-required' and type(result['reason'])is str)
        nested=terminal(result['remoteTerminal'],request)
        return {k:v for k,v in result.items() if k!='remoteTerminal'}|{'terminalObservation':nested}
    fields(result,{'state','correlationId','reason','replayAllowed'}|({'sourceSha'} if 'sourceSha' in result else set()));bound(result,request,'sourceSha' in result)
    need(type(state)is str and type(result['reason'])is str and ((state=='running' and result['reason']=='running' and 'sourceSha' in result) or (state=='unknown' and result['reason'] in (_DRIVER_REASONS if 'sourceSha' in result else _STATUS_REASONS))))
    return dict(result)
