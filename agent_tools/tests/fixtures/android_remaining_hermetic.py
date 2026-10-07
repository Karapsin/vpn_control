"""Declared synthetic upstream history for the actual current readonly reader.

Public source bytes are authenticated and copied unchanged. Ledger identities
are test protocol examples, not original native receipts or dispatch authority.
Only the upstream census producer and its historical receipt hashes are seams.
"""
import copy
import hashlib
import json
import types
from pathlib import Path
from agent_tools.tests.fixtures import historical_source
from agent_tools import android_device_availability as availability


def existing_reader(context, current):
    root=context.root
    raw=Path(current.__file__).read_bytes()
    path=root/'agent_tools/android_avd_coldboot.py';path.write_bytes(raw)
    reader=historical_source.load(path,hashlib.sha256(raw).hexdigest())
    dependency=Path(current.admitted_census.__file__)
    depraw=dependency.read_bytes();deppath=root/'agent_tools/android_current_admitted_census.py';deppath.write_bytes(depraw)
    if hashlib.sha256(depraw).hexdigest()!=reader.ADMITTED_SOURCE:
        raise ValueError('test_current_census_source_incompatible')
    historical=context.modules['coldboot']
    reader.census=context.modules['reader']
    def upstream(root,correlation):
        prepared=context.modules['census'].prepare_census(root,correlation)
        prepared['snapshots'][deppath]=availability._snapshot(deppath)
        return prepared
    reader.admitted_census=types.SimpleNamespace(__file__=str(deppath),prepare_census=upstream)
    reader.CENSUS_SHA=historical.CENSUS_SHA
    ledger=root/'.rag_index/android-avd-coldboot'/context.getter.CORRELATION/'launch.json'
    launch=json.loads(ledger.read_bytes())
    launch['intent']['source']['agent_tools/android_avd_coldboot.py']=reader.EXISTING_API35_PRODUCER_SHA
    intent=(json.dumps(launch['intent'],sort_keys=True,separators=(',',':'))+'\n').encode()
    launch['intentSha256']=hashlib.sha256(intent).hexdigest()
    context.write(ledger.relative_to(root),launch,size=67499)
    reader.EXISTING_API35_LAUNCH_SHA=hashlib.sha256(ledger.read_bytes()).hexdigest()
    reader.EXISTING_API35_INTENT_SHA=launch['intentSha256']
    return reader


def component_command(context,current):
    """Actual current command/reader; external census/JDK receipts are protocol seams."""
    owner=types.SimpleNamespace(COMPONENT_SOURCE='c466a58180280fc0606481b423f19e51f9900b82ea09718df4f3b8b504ad7782')
    context._component(owner)
    command=context.consumer(current)
    reader=context.consumer(command.readonly)
    for key in ('proven','bounded_source','CENSUS_SHA','PROOF_SHA'):
        setattr(reader,key,getattr(owner.component,key))
    reader.getter_source=context.consumer(reader.getter_source)
    command.readonly=reader
    return command
