"""Finite native fixture recipes and whole-entry causal regressions.

Authenticated complete sources reproduce reviewed operators and local readers.
Fixture peers exercise saved entry points; no SSH, SDK server, or guest starts.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path
import sys
import tempfile
import unittest
import uuid


FIXTURES = Path(__file__).parent / "fixtures/windows_native_packet_recipe"
OPERATOR_PINS = {
    "direct": {
        "before": "35d4eba5c7917d0574439bdd4cadbdb8fe06e42d72660e155c1437b8efa18c55",
        "current": "dbbf35f31a94100d76fd3db1670d2bf3e39e825fe5dc7135644b154cd4d928ba",
        "fixture": "operator-direct.before.source",
    },
    "mcp": {
        "before": "36edacaa3412153ad65e7468ee5f67ae70a52aa2dcb46f1e1ca78f78e392a25c",
        "current": "0d2adf9b107f9ff59824af6edc07f5716248665b25e75b625515b8e5e1391f24",
        "fixture": "operator-mcp.before.source",
    },
}
LOADER_PINS = {
    "fixture": "held-loader.source",
    "before": "312b8035fba337a6306bcd080bbec73e359b650438941ce029681dd9ffa129c0",
    "systemExitFixture": "held-loader-systemexit.before.source",
    "systemExitBefore": "d03ff48f0e0411266755e393b171b5377450c6a582aa4fbcde02cdd77a59e837",
    "current": "f9d5b99d1dac6f13e02d01fbd268b66f08f6ec7230c4ff2a170648e8838c8d3b",
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _before(route):
    if type(route) is not str or route not in OPERATOR_PINS:
        raise ValueError("native_packet_recipe_route")
    raw = (FIXTURES / OPERATOR_PINS[route]["fixture"]).read_bytes()
    if _sha(raw) != OPERATOR_PINS[route]["before"]:
        raise ValueError("native_packet_recipe_before_source")
    return raw


def render_operator(route):
    """Return the exact fixed operator from its complete authenticated source."""
    before = _before(route)
    old = b"manifest_path=BASE/'retained-api-native-requests-v2/manifest.private.json'"
    new = b"manifest_path=BASE/'packet/manifest.private.json'"
    if before.count(old) != 1:
        raise ValueError("native_packet_recipe_unique_manifest_literal")
    fixed = before.replace(old, new, 1)
    compile(fixed, "<native-packet-operator-" + route + ">", "exec")
    functions = lambda raw: [ast.dump(node, include_attributes=False)
        for node in ast.parse(raw).body if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    if functions(before) != functions(fixed):
        raise ValueError("native_packet_recipe_function_changed")
    if _sha(fixed) != OPERATOR_PINS[route]["current"]:
        raise ValueError("native_packet_recipe_fixed_source")
    return fixed


def render_loader():
    """Close held source custody on normal return and every entry exception."""
    before = (FIXTURES / LOADER_PINS["systemExitFixture"]).read_bytes()
    if _sha(before) != LOADER_PINS["systemExitBefore"]:
        raise ValueError("native_packet_recipe_loader_before")
    replacements = ((b'operator_path, operator_sha256, label, manifest_sha256 = sys.argv[1:]',
      b'if len(sys.argv) not in (5, 8):\n    raise ValueError("operator_entry_arguments")\noperator_pa'
      b'th, operator_sha256, label, manifest_sha256 = sys.argv[1:5]'),
     (b'try:\n    opening = os.fstat(fd)',
      b'source_admitted = False\ntry:\n    opening = os.fstat(fd)'),
     (b'    sys.argv = [operator_path, label, manifest_sha256]',
      b'    source_admitted = True\n    sys.argv = [operator_path, *(sys.argv[5:] if len(sys.argv) =='
      b' 8 else [label, manifest_sha256])]'),
     (b'    exec(compile(bytes(raw), operator_path, "exec"), namespace, namespace)\n    if generation'
      b'(os.fstat(fd)) != expected_generation or generation(os.stat(operator_path, follow_symlinks=F'
      b'alse)) != expected_generation:\n        raise ValueError("operator_source_changed")\nfinally:\n'
      b'    os.close(fd)\n',
      b'    exec(compile(bytes(raw), operator_path, "exec"), namespace, namespace)\nfinally:\n    try:'
      b'\n        if source_admitted:\n            if generation(os.fstat(fd)) != expected_generation '
      b'or generation(os.stat(operator_path, follow_symlinks=False)) != expected_generation:\n       '
      b'         raise ValueError("operator_source_changed")\n            os.lseek(fd, 0, os.SEEK_SET'
      b')\n            closing_digest = hashlib.sha256()\n            closing_size = 0\n            whi'
      b'le True:\n                closing_chunk = os.read(fd, 65536)\n                if not closing_c'
      b'hunk:\n                    break\n                closing_size += len(closing_chunk)\n         '
      b'       if closing_size > opening.st_size:\n                    raise ValueError("operator_sou'
      b'rce_changed")\n                closing_digest.update(closing_chunk)\n            if closing_si'
      b'ze != opening.st_size or closing_digest.hexdigest() != operator_sha256:\n                rais'
      b'e ValueError("operator_source_bytes")\n            if generation(os.fstat(fd)) != expected_ge'
      b'neration or generation(os.stat(operator_path, follow_symlinks=False)) != expected_generation'
      b':\n                raise ValueError("operator_source_changed")\n    finally:\n        os.close('
      b'fd)\n'))
    fixed = before
    for old, new in replacements:
        if fixed.count(old) != 1:
            raise ValueError("native_packet_recipe_loader_anchor")
        fixed = fixed.replace(old, new, 1)
    compile(fixed, "<native-packet-held-loader>", "exec")
    if _sha(fixed) != LOADER_PINS["current"]:
        raise ValueError("native_packet_recipe_loader_fixed_source")
    return fixed


PREFIX_PINS = {
    "fixture": "fifo/pending-prefix.before.source",
    "before": "5ad9c4fc86ae47bbb4e69a2b365334509e7edbe7f991ca9c5d2366e18d5cc7eb",
    "current": "b1092da71d6688aa4cb90ed910a62ed3dad1572888db30f357fb4f373f46a279",
    "qualifierFixture": "fifo/qualify-pending-prefix.source",
    "qualifier": "0bb83f1aba8d1742f969dad39534642d3bd310e4cc0572ef5b10905383da0e1d",
}


def render_pending_prefix():
    """Derive the complete current observer from authenticated historical bytes."""
    before = (FIXTURES / PREFIX_PINS["fixture"]).read_bytes()
    if hashlib.sha256(before).hexdigest() != PREFIX_PINS["before"]:
        raise ValueError("native_packet_recipe_prefix_before")
    replacements = (
        (
            b"    terminal state.  A pre-first-open same-bytes replacement remains outside\n"
            b"    what a hash-only receipt can prove.\n",
            b"    terminal state.  Calls to read()/close_known() must be serialized by one\n"
            b"    observer; concurrent use of this private object is unsupported.  A\n"
            b"    pre-first-open same-bytes replacement remains outside what a hash-only\n"
            b"    receipt can prove.\n",
        ),
        (
            b"            self._stream_fd = os.open(name, flags, dir_fd=parent)\n",
            b"            # A same-owner file-to-FIFO race must not turn this observer into a\n"
            b"            # blocking reader before the post-open regular-file check.\n"
            b"            self._stream_fd = os.open(name, flags | os.O_NONBLOCK, dir_fd=parent)\n",
        ),
        (
            b"    records: list[dict] = []\n    pieces = prefix.split(b\"\\n\")\n",
            b"    records: list[dict] = []\n"
            b"    if prefix.count(b\"\\n\") > MAXIMUM_RECORDS:\n"
            b"        raise PrefixError(\"complete JSON record count exceeds the private hard cap\")\n"
            b"    pieces = prefix.split(b\"\\n\")\n",
        ),
    )
    fixed = before
    for old, new in replacements:
        if fixed.count(old) != 1:
            raise ValueError("native_packet_recipe_prefix_unique_literal")
        fixed = fixed.replace(old, new, 1)
    compile(fixed, "<native-packet-pending-prefix>", "exec")
    if hashlib.sha256(fixed).hexdigest() != PREFIX_PINS["current"]:
        raise ValueError("native_packet_recipe_prefix_fixed_source")
    return fixed


ROUTING_PINS = {
    "fixture": "routing/operator.before.source",
    "before": "5611366787f5dc4f69f586ac9c1f6da7978cb76ab11005fdec08f9ed27f99b87",
    "eofBeforeFixture": "routing/operator.eof-before.source",
    "eofBefore": "5a19d3381c800ac4fd4fcafda0dfa3bc094afcf7250143025d70e95d3ba69db8",
    "current": "7434e64bc639dcaefb79d25cabc2f6ab1a4e1a9b31735b7cc2b13b116c5a4945",
}


def render_uac_outer_operator():
    """Derive exact final whole operator from authentic historical source only.

    Declared deltas: stable terminal/raw bytes; per-stream EOF routing while
    waiting for original terminal; held-loader entry contract; observations-only
    local closing metadata. Current whole fixture is provenance, not authority.
    """
    before = (FIXTURES / ROUTING_PINS["fixture"]).read_bytes()
    if hashlib.sha256(before).hexdigest() != ROUTING_PINS["before"]:
        raise ValueError("native_packet_recipe_routing_before")
    replacements = (
        (b"        need(value.get('state')in ('pending','terminal'),'original_start_unknown')\n        return self.jobs[operation]\n    def observe(self,job):\n        self.sequence+=1;tag='observe-'+str(self.sequence).zfill(6)\n",
         b"        need(value.get('state')in ('pending','terminal'),'original_start_unknown')\n        return self.jobs[operation]\n    def terminal_bytes(self,reader,pin,path):\n        # Terminal collection follows the authentic stable-file/raw-hash path,\n        # using the very same FD held during pending observations.\n        need(type(pin)is dict and set(pin)=={'bytes','receivedBytes','retainedSha256','receivedSha256','eof'} and pin['eof']is True,'original_terminal_stream_schema')\n        count=pin['bytes']\n        need(type(count)is int and 0<=count<=16*1024**2 and count==pin['receivedBytes'],'original_terminal_stream_count')\n        reader._check()\n        before=os.fstat(reader._stream_fd)\n        need(before.st_size==count,'original_terminal_stream_size')\n        raw=os.pread(reader._stream_fd,count+1,0)\n        need(len(raw)==count and SHA(raw)==pin['retainedSha256']==pin['receivedSha256'],'original_terminal_stream_hash')\n        need(HeldSources.generation(os.fstat(reader._stream_fd))==HeldSources.generation(before)==HeldSources.generation(os.lstat(path)),'original_terminal_stream_changed')\n        reader._check();return raw\n    def observe(self,job):\n        self.sequence+=1;tag='observe-'+str(self.sequence).zfill(6)\n"),
        (b"        need(type(pins)is dict and set(pins)=={'stdout','stderr'},'original_stream_schema')\n        directory=self.ledger_root/'.rag_index/ssh-program-execution'/job['request']['operationId']\n        raw={}\n        for name in ('stdout','stderr'):\n            key=(job['request']['operationId'],name)\n            if key not in self.streams:self.streams[key]=self.prefix.HeldPrefix(directory,name+'.private')\n            raw[name]=self.streams[key].read(pins[name])\n        need(not raw['stderr'],'original_outer_stderr_nonempty')\n        need(raw['stdout'].startswith(job['prefix']),'original_stream_prefix_changed')\n",
         b"        need(type(pins)is dict and set(pins)=={'stdout','stderr'},'original_stream_schema')\n        directory=self.ledger_root/'.rag_index/ssh-program-execution'/job['request']['operationId']\n        if value['state']=='terminal':\n            need(value.get('exitCode')==0 and capture.get('complete')is True and capture.get('eof')=={'stdout':True,'stderr':True},'original_outer_terminal_not_success')\n        raw={}\n        for name in ('stdout','stderr'):\n            key=(job['request']['operationId'],name)\n            if key not in self.streams:self.streams[key]=self.prefix.HeldPrefix(directory,name+'.private')\n            raw[name]=(self.terminal_bytes(self.streams[key],pins[name],directory/(name+'.private'))\n                       if pins[name].get('eof')is True else self.streams[key].read(pins[name]))\n        need(not raw['stderr'],'original_outer_stderr_nonempty')\n        need(raw['stdout'].startswith(job['prefix']),'original_stream_prefix_changed')\n"),
        (b"            self.held.guard()\n            for reader in self.streams.values():reader.close_known(terminal=True)\n            self.save('qualified.json',{'state':'qualified','operationId':self.owner_id,'deploymentId':self.manifest['deploymentId'],'targetSha':self.manifest['targetSha'],'completeOuterSourceClosing':True,'nativeVisualVerdict':'opened-review-and58-scene-workflow-still-required'})\n            self.held.close();self.closed=True\n            if self.scope is not None:self.scope.__exit__(None,None,None);self.scope=None\n            self.emit({'state':'qualified','operationId':self.owner_id,'sourceClosing':True});return 0\n        except BaseException as error:\n            if self.started:self.park(error)\n",
         b"            self.held.guard()\n            for reader in self.streams.values():reader.close_known(terminal=True)\n            self.save('observations-complete.json',{'state':'observations-complete','operationId':self.owner_id,'deploymentId':self.manifest['deploymentId'],'targetSha':self.manifest['targetSha'],'completeOuterSourceClosing':False,'upstreamTerminalAndLoaderClosureRequired':True,'nativeVisualVerdict':'opened-review-and58-scene-workflow-still-required'})\n            self.held.close();self.closed=True\n            if self.scope is not None:self.scope.__exit__(None,None,None);self.scope=None\n            self.emit({'state':'observations-complete','operationId':self.owner_id,'ownSourceDescriptorsClosed':True,'upstreamTerminalAndLoaderClosureRequired':True});return 0\n        except BaseException as error:\n            if self.started:self.park(error)\n"),
        (b"    return owner.run()\n\nif __name__=='__main__':raise SystemExit(main(sys.argv[1:]))\n",
         b"    return owner.run()\n\nif __name__=='__main__':\n    # The shared held loader passes exactly label + reviewed manifest digest.\n    # Return normally so its post-exec generation guard necessarily runs.\n    need(len(sys.argv)==3 and '@'in sys.argv[1],'explicit_held_loader_label')\n    route,manifest_path=sys.argv[1].split('@',1)\n    need(Path(manifest_path).is_absolute(),'absolute_reviewed_manifest')\n    main([route,manifest_path,sys.argv[2]])\n"),
    )
    fixed = before
    for old, new in replacements:
        if fixed.count(old) != 1:
            raise ValueError("native_packet_recipe_routing_unique_literal")
        fixed = fixed.replace(old, new, 1)
    compile(fixed, "<native-packet-uac-outer>", "exec")
    if hashlib.sha256(fixed).hexdigest() != ROUTING_PINS["current"]:
        raise ValueError("native_packet_recipe_routing_fixed_source")
    return fixed




OWNED_ACTOR_PINS = {'collector.native-before.source': {'fixture': 'namespace_timestamps/collector.native-before.source',
                                    'sha256': '81f3957f0985c49bb7d9752e63008e0a31c6bdb7be49e4eef29f10b4dbe9be20'},
 'collector.reporting-before.source': {'fixture': 'namespace_timestamps/collector.reporting-before.source',
                                       'sha256': '200bd3ad00041c7b4c9ab5f0079bb5f6de621af37c35ce54d39e3f105bec194d'},
 'wrapper.before.source': {'fixture': 'namespace_timestamps/wrapper.before.source',
                           'sha256': 'c1baa6c6c9a4fb6ae8f5e220298792d514ee54ff8808898f8d9971c7dc363d45'}}

def _owned_actor_source(name, replacements, expected):
    pin = OWNED_ACTOR_PINS[name]
    raw = (FIXTURES / pin["fixture"]).read_bytes()
    if _sha(raw) != pin["sha256"]:
        raise ValueError("native_packet_actor_before_source")
    for old, new in replacements:
        if raw.count(old) != 1:
            raise ValueError("native_packet_actor_unique_replacement")
        raw = raw.replace(old, new, 1)
    compile(raw, "<native-packet-owned-actor>", "exec")
    if _sha(raw) != expected:
        raise ValueError("native_packet_actor_current_source")
    return raw


def render_owned_actor_collector():
    """Derive the complete owned readonly source; preserve full observations."""
    replacements = ((b"COLLECTOR_ID='65f4ce7a-03fb-417d-ba01-f802b06bc7e7'",
      b"COLLECTOR_ID='29650277-5a0b-47f0-afa3-7f0695c983ea'"),
     (b"def stable_actor_identity(value):\n keys=('pid','uid','startTicks','exe','executableGeneratio"
      b"n','cmdlineBase64','cmdlineSha256','argvBytesBase64','requiredSourceAndRequestFds','socketFd"
      b"s','namespaces','processRoot')\n return {key:value[key]for key in keys}\n",
      b"def actor_identity_observation(value):\n keys=('pid','uid','startTicks','exe','executableGene"
      b"ration','cmdlineBase64','cmdlineSha256','argvBytesBase64','requiredSourceAndRequestFds','soc"
      b"ketFds','namespaces','processRoot')\n return {key:value[key]for key in keys}\n\ndef stable_acto"
      b"r_identity(value):\n projection=actor_identity_observation(value);namespaces=projection['name"
      b"spaces']\n if type(namespaces)is not dict or not namespaces:raise ValueError('collector_names"
      b"pace_projection_shape')\n projected={}\n for name,metadata in namespaces.items():\n  if type(me"
      b"tadata)is not dict or type(metadata.get('targetGeneration'))is not list or len(metadata['tar"
      b"getGeneration'])!=9:raise ValueError('collector_namespace_projection_shape')\n  projected[nam"
      b"e]={**metadata,'targetGeneration':metadata['targetGeneration'][:7]}\n projection['namespaces'"
      b']=projected\n return projection\n'),
     (b" result['actorStableProjectionDiff']=stable_projection_paths(stable_actor_identity(actor),st"
      b'able_actor_identity(actor_closing))\n',
      b" result['actorStableProjectionDiff']=stable_projection_paths(actor_identity_observation(acto"
      b"r),actor_identity_observation(actor_closing))\n result['actorIdentityProjectionDiff']=stable_"
      b'projection_paths(stable_actor_identity(actor),stable_actor_identity(actor_closing))\n'))
    return _owned_actor_source('collector.reporting-before.source', replacements, 'c8365ace8f9162837b4b6f393a90597a59fbfe1bf2728aaeda14ddabb9714a99')


def render_owned_actor_wrapper():
    """Derive the complete owned readonly source; preserve full observations."""
    replacements = ((b'def stable_projection_paths(opening,closing):\n',
      b"def actor_identity_observation(value):\n keys=('pid','uid','startTicks','exe','executableGene"
      b"ration','cmdlineBase64','cmdlineSha256','argvBytesBase64','requiredSourceAndRequestFds','soc"
      b"ketFds','namespaces','processRoot')\n return {key:value[key]for key in keys}\n\ndef stable_acto"
      b"r_identity(value):\n projection=actor_identity_observation(value);namespaces=projection['name"
      b"spaces']\n if type(namespaces)is not dict or not namespaces:raise ValueError('collector_names"
      b"pace_projection_shape')\n projected={}\n for name,metadata in namespaces.items():\n  if type(me"
      b"tadata)is not dict or type(metadata.get('targetGeneration'))is not list or len(metadata['tar"
      b"getGeneration'])!=9:raise ValueError('collector_namespace_projection_shape')\n  projected[nam"
      b"e]={**metadata,'targetGeneration':metadata['targetGeneration'][:7]}\n projection['namespaces'"
      b']=projected\n return projection\n\ndef stable_projection_paths(opening,closing):\n'),
     (b"  actor=result.get('actorOpening');closing_actor=result.get('actorClosing');keys=('pid','uid"
      b"','startTicks','exe','executableGeneration','cmdlineBase64','cmdlineSha256','argvBytesBase64"
      b"','requiredSourceAndRequestFds','socketFds','namespaces','processRoot')\n",
      b"  actor=result.get('actorOpening');closing_actor=result.get('actorClosing')\n"),
     (b'  opening_projection={key:actor[key]for key in keys};closing_projection={key:closing_actor[k'
      b'ey]for key in keys};diff=stable_projection_paths(opening_projection,closing_projection)\n  if'
      b" result.get('actorStableProjectionDiff')!=diff:raise ValueError('original_collector_projecti"
      b"on_diff_join')\n  if identity_qualified and(diff or opening_projection!=closing_projection):r"
      b"aise ValueError('original_collector_identity_unstable')\n  if closing_refused and(not diff or"
      b" opening_projection==closing_projection):raise ValueError('original_collector_refusal_withou"
      b"t_difference')\n",
      b'  opening_observation=actor_identity_observation(actor);closing_observation=actor_identity_o'
      b'bservation(closing_actor);diff=stable_projection_paths(opening_observation,closing_observati'
      b'on)\n  opening_projection=stable_actor_identity(actor);closing_projection=stable_actor_identi'
      b'ty(closing_actor);identity_diff=stable_projection_paths(opening_projection,closing_projectio'
      b"n)\n  if result.get('actorStableProjectionDiff')!=diff or result.get('actorIdentityProjection"
      b"Diff')!=identity_diff:raise ValueError('original_collector_projection_diff_join')\n  if ident"
      b'ity_qualified and(identity_diff or opening_projection!=closing_projection):raise ValueError('
      b"'original_collector_identity_unstable')\n  if closing_refused and(not identity_diff or openin"
      b"g_projection==closing_projection):raise ValueError('original_collector_refusal_without_diffe"
      b"rence')\n"),
     (b"'actorStableProjectionDiff':diff,'signalAuthorityGranted':False",
      b"'actorStableProjectionDiff':diff,'actorIdentityProjectionDiff':identity_diff,'signalAuthorit"
      b"yGranted':False"))
    return _owned_actor_source('wrapper.before.source', replacements, 'd535a9f02cf3893ff1a4cd44a896e943e15e8eee50a2f81d4fef54e5c884b171')


def render_qga_metadata_diagnostic():
    """Derive the whole diagnostic result mapping for the actual boot wrapper."""
    before = (FIXTURES / "diagnostic_result/diagnostic-body.before.source").read_bytes()
    if _sha(before) != "b076b5caacbeebc04e2b78e2ba27de5e026d6c04bf9666ea231eacf7ca5c2359":
        raise ValueError("native_packet_recipe_diagnostic_before")
    old = b"[pscustomobject]@{state='observed';query='qga-binary-metadata';"
    new = b"[ordered]@{state='observed';query='qga-binary-metadata';"
    if before.count(old) != 1:
        raise ValueError("native_packet_recipe_diagnostic_result_anchor")
    fixed = before.replace(old, new, 1)
    if _sha(fixed) != "ba72389db3e2dbddc8f5e3948c26f5cf1c884490983d3f524c2baa6333107cb8":
        raise ValueError("native_packet_recipe_diagnostic_result_source")
    return fixed


HOST_ASSET_OPERATOR_PINS = {
    "fixture": "host_asset_shadow/operator.before.source",
    "before": "115836dfac880948a1e1317975adb5c4edd25c32c398783e53813ad04e53477e",
    "current": "97e28e9a69724665288f4efd2ac075e5959ed0d2eefc942d0a9cdb0729b83fb2",
}


def render_host_asset_operator():
    """Preserve the metadata decoder's generation() helper through terminal custody."""
    before = (FIXTURES / HOST_ASSET_OPERATOR_PINS["fixture"]).read_bytes()
    if _sha(before) != HOST_ASSET_OPERATOR_PINS["before"]:
        raise ValueError("native_packet_host_asset_before")
    old = b"   generation=item['openingGeneration']"
    new = b"   file_generation=item['openingGeneration']"
    old_guard = b"type(generation)is not list or len(generation)!=9 or any(type(v)is not int for v in generation) or generation[6]"
    new_guard = b"type(file_generation)is not list or len(file_generation)!=9 or any(type(v)is not int for v in file_generation) or file_generation[6]"
    if before.count(old) != 1 or before.count(old_guard) != 1:
        raise ValueError("native_packet_host_asset_unique_rename")
    current = before.replace(old, new, 1).replace(old_guard, new_guard, 1)
    compile(current, "<native-packet-host-asset-operator>", "exec")
    functions = lambda raw: [ast.dump(node, include_attributes=False)
        for node in ast.parse(raw).body if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    if functions(before) != functions(current) or _sha(current) != HOST_ASSET_OPERATOR_PINS["current"]:
        raise ValueError("native_packet_host_asset_fixed_source")
    return current


SYSTEM_INTAKE_CALLER_PINS = {
    "fixture": "system_intake_caller/caller.before.source",
    "before": "495b28e31c71faba29e31cc61bd57c869f88f72cf5b1c32c7d102d6cdceddbc6",
    "current": "aa3b9c6d1928829a8bb703f1a9369c10a153cc43f42be4af999d7625122f6b7c",
}


def render_system_intake_caller():
    """Derive the complete caller with the reviewed module-name whitespace fix."""
    before = (FIXTURES / SYSTEM_INTAKE_CALLER_PINS["fixture"]).read_bytes()
    if _sha(before) != SYSTEM_INTAKE_CALLER_PINS["before"]:
        raise ValueError("native_packet_system_intake_before")
    old = b"decoder.__name__not in sys.modules"
    new = b"decoder.__name__ not in sys.modules"
    if before.count(old) != 1:
        raise ValueError("native_packet_system_intake_unique_space")
    current = before.replace(old, new, 1)
    compile(current, "<native-packet-system-intake-caller>", "exec")
    functions = lambda raw: [ast.dump(node, include_attributes=False)
        for node in ast.parse(raw).body if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    if functions(before) != functions(current) or _sha(current) != SYSTEM_INTAKE_CALLER_PINS["current"]:
        raise ValueError("native_packet_system_intake_fixed_source")
    return current


MSI_METADATA_BODY_PINS = {
    "fixture": "msi_metadata_rows/metadata-body.before.source",
    "before": "4eab4f008f2d23a87196f9893e8b35df96646201d852c6638448ba7523732de8",
    "current": "8b912c9c61edbaa39d52004fc467bc4595272f46a4226c1ed33d08add76a4618",
}


def render_msi_metadata_body():
    """Return the complete metadata body with method results excluded from rows."""
    before = (FIXTURES / MSI_METADATA_BODY_PINS["fixture"]).read_bytes()
    if _sha(before) != MSI_METADATA_BODY_PINS["before"]:
        raise ValueError("native_packet_msi_metadata_before")
    replacements = (
        (b"$view=$Database.OpenView($Query);$view.Execute()",
         b"$view=$Database.OpenView($Query);[void]$view.Execute()"),
        (b"if($null -ne $view){$view.Close();[void]",
         b"if($null -ne $view){[void]$view.Close();[void]"),
    )
    current = before
    for old, new in replacements:
        if current.count(old) != 1:
            raise ValueError("native_packet_msi_metadata_unique_method")
        current = current.replace(old, new, 1)
    if _sha(current) != MSI_METADATA_BODY_PINS["current"]:
        raise ValueError("native_packet_msi_metadata_fixed_source")
    return current


def render_metadata_disposition_caller():
    """Render the exact whole reviewed report correction; effect bodies stay whole."""
    raw = (FIXTURES / "metadata_disposition/caller.before.source").read_bytes()
    if _sha(raw) != "03ad7964d97e6166e22959c33fde336b9d06c9a14874187b795a302ca2333ee7":
        raise ValueError("metadata_disposition_authentic_before")
    old, new = b"'originalGuestPid':152,", b"'originalGuestPid':7820,"
    if raw.count(old) != 1:
        raise ValueError("metadata_disposition_unique_report_field")
    current = raw.replace(old, new, 1)
    compile(current, "<whole-metadata-disposition-caller>", "exec")
    if _sha(current) != "1132d6870e9d05da5b12e35f45e53200409f18f0bc66df13ed83e042c41fb5db":
        raise ValueError("metadata_disposition_exact_current")
    return current


def _production_root():
    for root in Path(__file__).resolve().parents:
        if (root / "agent_tools/ssh_program_execution.py").is_file():
            return root
    raise ValueError("native_packet_recipe_production_root")


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "getuid"),
    "requires POSIX descriptor operations",
)
class WindowsNativePacketRecipeTest(unittest.TestCase):
    def _pair(self, route):
        before = _before(route)
        fixed = render_operator(route)
        path = FIXTURES / "boundary.py"
        name = "_native_packet_recipe_boundary_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, path, loader=SourceFileLoader(name, str(path)))
        boundary = importlib.util.module_from_spec(spec)
        sys.modules[name] = boundary
        try:
            spec.loader.exec_module(boundary)
            with tempfile.TemporaryDirectory(prefix="native-packet-recipe-") as temporary:
                pair = boundary.run_pair(route, before, fixed, _production_root(), Path(temporary))
                red, green = pair["before"], pair["after"]
                self.assertIn("retained-api-native-requests-v2/manifest.private.json", red["error"]["message"])
                self.assertEqual((0, 0), (red["startCount"], red["collectCount"]))
                self.assertEqual([], red["apiCalls"])
                self.assertIsNone(green["error"])
                self.assertEqual((1, 2), (green["startCount"], green["collectCount"]))
                self.assertEqual(OPERATOR_PINS[route]["current"], green["operatorSha256"])
                self.assertTrue(green["productionRequestProofs"])
                self.assertIs(green["completeActualMcpClientNamespace"], route == "mcp")
                for receipt in (red, green):
                    self.assertTrue(receipt["allOwnDescriptorsClosed"])
                    self.assertTrue(receipt["allInputsAndSyntheticLedgerUnchanged"])
                    self.assertTrue(receipt["noFunctionReplacement"])
                    self.assertTrue(receipt["noSourceRewrite"])
        finally:
            sys.modules.pop(name, None)

    def test_direct_manifest_path_causal_whole_entry(self):
        self._pair("direct")

    def test_mcp_manifest_path_causal_whole_entry(self):
        self._pair("mcp")

    def test_mcp_named_source_replacement_requires_loader_closing_guard(self):
        before = (FIXTURES / LOADER_PINS["fixture"]).read_bytes()
        fixed = render_loader()
        path = FIXTURES / "boundary.py"
        name = "_native_packet_closing_boundary_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, path, loader=SourceFileLoader(name, str(path)))
        boundary = importlib.util.module_from_spec(spec)
        sys.modules[name] = boundary
        try:
            spec.loader.exec_module(boundary)
            with tempfile.TemporaryDirectory(prefix="native-packet-closing-") as temporary:
                pair = boundary.run_loader_closing_pair(before, fixed,
                    render_operator("direct"), render_operator("mcp"),
                    _production_root(), Path(temporary))
                red, green = pair["before"], pair["after"]
                self.assertIsNone(red["error"], "authentic old loader must expose accepted RED")
                self.assertIn("operator_source_changed", green["error"]["message"])
                for receipt in (red, green):
                    self.assertEqual((1, 2), (receipt["startCount"], receipt["collectCount"]))
                    proof = receipt["physicalSelfReplacement"]
                    self.assertTrue(proof["sameBytes"])
                    self.assertNotEqual(proof["heldInode"], proof["namedInode"])
                    self.assertTrue(receipt["allOwnDescriptorsClosed"])
                    self.assertTrue(receipt["allInputsAndSyntheticLedgerUnchanged"])
                    self.assertTrue(receipt["completeActualMcpClientNamespace"])
            # The authentic later d03 getter still skips normal post-exec
            # guards when the unchanged whole entry raises SystemExit(0).
            systemexit_before = (FIXTURES / LOADER_PINS["systemExitFixture"]).read_bytes()
            self.assertEqual(LOADER_PINS["systemExitBefore"], _sha(systemexit_before))
            with tempfile.TemporaryDirectory(prefix="native-packet-systemexit-") as temporary:
                root = Path(temporary)
                red_root = root / "before"; red_root.mkdir()
                green_root = root / "after"; green_root.mkdir()
                red = boundary.run_loader_systemexit_case(systemexit_before, red_root, "replacement")
                green = boundary.run_loader_systemexit_case(fixed, green_root, "replacement")
                self.assertEqual(("SystemExit", 0), (red["error"]["class"], red["error"]["code"]))
                self.assertEqual("operator_source_changed", green["error"]["message"])
                self.assertEqual("SystemExit", green["error"]["contextClass"])
                for receipt in (red, green):
                    self.assertTrue(receipt["pathReplaced"])
                    self.assertTrue(receipt["sameByteSource"])
                    self.assertTrue(receipt["allOwnDescriptorsClosed"])
                    self.assertTrue(receipt["completeSavedNamespaces"])
                    self.assertEqual(0, receipt["actualSDKInvocations"])
                argv = boundary.run_loader_systemexit_case(fixed, green_root, "three-argv")
                self.assertEqual(("SystemExit", 0), (argv["error"]["class"], argv["error"]["code"]))
                self.assertTrue(argv["closingHashRan"])
                self.assertTrue(argv["allOwnDescriptorsClosed"])
                self.assertEqual(["connection-direct-channel-prepare", "new-channel-prepare", "owned-identity.json"],
                                 argv["receivedEntryArguments"])
        finally:
            sys.modules.pop(name, None)


    def test_pending_prefix_fifo_replacement_is_nonblocking_and_refused(self):
        before = (FIXTURES / PREFIX_PINS["fixture"]).read_bytes()
        fixed = render_pending_prefix()
        self.assertEqual(fixed, (FIXTURES / "fifo/pending-prefix.current.source").read_bytes())
        path = FIXTURES / "fifo/boundary.py"
        name = "_native_packet_fifo_boundary_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, path,
            loader=SourceFileLoader(name, str(path)))
        boundary = importlib.util.module_from_spec(spec)
        sys.modules[name] = boundary
        try:
            spec.loader.exec_module(boundary)
            with tempfile.TemporaryDirectory(prefix="native-packet-fifo-") as temporary:
                pair = boundary.run_fifo_pair(before, fixed, Path(temporary))
                red, green = pair["before"], pair["after"]
                self.assertEqual((1, 1, 0, 0),
                    (red["testsRun"], red["failures"], red["errors"], red["skipped"]))
                self.assertIn("actual FIFO open required an external writer to unblock", red["output"])
                self.assertEqual((1, 0, 0, 0),
                    (green["testsRun"], green["failures"], green["errors"], green["skipped"]))
                self.assertTrue(red["proof"]["writerNeeded"])
                self.assertTrue(red["proof"]["writerOpened"])
                self.assertIs(red["proof"]["afterOpenBeforeWriterRelease"], False)
                self.assertFalse(green["proof"]["writerNeeded"])
                self.assertFalse(green["proof"]["writerOpened"])
                self.assertEqual(PREFIX_PINS["current"], green["prefixSha256"])
                for receipt in (red, green):
                    proof = receipt["proof"]
                    self.assertTrue(proof["workerJoined"])
                    self.assertEqual(proof["openedDescriptors"], proof["closedDescriptors"])
                    self.assertEqual(["PrefixError"], proof["outcomeTypes"])
                    self.assertTrue(receipt["completeNormallyRegisteredPrefix"])
                    self.assertTrue(receipt["completeNormallyRegisteredQualifier"])
                    self.assertTrue(receipt["sourcesUnchanged"])
                    self.assertTrue(receipt["noFunctionReplacement"])
                    self.assertTrue(receipt["noInjectedModuleGlobals"])
        finally:
            sys.modules.pop(name, None)


    def test_uac_receipt_routing_preserves_original_terminal_wait(self):
        path = FIXTURES / "routing/boundary.py"
        name = "_native_packet_routing_boundary_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, path,
            loader=SourceFileLoader(name, str(path)))
        boundary = importlib.util.module_from_spec(spec)
        sys.modules[name] = boundary
        try:
            spec.loader.exec_module(boundary)
            current = render_uac_outer_operator()
            self.assertEqual(current, (FIXTURES / "routing/operator.current.source").read_bytes())
            # A managed test worker may already cache the canonical guest fixture.
            # Exercise a cold import explicitly so that cache cannot mask leakage
            # from a prior staged tree; also preserve a pre-existing alias case.
            original_path = list(sys.path)
            def restore_import_path():
                sys.path[:] = original_path
            self.addCleanup(restore_import_path)
            sys.path.insert(0, str(_production_root()))
            parents = [importlib.import_module(package) for package in ("agent_tools", "agent_tools.tests")]
            missing = object()
            aliases = (("agent_tools.windows_vm_guest", parents[0], "windows_vm_guest"),
                       ("agent_tools.tests.test_windows_vm_guest", parents[1], "test_windows_vm_guest"))
            def alias_state():
                return [(name, parent, key, sys.modules.get(name, missing), vars(parent).get(key, missing))
                        for name, parent, key in aliases]
            def restore_aliases(state):
                for name, parent, key, module, attribute in state:
                    if module is missing:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = module
                    if attribute is missing:
                        vars(parent).pop(key, None)
                    else:
                        setattr(parent, key, attribute)
            original_aliases = alias_state()
            self.addCleanup(restore_aliases, original_aliases)
            for cache, variant in (("cold", "normal"), ("cold", "stdout-eof"),
                                   ("cold", "dual-eof"), ("preexisting", "normal")):
                if cache == "cold":
                    for alias_name, parent, key in aliases:
                        sys.modules.pop(alias_name, None)
                        vars(parent).pop(key, None)
                else:
                    restore_aliases(original_aliases)
                    importlib.import_module("agent_tools.tests.test_windows_vm_guest")
                expected_aliases = alias_state()
                with self.subTest(cache=cache, variant=variant), tempfile.TemporaryDirectory(prefix="native-packet-routing-") as temporary:
                    fixture = ROUTING_PINS["fixture" if variant == "normal" else "eofBeforeFixture"]
                    before = (FIXTURES / fixture).read_bytes()
                    pair = boundary.run_routing_pair(before, current, variant, _production_root(), Path(temporary))
                    red, green = pair["before"], pair["after"]
                    self.assertEqual(1, red["exitCode"])
                    self.assertEqual(0, green["exitCode"])
                    self.assertIn("Ran 1 test", red["output"])
                    self.assertIn("FAILED (failures=1)", red["output"])
                    self.assertIn("Ran 1 test", green["output"])
                    self.assertEqual("terminal EOF is outside the pending-prefix reader", red["report"]["latchedError"]["reason"])
                    self.assertIsNone(green["report"]["latchedError"])
                    self.assertTrue(green["report"]["ownSourceClosing"])
                    self.assertEqual(8, green["report"]["liveFreshQueryCount"])
                    for receipt in (red, green):
                        self.assertIsNone(receipt["error"])
                        self.assertTrue(receipt["completeNormallyRegisteredNamespaces"])
                        self.assertTrue(receipt["originalConstructorUnchanged"])
                        self.assertTrue(receipt["sourcesUnchanged"])
                        self.assertEqual(receipt["ownedTestCleanupDescriptors"], receipt["ownedTestCleanupClosedDescriptors"])
                        self.assertTrue(receipt["allOwnedFixtureListenersClosed"])
                        self.assertEqual(0, receipt["actualSocketCalls"])
                    for alias, parent, key, module, attribute in expected_aliases:
                        self.assertIs(sys.modules.get(alias, missing), module,
                                      "Routing changed its caller's module-cache slot")
                        self.assertIs(vars(parent).get(key, missing), attribute,
                                      "Routing changed its caller's parent-package binding")
        finally:
            sys.modules.pop(name, None)


    def test_host_asset_decoder_preserves_generation_helper_whole_entry(self):
        path = FIXTURES / "host_asset_shadow/boundary.py"
        name = "_native_packet_host_asset_shadow_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, path,
            loader=SourceFileLoader(name, str(path)))
        boundary = importlib.util.module_from_spec(spec)
        sys.modules[name] = boundary
        try:
            spec.loader.exec_module(boundary)
            before = (FIXTURES / HOST_ASSET_OPERATOR_PINS["fixture"]).read_bytes()
            current = render_host_asset_operator()
            with tempfile.TemporaryDirectory(prefix="native-packet-host-asset-") as temporary:
                pair = boundary.run_shadow_pair(before, current, render_loader(),
                    _production_root(), Path(temporary))
                red, green = pair["before"], pair["after"]
                self.assertIs(red["positiveOraclePassed"], False)
                self.assertEqual("TypeError", red["error"]["class"])
                self.assertEqual("'list' object is not callable", red["error"]["message"])
                self.assertEqual(1, len(red["leakedOwnedVirtualDescriptors"]))
                self.assertFalse(red["allOwnDescriptorsClosed"])
                self.assertIsNone(green["error"])
                self.assertEqual((1, 2), (green["startCount"], green["collectCount"]))
                self.assertTrue(green["allOwnDescriptorsClosed"])
                self.assertTrue(pair["samePositiveOracle"])
                self.assertFalse(pair["nativeOrNetworkActions"])
                self.assertEqual(HOST_ASSET_OPERATOR_PINS["before"], red["sourceSha256"])
                self.assertEqual(HOST_ASSET_OPERATOR_PINS["current"], green["operatorSha256"])
                self.assertTrue(red["productionRequestProofs"])
                self.assertTrue(green["productionRequestProofs"])
                self.assertEqual(3, len(pair["controls"]))
                for control in pair["controls"]:
                    self.assertTrue(control["allOwnDescriptorsClosed"])
                    self.assertTrue(control["allInputsAndSyntheticLedgerUnchanged"])
        finally:
            sys.modules.pop(name, None)

    def test_system_intake_module_name_space_causal_whole_caller(self):
        module_prefixes = ("_initial_system_intake_decoder_", "_private_initial_system_emitter_")
        prior_modules = {key: value for key, value in sys.modules.items() if key.startswith(module_prefixes)}
        path = FIXTURES / "system_intake_caller/boundary.py"
        name = "_native_packet_system_intake_lexical_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, path,
            loader=SourceFileLoader(name, str(path)))
        boundary = importlib.util.module_from_spec(spec)
        sys.modules[name] = boundary
        try:
            spec.loader.exec_module(boundary)
            before = (FIXTURES / SYSTEM_INTAKE_CALLER_PINS["fixture"]).read_bytes()
            current = render_system_intake_caller()
            with tempfile.TemporaryDirectory(prefix="native-packet-system-intake-") as temporary:
                pair = boundary.run_lexical_pair(before, current, Path(temporary))
                red, green, unknown = pair["before"], pair["after"], pair["unknown"]
                self.assertFalse(red["samePositiveOraclePassed"])
                self.assertEqual("AttributeError", red["originalFailure"]["class"])
                self.assertIn("has no attribute '__name__not'", red["originalFailure"]["message"])
                self.assertEqual(0, red["guestExecCount"])
                self.assertTrue(green["samePositiveOraclePassed"])
                self.assertIsNone(green["error"])
                self.assertEqual(1, green["guestExecCount"])
                self.assertEqual(1, green["decoderRegisteredWholeModuleCalls"]["<module>"])
                self.assertEqual(1, green["decoderRegisteredWholeModuleCalls"]["decode_result"])
                self.assertIn("retained_rpc_deadline", unknown["originalFailure"]["message"])
                self.assertEqual(1, unknown["guestExecCount"])
                self.assertTrue(unknown["retainedOriginalHostDescriptors"])
                self.assertEqual(unknown["outboundFrames"], unknown["outboundFramesAtUnknown"])
                self.assertTrue(pair["allOriginalFixtureBytesUnchanged"])
                self.assertTrue(pair["moduleAliasesAndImportPathRestored"])
                self.assertEqual(prior_modules, {key: value for key, value in sys.modules.items()
                                                if key.startswith(module_prefixes)})
                self.assertFalse(pair["nativeOrNetworkActions"])
        finally:
            sys.modules.pop(name, None)

    def test_owned_actor_namespace_timestamps_preserve_identity(self):
        path = FIXTURES / "namespace_timestamps/boundary.py"
        name = "_native_packet_namespace_boundary_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, path,
            loader=SourceFileLoader(name, str(path)))
        boundary = importlib.util.module_from_spec(spec)
        sys.modules[name] = boundary
        try:
            spec.loader.exec_module(boundary)
            before = (FIXTURES / OWNED_ACTOR_PINS["collector.native-before.source"]["fixture"]).read_bytes()
            current = render_owned_actor_collector()
            with tempfile.TemporaryDirectory(prefix="native-packet-namespace-") as temporary:
                pair = boundary.run_namespace_pair(before, current, Path(temporary))
                red, green = pair["before"], pair["after"]
                self.assertEqual(1, red["exitCode"])
                self.assertIn("collector_actor_closing_changed", red["stderr"])
                self.assertEqual(0, green["exitCode"], green["stderr"])
                self.assertEqual(9, green["result"]["caseCount"])
                self.assertTrue(green["result"]["samePositiveOracle"])
                self.assertEqual(18, green["result"]["rawNamespaceTimestampDifferenceCount"])
                self.assertEqual(8, green["result"]["structuralRefusalCount"])
                self.assertEqual(OWNED_ACTOR_PINS["collector.native-before.source"]["sha256"], red["sourceSha256"])
                self.assertEqual("c8365ace8f9162837b4b6f393a90597a59fbfe1bf2728aaeda14ddabb9714a99", green["sourceSha256"])
                for outcome in (red, green):
                    self.assertTrue(outcome["sourcesUnchanged"])
                    self.assertTrue(outcome["normallyRegisteredCompleteQualifier"])
                    self.assertTrue(outcome["noSourceOrFunctionReplacement"])
                    self.assertFalse(outcome["nativeOrNetworkActions"])
            with tempfile.TemporaryDirectory(prefix="native-packet-retained-refusal-") as temporary:
                pair = boundary.run_retained_refusal_pair(before, current, Path(temporary))
                red, green = pair["before"], pair["after"]
                self.assertEqual(1, red["exitCode"])
                self.assertIn("refusal must retain actorClosing", red["stderr"])
                self.assertEqual(0, green["exitCode"], green["stderr"])
                self.assertTrue(green["result"]["sameRetainedRefusalOracle"])
                self.assertTrue(green["result"]["actorOpeningAndClosingRetained"])
                self.assertGreater(green["result"]["rawProjectionDifferenceCount"], 0)
                self.assertGreater(green["result"]["identityProjectionDifferenceCount"], 0)
                for outcome in (red, green):
                    self.assertTrue(outcome["sourcesUnchanged"])
                    self.assertTrue(outcome["normallyRegisteredCompleteQualifier"])
                    self.assertTrue(outcome["noSourceOrFunctionReplacement"])
                    self.assertFalse(outcome["nativeOrNetworkActions"])
            disposition_path = FIXTURES / "metadata_disposition/boundary.py"
            disposition_name = "_native_metadata_disposition_" + uuid.uuid4().hex
            disposition_spec = importlib.util.spec_from_file_location(disposition_name,
                disposition_path, loader=SourceFileLoader(disposition_name, str(disposition_path)))
            disposition = importlib.util.module_from_spec(disposition_spec)
            sys.modules[disposition_name] = disposition
            try:
                disposition_spec.loader.exec_module(disposition)
                with tempfile.TemporaryDirectory(prefix="native-metadata-disposition-") as temporary:
                    pair = disposition.run_disposition_pair(render_metadata_disposition_caller(),
                        _production_root(), Path(temporary))
                    red, green = pair["before"], pair["after"]
                    self.assertEqual(1, red["exitCode"])
                    self.assertFalse(red["sameOriginalPositiveOraclePassed"])
                    self.assertEqual("AssertionError", red["error"]["class"])
                    self.assertEqual(0, green["exitCode"])
                    self.assertTrue(green["sameOriginalPositiveOraclePassed"])
                    self.assertIsNone(green["error"])
                    self.assertTrue(pair["sameOriginalPositiveOracle"])
                    self.assertTrue(pair["completeAuthenticCallers"])
                    self.assertTrue(pair["allOriginalFixtureBytesUnchanged"])
                    self.assertFalse(pair["nativeOrNetworkActions"])
                    for outcome in (red, green):
                        self.assertEqual(outcome["sourceDescriptorsOpened"], outcome["sourceDescriptorsClosed"])
                        for flag in ("sourcesUnchanged", "naturalExit", "streamsEof",
                                     "noCallerOrOracleFunctionReplacement", "onlyTopLevelOwnedPathRoleRelocated"):
                            self.assertTrue(outcome[flag])
                        self.assertEqual(1, outcome["registeredWholeQualifierCalls"]["main"])
                        self.assertEqual(1, outcome["registeredWholeQualifierCalls"]["<module>"])
                        original = outcome["completeOriginalCaller"]
                        self.assertTrue(original["completeNamespace"])
                        self.assertFalse(original["postExecFunctionReplacement"])
                        self.assertTrue(original["originalFilesUnchanged"])
                        self.assertIsNone(original["originalFailure"])
                        self.assertIsNone(original["error"])
                        self.assertEqual(1, len(original["signals"]))
                        self.assertEqual(1, len(original["pidfdCalls"]))
                        self.assertEqual([], original["retainedDescriptors"])
                        self.assertFalse(original["realSignalsOrProcessNetworkApiActions"])
            finally:
                sys.modules.pop(disposition_name, None)
        finally:
            sys.modules.pop(name, None)



class DiagnosticResultContainerPowerShellTest(unittest.TestCase):
    """Real PowerShell body/object boundary; complete native bootstrap stays separate."""

    def test_complete_diagnostic_body_accepts_actual_generated_actor_properties(self):
        import json
        import os
        import shutil
        executable = (os.environ.get("VPN_CONTROL_TEST_POWERSHELL")
                      or (shutil.which("powershell.exe") if os.name == "nt" else None)
                      or shutil.which("pwsh"))
        if executable is None:
            self.skipTest("PowerShell runtime unavailable; complete Windows native scenario is separate")
        directory = FIXTURES / "diagnostic_result"
        path = directory / "object_boundary.py"
        name = "_diagnostic_real_object_boundary_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, path,
            loader=SourceFileLoader(name, str(path)))
        boundary = importlib.util.module_from_spec(spec)
        sys.modules[name] = boundary
        try:
            spec.loader.exec_module(boundary)
            before = (directory / "diagnostic-body.before.source").read_bytes()
            after = render_qga_metadata_diagnostic()
            with tempfile.TemporaryDirectory(prefix="diagnostic-object-") as temporary:
                pair = boundary.run_diagnostic_object_pair(before, after,
                    (_production_root() / "agent_tools/windows_artifact_transfer.py").read_bytes(),
                    (directory / "diagnostic-draft.native-before.ps1.source").read_bytes(),
                    json.loads((directory / "actual-guest-context.json").read_bytes()),
                    Path(temporary), executable)
                self.assertEqual(1, pair["before"]["exitCode"])
                self.assertIn("bootstrapOpening", pair["before"]["stderr"])
                self.assertIn("SetValueInvocationException", pair["before"]["stderr"])
                self.assertEqual(0, pair["after"]["exitCode"], pair["after"]["stderr"])
                result = pair["after"]["result"]
                self.assertTrue(result["completeBodyExecuted"])
                self.assertTrue(result["actualGeneratedAssignmentsExecuted"])
                self.assertTrue(result["realObjectFileProcessSemantics"])
                self.assertTrue(result["declaredCimPeerOnlyOwnChild"])
                self.assertFalse(result["foreignProcessOrServiceQueried"])
                self.assertFalse(result["bootstrapGuardsExecuted"])
                self.assertEqual(1, result["peerProcessCalls"])
                self.assertEqual(1, result["peerServiceCalls"])
                self.assertEqual(1, result["ownImageFileObserved"])
                self.assertEqual("System.Management.Automation.PSCustomObject", result["resultType"])
                for key in ("bootstrapOpening", "bootstrapClosing", "guestBootClosing", "bootstrapActorClosing"):
                    self.assertIn(key, result["propertyNames"])
                self.assertEqual(pair["before"]["actualGeneratedAssignmentSha256"],
                                 pair["after"]["actualGeneratedAssignmentSha256"])
                for outcome in pair.values():
                    self.assertTrue(outcome["sourcesUnchanged"])
                    self.assertTrue(outcome["naturalExit"])
                    self.assertFalse(outcome["bootstrapGuardsExecuted"])
        finally:
            sys.modules.pop(name, None)

    def test_complete_msi_metadata_recipe_suppresses_com_method_success_values(self):
        import os
        import shutil
        executable = (os.environ.get("VPN_CONTROL_TEST_POWERSHELL")
                      or (shutil.which("powershell.exe") if os.name == "nt" else None)
                      or shutil.which("pwsh"))
        if executable is None:
            self.skipTest("PowerShell runtime unavailable; complete Windows native scenario is separate")
        directory = FIXTURES / "msi_metadata_rows"
        path = directory / "boundary.py"
        name = "_msi_metadata_rows_portable_boundary_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, path,
            loader=SourceFileLoader(name, str(path)))
        boundary = importlib.util.module_from_spec(spec)
        sys.modules[name] = boundary
        try:
            spec.loader.exec_module(boundary)
            before = (directory / "metadata-body.before.source").read_bytes()
            current = render_msi_metadata_body()
            self.assertEqual(len(before) + 12, len(current))
            with tempfile.TemporaryDirectory(prefix="msi-metadata-rows-") as temporary:
                pair = boundary.run_rows_pair(before, current, Path(temporary), executable)
            self.assertEqual(1, pair["before"]["exitCode"])
            self.assertEqual(24, pair["before"]["matrix"]["oracleFailures"])
            self.assertEqual(4, sum(case["ok"] for case in pair["before"]["matrix"]["cases"]))
            self.assertEqual(0, pair["after"]["exitCode"])
            self.assertEqual(0, pair["after"]["matrix"]["oracleFailures"])
            self.assertEqual(28, sum(case["ok"] for case in pair["after"]["matrix"]["cases"]))
            for outcome in pair.values():
                self.assertEqual(28, len(outcome["matrix"]["cases"]))
                for flag in ("sourcesUnchanged", "naturalExit", "streamsEof", "portableCauseWitness"):
                    self.assertTrue(outcome[flag])
                for flag in ("actualMsiComAbiQualified", "windowsBootstrapGuardsExecuted", "nativeOrNetworkActions"):
                    self.assertFalse(outcome[flag])
        finally:
            sys.modules.pop(name, None)



if __name__ == "__main__":
    unittest.main()
