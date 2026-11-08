"""Readiness adapter for trusted SSH routes; no VM or job lifecycle effects.

Observers and transport builders stay effect free. Reconnect owns separate
connection identities and never replaces a job, edits inventory, or removes a
canonical socket. Existing uncertain connection intents remain observation only.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import subprocess
import stat
import time

from . import private_inventory_lock as private
from . import readiness
from . import readiness_ssh_master as master
from . import ssh_channel_selection as selection
from . import ssh_connection_session as session
from . import ssh_direct_nested_channel as direct
from . import ssh_fresh_nested_channel as channel
from . import readiness_nested_channel as nested_ready
from . import ssh_transport as transport

PROBE = r'''import json,os,pwd,subprocess,sys
from pathlib import Path
entry=pwd.getpwuid(os.geteuid())
if sys.platform.startswith('linux'):boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
elif sys.platform=='darwin':boot=subprocess.check_output(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],text=True,timeout=3).strip().lower()
else:raise SystemExit(3)
print(json.dumps({'boot':boot,'uid':os.geteuid(),'principal':entry.pw_name,'home':entry.pw_dir,'connection':os.environ.get('SSH_CONNECTION')},sort_keys=True))
'''
PROBE_COMMAND = ('python3', '-I', '-B', '-c', 'exec(' + repr(PROBE) + ')')
# Exact status of a correlation with no channel intent in any namespace.
_INTENT_ABSENT = {'state': 'unknown', 'nativeActionAllowed': False, 'replayAllowed': False, 'reason': 'intent_absent'}
_PREDECESSOR_FIELDS = {'state', 'correlationId', 'receiptSha256', 'proof', 'originalHistoryPreserved', 'replayAllowed'}


def _bounded(argv, deadline):
    """Read-only child with complete bounded streams; overflow is never ready."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')})
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    overflow = False
    with selectors.DefaultSelector() as selector:
        for name in streams:
            pipe = getattr(process, name); os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map() and time.monotonic() < deadline:
            for key, _ in selector.select(min(.05, max(0, deadline-time.monotonic()))):
                block = os.read(key.fileobj.fileno(), 4096)
                if not block:
                    selector.unregister(key.fileobj); continue
                if len(streams[key.data])+len(block) > 8192:
                    overflow = True
                streams[key.data].extend(block[:max(0,8192-len(streams[key.data]))])
        complete = not selector.get_map()
    if not complete:
        # This fixed probe has no remote mutation. Stop only its owned local SSH
        # observer, never a master, VM, runtime or original application job.
        process.terminate()
    try:
        code = process.wait(timeout=max(.1, min(1, deadline-time.monotonic())))
    except subprocess.TimeoutExpired:
        return {'complete': False, 'overflow': overflow, 'returnCode': None, **{k:bytes(v)for k,v in streams.items()}}
    finally:
        process.stdout.close(); process.stderr.close()
    return {'complete': complete, 'overflow': overflow, 'returnCode': code, **{k:bytes(v)for k,v in streams.items()}}


def _failure(result):
    if result['overflow']:
        raise readiness.AdapterBlocked('connection_outcome_unknown')
    if not result['complete']:
        return 'unavailable'
    output = (result['stdout']+result['stderr']).lower()
    if b'host key verification failed' in output or b'remote host identification has changed' in output:
        raise readiness.AdapterBlocked('trust_mismatch')
    if any(word in output for word in (b'connection refused', b'no route to host', b'connection timed out',
                                      b'network is unreachable', b'could not resolve hostname', b'connection closed',
                                      b'broken pipe',b'connection reset by peer')):
        return 'unavailable'
    if b'permission denied' in output or b'authentication failed' in output:
        raise readiness.AdapterBlocked('authentication_rejected')
    raise readiness.AdapterBlocked('connection_outcome_unknown')


def _private_directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    with private.Directory(path):
        if path.stat().st_mode & 0o077:
            raise readiness.AdapterBlocked('ownership_mismatch')
    return path


class TransportAdapter:
    capabilities = frozenset({'reconnect'})

    def __init__(self, root, host):
        self.root = Path(root).resolve(strict=True)
        self.host = host
        self._unavailable=None
        self._nested_drift=None
        try:
            config = transport.load_config(self.root)
            if host not in config.hosts:
                raise ValueError('unknown_host')
            self.machine = master.identity(config, host)
        except (OSError, ValueError, KeyError, TypeError):
            raise readiness.AdapterBlocked('integrity_mismatch') from None

    def _config(self):
        try:
            config = transport.load_config(self.root)
            if master.identity(config, self.host) != self.machine:
                raise readiness.AdapterBlocked('machine_identity_mismatch')
            return config
        except readiness.AdapterBlocked:
            raise
        except (OSError, ValueError, KeyError, TypeError):
            raise readiness.AdapterBlocked('integrity_mismatch') from None

    def _base(self, **values):
        return readiness.Observation(target=self.host, machine=self.machine,
            trusted=True, integrity=True, **values)

    def _anchor(self, config):
        candidates = [entry for entry in transport._route_hosts(config.hosts,self.host)
                      if entry.remote_control_path is not None]
        return candidates[-1] if candidates else None

    def _nested_state(self, config, anchor, deadline):
        # The configured legacy socket is observed; it is never repaired,
        # removed, adopted, or used as the new channel's socket pathname.
        command = ['ssh']
        if anchor.remote_config_file is not None:
            command += ['-F', str(anchor.remote_config_file)]
        command += ['-S', str(anchor.remote_control_path), '-O', 'check', anchor.remote_host_alias]
        result = _bounded(transport.build_ssh_argv(config, anchor.gateway, 10, tuple(command)), deadline)
        if result['complete'] and not result['overflow'] and result['returnCode'] == 0 and not result['stdout'] and re.fullmatch(rb'Master running \(pid=[1-9][0-9]*\)\r?\n',result['stderr']):
            return 'ready'
        expected = ('Control socket connect('+str(anchor.remote_control_path)+'): ').encode()
        if result['complete'] and not result['overflow'] and result['returnCode'] == 255 and not result['stdout'] and result['stderr'] in tuple(expected+suffix+ending for suffix in (b'No such file or directory',b'Connection refused') for ending in (b'\n',b'\r\n')):
            return 'dead'
        return _failure(result)

    def observe(self, requirements, deadline):
        config = self._config()
        target = config.hosts[self.host]
        if not requirements.required or 'disconnected' in requirements.intentional_states:
            return self._base(transport='unknown')
        if time.monotonic() >= deadline:
            return self._base(transport='unavailable')
        connection_owner = None
        qualified_route = None
        try:
            if target.transport == 'direct':
                if target.password is not None:
                    raise readiness.AdapterBlocked('provider_unavailable')
                owner = master.status(self.root, self.host, config)
                if owner['state'] == 'absent':
                    return self._base(transport='unavailable')
                if owner['state'] == 'dead':
                    return self._base(transport='dead')
                if owner['state']=='starting':
                    return self._base(transport='unavailable')
                if owner['state'] != 'ready':
                    raise readiness.AdapterBlocked('connection_outcome_unknown')
                connection_owner = owner['recoveryId']
            else:
                anchor = self._anchor(config)
                if anchor is None:
                    raise readiness.AdapterBlocked('provider_unavailable')
                if nested_ready.present(self.root,anchor.alias):
                    qualified_route=nested_ready.qualified_route(self.root,anchor.alias,config,deadline)
                    metadata=nested_ready.source_options(qualified_route,self.root,anchor.alias,config)
                    connection_owner=metadata['correlationId']
                elif not selection.selection_present(self.root, anchor.alias):
                    state = self._nested_state(config, anchor, deadline)
                    if state != 'ready':
                        return self._base(transport=state)
                else:
                    metadata = selection.selected_route_options(self.root, anchor.alias, config)
                    connection_owner = metadata['correlationId']
            with transport._qualified_route_scope(qualified_route)if qualified_route is not None else __import__('contextlib').nullcontext():
                argv = transport.build_ssh_argv(config,self.host,min(10,max(1,int(deadline-time.monotonic()))),PROBE_COMMAND)
        except readiness.AdapterBlocked:
            raise
        except nested_ready.NestedEnded:
            return self._base(transport='expired')
        except nested_ready.DirectoryMembershipChanged as proof:
            self._nested_drift=proof
            return self._base(transport='unavailable')
        except master.MasterUnknown as error:
            if str(error)=='master_socket_owner_unresolved':return self._base(transport='unavailable')
            raise readiness.AdapterBlocked('connection_generation_changed')from None
        except nested_ready.NestedIntegrityChanged:
            raise readiness.AdapterBlocked('integrity_mismatch') from None
        except nested_ready.NestedUnknown as error:
            # An exhausted observation budget is not a changed generation.
            if str(error) == 'nested_original_deadline':
                return self._base(transport='unavailable')
            raise readiness.AdapterBlocked('connection_generation_changed') from None
        except (selection.SelectionUnknown, transport.SshConfigError):
            raise readiness.AdapterBlocked('connection_generation_changed') from None
        result = _bounded(argv, min(deadline,time.monotonic()+10))
        if result['returnCode'] != 0 or result['overflow'] or not result['complete']:
            state=_failure(result)
            if target.transport=='direct' and state=='unavailable':
                self._unavailable=master.UnavailableProof(owner['recoveryId'],owner['child']['actor'],
                                                         tuple(owner['ready']['socketFingerprint']))
            return self._base(transport=state)
        try:
            if result['stderr']:
                raise ValueError('probe_stderr')
            value = json.loads(result['stdout'], object_pairs_hook=transport._reject_duplicate_keys)
            if set(value) != {'boot','uid','principal','home','connection'}:
                raise ValueError('probe_schema')
            if type(value['boot']) is not str or re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot']) is None:
                raise readiness.AdapterBlocked('boot_identity_unavailable')
            if type(value['uid']) is not int or value['uid'] < 0 or value['principal'] != target.user:
                raise readiness.AdapterBlocked('wrong_account')
            if type(value['connection']) is not str or len(value['connection'].split()) != 4:
                raise ValueError('probe_connection')
            connection = hashlib.sha256(json.dumps([connection_owner,value['connection']],separators=(',',':')).encode()).hexdigest()
            self._config()  # Exact target/trust generation again after capture.
            if qualified_route is not None:
                nested_ready.source_options(qualified_route,self.root,self.host,config)
                self._qualified_route=(qualified_route,connection)
            return self._base(connection=connection,boot=value['boot'],account=str(value['uid'])+':'+value['principal'],
                              transport='ready',guest='running')
        except readiness.AdapterBlocked:
            raise
        except (ValueError, KeyError, TypeError):
            raise readiness.AdapterBlocked('connection_outcome_unknown') from None

    def _campaign(self, anchor):
        # The original unversioned transport campaign is immutable history.
        # A new independently owned connection never relabels its outcome.
        for path in (self.root/'.rag_index',self.root/'.rag_index/readiness-transport-v2'):
            _private_directory(path)
        return _private_directory(self.root/'.rag_index/readiness-transport-v2'/anchor)

    @contextmanager
    def _campaign_sources(self):
        from .native_review_source_closure import _Held
        held=_Held();bodies={};pins={}
        try:
            for name in ('readiness_transport.py','readiness_nested_channel.py','readiness_nested_membership.py',
                         'ssh_direct_nested_channel.py','ssh_fresh_nested_channel.py'):
                path=Path(__file__).with_name(name).absolute()
                parent=held.directory(str(path.parent))
                fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                try:
                    info=os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode)or info.st_uid!=os.getuid()or info.st_nlink!=1 or not 0<info.st_size<=1048576:
                        raise readiness.AdapterBlocked('integrity_mismatch')
                    raw=os.read(fd,1048577)
                    if len(raw)!=info.st_size:raise readiness.AdapterBlocked('integrity_mismatch')
                    digest=hashlib.sha256(raw).hexdigest()
                finally:os.close(fd)
                bodies[name]=held.read(str(path),digest,max_bytes=1048576);pins[name]=digest
            held.finish();held.final_identity_pass()
            def guard():held.finish();held.final_identity_pass()
            yield bodies,pins,guard
            guard()
        finally:held.close()

    def _candidate_guard(self,directory,candidate,anchor,stack,expected_recovery=None):
        names={'readiness_transport.py','readiness_nested_channel.py','readiness_nested_membership.py',
               'ssh_direct_nested_channel.py','ssh_fresh_nested_channel.py'}
        if (type(candidate)is not dict or set(candidate)!={'version','recoveryId','host','correlationId','ownerSources'}
                or type(candidate['version'])is not int or candidate['version']!=2 or candidate['host']!=anchor
                or type(candidate['recoveryId'])is not str or master.HASH.fullmatch(candidate['recoveryId'])is None
                or candidate['correlationId']!=hashlib.sha256((candidate['recoveryId']+anchor).encode()).hexdigest()[:32]
                or expected_recovery is not None and candidate['recoveryId']!=expected_recovery
                or type(candidate['ownerSources'])is not dict or set(candidate['ownerSources'])!=names
                or any(type(v)is not str or master.HASH.fullmatch(v)is None for v in candidate['ownerSources'].values())):
            raise readiness.AdapterBlocked('integrity_mismatch')
        snapshots=[]
        intent=stack.enter_context(private.Snapshot(directory,candidate['recoveryId']+'.intent.json'))
        if json.loads(intent.body,object_pairs_hook=transport._reject_duplicate_keys)!=candidate:
            raise readiness.AdapterBlocked('integrity_mismatch')
        snapshots.append(intent)
        for name,digest in candidate['ownerSources'].items():
            source=stack.enter_context(private.Snapshot(directory,candidate['recoveryId']+'.'+name+'.source'))
            if source.digest!=digest:raise readiness.AdapterBlocked('integrity_mismatch')
            snapshots.append(source)
        def guard():
            for snapshot in snapshots:snapshot.guard()
        guard();return guard

    def _predecessor(self, directory, recovery_identity):
        name = recovery_identity + '.predecessor.json'
        if not os.path.lexists(directory.path / name):
            return None
        value = master._read(directory, name)
        if (set(value) - {'inheritedFromRecoveryId'} != _PREDECESSOR_FIELDS or value['state'] != 'unavailable'
                or value['originalHistoryPreserved'] is not True or value['replayAllowed'] is not False
                or type(value['proof']) is not dict or type(value['correlationId']) is not str
                or re.fullmatch('[0-9a-f]{32}', value['correlationId']) is None
                or type(value['receiptSha256']) is not str or master.HASH.fullmatch(value['receiptSha256']) is None
                or 'inheritedFromRecoveryId' in value and (type(value['inheritedFromRecoveryId']) is not str
                    or master.HASH.fullmatch(value['inheritedFromRecoveryId']) is None)):
            raise readiness.AdapterBlocked('integrity_mismatch')
        return value

    def _inherited_predecessor(self, directory, ended):
        """The ended selection's own candidate names any original it superseded."""
        names = os.listdir(directory.fd)
        if len(names) > 8192:
            raise readiness.AdapterBlocked('integrity_mismatch')
        owners = [name[:-len('.intent.json')] for name in sorted(names) if name.endswith('.intent.json')
                  and master.HASH.fullmatch(name[:-len('.intent.json')]) is not None
                  and master._read(directory, name).get('correlationId') == ended]
        if len(owners) != 1:
            return None
        record = self._predecessor(directory, owners[0])
        if record is None:
            return None
        return {**{key: record[key] for key in _PREDECESSOR_FIELDS}, 'inheritedFromRecoveryId': owners[0]}

    def _retain_predecessor(self, directory, recovery_identity, predecessor):
        name = recovery_identity + '.predecessor.json'
        if not os.path.lexists(directory.path / name):
            master._save(directory, name, predecessor)
        elif self._predecessor(directory, recovery_identity) != predecessor:
            raise readiness.AdapterBlocked('integrity_mismatch')

    def observe_recovery(self, action, recovery_identity, observed, deadline, attempt, dispatch_digest):
        """Prove only that a nested candidate's channel intent never existed."""
        if (action != 'reconnect' or observed.target != self.host or observed.machine != self.machine
                or type(attempt) is not int or not 1 <= attempt <= readiness.MAX_DISPATCH_ATTEMPTS
                or any(type(value) is not str or master.HASH.fullmatch(value) is None
                       for value in (recovery_identity, dispatch_digest))):
            return None
        config = self._config()
        if config.hosts[self.host].transport == 'direct':
            return None
        anchor = self._anchor(config)
        if anchor is None:
            return None
        path = self.root/'.rag_index/readiness-transport-v2'/anchor.alias
        if not os.path.lexists(path):
            return None
        # The campaign lock is held by every prepare of a candidate; status
        # also holds the repository ownership lock while it finds no intent.
        with private.Directory(path) as directory, master.Lock(directory), ExitStack() as held:
            name = recovery_identity + '.intent.json'
            if not os.path.lexists(directory.path / name):
                return None
            candidate = master._read(directory, name)
            candidate_guard = self._candidate_guard(directory, candidate, anchor.alias, held, recovery_identity)
            if direct.status(self.root, anchor.alias, candidate['correlationId']) != _INTENT_ABSENT:
                return None
            candidate_guard()
            proof = {'version': 1, 'recoveryId': recovery_identity, 'attempt': attempt, 'dispatchDigest': dispatch_digest,
                     'correlationId': candidate['correlationId'], 'channelIntent': 'absent',
                     'candidateSha256': hashlib.sha256(session._json(candidate)).hexdigest(), 'replayAllowed': False}
            record = recovery_identity + '.unsubmitted-' + str(attempt) + '.json'
            if not os.path.lexists(directory.path / record):
                master._save(directory, record, proof)
            elif master._read(directory, record) != proof:
                return None
            with private.Snapshot(directory, record) as retained:
                digest = retained.digest
            candidate_guard()
            return readiness.RecoveryUnsubmitted(recovery_identity, attempt, dispatch_digest, digest)

    def reconcile_recovery(self, action, recovery_identity, observed, deadline, attempt, dispatch_digest):
        """Observe the consumed original connection attempt, without replay."""
        if (action!='reconnect' or observed.target!=self.host or observed.machine!=self.machine):
            raise readiness.AdapterBlocked('machine_identity_mismatch')
        config=self._config()
        if config.hosts[self.host].transport!='direct':
            anchor=self._anchor(config)
            if anchor is None:return None
            # Recovery owns only its original campaign. Never call prepare or
            # generate a successor while reconciling its lost acknowledgement.
            path=self.root/'.rag_index/readiness-transport-v2'/anchor.alias
            if not os.path.lexists(path):return None
            with private.Directory(path)as directory,master.Lock(directory),ExitStack()as held_candidate:
                try:candidate=master._read(directory,'current.json')
                except FileNotFoundError:return None
                if candidate.get('recoveryId')!=recovery_identity:return None
                candidate_guard=self._candidate_guard(directory,candidate,anchor.alias,held_candidate,recovery_identity)
                expected=candidate
                if master._read(directory,recovery_identity+'.intent.json')!=expected:
                    raise readiness.AdapterBlocked('integrity_mismatch')
                if nested_ready.present(self.root,anchor.alias):
                    try:selected=nested_ready.route_options(self.root,anchor.alias,config,deadline)
                    except (nested_ready.NestedEnded,nested_ready.DirectoryMembershipChanged):pass
                    else:
                        candidate_guard()
                        return selected['correlationId']==candidate['correlationId']
                candidate_guard()
                result=direct.status(self.root,anchor.alias,candidate['correlationId'])
                candidate_guard()
                if result.get('state')!='ready':return None
                selected=nested_ready.admit(self.root,anchor.alias,candidate['correlationId'],result['receiptSha256'])
                candidate_guard()
                return selected.get('state')=='selected'
        try:
            result=master.reconcile_original(self.root,self.host,recovery_identity,deadline=deadline)
        except FileNotFoundError:
            return None
        except master.MasterUnknown:
            raise readiness.AdapterBlocked('connection_outcome_unknown')from None
        if result['state']=='ready':return True
        if result['state']=='terminal-failed':
            return readiness.RecoveryEnded(recovery_identity,attempt,dispatch_digest,result['proofSha256'])
        return None

    def recover(self, action, recovery_identity, observed, deadline):
        if (action != 'reconnect' or observed.target != self.host or observed.machine != self.machine
                or type(recovery_identity) is not str or master.HASH.fullmatch(recovery_identity) is None):
            raise readiness.AdapterBlocked('machine_identity_mismatch')
        config = self._config()
        if config.hosts[self.host].transport == 'direct':
            master.start(self.root,self.host,recovery_identity,deadline=deadline,
                         unavailable=self._unavailable if observed.transport=='unavailable'else None)
            return
        anchor = self._anchor(config)
        if anchor is None or len(transport._route_hosts(config.hosts,anchor.alias)) != 2:
            raise readiness.AdapterBlocked('provider_unavailable')
        drift=None
        ended=None
        if nested_ready.present(self.root,anchor.alias):
            try:
                nested_ready.route_options(self.root,anchor.alias,config,deadline)
            except nested_ready.DirectoryMembershipChanged as current:
                # A new independently observed connection may supersede this
                # unusable authority. The original master/history stays intact.
                drift=current
            except nested_ready.NestedEnded:
                with private.Directory(nested_ready.directory(self.root,anchor.alias))as selected:
                    value=master._read(selected,'current.json')
                terminal=direct.reconcile_original(self.root,anchor.alias,value['correlationId'])
                if terminal.get('state')!='ended':raise readiness.AdapterBlocked('connection_outcome_unknown')
                ended=value['correlationId']
            else:
                return
        path = self._campaign(anchor.alias)
        with private.Directory(path) as directory, master.Lock(directory), self._campaign_sources()as(bodies,source_pins,source_guard),ExitStack()as held_candidate:
            try:candidate = master._read(directory,'current.json')
            except FileNotFoundError:candidate = None
            retry=False
            if candidate is not None:
                # Missing evidence for an existing candidate never means that
                # no candidate existed and never authorizes a replacement.
                candidate_guard=self._candidate_guard(directory,candidate,anchor.alias,held_candidate)
                correlation = candidate['correlationId']
                if drift is not None and correlation==drift.correlation:
                    candidate=None
                else:
                    candidate_guard()
                    result = direct.status(self.root,anchor.alias,correlation)
                    candidate_guard()
                    if result.get('state') == 'ended':
                        candidate = None
                    elif result == _INTENT_ABSENT:
                        # Every prepare of this correlation holds this campaign
                        # lock, and its channel intent precedes any remote
                        # effect, so this candidate provably never ran.
                        if candidate['recoveryId'] == recovery_identity:
                            retry = True
                        else:
                            candidate = None
            # A successor of an unusable original that later ended normally
            # inherits that original; it stays unresolved and is never reused.
            predecessor=None
            if drift is not None:
                predecessor={'state':'unavailable','correlationId':drift.correlation,'receiptSha256':drift.receipt,
                             'proof':drift.proof,'originalHistoryPreserved':True,'replayAllowed':False}
            elif ended is not None:
                predecessor=self._inherited_predecessor(directory,ended)
            if retry:
                if predecessor is not None:
                    self._retain_predecessor(directory,recovery_identity,predecessor)
                candidate_guard()
                if predecessor is not None:
                    result=direct.prepare_successor(self.root,anchor.alias,correlation,predecessor['correlationId'],
                                                    predecessor['receiptSha256'],deadline=deadline)
                else:
                    result = direct.prepare(self.root,anchor.alias,correlation)
            elif candidate is None:
                correlation = hashlib.sha256((recovery_identity+anchor.alias).encode()).hexdigest()[:32]
                candidate = {'version':2,'recoveryId':recovery_identity,'correlationId':correlation,'host':anchor.alias,'ownerSources':source_pins}
                for name,raw in bodies.items():
                    fd=os.open(recovery_identity+'.'+name+'.source',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
                    try:
                        with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                        os.fsync(directory.fd)
                    except BaseException:raise
                    with private.Snapshot(directory,recovery_identity+'.'+name+'.source')as source:
                        if source.digest!=source_pins[name]:raise readiness.AdapterBlocked('integrity_mismatch')
                master._save(directory,recovery_identity+'.intent.json',candidate)
                candidate_guard=self._candidate_guard(directory,candidate,anchor.alias,held_candidate,recovery_identity)
                source_guard();candidate_guard()
                if predecessor is not None:
                    master._save(directory,recovery_identity+'.predecessor.json',predecessor)
                # Durable original correlation precedes even provider admission.
                name=recovery_identity+'.pointer.json'
                master._save(directory,name,candidate)
                os.replace(name,'current.json',src_dir_fd=directory.fd,dst_dir_fd=directory.fd);os.fsync(directory.fd)
                if predecessor is not None:
                    result=direct.prepare_successor(self.root,anchor.alias,correlation,predecessor['correlationId'],
                                                    predecessor['receiptSha256'],deadline=deadline)
                else:
                    result = direct.prepare(self.root,anchor.alias,correlation)
            source_guard();candidate_guard()
            if result.get('state') != 'ready':
                if result.get('failureReason') == 'arch_identity':
                    raise readiness.AdapterBlocked('machine_identity_mismatch')
                raise readiness.AdapterBlocked('connection_outcome_unknown')
            selected = nested_ready.admit(self.root,anchor.alias,correlation,result['receiptSha256'])
            candidate_guard()
            if selected.get('state') != 'selected':
                raise readiness.AdapterBlocked('connection_generation_changed')


def context(root, host, *, deadline=None, **kwargs):
    """Explicit readiness initialization creates only its private local journal."""
    adapter = TransportAdapter(root, host)
    for path in (adapter.root/'.rag_index',adapter.root/'.rag_index/readiness'):
        _private_directory(path)
    path = _private_directory(adapter.root/'.rag_index/readiness'/hashlib.sha256(host.encode()).hexdigest())
    return readiness.Context(host,adapter.machine,adapter,readiness.RecoveryJournal(path),deadline=deadline,**kwargs)
