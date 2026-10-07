"""One terminal V2 build: bounded pipe reads, no stage/build/release capability.

Original partial captures remain immutable. Fresh query capsules are private and
create-only. Read-only chunk queries may resume the inherited verified collector;
this never repeats a native build. Ownership assumes cooperating single operator.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from uuid import uuid4
from . import ssh_tmux_source_staging_recovery as recovery
from . import ssh_tmux_session_ssh as old
from . import ssh_tmux_session as session
from . import ssh_transport
from .private_inventory_lock import Directory

MAX_STDOUT=2*1024**2
MAX_STDERR=65536
CORRELATION='86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0'
REQUEST={'sourceSha':'d32f719a08db57e5d40ce2bf77e0d7c5b42de557','baseVersion':'2.1.19','targetVersion':'2.2.2','correlationId':CORRELATION}
ANCHOR={'generation':[66307,103958983,33152,1000,1000,1057,1791042083188307119,1791042083188307119,1],'sha256':'867f4bcc73918132385eaead6b1ae392e6ffad8add586bd07f70903d61453e04'}
STAGE={'generation':[66307,103947958,33152,1000,1000,1093,1791042083032310837,1791042083032310837,1],'sha256':'734c631067f399124c7efa0ad172b52978a46f87c47e839657c18f0d76226ebb'}
TERMINAL={'generation':[66307,103963695,33152,1000,1000,305,1791042396888885383,1791042396888885383,1],'sha256':'397a88178b47b69ad5f1b5d71f2965931dcd80a2c223c1738b3ab42eb4487fe6'}
FROZEN={'ssh_tmux_source_staging_recovery.py':'841cd9f40b045df5471184fca0997ce0d51151741db0f12d0b66d10f6fc36749','ssh_tmux_session_ssh.py':'bec936bd1a34679939a817777443255fbb7c6d5fc2adafc3193e25ce9ed07c44','ssh_tmux_session.py':'468adbbb45d7b68de50c6df601cf9c25421ef0e09ca3b1c13dddb1dffc580fb3','linux_package_fixture_build.py':'2aeaef328f9ccb9b7a1d929603929c9ee1fbb827c027ca09d3953dc0cb00a8c8'}
HISTORY_PINS={'.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0.json': {'generation': [16777234, 111574882, 33152, 503, 20, 159, 1791042042439142585, 1791042042439142585, 1], 'sha256': 'cbeb6a041cd73d4843fe8ac46f820a0fa803b89cfefbdfd30cbb7d6d6f107d27'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-adapter-intent.json': {'generation': [16777234, 111574884, 33152, 503, 20, 2387, 1791042042991804901, 1791042042991804901, 1], 'sha256': 'e1951161169d763342d204cca943fb964e6c00124ac7b35307996b9c1c6e7fb7'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-anchor.json': {'generation': [16777234, 111574910, 33152, 503, 20, 315, 1791042083220868135, 1791042083220868135, 1], 'sha256': '58fedb113c2e7897c334b56010a82f86d3577ded79b5556a3ab209b905ce1f28'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-collection.json': {'generation': [16777234, 111575508, 33152, 503, 20, 355, 1791042596653305933, 1791042596653305933, 1], 'sha256': '60801fb89a9c86862958e710432269c4e82a2673b816fe30b504adc53b3e6f3b'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-061c9ed7-787b-4915-b30e-4583d0bd86a0/receipt.json': {'generation': [16777234, 111575507, 33152, 503, 20, 598, 1791042596653103644, 1791042596653103644, 1], 'sha256': 'deb718a6ada757bda94623284d3352c7491c34c77f9a9121ca013f2915dcc54c'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-061c9ed7-787b-4915-b30e-4583d0bd86a0/stderr': {'generation': [16777234, 111575506, 33152, 503, 20, 0, 1791042596502442379, 1791042596502471837, 1], 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-061c9ed7-787b-4915-b30e-4583d0bd86a0/stdout': {'generation': [16777234, 111575505, 33152, 503, 20, 330, 1791042596598800486, 1791042596598800486, 1], 'sha256': '6ed2f18ce02fa78409cc2f1019d41d6f47f2b235c452e0b6d3ccf1c838045372'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-20244332-0652-4691-87ca-7d49fdf69f85/receipt.json': {'generation': [16777234, 111575144, 33152, 503, 20, 598, 1791042266581270252, 1791042266581270252, 1], 'sha256': 'cfa6a6eadf136128ce14b8597c7be4fd147ed9e4141b5f78cc7465e24ee92ed8'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-20244332-0652-4691-87ca-7d49fdf69f85/stderr': {'generation': [16777234, 111575143, 33152, 503, 20, 0, 1791042266436500136, 1791042266436527302, 1], 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-20244332-0652-4691-87ca-7d49fdf69f85/stdout': {'generation': [16777234, 111575142, 33152, 503, 20, 131, 1791042266536070168, 1791042266536070168, 1], 'sha256': '8a3498fb522c0788adc9c93af50f4d5d2ed4effcf1de0a9d1101b822c015625a'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-2a8d286e-db30-4365-bb3e-1014d7700f1f/receipt.json': {'generation': [16777234, 111574903, 33152, 503, 20, 600, 1791042083032533460, 1791042083032533460, 1], 'sha256': '5fd3e537ede13b57c2df475b98344d6ceca71691cc1b20a41b70925861fb3e63'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-2a8d286e-db30-4365-bb3e-1014d7700f1f/stderr': {'generation': [16777234, 111574888, 33152, 503, 20, 926, 1791042082718442976, 1791042082718442976, 1], 'sha256': '68b1a762429170af2004bbdbd1256327f07529545a3ca90f22c145a931389e48'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-2a8d286e-db30-4365-bb3e-1014d7700f1f/stdout': {'generation': [16777234, 111574887, 33152, 503, 20, 257, 1791042083015938920, 1791042083015938920, 1], 'sha256': '488f3cc8a7a39da7b0facff9c4a9b15e09cdc1b951f24ec594294d9a3483c79c'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-68209615-84f6-468d-b153-164ee4597947/receipt.json': {'generation': [16777234, 111574916, 33152, 503, 20, 598, 1791042083405825886, 1791042083405825886, 1], 'sha256': '38c42d9b25c80e527f74bdfd785e7a9e37cca0bdbf6ce678e4831395ec5b6194'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-68209615-84f6-468d-b153-164ee4597947/stderr': {'generation': [16777234, 111574915, 33152, 503, 20, 0, 1791042083250643333, 1791042083250689083, 1], 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-68209615-84f6-468d-b153-164ee4597947/stdout': {'generation': [16777234, 111574914, 33152, 503, 20, 132, 1791042083365293547, 1791042083365293547, 1], 'sha256': 'e6e93a13e33ebd3f49e2a0c24eb8479749f63728ba25fd1dca25c4933f199c70'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-89cee267-eed5-4593-b8e3-3cd58bdc33ce/receipt.json': {'generation': [16777234, 111574929, 33152, 503, 20, 598, 1791042098589612795, 1791042098589612795, 1], 'sha256': 'b61a1d298b10bbe149afbe1b803a40a8112ca4a649405f859ccbb697359b8d8f'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-89cee267-eed5-4593-b8e3-3cd58bdc33ce/stderr': {'generation': [16777234, 111574928, 33152, 503, 20, 0, 1791042098446740701, 1791042098446774409, 1], 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-89cee267-eed5-4593-b8e3-3cd58bdc33ce/stdout': {'generation': [16777234, 111574927, 33152, 503, 20, 131, 1791042098553480245, 1791042098553480245, 1], 'sha256': '8a3498fb522c0788adc9c93af50f4d5d2ed4effcf1de0a9d1101b822c015625a'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-9e0a66f5-df6c-45af-b843-f65ebcefffac/receipt.json': {'generation': [16777234, 111575307, 33152, 503, 20, 598, 1791042512733638996, 1791042512733638996, 1], 'sha256': '9b15bc5864e887b5f856365d63eb769163f5ceebc6c0da1aea0081331cbe61aa'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-9e0a66f5-df6c-45af-b843-f65ebcefffac/stderr': {'generation': [16777234, 111575306, 33152, 503, 20, 0, 1791042512582358279, 1791042512582388570, 1], 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-9e0a66f5-df6c-45af-b843-f65ebcefffac/stdout': {'generation': [16777234, 111575305, 33152, 503, 20, 330, 1791042512679599585, 1791042512679599585, 1], 'sha256': '6ed2f18ce02fa78409cc2f1019d41d6f47f2b235c452e0b6d3ccf1c838045372'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-a3733032-6e24-4ac2-b62f-830521db7e84/receipt.json': {'generation': [16777234, 111574909, 33152, 503, 20, 598, 1791042083220448348, 1791042083220448348, 1], 'sha256': '8b2e7376e50b02d691edd17c033cc6a13dc8a872f8ed465b42b6f1a28c80af04'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-a3733032-6e24-4ac2-b62f-830521db7e84/stderr': {'generation': [16777234, 111574908, 33152, 503, 20, 0, 1791042083066252994, 1791042083066291701, 1], 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-a3733032-6e24-4ac2-b62f-830521db7e84/stdout': {'generation': [16777234, 111574907, 33152, 503, 20, 316, 1791042083180806333, 1791042083180806333, 1], 'sha256': '2d906c385cd22149d2ec0c7e3a191421af4fe13f2c297ffcec8bbe54ea98e897'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-e2d9a5fb-c38e-4e6f-a72d-b5ab972e0edc/receipt.json': {'generation': [16777234, 111575515, 33152, 503, 20, 599, 1791042597436336458, 1791042597436336458, 1], 'sha256': 'c494cc28f74d6b9dcefe39ac96f9faa2f98f55c974a633db7d863f2f3cac1d41'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-e2d9a5fb-c38e-4e6f-a72d-b5ab972e0edc/stderr': {'generation': [16777234, 111575513, 33152, 503, 20, 0, 1791042596671949744, 1791042596671979786, 1], 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-query-e2d9a5fb-c38e-4e6f-a72d-b5ab972e0edc/stdout': {'generation': [16777234, 111575512, 33152, 503, 20, 4096, 1791042597280889116, 1791042597280889116, 1], 'sha256': 'b7a507d9caf99d32e92bb0cd26b5936eabb6c4082d72aa8173a60c1288ab44ed'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-release-intent.json': {'generation': [16777234, 111574911, 33152, 503, 20, 170, 1791042083222383495, 1791042083222383495, 1], 'sha256': '0ec2b52bbcb89fcfadf2f407387749c40fab216cd99cf02a2ae356e8b814ae60'}, '.rag_index/linux-package-fixture-build/86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/tmux-stage.json': {'generation': [16777234, 111574904, 33152, 503, 20, 256, 1791042083033062038, 1791042083033062038, 1], 'sha256': 'cb462695343427a8e6b232bd17f98afbd7ebae84e0e2346eeb9acfe444249000'}, '.rag_index/linux-package-fixture-build/archlinux.claim': {'generation': [16777234, 111574881, 33152, 503, 20, 76, 1791042042438962962, 1791042042438962962, 1], 'sha256': '28e86e65e06fd9dfb44d892fc8c4f9ccd3b80d7f52adc25d0ac0a9af89bb5b5c'}, '.runtime/parity-evidence/tmux-native-v2-86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0/status-61693622-af83-48f8-b3ab-3fddca856e81.json': {'generation': [16777234, 111575308, 33152, 503, 20, 571, 1791042512733993909, 1791042512733993909, 1], 'sha256': '79e230fa1c0d82ed63daa79af0436ccbfdb480193da7780d8d9b617bb41cd2c7'}}

class CollectionError(ValueError):pass

def need(value,reason='collection_unknown'):
    if not value:raise CollectionError(reason)


def _read_named(directory,name,maximum,private=True):
    directory.guard();fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory.fd)
    try:
        info=os.fstat(fd);pin=session.generation(info)
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and 0<=info.st_size<=maximum and (not private or stat.S_IMODE(info.st_mode)==0o600),'capture_file_unsafe')
        raw=b''
        while len(raw)<=maximum:
            block=os.read(fd,min(65536,maximum+1-len(raw)))
            if not block:break
            raw+=block
        need(len(raw)==info.st_size and pin==session.generation(os.fstat(fd))==session.generation(os.stat(name,dir_fd=directory.fd,follow_symlinks=False)),'capture_file_changed')
        directory.guard();return raw,{'generation':pin,'sha256':hashlib.sha256(raw).hexdigest()}
    finally:os.close(fd)


def _read(path,maximum=131072,private=True):
    with Directory(Path(path).absolute().parent) as directory:return _read_named(directory,Path(path).name,maximum,private)


def _write_once(path,data):
    need(type(data)is bytes and len(data)<=MAX_STDOUT+1,'capture_data_invalid')
    with Directory(Path(path).absolute().parent) as directory:
        directory.guard();fd=os.open(Path(path).name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
        try:
            created=os.fstat(fd);need(stat.S_ISREG(created.st_mode) and created.st_uid==os.getuid() and stat.S_IMODE(created.st_mode)==0o600 and created.st_nlink==1,'capture_file_unsafe')
            directory.guard();need(session.generation(created)==session.generation(os.stat(Path(path).name,dir_fd=directory.fd,follow_symlinks=False)),'capture_file_changed')
            view=memoryview(data)
            while view:
                count=os.write(fd,view);need(count>0,'capture_short_write');view=view[count:]
            os.fsync(fd);pin=session.generation(os.fstat(fd));directory.guard()
            need(pin==session.generation(os.stat(Path(path).name,dir_fd=directory.fd,follow_symlinks=False)),'capture_file_changed')
            os.fsync(directory.fd);raw,result=_read_named(directory,Path(path).name,MAX_STDOUT+1)
            need(raw==data and result['generation']==pin,'capture_file_changed');return result
        finally:os.close(fd)


def _mkdir(parent,name):
    need(Path(name).name==name and name not in ('.','..'),'capture_directory_invalid')
    with Directory(parent) as directory:
        directory.guard();os.mkdir(name,0o700,dir_fd=directory.fd);os.fsync(directory.fd);directory.guard()
    with Directory(Path(parent)/name):pass
    return Path(parent)/name


def _capsule(root):
    root=Path(root).absolute();need(not root.is_symlink(),'capture_root_changed')
    for name in ('.rag_index','linux-package-fixture-build-pipe-collection'):
        candidate=root/name
        if not os.path.lexists(candidate):_mkdir(root,name)
        with Directory(candidate):pass
        root=candidate
    return _mkdir(root,'attempt-'+str(uuid4()))


def _capture(root,*,authority,launch,payload,guard,timeout_seconds=95):
    """One nonblocking duplex query; durable finite outcome even on response loss."""
    fields={'sourceSha','intentPin','anchorPin','terminalPin','action','collectorSourcePin','argvSha256'}
    need(type(authority)is dict and set(authority)==fields and authority['action'] in ('status','collect') and type(authority['sourceSha'])is str and re.fullmatch(r'[0-9a-f]{40}',authority['sourceSha']) and all(session._valid_pin(authority[k]) for k in ('intentPin','anchorPin','terminalPin','collectorSourcePin')) and type(authority['argvSha256'])is str and re.fullmatch(r'[0-9a-f]{64}',authority['argvSha256']),'capture_authority_invalid')
    need(type(payload)is bytes and len(payload)<=16384 and type(timeout_seconds)in (int,float) and 0<timeout_seconds<=95,'capture_payload_invalid')
    try:guard()
    except Exception:raise CollectionError('authority_changed') from None
    capsule=_capsule(root);intent=_write_once(capsule/'intent.json',session.canonical({'authority':authority,'payloadSha256':hashlib.sha256(payload).hexdigest(),'replayAllowed':False}))
    process=None;selector=None;stdout=bytearray();stderr=bytearray();written=0;failure=None;timed_out=False;capped=False;code=None
    try:
        guard();process=launch();need(all(getattr(process,k,None)is not None for k in ('stdin','stdout','stderr')),'pipe_launch_unknown')
        selector=selectors.DefaultSelector()
        for stream,label in ((process.stdout,'stdout'),(process.stderr,'stderr'),(process.stdin,'stdin')):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_WRITE if label=='stdin' else selectors.EVENT_READ,label)
        deadline=time.monotonic()+timeout_seconds
        while selector.get_map():
            left=deadline-time.monotonic()
            if left<=0:timed_out=True;failure='query_timeout';break
            for key,_ in selector.select(min(.2,left)):
                label=key.data;stream=key.fileobj
                if label=='stdin':
                    if written==len(payload):selector.unregister(stream);stream.close();continue
                    try:count=os.write(stream.fileno(),memoryview(payload)[written:written+65536])
                    except (BlockingIOError,InterruptedError):continue
                    need(count>0,'stdin_write_unknown');written+=count
                else:
                    sink,limit=(stdout,MAX_STDOUT) if label=='stdout' else (stderr,MAX_STDERR)
                    try:block=os.read(stream.fileno(),min(65536,limit+1-len(sink)))
                    except (BlockingIOError,InterruptedError):continue
                    if not block:selector.unregister(stream);stream.close()
                    else:
                        sink.extend(block)
                        if len(sink)>limit:capped=True;failure='query_output_limit';break
            if failure:break
        if not failure:
            code=process.wait(timeout=max(.01,min(2,deadline-time.monotonic())))
            if code!=0:failure='query_exit_unknown'
    except subprocess.TimeoutExpired:
        timed_out=True;failure='query_timeout'
    except Exception:
        if failure is None:failure='query_transport_unknown'
    finally:
        if selector is not None:selector.close()
        if process is not None:
            try:
                if process.poll()is None:process.kill()
                code=process.wait(timeout=2)
            except (OSError,subprocess.SubprocessError):failure=failure or 'query_reap_unknown'
            for name in ('stdin','stdout','stderr'):
                stream=getattr(process,name,None)
                if stream is not None:
                    try:stream.close()
                    except OSError:pass
        try:guard()
        except Exception:failure='authority_changed'
        out_pin=_write_once(capsule/'stdout',bytes(stdout));err_pin=_write_once(capsule/'stderr',bytes(stderr))
        receipt={'schemaVersion':1,'intentPin':intent,'stdoutPin':out_pin,'stderrPin':err_pin,'exitCode':code,'capped':capped,'timedOut':timed_out,'stdinBytesWritten':written,'failure':failure,'replayAllowed':False}
        receipt_pin=_write_once(capsule/'receipt.json',session.canonical(receipt))
    return {'state':'captured' if code==0 and failure is None and written==len(payload) else 'unknown','receiptPin':receipt_pin,'replayAllowed':False,'nativeActionAllowed':False},capsule


def _sources(root):
    pins={}
    for name,wanted in FROZEN.items():
        raw,pin=_read(Path(root)/'agent_tools'/name,262144,False);need(pin['sha256']==wanted,'frozen_source_changed');pins[str(Path(root)/'agent_tools'/name)]=pin
    path=Path(__file__).absolute();pins[str(path)]=_read(path,262144,False)[1]
    return pins


# Separate catalogue for fresh MCP jobs. Historical _sources never adopts
# these successors, and no caller can supply an expected source hash.
CURRENT_SOURCES={
    'ssh_tmux_source_staging_recovery.py': '75bfd68d3aca2fa0a915f395ecdc9e62bd68c7ef7f809d17ba6e966af3a015b2',
    'ssh_tmux_session_ssh.py': '91c8af7b5e47412f8bf9fbe907e69d163ad174c3dc2200bf10f795cee545cc21',
    'ssh_tmux_session.py': '0b865df3b9c5221229f4bd3c6f49a63c569a609d6258a269ab92c61b013a41fb',
    'linux_package_fixture_build.py': '874b7be8d70e917553d466ed2b8ad71419dec5f21bfd3092060f16180c284cf5',
}

def _current_sources(root):
    pins={}
    for name,wanted in CURRENT_SOURCES.items():
        path=Path(root)/'agent_tools'/name
        raw,pin=_read(path,262144,False)
        need(pin['sha256']==wanted,'current_source_changed')
        pins[str(path)]=pin
    path=Path(__file__).absolute();pins[str(path)]=_read(path,262144,False)[1]
    return pins


def _history(root):
    for relative,pin in HISTORY_PINS.items():need(_read(Path(root)/relative,MAX_STDOUT)[1]==pin,'original_history_changed')


class _PipeDriver(recovery.ExactFetchDriver):
    """Same verified collector; fixed status/collect pipe transport only."""
    def availability(self):raise CollectionError('collection_only')
    def preflight(self,raw):raise CollectionError('collection_only')
    def submit(self,raw):raise CollectionError('collection_only')
    def release(self,raw):raise CollectionError('collection_only')

    def _query(self,program,payload,*,job=None,guard=None):
        need(program==old._ACTION and type(payload)is dict and payload.get('action')in ('status','collect'),'collection_only')
        action=payload['action'];keys={'action','request','stagePin','anchorPin'}|({'terminalPin','offset','limit','resultPin'} if action=='collect' else set())
        need(set(payload)==keys and payload['request']==old.purpose(REQUEST) and payload['stagePin']==STAGE and payload['anchorPin']==ANCHOR,'original_query_changed')
        if action=='collect':need(payload['terminalPin']==TERMINAL and type(payload['offset'])is int and 0<=payload['offset']<=session.MAX_RESULT and type(payload['limit'])is int and 1<=payload['limit']<=1024**2 and (payload['resultPin']is None or session._valid_pin(payload['resultPin'])),'original_query_changed')
        original=self._snapshot(REQUEST);sources=_sources(self.root);_history(self.root)
        config,transport_pin=self._transport();argv=ssh_transport.build_ssh_argv(config,'archlinux',10,command=recovery.command(old._ACTION))
        def exact_guard():
            need(self._snapshot(REQUEST)==original and self._transport()[1]==transport_pin and _sources(self.root)==sources,'authority_changed');_history(self.root)
            if guard:guard()
        connection=ssh_transport.connection_host(config,'archlinux');need(connection.password is None,'password_transport_not_supported')
        def launch():
            exact_guard();return subprocess.Popen(argv,cwd=self.root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        own=sources[str(Path(__file__).absolute())]
        authority={'sourceSha':REQUEST['sourceSha'],'intentPin':original['coordinator']['records']['intent'],'anchorPin':ANCHOR,'terminalPin':TERMINAL,'action':action,'collectorSourcePin':own,'argvSha256':hashlib.sha256(session.canonical(argv)).hexdigest()}
        receipt,capsule=_capture(self.root,authority=authority,launch=launch,payload=session.canonical(payload),guard=exact_guard)
        need(receipt['state']=='captured','transport_unknown')
        raw,receipt_pin=_read(capsule/'receipt.json');need(receipt_pin==receipt['receiptPin'],'capture_receipt_changed');record=json.loads(raw)
        raw,out_pin=_read(capsule/'stdout',MAX_STDOUT);need(out_pin==record['stdoutPin'] and _read(capsule/'stderr',MAX_STDERR)[1]==record['stderrPin'],'capture_stream_changed')
        try:value=json.loads(raw,object_pairs_hook=ssh_transport._reject_duplicate_keys)
        except (ValueError,UnicodeError):raise CollectionError('transport_unknown') from None
        need(type(value)is dict,'transport_unknown');exact_guard()
        if action=='status':need(value=={'state':'terminal','correlationId':CORRELATION,'exitCode':0,'terminalPin':TERMINAL,'artifactVerification':'required','replayAllowed':False} and value['replayAllowed']is False and type(value['exitCode'])is int,'terminal_authority_changed')
        return value


def collect_existing(root,correlation_id):
    """Fixed completed job; original authority and all old captures stay pinned."""
    need(os.name=='posix','unsupported_coordinator')
    need(correlation_id==CORRELATION and type(correlation_id)is str,'fixed_correlation_required')
    root=Path(root).absolute();sources=_sources(root);_history(root)
    directory=recovery.build._directory(root,False);need(directory is not None,'coordinator_journal_missing')
    request=json.loads(_read(directory/(CORRELATION+'.json'))[0]);need(request==REQUEST,'original_request_changed')
    driver=_PipeDriver(root);job,original=driver._saved(REQUEST)
    fence=json.loads(_read(job/'tmux-collection.json')[0]);need(fence=={'request':REQUEST,'terminalPin':TERMINAL},'collection_changed')
    need(_sources(root)==sources,'collector_source_changed')
    result=driver.collect_existing(REQUEST)
    _history(root);need(_sources(root)==sources,'collector_source_changed')
    return result
