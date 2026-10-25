import base64
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock
from uuid import uuid4
from agent_tools import durable_remote_job as jobs,readiness,readiness_android as android,readiness_fixture_registry as registry,readiness_adb_transport as adb_transport,readiness_providers as providers


class NativeCompanionInventoryTest(unittest.TestCase):
    def wait(self,function):
        end=time.monotonic()+10
        while time.monotonic()<end:
            result=function()
            if result:return result
            time.sleep(.02)
        self.fail('original controlled owner did not settle')

    def test_complete_idle_rejects_actual_extra_unknown_native_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            base=root/'.runtime/native';base.mkdir(parents=True,mode=0o700)
            native=base/'native-jobs';native.mkdir(mode=0o700);generation=jobs.root_generation(native)
            host=jobs.current_binding('owned','controlled-host');hostdict=host.__dict__
            mode=base/'mode';mode.write_text('exit')
            emulator=base/'emulator';emulator.write_text('#!'+sys.executable+'\nimport pathlib,time\nif pathlib.Path('+repr(str(mode))+').read_text()=="run":time.sleep(60)\n');emulator.chmod(0o700)
            adb=base/'adb';adb.write_text('#!'+sys.executable+'\nimport time\ntime.sleep(60)\n');adb.chmod(0o700)
            binding=providers.AndroidBinding('owned','avd',adb,'avd','emulator-5662',5042)
            env={'PATH':os.defpath};argv=[str(emulator)]
            processes=[]
            def launch(program,operation,receipt):
                jobs.submit(native,operation,host,program,generation=generation)
                actor=self.wait(lambda:jobs._record(native/operation/receipt)['actor'] if (native/operation/receipt).exists() else None)
                owner=jobs._record(native/operation/'owner.json')['owner'];processes.append((actor,owner))
                return actor
            prior=str(uuid4());priorprogram=android.launch_program(native,prior,host,argv,env)
            launch(priorprogram,prior,'emulator.json')
            self.wait(lambda:jobs.observe(native,prior,host,generation=generation)['state']=='terminal')
            collected,out,err=jobs.collect(native,prior,host,generation=generation)
            mode.write_text('run')
            seed=str(uuid4());seedprogram=android.launch_program(native,seed,host,argv,env)
            seedactor=launch(seedprogram,seed,'emulator.json')
            adbop=str(uuid4());adbprogram=adb_transport.daemon_program(native,adbop,host,binding)
            adbactor=launch(adbprogram,adbop,'adb.json');server=registry.process_identity(adbactor['pid'])
            seedvalue={'jobRoot':str(native),'operationId':seed,'hostBinding':hostdict,'rootGeneration':list(generation),'programSha256':seedprogram.digest}
            records={'private-adb-intent.json':{'operationId':adbop,'hostBinding':hostdict,'rootGeneration':list(generation),'programSha256':adbprogram.digest},
              'private-adb-ready.json':{'operationId':adbop,'server':server,'root':str(native),'hostBinding':hostdict,'generation':list(generation)},
              'retry-launch-intent.json':{'operationId':prior,'hostBinding':hostdict,'rootGeneration':list(generation),'programSha256':priorprogram.digest,'argv':argv,'environment':env},
              'existing-start-intent.json':{'durableOwner':seedvalue},
              'existing-stop-before-terminal.json':{'originalVmOperationId':prior,'status':collected,'stdout':base64.b64encode(out).decode(),'stderr':base64.b64encode(err).decode()}}
            for name,value in records.items():jobs._publish(base/name,value)
            descriptor={'binding':{'target':'owned','machine':'avd','adb':str(adb),'avdName':'avd','serial':'emulator-5662','serverPort':5042},
              'hostBinding':hostdict,'jobRootGeneration':list(generation),'storagePlan':'owned','avdConfig':str(base/'avd/config.ini'),
              'initialActor':seedactor,'writableDisks':[],'memoryMiB':2048,'jobBaseline':['init'],'argv':argv,'environment':env,'adbServer':server,
              'qualification':{str(base/'existing-start-intent.json'):registry._json(base/'existing-start-intent.json')[1]},
              'initialOwner':{**seedvalue,'programPin':registry._body(native/seed/'program.py')[1]}}
            backend=android.AndroidInstanceBackend(root,descriptor,lambda:'same',base);backend._operator_held=True
            observed=readiness.Observation('owned','avd',guest='running',boot='guestboot')
            def command(args,deadline):
                if args==['shell','ps','-A','-o','NAME']:return 'NAME\ninit\nps\n','same'
                if args==['shell','pm','list','packages','com.kardinal.vpncontrol']:return '','same'
                if args==['shell','dumpsys','package','installs']:return 'Active install sessions:\n\nFinalized install sessions:\n\nHistorical install sessions:\n\nLegacy install sessions:\n{}\nGentle update with constraints info:\nhasPendingIdleJob=false\n','same'
                self.fail('unexpected fixed probe')
            try:
                with mock.patch.object(backend,'_current',return_value=(seedactor,'live',None)), \
                     mock.patch.object(backend,'_launches',return_value=[]), \
                     mock.patch.object(android.visual,'_read_reservations',return_value={'android':{'memory_mib':2048,'pid':seedactor['pid']}}), \
                     mock.patch.object(backend.adb,'_command',side_effect=command):
                    self.assertEqual(backend._idle(observed,time.monotonic()+5).idle_visibility,readiness.IDLE_VISIBILITY)
                    extra=str(uuid4());extra_program=android.launch_program(native,extra,host,argv,env)
                    extraactor=launch(extra_program,extra,'emulator.json');extraowner=processes[-1][1]
                    os.kill(extraowner['pid'],signal.SIGKILL);os.kill(extraactor['pid'],signal.SIGTERM)
                    self.wait(lambda:jobs._birth(extraowner['pid']) is None and jobs._birth(extraactor['pid']) is None)
                    self.assertEqual(jobs.observe(native,extra,host,generation=generation)['state'],'unknown')
                    method=backend._idle
                    if os.environ.get('VPN_CONTROL_ANDROID_INVENTORY_BEFORE'):
                        self.assertEqual(os.environ['VPN_CONTROL_ANDROID_INVENTORY_BEFORE'],'1')
                        path=Path(__file__).parent/'fixtures'/'android_native_inventory_before.py'
                        namespace=dict(vars(android));exec(compile(path.read_text(),str(path),'exec'),namespace)
                        method=lambda value,deadline:namespace['_idle'](backend,value,deadline)
                    with self.assertRaisesRegex(providers.ProviderError,'android_idle_visibility_incomplete'):
                        method(observed,time.monotonic()+5)
                    self.assertEqual(len(list(native.iterdir())),4)
            finally:
                for actor,owner in processes:
                    if jobs._birth(actor['pid'])==actor['birth']:os.kill(actor['pid'],signal.SIGTERM)
                for actor,owner in processes:
                    end=time.monotonic()+5
                    while jobs._birth(owner['pid'])==owner['birth'] and time.monotonic()<end:time.sleep(.02)
                    if jobs._birth(owner['pid'])==owner['birth']:os.kill(owner['pid'],signal.SIGKILL)

    def test_source_refresh_retains_original_adb_owner_after_connection_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary).resolve();base.chmod(0o700)
            original={'pid':101,'birth':'original','uid':os.geteuid(),'commandSha256':'a'*64}
            current={'pid':202,'birth':'replacement','uid':os.geteuid(),'commandSha256':'b'*64}
            owner={'jobRoot':str(base/'jobs'),'rootGeneration':[1,2],'hostBinding':{'target':'same'}}
            jobs._publish(base/'private-adb-ready.json',{'root':owner['jobRoot'],'generation':owner['rootGeneration'],'hostBinding':owner['hostBinding'],'server':original})
            method=android._original_server
            if os.environ.get('VPN_CONTROL_ANDROID_SERVER_BEFORE'):
                self.assertEqual(os.environ['VPN_CONTROL_ANDROID_SERVER_BEFORE'],'1')
                path=Path(__file__).parent/'fixtures'/'android_original_server_before.py'
                namespace=dict(vars(android));namespace['registry']=registry
                exec(compile(path.read_text(),str(path),'exec'),namespace);method=namespace['_original_server']
            with mock.patch.object(registry,'adb_server_identity',return_value=current):
                self.assertEqual(method(base,{'durableOwner':owner},5042),original)


if __name__=='__main__':unittest.main()
