"""Private selector derivation never supplies public ownership authority."""
from pathlib import Path
from types import SimpleNamespace
import unittest

from agent_tools import readiness_fixture_registry as registry
from agent_tools import readiness_providers as providers


class ExplicitTargetTests(unittest.TestCase):
    def fixture(self,backend):return SimpleNamespace(adapter=SimpleNamespace(backend=backend))

    def test_android_selector_is_actual_private_avd_not_alias_or_default(self):
        binding=providers.AndroidBinding('owned','task-avd',Path('/owned/adb'),'task-avd','emulator-5660',5038)
        fixture=self.fixture(SimpleNamespace(binding=binding))
        self.assertEqual(registry.explicit_target(fixture,'android'),'android:task-avd')

    def test_tart_and_libvirt_use_only_backend_derived_instance_names(self):
        backend=SimpleNamespace(dispatch_binding=lambda family:{'vmName':'actual-mac'}if family=='tart'else{'uri':'qemu+unix:///session?socket=/owned/socket','domain':'actual-domain'})
        self.assertEqual(registry.explicit_target(self.fixture(backend),'tart'),'tart:actual-mac')
        self.assertEqual(registry.explicit_target(self.fixture(backend),'libvirt'),'libvirt:actual-domain')

    def test_remote_qmp_path_or_local_relay_does_not_grant_local_disk_authority(self):
        for path in ('/home/remote/vm/qmp.sock','/owned/relay.sock'):
            backend=SimpleNamespace(dispatch_binding=lambda family:{'qmpSocket':path})
            with self.assertRaisesRegex(registry.FixtureRegistryError,'fixture_local_disk_authority_unavailable'):
                registry.explicit_target(self.fixture(backend),'qmp')


if __name__=='__main__':unittest.main()
