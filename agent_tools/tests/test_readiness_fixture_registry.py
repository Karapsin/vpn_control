import json
import os
from pathlib import Path
import tempfile
import sys
import types
import unittest
from unittest import mock

from agent_tools import readiness_fixture_registry as registry
from agent_tools import readiness,readiness_providers as providers


@unittest.skipUnless(os.name == "posix", "private fixture registry requires POSIX descriptors")
class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def record(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def test_private_record_is_read_under_physical_file_pin(self):
        path = self.record("record.json", {"value": 1})
        value, pin = registry._json(path)
        self.assertEqual(value, {"value": 1})
        self.assertEqual(len(pin["sha256"]), 64)
        self.assertGreater(len(pin["generation"]), 4)

    def test_duplicate_fields_and_public_readable_receipts_refuse(self):
        path = self.record("record.json", {})
        path.write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex(registry.FixtureRegistryError, "fixture_duplicate_field"):
            registry._json(path)
        path.chmod(0o644)
        with self.assertRaisesRegex(registry.FixtureRegistryError, "fixture_file_unsafe"):
            registry._json(path)

    def test_linked_or_symlinked_receipts_cannot_register_owned_fixtures(self):
        path = self.record("original.json", {"value": 1})
        alias = self.root / "alias.json"
        os.link(path, alias)
        with self.assertRaisesRegex(registry.FixtureRegistryError, "fixture_file_unsafe"):
            registry._json(alias)
        alias.unlink()
        alias.symlink_to(path)
        with self.assertRaises(OSError):
            registry._json(alias)

    def test_public_fixture_selector_rejects_paths_before_observing(self):
        for value in ("../other", "/tmp/fixture", "name.json", "UPPER", True):
            with self.subTest(value=value), mock.patch.object(registry, "_json") as read:
                with self.assertRaisesRegex(registry.FixtureRegistryError, "fixture_id_invalid"):
                    registry.registered_fixture(self.root, value)
                read.assert_not_called()

    def test_pid_reuse_between_command_observations_refuses(self):
        with mock.patch.object(registry.jobs, "_birth", side_effect=["birth-1", "birth-2"]), \
                mock.patch.object(registry, "_run", side_effect=[str(os.getuid()), "inert-process"]):
            with self.assertRaisesRegex(registry.FixtureRegistryError, "fixture_process_identity_changed"):
                registry.process_identity(123)

    def test_ambiguous_or_foreign_adb_listener_cannot_supply_connection_identity(self):
        with mock.patch.object(registry, "_run", return_value="p1\np2"):
            with self.assertRaisesRegex(registry.FixtureRegistryError, "fixture_adb_server_ambiguous"):
                registry.adb_server_identity(5038)
        with mock.patch.object(registry, "_run", side_effect=["p123", "/usr/bin/other"]), \
                mock.patch.object(registry, "process_identity", return_value={"pid": 123}):
            with self.assertRaisesRegex(registry.FixtureRegistryError, "fixture_adb_server_foreign"):
                registry.adb_server_identity(5038)

    def test_dispatch_binding_is_finite_and_excludes_private_backend_fields(self):
        from types import SimpleNamespace
        backend = SimpleNamespace(dispatch_binding=lambda family: {"qmpSocket": "/owned/relay.sock"})
        fixture = SimpleNamespace(adapter=SimpleNamespace(backend=backend))
        self.assertEqual(registry.dispatch_binding(fixture, "qmp"), {"qmpSocket": "/owned/relay.sock"})
        backend.dispatch_binding = lambda family: {"qmpSocket": "/owned/relay.sock", "password": "private-canary"}
        with self.assertRaisesRegex(registry.FixtureRegistryError, "^fixture_dispatch_binding_invalid$"):
            registry.dispatch_binding(fixture, "qmp")

    def test_original_job_source_alias_preserves_identity_and_only_recovers_transport(self):
        from agent_tools import readiness_android
        from types import SimpleNamespace
        directory=self.root/".rag_index/readiness-fixtures";directory.mkdir(parents=True,mode=0o700)
        original={"schemaVersion":2,"provider":"android-emulator","fixtureId":"old","sources":{"old":"source"},
                  "binding":{"target":"owned","machine":"task-avd"},"stateRoot":"unchanged","jobRootGeneration":[1,2],
                  "endpoint":{"port":5038},"qualification":{"original":"pin"}}
        current={**original,"fixtureId":"new","sources":{"new":"source"}}
        for name,value in (("old",original),("new",current)):
            path=directory/(name+".json");path.write_text(json.dumps(value));path.chmod(0o600)
        backend=SimpleNamespace(binding="original-adb-binding",adb="original-adb-executor",
                                capabilities=frozenset({"reconnect","start","reboot","wake_display"}),
                                observe=mock.Mock(return_value=readiness.Observation("owned","task-avd")),recover=mock.Mock())
        fixture=registry.RegisteredFixture("owned","task-avd",providers.ProviderAdapter("android-emulator","owned","task-avd",backend),self.root/"journal")
        def load(root,fixture_id):
            if fixture_id=="old":raise providers.ProviderError("android_lifecycle_spec_changed")
            self.assertEqual(fixture_id,"new");return fixture
        with mock.patch.object(registry,"registered_fixture",side_effect=load), \
                mock.patch.object(readiness_android,"_source_pins",return_value={"new":"source"}):
            # Original tools had only the normal fixture loader; source updates
            # made original-job inspection fail before reaching its old owner.
            resolve=getattr(registry,"registered_fixture_for_original",
                            lambda root,fixture_id,target,machine:registry.registered_fixture(root,fixture_id))
            observer=resolve(self.root,"old","owned","task-avd")
        self.assertEqual(observer.adapter.capabilities,frozenset({"reconnect"}))
        self.assertEqual(observer.journal_directory,fixture.journal_directory)
        self.assertEqual(observer.required_readiness,frozenset({"guest_agent"}))
        self.assertEqual(observer.adapter.backend.binding,"original-adb-binding")
        observed=readiness.Observation("owned","task-avd")
        observer.adapter.backend.recover("reconnect","1"*64,observed,1)
        backend.recover.assert_called_once()
        for action in ("start","reboot","resume","login","wake_display"):
            with self.assertRaisesRegex(registry.FixtureRegistryError,"original_fixture_observation_only"):
                observer.adapter.backend.recover(action,"1"*64,observed,1)
        with self.assertRaisesRegex(registry.FixtureRegistryError,"original_fixture_observation_only"):
            observer.adapter.backend.observe(readiness.Requirements(frozenset({"interactive_desktop"})),1)

    def test_original_job_alias_never_hides_non_source_or_current_custody_mismatch(self):
        from agent_tools import readiness_android
        directory=self.root/".rag_index/readiness-fixtures";directory.mkdir(parents=True,mode=0o700)
        original={"schemaVersion":2,"provider":"android-emulator","fixtureId":"old","sources":{"old":1},
                  "binding":{"target":"owned","machine":"task-avd"},"endpoint":{"port":5038}}
        for name,value in (("old",original),("new",{**original,"fixtureId":"new","sources":{"new":1},"endpoint":{"port":5039}})):
            path=directory/(name+".json");path.write_text(json.dumps(value));path.chmod(0o600)
        with mock.patch.object(registry,"registered_fixture",side_effect=providers.ProviderError("android_lifecycle_spec_changed")), \
                mock.patch.object(readiness_android,"_source_pins",return_value={"new":1}):
            with self.assertRaisesRegex(registry.FixtureRegistryError,"original_fixture_current_registration_missing"):
                registry.registered_fixture_for_original(self.root,"old","owned","task-avd")
        with mock.patch.object(registry,"registered_fixture",side_effect=providers.ProviderError("android_owner_unavailable")), \
                mock.patch.object(readiness_android,"_source_pins") as sources:
            with self.assertRaisesRegex(providers.ProviderError,"android_owner_unavailable"):
                registry.registered_fixture_for_original(self.root,"old","owned","task-avd")
            sources.assert_not_called()
        path=directory/"new.json";path.write_text(json.dumps({**original,"fixtureId":"new","sources":{"new":1}}));path.chmod(0o600)
        def untrusted_current(root,fixture_id):
            raise providers.ProviderError("android_lifecycle_spec_changed" if fixture_id=="old" else "android_owner_unavailable")
        with mock.patch.object(registry,"registered_fixture",side_effect=untrusted_current), \
                mock.patch.object(readiness_android,"_source_pins",return_value={"new":1}):
            with self.assertRaisesRegex(providers.ProviderError,"android_owner_unavailable"):
                registry.registered_fixture_for_original(self.root,"old","owned","task-avd")

    def test_lease_status_factory_uses_original_snapshot_without_live_fixture(self):
        module = types.ModuleType("agent_tools.readiness_windows")
        factory = mock.Mock(return_value="original-executor")
        module.lease_executor_from_snapshot = factory
        snapshot = {"provider": "raw-qemu-windows", "operationId": "original"}
        with mock.patch.dict(sys.modules, {module.__name__: module}), \
                mock.patch("agent_tools.readiness_windows", module, create=True), \
                mock.patch.object(registry, "registered_fixture", side_effect=AssertionError("live admission forbidden")):
            result = registry.lease_executor_from_snapshot(self.root, snapshot)
        self.assertEqual(result, "original-executor")
        factory.assert_called_once_with(self.root, snapshot)
        with self.assertRaisesRegex(registry.FixtureRegistryError, "^fixture_lease_executor_unavailable$"):
            registry.lease_executor_from_snapshot(self.root, {"provider": "unrecognized-private-canary"})

    def test_native_process_birth_is_observed_twice_on_host(self):
        actual = registry.process_identity(os.getpid())
        self.assertEqual(actual["pid"], os.getpid())
        self.assertEqual(actual["uid"], os.getuid())
        self.assertTrue(actual["birth"].startswith(("darwin:", "linux:")))
        self.assertEqual(len(actual["commandSha256"]), 64)


if __name__ == "__main__":
    unittest.main()
