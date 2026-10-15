"""Actual SSH argv producer; only fake route/selection authorities, no network."""
from dataclasses import replace
import importlib.util
from pathlib import Path, PurePosixPath
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'ssh_transport.py'
spec = importlib.util.spec_from_file_location('selected_arch_descendant_transport', SOURCE)
transport = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = transport
spec.loader.exec_module(transport)


class SelectedArchDescendantTests(unittest.TestCase):
    def setUp(self):
        host = transport.SshHost
        gateway = host('gateway','gateway.example.invalid',22,'outeruser',Path('/not-read/outer-key'),Path('/not-read/outer-known'))
        arch = host('archlinux','arch.example.invalid',22,'hostuser',Path('/not-read/arch-key'),PurePosixPath('/owned/arch-known'),
                    transport='nested',gateway='gateway',remote_host_alias='arch-route',
                    remote_control_path=PurePosixPath('/historical/stale-arch.sock'),remote_config_file=PurePosixPath('/owned/arch-config'))
        guest = host('ubuntu2341-owned-current','127.0.0.1',2341,'vpnfixture',Path('/not-read/guest-key'),PurePosixPath('/owned/guest-known'),
                     transport='nested',gateway='archlinux',remote_host_alias='guest-route',remote_config_file=PurePosixPath('/owned/guest-config'))
        self.config = transport.SshConfig(Path('/not-read/root'),{h.alias:h for h in (gateway,arch,guest)})
        self.command = ['python3','-I','-c','print("two words; $inert")']
        self.metadata = dict(innerOptions=['-S','/owned/selected-inner.sock','-o','ProxyCommand=false'],
                             outerOptions=['-S','/owned/selected-outer.sock','-o','ProxyCommand=false'],transportMode='direct')
        self.selection = SimpleNamespace(SelectionUnknown=type('SelectionUnknown',(RuntimeError,),{}),
                                         transport=transport,
                                         selection_present=lambda _root,alias:alias=='archlinux',
                                         selected_route_options=mock.Mock(return_value=self.metadata))
        self.session = SimpleNamespace(SessionUnknown=type('SessionUnknown',(RuntimeError,),{}),transport=SimpleNamespace(load_config=mock.Mock(return_value=self.config),SshConfigError=transport.SshConfigError),
                                       _outer_prefix=mock.Mock(return_value=(['outer-ssh','-F','/owned/outer-config'],'selected-gateway')),
                                       selected_options=mock.Mock())
        self.calls = []

    def build(self, host='ubuntu2341-owned-current', *, config=None, selected=True, outer_session=False, vanishes=False):
        def exists(path):
            if Path(path).name == 'ssh-channel-selection':
                self.calls.append('selection-directory')
                return selected and (not vanishes or len(self.calls)==1)
            return outer_session and Path(path).name == 'ssh-connection-session'
        with mock.patch.object(transport.os.path,'lexists',side_effect=exists), \
             mock.patch.object(transport,'_selection_module',return_value=self.selection), \
             mock.patch.object(transport,'_session_module',return_value=self.session):
            return transport.build_ssh_argv(config or self.config,host,command=self.command,ssh_binary='ssh-test',nested_ssh_binary='inner-test')

    def guest_command(self, guest, command):
        return ['inner-test','-F',str(guest.remote_config_file),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','UserKnownHostsFile='+str(guest.known_hosts_file),guest.remote_host_alias,shlex.join(command)]

    def expected_selected(self, command):
        inner=['inner-test','-F','/owned/arch-config',*self.metadata['innerOptions'],'-T','-o','BatchMode=yes',
               '-o','StrictHostKeyChecking=yes','-o','PermitLocalCommand=no','-o','ClearAllForwardings=yes',
               '-o','UpdateHostKeys=no','arch-route',shlex.join(command)]
        return ['ssh-test','-F','/owned/outer-config',*self.metadata['outerOptions'],'-o','PermitLocalCommand=no',
                '-o','ClearAllForwardings=yes','-o','UpdateHostKeys=no','-T','selected-gateway',shlex.join(inner)]

    def test_actual_descendant_producer_uses_selected_arch_route(self):
        argv=self.build()
        self.selection.selected_route_options.assert_called_once_with(self.config.root,'archlinux',self.config)
        self.assertEqual(argv,self.expected_selected(self.guest_command(self.config.hosts['ubuntu2341-owned-current'],self.command)))
        self.assertNotIn('/historical/stale-arch.sock',shlex.join(argv))
        guest=shlex.split(shlex.split(argv[-1])[-1])
        self.assertEqual(shlex.split(guest[-1]),self.command)
        self.session.selected_options.assert_not_called()

    def test_arch_itself_retains_exact_selected_producer(self):
        self.assertEqual(self.build('archlinux'),self.expected_selected(self.command))

    def test_all_descendant_layers_retained(self):
        leaf=replace(self.config.hosts['ubuntu2341-owned-current'],alias='fourth',gateway='ubuntu2341-owned-current',remote_host_alias='fourth-route',remote_config_file=PurePosixPath('/owned/fourth-config'))
        config=replace(self.config,hosts={**self.config.hosts,'fourth':leaf})
        self.session.transport.load_config.return_value=config
        nested=self.guest_command(self.config.hosts['ubuntu2341-owned-current'],self.guest_command(leaf,self.command))
        self.assertEqual(self.build('fourth',config=config),self.expected_selected(nested))
        self.selection.selected_route_options.assert_called_once_with(config.root,'archlinux',config)

    def test_complete_changed_configuration_refused(self):
        for field,value in (('port',2342),('known_hosts_file',PurePosixPath('/different/known')),('identity_file',Path('/different/key'))):
            changed=replace(self.config.hosts['ubuntu2341-owned-current'],**{field:value})
            self.session.transport.load_config.return_value=replace(self.config,hosts={**self.config.hosts,changed.alias:changed})
            with self.subTest(field=field),self.assertRaises(transport.SshConfigError):self.build()
        self.session._outer_prefix.assert_not_called()

    def test_selected_metadata_or_session_refusal_has_no_generic_fallback(self):
        self.selection.selected_route_options.return_value=None
        with self.assertRaises(transport.SshConfigError):self.build()
        self.selection.selected_route_options.side_effect=self.selection.SelectionUnknown('invalid-metadata')
        with self.assertRaises(transport.SshConfigError):self.build()
        self.selection.selected_route_options.side_effect=None;self.selection.selected_route_options.return_value=self.metadata
        self.session._outer_prefix.side_effect=self.session.SessionUnknown('expired-original')
        with self.assertRaises(transport.SshConfigError):self.build()
        self.session.selected_options.assert_not_called()

    def test_disappearing_selection_cannot_take_generic_route(self):
        self.selection.selected_route_options.return_value=None
        with self.assertRaises(transport.SshConfigError):self.build(vanishes=True)
        self.selection.selected_route_options.assert_called_once_with(self.config.root,'archlinux',self.config)

    def test_invalid_original_arch_suffix_refuses(self):
        arch=replace(self.config.hosts['archlinux'],transport='direct',gateway=None,remote_host_alias=None,remote_control_path=None,remote_config_file=None)
        config=replace(self.config,hosts={**self.config.hosts,'archlinux':arch})
        with self.assertRaises(transport.SshConfigError):self.build(config=config)
        self.session._outer_prefix.assert_not_called()

    def test_original_unknown_or_cyclic_route_refuses(self):
        for gateway in ('missing','ubuntu2341-owned-current'):
            guest=replace(self.config.hosts['ubuntu2341-owned-current'],gateway=gateway)
            config=replace(self.config,hosts={**self.config.hosts,guest.alias:guest})
            with self.subTest(gateway=gateway),self.assertRaises(transport.SshConfigError):self.build(config=config)
        self.selection.selected_route_options.assert_not_called()

    def test_no_selection_preserves_exact_generic_route(self):
        guest=self.guest_command(self.config.hosts['ubuntu2341-owned-current'],self.command)
        arch=['inner-test','-F','/owned/arch-config','-S','/historical/stale-arch.sock','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
              '-o','UserKnownHostsFile=/owned/arch-known','arch-route',shlex.join(guest)]
        gateway=self.config.hosts['gateway']
        expected=['ssh-test','-p','22','-l','outeruser','-i',str(gateway.identity_file),'-o','IdentitiesOnly=yes',
                  '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(gateway.known_hosts_file),'-o','ConnectTimeout=15',
                  '-o','NumberOfPasswordPrompts=1','-o','BatchMode=yes','gateway.example.invalid',shlex.join(arch)]
        self.assertEqual(self.build(selected=False),expected)
        self.selection.selected_route_options.assert_not_called()

    def test_real_selection_directory_removed_during_descendant_quoting_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=root/'.rag_index'/'ssh-channel-selection';directory.mkdir(parents=True)
            config=replace(self.config,root=root);self.session.transport.load_config.return_value=config
            original_join=shlex.join
            def remove_during_setup(argv):
                if directory.exists():directory.rmdir()
                return original_join(argv)
            def observe_actual_directory(*args):
                if not directory.exists():raise self.selection.SelectionUnknown('selection-disappeared')
                return self.metadata
            self.selection.selected_route_options.side_effect=observe_actual_directory
            self.assertTrue(directory.exists())
            with mock.patch.object(transport,'_selection_module',return_value=self.selection), \
                 mock.patch.object(transport,'_session_module',return_value=self.session), \
                 mock.patch.object(transport.shlex,'join',side_effect=remove_during_setup):
                with self.assertRaises(transport.SshConfigError):
                    transport.build_ssh_argv(config,'ubuntu2341-owned-current',command=self.command,ssh_binary='ssh-test',nested_ssh_binary='inner-test')
            self.assertFalse(directory.exists())
            self.selection.selected_route_options.assert_called_once_with(root,'archlinux',config)
            self.session.selected_options.assert_not_called()

    def test_absence_at_entry_stays_generic_if_directory_appears_during_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=root/'.rag_index'/'ssh-channel-selection'
            config=replace(self.config,root=root);self.session.transport.load_config.return_value=config
            original_join=shlex.join
            def create_during_setup(argv):
                directory.mkdir(parents=True,exist_ok=True)
                return original_join(argv)
            self.assertFalse(directory.exists())
            with mock.patch.object(transport,'_selection_module',return_value=self.selection), \
                 mock.patch.object(transport,'_session_module',return_value=self.session), \
                 mock.patch.object(transport.shlex,'join',side_effect=create_during_setup):
                argv=transport.build_ssh_argv(config,'ubuntu2341-owned-current',command=self.command,ssh_binary='ssh-test',nested_ssh_binary='inner-test')
            self.assertTrue(directory.exists())
            self.assertIn('/historical/stale-arch.sock',original_join(argv))
            self.selection.selected_route_options.assert_not_called()


if __name__=='__main__':unittest.main()
