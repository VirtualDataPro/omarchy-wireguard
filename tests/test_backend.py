import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('backend', Path(__file__).parents[1] / 'backend.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)
UUID = '11111111-1111-1111-1111-111111111111'


class BackendTests(unittest.TestCase):
    def test_escaped_names_and_non_wireguard_filtered(self):
        output = f'{UUID}:wireguard:Work\\: VPN\\\\office:activated:wg0\nother:ethernet:Wired:activated:eth0\n'
        with patch.object(backend, 'nmcli', return_value=output), patch.object(backend, 'counters', return_value=None):
            self.assertEqual(backend.profiles(), [dict(uuid=UUID, name='Work: VPN\\office', state='activated', active=True, device='wg0', counters=None)])

    def test_rejects_non_wireguard_before_action(self):
        with patch.object(backend, 'profiles', return_value=[]), patch.object(backend, 'nmcli') as command:
            with self.assertRaises(ValueError):
                backend.main(['down', UUID])
            command.assert_not_called()

    def test_uuid_passed_as_argument(self):
        with patch.object(backend, 'profiles', return_value=[{'uuid': UUID}]), patch.object(backend, 'nmcli') as command:
            backend.main(['up', UUID])
            command.assert_called_once_with('connection', 'up', 'uuid', UUID)

    def test_invalid_uuid_rejected(self):
        with self.assertRaises(ValueError):
            backend.main(['up', '$(touch /tmp/unwanted)'])


if __name__ == '__main__':
    unittest.main()

class ConfigurationTests(unittest.TestCase):
    @staticmethod
    def config():
        import base64
        key = base64.b64encode(bytes(range(32))).decode()
        return f'[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32, fd00::2/128\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = example.com:51820\nPersistentKeepalive = 25\n'

    def test_native_connection_is_disabled_and_has_both_families(self):
        conn, identifier = backend.build_tunnel({'name': 'Test tunnel', 'config': self.config()})
        self.assertFalse(conn.get_setting_connection().get_autoconnect())
        self.assertEqual(conn.get_setting_ip4_config().get_num_addresses(), 1)
        self.assertEqual(conn.get_setting_ip6_config().get_num_addresses(), 1)
        self.assertEqual(conn.get_setting(backend.libraries()[0].SettingWireGuard).get_peer(0).get_persistent_keepalive(), 25)
        self.assertTrue(conn.verify())

    def test_import_keeps_multiple_peers(self):
        config = self.config()
        second = config.split('[Peer]')[1].replace('example.com', 'second.example.com')
        interface, peers = backend.parse_config(config + '\n[Peer]' + second)
        self.assertEqual(len(peers), 2)

    def test_hooks_rejected_without_echoing_command(self):
        config = self.config().replace('[Interface]', '[Interface]\nPostUp = secret-command')
        with self.assertRaises(ValueError) as caught:
            backend.parse_config(config)
        self.assertNotIn('secret-command', str(caught.exception))

    def test_invalid_private_key_rejected(self):
        with self.assertRaises(ValueError):
            backend.parse_config('[Interface]\nPrivateKey=bad\n[Peer]\nPublicKey=bad')


class SwitchingTests(unittest.TestCase):
    old = '22222222-2222-2222-2222-222222222222'
    other = '33333333-3333-3333-3333-333333333333'

    def profiles(self):
        return [{'uuid': UUID, 'active': False}, {'uuid': self.old, 'active': True}]

    def test_connects_target_before_disconnecting_previous(self):
        from unittest.mock import call
        with patch.object(backend, 'profiles', return_value=self.profiles()), patch.object(backend, 'nmcli') as command:
            backend.switch(UUID)
            self.assertEqual(command.call_args_list, [call('connection', 'up', 'uuid', UUID), call('connection', 'down', 'uuid', self.old)])

    def test_failed_activation_keeps_old_tunnel(self):
        from unittest.mock import call
        with patch.object(backend, 'profiles', return_value=self.profiles()), patch.object(backend, 'nmcli', side_effect=RuntimeError('failed')) as command:
            with self.assertRaises(RuntimeError): backend.switch(UUID)
            self.assertNotIn(call('connection', 'down', 'uuid', self.old), command.call_args_list)

    def test_partial_teardown_rolls_back(self):
        from unittest.mock import call
        profiles = self.profiles() + [{'uuid': self.other, 'active': True}]
        with patch.object(backend, 'profiles', return_value=profiles), patch.object(backend, 'nmcli', side_effect=['', '', RuntimeError('failed'), '', '', '']) as command:
            with self.assertRaises(RuntimeError): backend.switch(UUID)
            self.assertEqual(command.call_args_list[-3:], [call('connection', 'up', 'uuid', self.old), call('connection', 'up', 'uuid', self.other), call('connection', 'down', 'uuid', UUID)])

    def test_timeout_rolls_back(self):
        from unittest.mock import call
        with patch.object(backend, 'profiles', return_value=self.profiles()), patch.object(backend, 'nmcli', side_effect=[backend.subprocess.TimeoutExpired('nmcli', 35), '']) as command:
            with self.assertRaises(RuntimeError): backend.switch(UUID)
            self.assertEqual(command.call_args_list[-1], call('connection', 'down', 'uuid', UUID))

class ExportTests(unittest.TestCase):
    def test_qr_export_uses_private_runtime_file_and_stdin(self):
        import tempfile
        from unittest.mock import Mock
        conn, identifier = backend.build_tunnel({'name': 'Test', 'config': ConfigurationTests.config()})
        wrapper = Mock()
        wrapper.get_setting.side_effect = conn.get_setting
        info = {'addresses': '10.0.0.2/32', 'dns': '1.1.1.1', 'mtu': 0}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with patch.object(backend, 'remote', return_value=(None, wrapper)), patch.object(backend, 'details', return_value=info), patch.object(backend, 'qr_directory', return_value=directory), patch.object(backend.subprocess, 'run', return_value=Mock(returncode=0)) as command:
                result = backend.export_qr(identifier)
                self.assertEqual(Path(result['qr']).stat().st_mode & 0o777, 0o600)
                argv = command.call_args.args[0]
                self.assertNotIn('PrivateKey', ' '.join(argv))
                self.assertIn('PrivateKey = ', command.call_args.kwargs['input'])
                backend.clear_qr()
                self.assertFalse(Path(result['qr']).exists())

    def test_unknown_interface_counters_do_not_traverse(self):
        self.assertIsNone(backend.counters('../secrets'))
        self.assertIsNone(backend.counters('..'))
