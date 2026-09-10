import importlib.util
import os
import stat
import tempfile
from types import SimpleNamespace
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
            with patch.object(backend, 'remote', return_value=(None, wrapper)), patch.object(backend, 'details', return_value=info), patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(directory)}), patch.object(backend.subprocess, 'run', return_value=Mock(returncode=0)) as command:
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


class FileBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)
        self.environment = patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(self.runtime)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.directory = self.runtime / 'omarchy-wireguard'

    def test_runtime_symlink_rejected(self):
        link = self.runtime / 'runtime-link'
        link.symlink_to(self.runtime, target_is_directory=True)
        with patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(link)}):
            with self.assertRaises(OSError):
                backend.clear_qr()

    def test_qr_directory_symlink_does_not_chmod_or_delete_target(self):
        target = self.runtime / 'victim'
        target.mkdir(mode=0o755)
        victim = target / ('qr-' + 'a' * 32 + '.png')
        victim.write_bytes(b'keep me')
        self.directory.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            backend.clear_qr()
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
        self.assertEqual(victim.read_bytes(), b'keep me')

    def test_directory_type_permissions_and_owner_rejected(self):
        self.directory.write_text('not a directory')
        with self.assertRaises(OSError):
            backend.clear_qr()
        self.directory.unlink()
        self.directory.mkdir(mode=0o755)
        with self.assertRaises(ValueError):
            backend.clear_qr()
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o755)
        self.directory.chmod(0o700)
        with patch.object(backend.os, 'getuid', return_value=os.getuid() + 1):
            with self.assertRaises(ValueError):
                backend.clear_qr()
        self.runtime.chmod(0o755)
        with self.assertRaises(ValueError):
            backend.clear_qr()

    def test_cleanup_only_removes_marked_private_regular_exports(self):
        with backend.qr_directory() as (fd, path):
            owned = path / ('qr-' + 'a' * 32 + '.png')
            owned.write_bytes(b'owned')
            owned.chmod(0o600)
            os.setxattr(owned, backend.QR_MARKER, backend.QR_MARKER_VALUE)
            unknown = path / ('qr-' + 'b' * 32 + '.png')
            unknown.write_bytes(b'unrelated')
            unknown.chmod(0o600)
            link = path / ('qr-' + 'c' * 32 + '.png')
            link.symlink_to(owned)
            subdir = path / ('qr-' + 'd' * 32 + '.png')
            subdir.mkdir()
            fifo = path / ('qr-' + 'e' * 32 + '.png')
            os.mkfifo(fifo)
            hardlink = path / ('qr-' + 'f' * 32 + '.png')
            hardlink.write_bytes(b'shared')
            hardlink.chmod(0o600)
            os.setxattr(hardlink, backend.QR_MARKER, backend.QR_MARKER_VALUE)
            os.link(hardlink, path / 'keep-hardlink')
        backend.clear_qr()
        self.assertFalse(owned.exists())
        self.assertTrue(link.is_symlink())
        self.assertTrue(subdir.is_dir())
        self.assertTrue(fifo.exists())
        self.assertEqual(unknown.read_bytes(), b'unrelated')
        self.assertEqual(hardlink.read_bytes(), b'shared')

    def test_replaced_directory_cannot_redirect_qr_output_or_cleanup(self):
        original_run = backend.subprocess.run
        moved = self.runtime / 'original'
        victim = self.runtime / 'victim'
        victim.mkdir(mode=0o700)
        def replace_then_encode(*args, **kwargs):
            self.directory.rename(moved)
            self.directory.symlink_to(victim, target_is_directory=True)
            return original_run(*args, **kwargs)
        with patch.object(backend.subprocess, 'run', side_effect=replace_then_encode):
            result = backend.write_qr('test content without secrets')
        self.assertEqual(list(victim.iterdir()), [])
        output = moved / Path(result['qr']).name
        self.assertTrue(output.read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaises(OSError):
            backend.clear_qr()

    def test_failed_encoder_cleans_up_private_output(self):
        for failure in (backend.subprocess.TimeoutExpired('qrencode', 10), OSError('missing')):
            with patch.object(backend.subprocess, 'run', side_effect=failure):
                with self.assertRaises(type(failure)):
                    backend.write_qr('test')
            self.assertEqual(list(self.directory.iterdir()), [])
        with patch.object(backend.subprocess, 'run', return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(ValueError):
                backend.write_qr('test')
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_qr_name_collision_never_overwrites(self):
        self.directory.mkdir(mode=0o700)
        victim = self.directory / ('qr-' + 'a' * 32 + '.png')
        victim.write_bytes(b'keep')
        with patch.object(backend.uuid, 'uuid4', return_value=SimpleNamespace(hex='a' * 32)):
            with self.assertRaises(FileExistsError):
                backend.write_qr('test')
        self.assertEqual(victim.read_bytes(), b'keep')

    def test_config_symlink_directory_and_fifo_rejected(self):
        config = self.runtime / 'config'
        config.write_text(ConfigurationTests.config())
        link = self.runtime / 'link'
        link.symlink_to(config)
        with self.assertRaises(OSError):
            backend.read_config_file(link)
        with self.assertRaises(ValueError):
            backend.read_config_file(self.runtime)
        fifo = self.runtime / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            backend.read_config_file(fifo)

    def test_config_read_stays_on_opened_inode(self):
        config = self.runtime / 'config'
        config.write_text('original')
        replacement = self.runtime / 'replacement'
        replacement.write_text('replacement')
        original_fstat = os.fstat
        def swap(fd):
            info = original_fstat(fd)
            replacement.replace(config)
            return info
        with patch.object(backend.os, 'fstat', side_effect=swap):
            self.assertEqual(backend.read_config_file(config), 'original')
        self.assertEqual(config.read_text(), 'replacement')

    def test_config_size_limit_including_growth_after_stat(self):
        config = self.runtime / 'config'
        config.write_bytes(b'x' * backend.CONFIG_LIMIT)
        self.assertEqual(len(backend.read_config_file(config)), backend.CONFIG_LIMIT)
        config.write_bytes(b'x' * (backend.CONFIG_LIMIT + 100))
        with self.assertRaises(ValueError):
            backend.read_config_file(config)
        real_read = os.read
        with patch.object(backend.os, 'fstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)), \
                patch.object(backend.os, 'read', wraps=real_read) as read:
            with self.assertRaises(ValueError):
                backend.read_config_file(config)
            self.assertEqual(sum(call.args[1] for call in read.call_args_list), backend.CONFIG_LIMIT + 1)

    def test_invalid_encoding_does_not_echo_contents(self):
        config = self.runtime / 'config'
        config.write_bytes(b'secret-value\xff')
        with self.assertRaises(ValueError) as caught:
            backend.read_config_file(config)
        self.assertNotIn('secret-value', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
