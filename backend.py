#!/usr/bin/env python3
"""WireGuard metadata, configuration and counters. Secrets never leave this process."""
import base64
import configparser
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
import uuid


def fields(line):
    result, value, escaped = [], '', False
    for char in line:
        if escaped:
            value += char
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == ':':
            result.append(value)
            value = ''
        else:
            value += char
    if escaped:
        value += '\\'
    return result + [value]


def nmcli(*args):
    result = subprocess.run(['nmcli', '--wait', '30', *args], capture_output=True,
                            text=True, timeout=35, env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'NetworkManager request failed')
    return result.stdout


def counters(device):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', device or '') or device in ('.', '..'):
        return None
    try:
        root = Path('/sys/class/net') / device / 'statistics'
        return {'rx': int((root / 'rx_bytes').read_text()),
                'tx': int((root / 'tx_bytes').read_text())}
    except (OSError, ValueError):
        return None


def profiles():
    output = nmcli('-t', '-e', 'yes', '-f', 'UUID,TYPE,NAME,STATE,DEVICE', 'connection', 'show')
    rows = []
    for line in output.splitlines():
        row = fields(line)
        if len(row) == 5 and row[1] == 'wireguard':
            active = row[3] == 'activated'
            rows.append(dict(uuid=row[0], name=row[2], state=row[3] or 'deactivated',
                             active=active, device=row[4], counters=counters(row[4]) if active else None))
    return sorted(rows, key=lambda row: row['name'].casefold())


def libraries():
    import gi
    gi.require_version('NM', '1.0')
    from gi.repository import NM, GLib
    return NM, GLib


def remote(identifier):
    NM, _ = libraries()
    client = NM.Client.new(None)
    conn = client.get_connection_by_uuid(str(uuid.UUID(identifier)))
    if not conn or conn.get_connection_type() != 'wireguard':
        raise ValueError('Select an existing WireGuard tunnel')
    return client, conn


def split_values(value):
    return [v.strip() for v in value.split(',') if v.strip()]


def valid_key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def parse_config(text):
    """Parse wg-quick format, retaining repeated Peer sections and rejecting hooks."""
    if len(text) > 262144:
        raise ValueError('Configuration is too large')
    count = 0
    lines = []
    for line in text.splitlines():
        if line.strip().lower() == '[peer]':
            count += 1
            line = f'[Peer{count}]'
        lines.append(line)
    parser = configparser.ConfigParser(interpolation=None, strict=True, inline_comment_prefixes=('#', ';'))
    try:
        parser.read_string('\n'.join(lines))
    except configparser.Error:
        raise ValueError('Invalid WireGuard configuration syntax') from None
    if 'Interface' not in parser or not count:
        raise ValueError('A configuration needs an Interface and at least one Peer')
    interface_keys = {'privatekey', 'address', 'dns', 'mtu', 'listenport'}
    peer_keys = {'publickey', 'presharedkey', 'endpoint', 'allowedips', 'persistentkeepalive'}
    for section in parser.sections():
        allowed = interface_keys if section == 'Interface' else peer_keys if re.fullmatch(r'Peer\d+', section) else None
        if allowed is None or set(parser[section]) - allowed:
            raise ValueError('Unsupported configuration options. Use PrivateKey, Address, DNS, MTU, ListenPort and standard peer fields; hooks and Table are not imported.')
    interface = dict(parser['Interface'])
    if not valid_key(interface.get('privatekey', '')):
        raise ValueError('Interface requires a valid private key')
    for address in split_values(interface.get('address', '')):
        ipaddress.ip_interface(address)
    peers = [dict(parser[f'Peer{i}']) for i in range(1, count + 1)]
    for peer in peers:
        if not valid_key(peer.get('publickey', '')) or ('presharedkey' in peer and not valid_key(peer['presharedkey'])):
            raise ValueError('Peer keys must be valid 32-byte base64 keys')
        if not peer.get('allowedips'):
            raise ValueError('Each peer needs AllowedIPs')
        for address in split_values(peer['allowedips']):
            ipaddress.ip_network(address, strict=False)
    return interface, peers


def apply_ip(conn, addresses, dns):
    NM, _ = libraries()
    networks = [ipaddress.ip_interface(a) for a in split_values(addresses)]
    servers = [ipaddress.ip_address(a) for a in split_values(dns)]
    for version, cls, family in [(4, NM.SettingIP4Config, socket.AF_INET), (6, NM.SettingIP6Config, socket.AF_INET6)]:
        setting = conn.get_setting_ip4_config() if version == 4 else conn.get_setting_ip6_config()
        if setting is None:
            setting = cls.new()
            conn.add_setting(setting)
        ips = [a for a in networks if a.version == version]
        setting.set_property('method', 'manual' if ips else 'disabled')
        setting.clear_addresses()
        setting.clear_dns()
        for address in ips:
            setting.add_address(NM.IPAddress.new(family, str(address.ip), address.network.prefixlen))
        for server in servers:
            if server.version == version:
                setting.add_dns(str(server))


def integer(value, minimum, maximum, label):
    try:
        result = int(value)
    except (ValueError, TypeError):
        raise ValueError(f'{label} must be a number') from None
    if not minimum <= result <= maximum:
        raise ValueError(f'{label} must be between {minimum} and {maximum}')
    return result


def build_tunnel(data):
    NM, GLib = libraries()
    content = data.get('config', '')
    if data.get('path'):
        content = read_config_file(data['path'])
    interface, peers = parse_config(content)
    name = str(data.get('name', '')).strip()
    if not name or len(name) > 128:
        raise ValueError('Give the tunnel a name (1–128 characters)')
    identifier = str(uuid.uuid4())
    conn = NM.SimpleConnection.new()
    setting = NM.SettingConnection.new()
    for key, value in [('id', name), ('uuid', identifier), ('type', 'wireguard'), ('autoconnect', False), ('interface-name', 'wg-' + identifier[:8])]:
        setting.set_property(key, value)
    conn.add_setting(setting)
    wg = NM.SettingWireGuard.new()
    wg.set_property('private-key', interface['privatekey'])
    wg.set_property('mtu', integer(interface.get('mtu', 0), 0, 65535, 'MTU'))
    wg.set_property('listen-port', integer(interface.get('listenport', 0), 0, 65535, 'Listen port'))
    for item in peers:
        peer = NM.WireGuardPeer.new()
        peer.set_public_key(item['publickey'], False)
        if item.get('presharedkey'):
            peer.set_preshared_key(item['presharedkey'], False)
        if item.get('endpoint') and not peer.set_endpoint(item['endpoint'], False):
            raise ValueError('Invalid peer endpoint; use host:port or [IPv6]:port')
        for address in split_values(item['allowedips']):
            peer.append_allowed_ip(address, False)
        peer.set_persistent_keepalive(integer(item.get('persistentkeepalive', 0), 0, 65535, 'Keepalive'))
        wg.append_peer(peer)
    conn.add_setting(wg)
    apply_ip(conn, interface.get('address', ''), interface.get('dns', ''))
    conn.verify()
    return conn, identifier


def add_tunnel(data):
    NM, GLib = libraries()
    conn, identifier = build_tunnel(data)
    client = NM.Client.new(None)
    loop = GLib.MainLoop()
    outcome = []
    def finished(source, result, _):
        try:
            source.add_connection_finish(result)
            outcome.append(None)
        except GLib.Error:
            outcome.append('NetworkManager could not save the tunnel. Check your permission to add connections.')
        loop.quit()
    client.add_connection_async(conn, True, None, finished, None)
    loop.run()
    if outcome[0]:
        raise RuntimeError(outcome[0])
    return {'ok': True, 'uuid': identifier}


def details(identifier):
    _, conn = remote(identifier)
    addresses, dns = [], []
    for setting in [conn.get_setting_ip4_config(), conn.get_setting_ip6_config()]:
        if setting:
            for i in range(setting.get_num_addresses()):
                address = setting.get_address(i)
                addresses.append(f'{address.get_address()}/{address.get_prefix()}')
            dns.extend(setting.get_dns(i) for i in range(setting.get_num_dns()))
    wg = conn.get_setting(libraries()[0].SettingWireGuard)
    peers = []
    for i in range(wg.get_peers_len()):
        peer = wg.get_peer(i)
        peers.append({'endpoint': peer.get_endpoint() or '', 'publicKey': peer.get_public_key(),
                      'allowedIPs': ', '.join(peer.get_allowed_ip(j) for j in range(peer.get_allowed_ips_len())),
                      'keepalive': peer.get_persistent_keepalive()})
    return {'uuid': identifier, 'name': conn.get_id(), 'addresses': ', '.join(addresses), 'dns': ', '.join(dns),
            'mtu': wg.get_mtu(), 'autoconnect': conn.get_setting_connection().get_autoconnect(), 'peers': peers}


def save(data):
    identifier = str(uuid.UUID(data['uuid']))
    name = str(data.get('name', '')).strip()
    if not name or len(name) > 128:
        raise ValueError('Give the tunnel a name (1–128 characters)')
    # Validate all fields before any mutation. nmcli modifies only these named properties;
    # existing peer keys and other secret settings remain untouched.
    addresses = [ipaddress.ip_interface(a) for a in split_values(data.get('addresses', ''))]
    dns = [ipaddress.ip_address(a) for a in split_values(data.get('dns', ''))]
    mtu = integer(data.get('mtu', 0), 0, 65535, 'MTU')
    remote(identifier)
    args = ['connection', 'modify', 'uuid', identifier, 'connection.id', name,
            'connection.autoconnect', 'yes' if data.get('autoconnect') is True else 'no', 'wireguard.mtu', str(mtu)]
    for version in [4, 6]:
        ips = [str(a) for a in addresses if a.version == version]
        args += [f'ipv{version}.addresses', ','.join(ips), f'ipv{version}.method', 'manual' if ips else 'disabled',
                 f'ipv{version}.dns', ','.join(str(a) for a in dns if a.version == version)]
    nmcli(*args)
    return {'ok': True, 'message': 'Saved. Reconnect an active tunnel to apply changes.'}


def switch(identifier):
    identifier = str(uuid.UUID(identifier))
    before = profiles()
    if not any(p['uuid'] == identifier for p in before):
        raise ValueError('Select an existing WireGuard tunnel')
    was_active = any(p['uuid'] == identifier and p['active'] for p in before)
    previous = [p['uuid'] for p in before if p['active'] and p['uuid'] != identifier]
    stopped = []
    try:
        if not was_active:
            nmcli('connection', 'up', 'uuid', identifier)
        for old in previous:
            stopped.append(old)
            nmcli('connection', 'down', 'uuid', old)
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
        rollback_failed = False
        for old in stopped:
            try:
                nmcli('connection', 'up', 'uuid', old)
            except (RuntimeError, subprocess.TimeoutExpired, OSError):
                rollback_failed = True
        if not was_active:
            try:
                nmcli('connection', 'down', 'uuid', identifier)
            except (RuntimeError, subprocess.TimeoutExpired, OSError):
                # A failed activation normally leaves nothing to deactivate.
                pass
        suffix = ' Some tunnels could not be restored; check their status.' if rollback_failed else ' Previous tunnels were retained or restored.'
        raise RuntimeError('Switch failed.' + suffix) from error
    return {'ok': True, 'message': 'Tunnel switched'}


CONFIG_LIMIT = 262144
QR_MARKER = 'user.omarchy-wireguard.qr'
QR_MARKER_VALUE = b'1'


@contextmanager
def open_directory(path):
    """Walk from / using directory descriptors; never traverse a symlink."""
    path = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def read_config_file(filename):
    path = Path(os.path.abspath(Path(filename).expanduser()))
    with open_directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > CONFIG_LIMIT:
            raise ValueError('Choose a regular configuration file no larger than 256 KiB')
        # The file can grow after fstat. Limit bytes read at the producer, too.
        content = bytearray()
        while len(content) <= CONFIG_LIMIT:
            chunk = os.read(fd, min(65536, CONFIG_LIMIT + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > CONFIG_LIMIT:
            raise ValueError('Configuration is too large')
        try:
            return content.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('Configuration must be UTF-8 text') from None
    finally:
        os.close(fd)


def require_private_directory(fd):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('QR runtime directory must be owned by you with mode 0700')


@contextmanager
def qr_directory():
    runtime = Path(os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}'))
    if not runtime.is_absolute():
        raise ValueError('QR runtime directory must be absolute')
    with open_directory(runtime) as parent:
        require_private_directory(parent)
        try:
            os.mkdir('omarchy-wireguard', mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
        fd = os.open('omarchy-wireguard', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            require_private_directory(fd)
            yield fd, runtime / 'omarchy-wireguard'
        finally:
            os.close(fd)


def clear_qr_files(directory):
    for name in os.listdir(directory):
        if not re.fullmatch(r'qr-[0-9a-f]{32}\.png', name):
            continue
        # Only remove our marked, private, singly-linked regular exports.
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory)
        except OSError:
            continue
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                continue
            try:
                if os.getxattr(fd, QR_MARKER) != QR_MARKER_VALUE:
                    continue
            except OSError:
                continue
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass
        finally:
            os.close(fd)


def clear_qr():
    with qr_directory() as (directory, _):
        clear_qr_files(directory)
    return {'ok': True}


def write_qr(content):
    with qr_directory() as (directory, path):
        clear_qr_files(directory)
        name = 'qr-' + uuid.uuid4().hex + '.png'
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        try:
            os.fchmod(fd, 0o600)
            os.setxattr(fd, QR_MARKER, QR_MARKER_VALUE)
            # qrencode writes to the already-open file, never reopens a path.
            result = subprocess.run(['qrencode', '-t', 'PNG', '-s', '6', '-m', '3', '-o', '-'],
                                    input=content, text=True, stdout=fd,
                                    stderr=subprocess.PIPE, timeout=10)
            if result.returncode:
                raise ValueError('This configuration is too large for a QR code')
        except BaseException:
            os.unlink(name, dir_fd=directory)
            raise
        finally:
            os.close(fd)
        return {'qr': str(path / name)}


def export_qr(identifier):
    _, conn = remote(identifier)
    secret_data = conn.get_secrets('wireguard', None)
    conn.update_secrets('wireguard', secret_data)
    wg = conn.get_setting(libraries()[0].SettingWireGuard)
    private_key = wg.get_private_key()
    if not private_key:
        raise ValueError('NetworkManager did not provide the private key for export')
    info = details(identifier)
    lines = ['[Interface]', 'PrivateKey = ' + private_key]
    if info['addresses']:
        lines.append('Address = ' + info['addresses'])
    if info['dns']:
        lines.append('DNS = ' + info['dns'])
    if info['mtu']:
        lines.append('MTU = ' + str(info['mtu']))
    if wg.get_listen_port():
        lines.append('ListenPort = ' + str(wg.get_listen_port()))
    for i in range(wg.get_peers_len()):
        peer = wg.get_peer(i)
        lines += ['', '[Peer]', 'PublicKey = ' + peer.get_public_key()]
        if peer.get_preshared_key():
            lines.append('PresharedKey = ' + peer.get_preshared_key())
        elif int(peer.get_preshared_key_flags()) & 3:
            raise ValueError('A peer key is unavailable; export cannot safely omit it')
        if peer.get_endpoint():
            lines.append('Endpoint = ' + peer.get_endpoint())
        lines.append('AllowedIPs = ' + ', '.join(peer.get_allowed_ip(j) for j in range(peer.get_allowed_ips_len())))
        if peer.get_persistent_keepalive():
            lines.append('PersistentKeepalive = ' + str(peer.get_persistent_keepalive()))
    return write_qr('\n'.join(lines) + '\n')


def main(args):
    if args == ['qr-clear']:
        return clear_qr()
    if len(args) == 2 and args[0] == 'qr':
        return export_qr(args[1])
    if len(args) == 2 and args[0] == 'switch':
        return switch(args[1])
    if args == ['status']:
        return {'profiles': profiles(), 'time': time.monotonic()}
    if args == ['add']:
        return add_tunnel(json.loads(sys.stdin.readline()))
    if args == ['save']:
        return save(json.loads(sys.stdin.readline()))
    if len(args) == 2 and args[0] == 'details':
        return details(args[1])
    if len(args) == 2 and args[0] in ('up', 'down'):
        identifier = str(uuid.UUID(args[1]))
        if not any(p['uuid'] == identifier for p in profiles()):
            raise ValueError('Select an existing NetworkManager WireGuard profile')
        nmcli('connection', args[0], 'uuid', identifier)
        return {'ok': True}
    raise ValueError('Unknown WireGuard action')


if __name__ == '__main__':
    try:
        print(json.dumps(main(sys.argv[1:])))
    except Exception as error:
        # Never echo parser snippets, D-Bus payloads or imported key material.
        safe = str(error) if isinstance(error, (ValueError, RuntimeError)) else 'Unable to complete request. Check the configuration, NetworkManager and connection permissions.'
        print(json.dumps({'error': safe}))
        sys.exit(1)
