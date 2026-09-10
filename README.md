# WireGuard for Omarchy

A native Omarchy bar widget for NetworkManager WireGuard tunnels.
Plugin ID: `virtualdatapro.wireguard` · Version 0.2.1.

## Features

- WireGuard dragon icon, Omarchy panel headers, buttons, switches and text fields.
- Tunnel status and individual enable/disable controls.
- **Switch here** activates the selected tunnel before deactivating the other active
  NetworkManager WireGuard tunnels. Failure triggers best-effort rollback of the
  previous state; rollback errors are reported. Switching can briefly overlap
  routes, and activation does not prove peer reachability.
- Import a `.conf` file or paste its contents. New tunnels are saved with
  autoconnect **off** and are never activated during import.
- Rename and edit addresses, DNS, MTU and autoconnect. Existing peers and keys
  are preserved; reconnect to apply changes to an active tunnel.
- QR export for scanning in the WireGuard app, after an explicit reveal action.
- A 60-second receive/send graph for the selected tunnel, sampled every two seconds.
- Desktop notifications when an active tunnel becomes inactive or disappears.
  Intentional disconnects/switches do not generate drop notifications.

Status is NetworkManager activation state, not a WireGuard handshake check.
A peer that stops responding while its interface stays up does not trigger a
notification. Graph rates use local interface byte counters and reset their
baseline on reconnect, counter reset, interface change, or a long sampling gap.

## Using the panel

Click the dragon in the bar. Select a tunnel row to view its traffic.
The row switch independently enables/disables that tunnel. **Switch here**
replaces the other active NetworkManager WireGuard tunnels with your selection.
The gear opens configuration and rename; the QR button opens export.
Use the plus button to import a tunnel.

Overview keyboard controls: ↑/↓ or j/k select, Enter toggles, R refreshes,
Escape closes. Forms use ordinary text input and focusable buttons.

## Import format

Supported Interface fields: `PrivateKey`, `Address`, `DNS` (IP addresses), `MTU`,
`ListenPort`. Supported Peer fields: `PublicKey`, `PresharedKey`, `Endpoint`,
`AllowedIPs`, `PersistentKeepalive`. Repeated Peer sections are supported.

Imports reject hooks, `Table`, `SaveConfig`, and unsupported options rather than
silently ignoring them. Use NetworkManager's own tooling for advanced routing
policies or configurations outside this supported subset. File imports reject symlinks
(including symlinked parent directories) and non-regular files. Reads use the
opened file descriptor and are limited to 256 KiB, including files that grow
during reading.

## Secrets and QR export

Imported configuration travels to the helper over stdin, never command-line
arguments. Secrets are not returned in status/details or written to project files.
NetworkManager stores the profile and applies its normal connection permissions.
No privilege rules are installed by this plugin.

QR export requests keys from NetworkManager only when selected. It creates a
0600 PNG in a 0700 directory under `$XDG_RUNTIME_DIR/omarchy-wireguard`, removed
on closing/backing out of the panel and at plugin startup. A QR code grants the
same access as the exported private key. Export covers the core WireGuard fields;
it does not reproduce custom NetworkManager route rules or DNS policies.

The runtime directory and export directory must be real directories owned by
the current user with mode 0700; unsafe existing paths are rejected, not repaired.
All directory traversal rejects symlinks. QR generation writes through an
exclusively created file descriptor; cleanup stays relative to the verified
export directory and only removes private, singly-linked regular files with
plugin-generated names and the plugin's `user.omarchy-wireguard.qr` extended
attribute. The runtime filesystem must support user extended attributes
(standard Linux `/run/user` tmpfs does). Unmarked files from older versions are
left untouched and expire with the runtime directory at logout/reboot.

## Requirements

- Omarchy with the Lua/Quickshell plugin shell
- NetworkManager with WireGuard support and `nmcli`
- Python 3, PyGObject and the libnm introspection bindings (`python-gobject`, `libnm`)
- `qrencode` for QR export
- `notify-send` for drop notifications

## Install

Install the external dependencies if they are missing:

```bash
omarchy pkg add networkmanager python python-gobject libnm qrencode libnotify
```

Then install and enable the plugin:

```bash
omarchy plugin add https://github.com/VirtualDataPro/omarchy-wireguard.git --enable
```

Adding the plugin does not import or activate a tunnel. NetworkManager must be
running and your user must have permission to manage its connections.

## Remove

```bash
omarchy plugin disable virtualdatapro.wireguard
python3 ~/.config/omarchy/plugins/virtualdatapro.wireguard/backend.py qr-clear
omarchy plugin remove virtualdatapro.wireguard
```

Removing the widget leaves your NetworkManager profiles and active connections
intact. Manage or remove those separately with NetworkManager when desired.

## Local development installation

Clone this repository, change into it, and link it into the user plugin directory:

```bash
omarchy plugin validate "$PWD"
mkdir -p ~/.config/omarchy/plugins
ln -s "$PWD" ~/.config/omarchy/plugins/virtualdatapro.wireguard
omarchy-shell shell rescanPlugins
omarchy plugin enable virtualdatapro.wireguard --section right
```

`ln -s` intentionally fails when an installation already exists. Reload cached
QML after editing the symlinked project with `omarchy restart shell`.
Open the panel with:

```bash
omarchy-shell virtualdatapro.wireguard open
```

## Validation

```bash
python3 -m unittest discover -s tests -v
node tests/test_traffic.cjs
omarchy plugin validate "$PWD"
python3 backend.py status
```

Tests cover import parsing/native connection construction, disabled imports,
UUID targeting, switching order/rollback/timeouts, QR symlink and directory
replacement attacks, private-file cleanup, bounded configuration reads,
counter resets, and drop-notification transitions. Live NetworkManager import,
rename/save, and QR export were verified using a temporary disabled profile,
then that profile was deleted. The maintainer also verified real tunnel traffic
and switching on their Omarchy desktop. Actual outage-notification delivery has
not yet been manually tested.

## Attribution

Dragon SVG: [Simple Icons, WireGuard](https://github.com/simple-icons/simple-icons/blob/develop/icons/wireguard.svg).
The SVG is an upstream asset; the project's MIT license does not claim ownership
of the WireGuard marks. “WireGuard” and the “WireGuard” logo are registered
trademarks of Jason A. Donenfeld. This is an independent third-party plugin.
[WireGuard](https://www.wireguard.com/) · [Trademark policy](https://www.wireguard.com/trademark-policy/).

[NetworkManager CLI reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html).
