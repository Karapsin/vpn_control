# SSH Routing

VPN Control can connect to a selected VPN location through an SSH server on your home network:

```text
device -> pinned SSH connection -> loopback-only home relay -> selected VPN -> internet
```

This is useful on public networks that block VPN handshakes or subscription endpoints. The feature is optional and disabled by default.

## Prepare The Home Relay

The SSH account must be allowed to open TCP forwarding channels. On Linux `amd64` and `arm64`, run:

```bash
./scripts/install_home_relay.sh --port 10808
```

The installer does not require or assume systemd. It uses an existing `sing-box`, or downloads and verifies the repository-pinned version from the official release when none is installed. It writes an owner-only runtime, configuration, and launcher under `${XDG_DATA_HOME:-$HOME/.local/share}/vpn-control-home-relay`. Run the printed launcher with the supervisor available on that host, such as `tmux`, `screen`, runit, s6, OpenRC, or systemd. Other Linux architectures can pass an existing binary with `--sing-box /path/to/sing-box`.

The SOCKS relay listens only on `127.0.0.1`. Do not expose its port on the LAN or internet; VPN Control reaches it through the authenticated SSH connection.

The SSH transport itself, including any DNS lookup needed to resolve its hostname, necessarily uses the device's current network. Enter the SSH server's verified IP address instead of a hostname if that network blocks external DNS. Once SSH is established, application traffic follows the chain above.

## Configure A Device

Open **Additional settings → SSH Routing** and enter:

- SSH host, port, and user (for example, `example.com`, `228`, and `kardinal`).
- The relay port printed by the installer (default `10808`).
- A pinned public host key. Obtain it through a trusted path. For example, run `ssh-keyscan -p 228 example.com` from a network where you can verify the result, then compare its fingerprint with `ssh-keygen -lf` on the home host.
- A dedicated, unencrypted SSH private key imported through the file picker. The app stores it in private application storage with owner-only permissions/ACLs and never writes it into the workspace/settings JSON.

Prefer a dedicated SSH account and key. Restrict the key in `authorized_keys` as appropriate for the host, while retaining the TCP forwarding needed by the relay.

If settings are changed while connected, VPN Control saves them without interrupting the session and asks before restarting. Until restart, the settings menu shows a pending indicator.

## Subscription And Find Best Behavior

- With an active VPN/proxy session, subscription downloads use that session's localhost management proxy.
- Without an active session, downloads use the home relay when SSH Routing is enabled; otherwise they connect directly.
- A failed active session may fall back to the home route only when that route is enabled. A failed home route never silently falls back to the public network.
- Desktop Find Best candidate traffic runs only in the dedicated probe process, so an already-active VPN does not bias the result. Custom full sing-box configs remain manual-only in Find Best.

Custom sing-box configs are rewritten only when every outbound path is recognized and can be chained through the home route. VPN Control rejects unknown outbound types instead of risking a direct leak.
