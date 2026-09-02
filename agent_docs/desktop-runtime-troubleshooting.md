# Desktop Runtime Details

This document owns desktop-specific runtime files, generated configs, and platform details. General safety rules and read-only diagnostic commands live in `agent_docs/runtime-troubleshooting.md`.

Desktop state and runtime files live under:

```text
~/.vpn-control-desktop/
```

Do not kill the running app or `sing-box` runtime during investigation unless the user approves it. Stopping VPN can interrupt the active connection.

On a Linux machine supervised without a GUI, the long-lived command is `vpn-control serve`. A service unit that invokes the internal `--headless-controller` argument will exit after its transient idle window when VPN is off and can enter a supervisor restart loop. Migrate that unit to `serve`; use `vpn-control status` for a read-only health check. Public setup guidance is in `docs/linux-headless-service.md`.

## Important Files

| Path | Purpose |
| --- | --- |
| `~/.vpn-control-desktop/workspace.json` | Persisted app state, selected location, source mode, runtime mode, refresh settings, and reconnect intent. |
| `~/.vpn-control-desktop/runtime/runtime-sing-box.log` | `sing-box` startup/runtime log for VPN and proxy-only mode. Start here for "proxy not ready", config errors, permission errors, and network failures. |
| `~/.vpn-control-desktop/runtime/runtime-sing-box-vpn.json` | Last generated VPN-mode `sing-box` config. |
| `~/.vpn-control-desktop/runtime/runtime-sing-box-proxy_only.json` | Last generated proxy-only `sing-box` config. |
| `~/.vpn-control-desktop/runtime/tools/` | Extracted bundled runtime tools used by the app. |

## VPN Mode Failures

Linux checks:

```bash
ls -l /dev/net/tun
getcap /opt/vpn-control/bin/sing-box
```

Expected Linux setup:

- `/dev/net/tun` exists. If missing, load it with `sudo modprobe tun`.
- The installed `sing-box` has `CAP_NET_ADMIN`.
- `scripts/arch_install.sh` handles both for local Arch installs.

Windows checks:

- VPN mode needs Administrator privileges.
- If proxy-only works but VPN mode does not, inspect `runtime-sing-box.log` for Wintun, route, or permission errors.
- Autostart can launch without a UAC prompt only if the installed startup mechanism grants the needed privileges.

macOS:

- Packaging exists, but full desktop VPN mode is not implemented yet.
- Use proxy-only mode when testing macOS packages.

## Proxy-Only Failures

Inspect:

```text
~/.vpn-control-desktop/runtime/runtime-sing-box.log
~/.vpn-control-desktop/runtime/runtime-sing-box-proxy_only.json
```

Common causes:

- The selected location cannot connect.
- The local proxy port is already in use.
- The app started `sing-box`, but readiness probing timed out.
- System or client proxy settings point to a stale host/port.

## Refresh And Reconnect Failures

Check `workspace.json` for selected location, selected subscription/group, refresh interval, runtime mode, and whether the previous session requested VPN reconnect.

Then inspect `runtime-sing-box.log` around the refresh time. A short controlled restart can happen when generated runtime config changes, but scheduled refresh should not leave VPN stopped.

## Find Best Troubleshooting

Desktop best-location checks should use direct probes so results are not biased by whether VPN is currently on. If results differ based on VPN status, inspect the connection log in the app and the runtime log for probe routing or timeout errors.
