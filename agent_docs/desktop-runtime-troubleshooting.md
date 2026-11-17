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
| `~/.vpn-control-desktop/workspace-recovery.json` | Written only when `workspace.json` could not be replaced; the newest readable of the two is loaded and the next successful save removes it. |
| `~/.vpn-control-desktop/workspace.json.unreadable-<UTC time>-<random>` | A saved workspace (or `workspace-recovery.json`) that existed but could not be read or decoded, or that a newer version wrote in another `format`, kept byte-for-byte without group or other access before an older readable copy or the defaults were loaded (`PRODUCT-003`). The GUI status and log name it, also on the next start when the start that kept it stopped before saving, and `status` warns `UNREADABLE_WORKSPACE_KEPT` while any such file remains. To restore one, stop every VPN Control process for that folder, repair it or put it back as `workspace.json`, and start again; delete it once it is no longer needed. |
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
- An approved VPN start that ends `RUNTIME_FAILED` before the old runtime stops failed in the scoped broker. The
  broker's exit code names the last step it entered, and the product writes it as a `vpn-control: scoped Windows
  broker ended at step ...` line to `runtime-sing-box.log` and as `windows_vpn_broker_last_failure` in the
  diagnostics export. The public error code stays `RUNTIME_FAILED`. The table is `VpnBrokerStep` in
  `windows-vpn-broker.cs` and `DesktopWindowsBrokerExit` in Kotlin; `DesktopWindowsBrokerOwnerAccessTest` keeps
  them equal.

  | Exit | Step | Refusal point |
  | --- | --- | --- |
  | 0 | `success` | The runtime ran and ended. |
  | 1 | `unclassified` | A failure outside every step below. |
  | 10 | `arguments` | The broker's argv. |
  | 11 | `runtime-authority` | The compiled runtime digest. |
  | 20 | `owner-open` | `OpenProcess` of the owner, or a query on that handle (admission and `Run`). |
  | 21 | `owner-token` | `OpenProcessToken` of the owner: its token DACL refused the broker's account. |
  | 22 | `owner-identity` | The owner's PID, creation time, token user or liveness differ. |
  | 23 | `package-admission` | The owner and broker images, their ancestry, ProgramData and the install gate. |
  | 30 | `pipe-create` | The pipe's DACL or `CreateNamedPipe`. |
  | 31 | `pipe-connect` | No client within 180 s. |
  | 32 | `peer` | The pipe client is not the owner, or the owner ended. |
  | 33 | `protocol` | The protocol version. |
  | 34 | `job` | `DuplicateHandle` of the owner's job or its limits. |
  | 35 | `resource-preparation` | The mutable resource frame (protocol 5). |
  | 40 | `runtime-image` | The runtime bytes or their digest. |
  | 41 | `stage` | The ProgramData pins, the private stage and its admission gate. |
  | 42 | `original-user` | The owner token duplicate for mutable publication. |
  | 43 | `configuration` | The configuration, its resources and normalization. |
  | 44 | `child-create` | Handles, attributes and `CreateProcess`. |
  | 45 | `ready-ack` | The child PID acknowledgment, COMMIT and resume. |
  | 50 | `running` | After the start was acknowledged. |
- VPN Control listens only on the loopback (`CONFIG-012`). A Windows Defender Firewall prompt to allow network access for VPN Control or `vpn-control-cli.exe` is a product defect, not a step to approve; record the operation and the time it appeared.

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
