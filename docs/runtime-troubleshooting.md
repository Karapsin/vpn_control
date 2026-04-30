# Runtime Troubleshooting

This document owns general runtime safety and read-only diagnostics before changing runtime code or stopping a running process. Desktop-specific file meanings and platform details live in `docs/desktop-runtime-troubleshooting.md`.

## Safety Rule

Do not kill VPN Control or its `sing-box` runtime unless the user explicitly approves it. Stopping VPN can interrupt the active coding session.

Start with read-only checks and logs.

## Desktop Read-Only Checks

Check running processes:

```bash
pgrep -af 'vpn-control|sing-box'
```

Check persisted state:

```bash
sed -n '1,220p' ~/.vpn-control-desktop/workspace.json
```

Check runtime log:

```bash
tail -n 200 ~/.vpn-control-desktop/runtime/runtime-sing-box.log
```

Check generated runtime configs:

```bash
sed -n '1,220p' ~/.vpn-control-desktop/runtime/runtime-sing-box-vpn.json
sed -n '1,220p' ~/.vpn-control-desktop/runtime/runtime-sing-box-proxy_only.json
```

Linux privilege checks:

```bash
ls -l /dev/net/tun
getcap /opt/vpn-control/bin/sing-box
```

These commands are diagnostic only. They should not interrupt the connection.

## What To Look For

`workspace.json`:

- selected profile/location
- source mode and selected subscription/group
- runtime mode, VPN vs proxy-only
- refresh interval
- reconnect intent after shutdown/reboot

`runtime-sing-box.log`:

- config parse failures
- missing TUN/Wintun privileges
- local port conflicts
- readiness probe timeouts
- remote connection errors

Generated config JSON:

- selected outbound profile
- route rules
- TUN inbound vs proxy-only inbound
- direct probe or direct route settings

## Desktop-Specific Guide

For file purposes and platform-specific notes, see `docs/desktop-runtime-troubleshooting.md`.

## Android Diagnostics

Android diagnostics should be exported from inside the app. Prefer exported diagnostics over shelling into the device unless an instrumentation test or emulator check specifically needs it.

If Android VPN/runtime behavior is broken, inspect:

- exported diagnostics text
- app connection log
- selected profile and routing settings in the app
- generated config coverage in `SingBoxConfigFactoryInstrumentedTest`

## When Runtime Interruption Is Required

If a check or fix requires stopping VPN:

1. Identify the current selected/running location.
2. Explain that stopping VPN can interrupt the coding connection.
3. Ask for explicit approval.
4. Prefer a controlled app action over killing processes.
5. Restore the prior connection when the test is complete, if practical.
