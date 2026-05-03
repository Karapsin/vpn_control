# Runtime Troubleshooting

This document owns general runtime safety and read-only diagnostics before changing runtime code or stopping a running process. Desktop-specific file meanings and platform details live in `docs/desktop-runtime-troubleshooting.md`.

## Safety Rule

Do not kill VPN Control or its `sing-box` runtime unless the user explicitly approves it. Stopping VPN can interrupt the active coding session.

Start with read-only, redacted checks. Do not paste full workspace, runtime config, or log dumps into reports unless they are sanitized; those files can contain endpoints, subscription URLs, or credentials.

## Desktop Read-Only Checks

Check running processes:

```bash
pgrep -af 'vpn-control|sing-box'
```

Identify the persisted selected/running location before requesting approval to stop anything:

```bash
python3 - <<'PY'
import json
import pathlib

workspace = pathlib.Path.home() / ".vpn-control-desktop" / "workspace.json"
root = json.loads(workspace.read_text())
state = root.get("persisted_state", {})
selected_records = [
    {
        "name": item.get("name", ""),
        "server_present": bool(item.get("server")),
        "source_url_present": bool(item.get("source_url")),
        "is_valid": item.get("is_valid", True),
    }
    for item in root.get("locations", [])
    if item.get("is_selected") is True
]

print("resume_connection_on_launch=", root.get("resume_connection_on_launch"))
print("is_vpn_running=", state.get("is_vpn_running"))
print("app_mode=", state.get("app_mode"))
print("profile_source_mode=", state.get("profile_source_mode"))
print("active_subscription_id=", state.get("active_subscription_id"))
print("selected_profile_name=", state.get("selected_profile_name"))
print("selected_profile_server_present=", bool(state.get("selected_profile_server")))
print("selected_profile_source_url_present=", bool(state.get("selected_profile_source_url")))
print("selected_profile_raw_link_present=", bool(state.get("selected_profile_raw_link")))
print("selected_location_records=", selected_records)
PY
```

The canonical persisted selection is under `persisted_state.selected_profile_name`, `persisted_state.selected_profile_server`, `persisted_state.selected_profile_raw_link`, and `persisted_state.selected_profile_source_url`. The top-level `resume_connection_on_launch` field records whether desktop should reconnect after launch.

Check recent runtime log lines locally. Redact endpoints, subscription URLs, UUIDs, credentials, and tokens before sharing output:

```bash
tail -n 200 ~/.vpn-control-desktop/runtime/runtime-sing-box.log
```

Identify the selected outbound in the generated config without dumping secrets:

```bash
python3 - <<'PY'
import json
import pathlib

runtime_dir = pathlib.Path.home() / ".vpn-control-desktop" / "runtime"
for name in ("runtime-sing-box-vpn.json", "runtime-sing-box-proxy_only.json"):
    path = runtime_dir / name
    if not path.exists():
        continue
    root = json.loads(path.read_text())
    proxy = next((item for item in root.get("outbounds", []) if item.get("tag") == "proxy"), None)
    if proxy:
        print(name, {
            "type": proxy.get("type"),
            "server_present": bool(proxy.get("server")),
            "server_port": proxy.get("server_port"),
        })
PY
```

If the redacted helpers are not enough, inspect full local files only for yourself and sanitize before reporting:

```bash
sed -n '1,220p' ~/.vpn-control-desktop/workspace.json
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

- `persisted_state.selected_profile_name`
- `persisted_state.selected_profile_server`
- `persisted_state.selected_profile_source_url`
- `persisted_state.profile_source_mode`
- `persisted_state.active_subscription_id`
- `persisted_state.app_mode`
- `persisted_state.is_vpn_running`
- `persisted_state.subscription_refresh_policy`
- `persisted_state.subscription_refresh_custom_hours`
- top-level `resume_connection_on_launch`

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
