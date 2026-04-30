# Desktop Smoke Testing

Use this checklist for Linux and Windows desktop verification. Android device/emulator protocol testing stays in `../protocol_smoke_checklist.md`.

## Preconditions

- Install the current desktop package for the platform being tested.
- Record the artifact path or GitHub Actions run used for the install.
- Use at least one known-good subscription or location.
- Do not stop an active VPN/runtime unless the user approves the interruption.

Linux VPN mode prerequisites:

- `/dev/net/tun` exists.
- The installed `sing-box` has `CAP_NET_ADMIN`.

Windows VPN mode prerequisites:

- Launch VPN Control as Administrator for VPN mode.
- Proxy-only mode can be tested without Administrator privileges.

## Automated Package Smoke

Linux:

```bash
./scripts/package_linux_desktop.sh
```

Windows in local VM:

```bash
./scripts/package_windows_desktop_vm.sh
```

macOS on a Mac:

```bash
./scripts/package_macos_desktop.sh
```

These scripts run extracted package smoke checks unless `--skip-package-regression-tests` is used.

## Manual Linux/Windows Flow

1. First launch

   - Open the app from the installed launcher.
   - Confirm no default subscriptions, default routing rules, or demo data appear.
   - Confirm the app writes `~/.vpn-control-desktop/workspace.json`.

2. Import and refresh

   - Add a subscription.
   - Refresh active subscriptions.
   - Confirm locations appear and cached-location counts update.

3. Find best

   - Run `Find Best`.
   - Confirm candidates are tested and a reachable location is selected.
   - Repeat once while VPN is already on; the result should not be biased by VPN state.

4. Proxy-only mode

   - Switch runtime mode to proxy-only.
   - Start the connection.
   - Confirm the local proxy accepts traffic from a client app.
   - Stop and reconnect using the saved selection.

5. VPN mode

   - Switch runtime mode to VPN.
   - Start the connection with the selected location.
   - Confirm ordinary browsing goes through the VPN.
   - Stop and reconnect using the saved selection.

6. Scheduled refresh

   - Set a short refresh interval of at least 5 minutes.
   - Leave VPN running through one refresh.
   - Confirm refresh does not leave VPN stopped. A short restart is acceptable when config changes.

7. Tray and single instance

   - Close the window and confirm the app hides to tray instead of exiting.
   - Launch the app again and confirm it shows the existing instance instead of opening a second one.
   - Use the tray menu to start/stop and run best-location selection.

8. Autostart and reconnect

   - Enable start on boot.
   - With VPN on, reboot and confirm the app starts in tray and reconnects to the remembered location.
   - With VPN off, reboot and confirm the app starts without connecting.

## Logs To Capture

Capture these files when a desktop smoke test fails:

```text
~/.vpn-control-desktop/workspace.json
~/.vpn-control-desktop/runtime/runtime-sing-box.log
~/.vpn-control-desktop/runtime/runtime-sing-box-vpn.json
~/.vpn-control-desktop/runtime/runtime-sing-box-proxy_only.json
```
