# Desktop Smoke Testing

Use this checklist for Linux and Windows desktop verification. Android device/emulator protocol testing lives in `agent_docs/smoke-android.md`.

## Preconditions

- Install the current desktop package for the platform being tested.
- Record the artifact path or GitHub Actions run used for the install.
- Use at least one known-good subscription or location.
- Do not stop an active VPN/runtime unless the user approves the interruption.

Linux VPN mode prerequisites:

- `/dev/net/tun` exists.
- The installed `sing-box` has `CAP_NET_ADMIN`.
- A tray/status-notifier host is available if close-to-tray behavior is being tested. Minimal window-manager panels may need AppIndicator/Ayatana support libraries or an XEmbed tray host; GNOME commonly needs an AppIndicator extension. For i3/polybar and similar XEmbed-only sessions, VPN Control uses the AWT tray backend first; use `VPN_CONTROL_LINUX_TRAY_BACKEND=native` or `awt` to compare backends.

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

6. Secure DNS

   - With VPN mode connected, select Automatic DNS and confirm `https://www.youtube.com/` and an ordinary non-Google site both load.
   - Select a known-good custom DoH endpoint, reconnect, and repeat both checks.
   - Select a known-good custom DoT endpoint, reconnect, and repeat both checks.
   - Confirm malformed or plaintext endpoints are rejected without closing the DNS dialog.
   - When upgrading a workspace that used an enabled raw-IP DNS server, confirm the app selects Automatic DNS and displays the migration notice.

7. Scheduled refresh

   - Set a short refresh interval of at least 5 minutes.
   - Leave VPN running through one refresh.
   - Confirm refresh does not leave VPN stopped. A short restart is acceptable when config changes.

8. Tray and single instance

   - Close the window and confirm the app hides to tray instead of exiting when the tray icon is visible.
   - Temporarily run without a tray host, when practical, and confirm close exits or keeps the window accessible instead of hiding it invisibly.
   - Launch the app again and confirm it shows the existing instance instead of opening a second one.
   - Use the tray menu to start/stop and run best-location selection.
   - On Linux, repeat on at least one StatusNotifier/AppIndicator host and one XEmbed-only panel when available.

9. Autostart and reconnect

   - Enable start on boot.
   - With VPN on, reboot and confirm the app starts in tray after the tray icon appears and reconnects to the remembered location.
   - With VPN off, reboot and confirm the app starts without connecting.

10. SSH Routing

   - Prepare the loopback-only relay from `docs/ssh-routing.md`, import a dedicated unencrypted key, and paste the verified host key.
   - Enable the route and connect. Confirm the public address belongs to the selected VPN rather than the home ISP.
   - Refresh a subscription while connected; then disconnect and refresh again with SSH Routing still enabled. Both should succeed through their specified routes.
   - Stop the home relay and confirm inactive-session refresh fails without direct fallback.
   - Change one SSH setting while connected. Confirm no automatic interruption occurs, the pending marker appears, and only `Restart now` reapplies it.
   - Repeat Find Best while connected and confirm the dedicated probe result is not biased by the active VPN, including when the active location is a custom config.

## Logs To Capture

Capture these files locally when a desktop smoke test fails:

```text
~/.vpn-control-desktop/workspace.json
~/.vpn-control-desktop/runtime/runtime-sing-box.log
~/.vpn-control-desktop/runtime/runtime-sing-box-vpn.json
~/.vpn-control-desktop/runtime/runtime-sing-box-proxy_only.json
```

Share only redacted snippets. Do not paste full workspace, log, or generated config dumps into reports; they can contain endpoints, subscription URLs, UUIDs, credentials, or tokens. Use the redacted helpers in `agent_docs/runtime-troubleshooting.md` first.
