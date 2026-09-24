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

- Start the installed GUI as the ordinary signed-in user; do not elevate the whole app.
- Use the installed `vpn-control-cli.exe` console launcher for CLI checks. GUI and CLI are clients of the same ordinary-user controller.
- Have a disposable UAC-capable account available so both approval and denial can be tested. Only the fixed authenticated VPN broker may request elevation for VPN setup; proxy-only remains available without elevation.

## Windows Installed-Package Acceptance Status

The current automated broker-admission and package checks prove the fixed helper's
packaged authority and the standard-user ownership boundary. They do not prove
real UAC interaction, installed GUI/CLI attachment, or live traffic continuity.
Treat the Windows-specific manual cases below as open native acceptance until a
receipt from the installed Windows package records them.

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
   - On Windows, start this from the non-elevated installed GUI and approve UAC only for the VPN broker. Confirm the GUI itself remains an ordinary-user client.
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
   - Leave VPN or proxy-only running through one refresh, then repeat with the GUI hidden or detached while the controller remains alive.
   - Confirm refresh does not leave the active runtime stopped. A short controlled restart is allowed only when the generated active configuration changes; it must preserve the actual active selection and must not apply a pending manual selection.

8. Tray and single instance

   - Close the window only after the tray icon is confirmed available, and confirm the app hides to tray instead of exiting.
   - Temporarily run without a tray host, when practical, and confirm close exits or keeps the window accessible instead of hiding it invisibly.
   - Launch the app again and confirm it shows the existing instance instead of opening a second one.
   - Use the tray menu to start/stop and run best-location selection.
   - On Linux, repeat on at least one StatusNotifier/AppIndicator host and one XEmbed-only panel when available.

9. Windows installed GUI/CLI owner and UAC scope

   - Start the installed GUI as a standard user, connect in proxy-only mode, and prove client traffic. Run `vpn-control-cli.exe status` and another read-only command; confirm they report the GUI's existing controller rather than starting a second owner, GUI, tray, or elevation prompt.
   - With traffic active, close the GUI to a confirmed tray, use the installed CLI to query the owner, then reopen the GUI. Confirm the same controller and runtime remain active and traffic continues through both GUI detach and reattach.
   - From the standard-user GUI, stage VPN mode, explicitly restart (or start if disconnected), and deny UAC. Confirm the GUI and CLI remain usable without elevation, the prior runtime state and reconnect intent are preserved, and an active proxy-only connection continues if one was running.
   - Repeat the explicit VPN start/restart with UAC approved. Confirm only the scoped broker is elevated, VPN traffic works, and the GUI/CLI remain attached to the ordinary-user owner.

10. Autostart and reconnect

   - Enable start on boot.
   - With VPN on, reboot and confirm the app starts in tray after the tray icon appears and reconnects to the remembered location.
   - With VPN off, reboot and confirm the app starts without connecting.

11. SSH Routing

   - Prepare the loopback-only relay from `docs/ssh-routing.md`, import a dedicated unencrypted key, and paste the verified host key.
   - Enable the route and connect. Confirm the public address belongs to the selected VPN rather than the local network ISP.
   - Refresh a subscription while connected; then disconnect and refresh again with SSH Routing still enabled. Both should succeed through their specified routes.
   - Stop the SSH relay and confirm inactive-session refresh fails without direct fallback.
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
