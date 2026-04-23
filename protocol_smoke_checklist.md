# Device Protocol Smoke Checklist

This checklist is for manual device or emulator verification of the non-VLESS protocols currently supported by the app:

- `Trojan`
- `Shadowsocks`
- `VMess`
- `SOCKS`

Use one known-good endpoint for each protocol. Run the same sequence for every protocol.

## Preconditions

- Install the current app build.
- Record the build date / APK path used for the run.
- Record whether the run is on a real device or an emulator.
- Make sure the test endpoint is valid and currently reachable.
- If the test uses VPN mode, grant VPN permission before starting.
- If the test uses subscription import, verify the source actually returns the expected protocol links.

## Per-Protocol Flow

1. Import
- Import the config from a direct link, clipboard, QR, or file.
- Confirm the app accepts the payload without rewriting it into an invalid form.
- Confirm the location appears in the `Locations` tab with the expected name and server.

2. Edit / round-trip
- Open the imported location in the editor.
- Verify the displayed config is readable and protocol-appropriate.
- Save without changing the payload.
- Export it and re-import it.
- Confirm the round-trip preserves a working config.

3. Benchmark
- Run `Check` on the location from the `Locations` tab.
- Confirm the benchmark completes without parser or runtime-config errors.
- Confirm the result is stored in the location detail line.

4. Manual selection
- Select the location manually from `Locations`.
- Confirm the selected location and selected profile/source labels update correctly.

5. Connect
- Start the connection in both:
  - `VPN`
  - `Proxy Only`
- Confirm the app reaches `started` state and does not immediately roll back.

6. Real traffic
- Open a real site through the connection.
- Confirm ordinary browsing works.
- For `Proxy Only`, verify the local proxy can be used by a client app.

7. Disconnect / reconnect
- Stop the connection.
- Start it again using the saved selection.
- Confirm the selection persists and reconnect works.

## Subscription Variant

If the protocol is also exercised through a subscription:

1. Add a subscription containing at least one location of that protocol.
2. Refresh the subscription.
3. Confirm the location appears in the cached list.
4. Run `Find Best`.
5. Confirm the selected winner can actually connect.
6. If `All` is active, confirm the protocol participates in the merged search set.
7. Confirm the Profile tab shows the correct cached-location count for that subscription.

## Regression Checks

For every protocol above, watch for:

- parser accepts import but connect fails immediately
- benchmark works but connect fails
- manual connect works but `Find Best` excludes the protocol unexpectedly
- export/import changes the payload meaningfully
- background refresh drops cached locations for that protocol
- source labeling becomes wrong when `All` is active

## Suggested Result Log

Record one short line per protocol:

- protocol
- device or emulator
- import method
- benchmark result
- VPN connect result
- proxy-only result
- real traffic result
- notes
