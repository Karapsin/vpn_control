# Linux Headless Service

VPN Control can keep one persistent controller on a Linux machine without a graphical session. Use the installed launcher from the same package as the desktop app:

```bash
vpn-control serve
```

`serve` acquires the normal single-instance lock, exposes the local CLI socket, restores the remembered connection only when reconnect was enabled, and stays alive while VPN is off. It is the correct process for systemd, runit, s6, or another supervisor. The internal `--headless-controller` argument is transient CLI plumbing and must not be used as a service entry point.

Control the running service from the same user account:

```bash
vpn-control status
vpn-control select <location-name-or-visible-index>
vpn-control find-best
vpn-control on
vpn-control off
```

`status` is read-only and does not start a controller when none is running.

## User systemd example

Create `~/.config/systemd/user/vpn-control.service`:

```ini
[Unit]
Description=VPN Control headless controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/vpn-control/bin/vpn-control serve
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Then enable it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now vpn-control.service
vpn-control status
```

Use the actual installed launcher path when it differs from `/opt/vpn-control/bin/vpn-control`. A system service may be appropriate on an unattended machine, but its service user must own the VPN Control state directory and have the Linux TUN/capability prerequisites described in the install documentation.

Do not run `serve` and the graphical app as the same user at the same time. The single-instance guard will keep the second process from taking ownership.
