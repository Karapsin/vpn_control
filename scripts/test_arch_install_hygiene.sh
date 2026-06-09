#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

script="scripts/arch_install.sh"

bash -n "$script"

generated_launcher_raw="$(mktemp)"
generated_launcher="$(mktemp)"
trap 'rm -f "$generated_launcher_raw" "$generated_launcher"' EXIT
awk '
  $0 == "sudo tee \"$launcher_path\" >/dev/null <<EOF" { in_block = 1; next }
  in_block && $0 == "EOF" { exit }
  in_block { print }
' "$script" >"$generated_launcher_raw"
sed 's/\\\$/\$/g' "$generated_launcher_raw" >"$generated_launcher"
if [[ ! -s "$generated_launcher" ]]; then
  echo "arch_install.sh generated launcher wrapper could not be extracted" >&2
  exit 1
fi
bash -n "$generated_launcher"

python3 - <<'PY'
import pathlib
import re
import sys

script = pathlib.Path("scripts/arch_install.sh")
text = script.read_text(encoding="utf-8")

required_snippets = [
    'stop_running_instance()',
    'terminate_pids()',
    'kill -KILL "${still_running[@]}"',
    'start_installed_app()',
    'nohup "$launcher_path"',
    '--no-start',
    'ensure_linux_tun_available()',
    'modules_dir="/lib/modules/$current_kernel"',
    'if [[ ! -d "$modules_dir" ]]; then',
    'find /lib/modules -maxdepth 1 -mindepth 1 -type d',
    'modprobe_output="$(sudo modprobe tun 2>&1)"',
    'installed_sing_box="$install_dir/bin/sing-box"',
    'sudo setcap cap_net_admin,cap_net_raw+ep "$installed_sing_box"',
    'installed_caps="$(getcap "$installed_sing_box" || true)"',
    '"cap_net_admin"',
    '"cap_net_raw"',
    'cleanup_legacy_user_systemd_autostart()',
    'systemctl --user disable vpn-control.service',
    'removed legacy user systemd autostart',
    'report_legacy_systemd_autostart_for_other_users()',
    'inspect_other_user_legacy_systemd_autostart()',
    'path_exists_or_symlink_sudo()',
    '/var/lib/systemd/linger',
    'found legacy user systemd autostart entries outside the current user',
    'these files were not removed because they belong to another user',
    'sudo -u %q XDG_RUNTIME_DIR=/run/user/%s systemctl --user disable vpn-control.service || true',
    'sudo rm -f %q %q',
    'sudo loginctl disable-linger %q',
    'state_dir="\\${VPN_CONTROL_STATE_DIR:-\\$HOME/.vpn-control-desktop}"',
    'lock_file="\\$state_dir/launcher.lock"',
    'port_file="\\$state_dir/activation.port"',
    'autostart_log="\\$state_dir/autostart.log"',
    'AUTOSTART_MAX_ATTEMPTS=3',
    'AUTOSTART_RETRY_DELAY_SECONDS=5',
    'AUTOSTART_STARTUP_WINDOW_SECONDS=20',
    'AUTOSTART_DESKTOP_WAIT_SECONDS=20',
    'is_autostart_launch()',
    'log_autostart()',
    'request_existing_instance()',
    'desktop_session_ready()',
    'wait_for_desktop_session()',
    'run_autostart_app_once()',
    'run_autostart_app_with_retries()',
    "port=\"\\$(tr -dc '0-9' <\"\\$port_file\")\"",
    'python3 - "\\$port"',
    'socket.create_connection(("127.0.0.1", port), timeout=0.5)',
    'exec 8<>"/dev/tcp/127.0.0.1/\\$port"',
    'flock -n 9',
    'log_autostart "existing instance lock held; requesting activation"',
    'run_autostart_app_with_retries "\\$@"',
]
missing = [snippet for snippet in required_snippets if snippet not in text]
if missing:
    print("arch_install.sh is missing required capability-install checks:", file=sys.stderr)
    for snippet in missing:
        print(f" - {snippet}", file=sys.stderr)
    sys.exit(1)

setcap_match = re.search(r'sudo setcap cap_net_admin,cap_net_raw\+ep "\$installed_sing_box"', text)
verify_match = re.search(r'installed_caps="\$\(getcap "\$installed_sing_box" \|\| true\)"', text)
if not setcap_match or not verify_match or verify_match.start() < setcap_match.end():
    print("arch_install.sh must verify installed_sing_box with getcap after setcap.", file=sys.stderr)
    sys.exit(1)

old_guidance = "sudo setcap cap_net_admin,cap_net_raw+ep $(command -v sing-box)"
if old_guidance in text:
    print("arch_install.sh must not direct users to capability-fix a PATH sing-box.", file=sys.stderr)
    sys.exit(1)

old_refusal = "refusing to replace $install_dir while VPN Control is running"
if old_refusal in text:
    print("arch_install.sh must restart the running instance instead of refusing replacement.", file=sys.stderr)
    sys.exit(1)

old_pipefail_port_parse = 'tr -dc \'0-9\' <"\\$port_file" | head -c 10'
if old_pipefail_port_parse in text:
    print("arch_install.sh launcher wrapper must not parse activation.port with a pipe under pipefail.", file=sys.stderr)
    sys.exit(1)

launcher_guard = text.find('lock_file="\\$state_dir/launcher.lock"')
launcher_exec = text.find('exec "$install_dir/bin/vpn-control" "\\$@"')
if launcher_guard < 0 or launcher_exec < 0 or launcher_guard > launcher_exec:
    print("arch_install.sh launcher wrapper must guard duplicate launches before execing app binary.", file=sys.stderr)
    sys.exit(1)

duplicate_launch_exit = text.find('request_existing_instance >/dev/null 2>&1 || true')
if duplicate_launch_exit < 0 or duplicate_launch_exit > launcher_exec:
    print("arch_install.sh launcher wrapper must activate the existing instance on duplicate launch.", file=sys.stderr)
    sys.exit(1)

autostart_retry = text.find('run_autostart_app_with_retries "\\$@"')
if autostart_retry < 0 or autostart_retry > launcher_exec:
    print("arch_install.sh launcher wrapper must run retrying autostart before the normal exec path.", file=sys.stderr)
    sys.exit(1)

autostart_log = text.find('autostart_log="\\$state_dir/autostart.log"')
autostart_wait = text.find('wait_for_desktop_session')
autostart_run = text.find('run_autostart_app_once')
if not (launcher_guard < autostart_log < autostart_wait < autostart_run < launcher_exec):
    print("arch_install.sh launcher wrapper must log, wait for desktop readiness, and retry autostart in order.", file=sys.stderr)
    sys.exit(1)

forbidden_systemd_autostart = [
    'ExecStart=$launcher_path --autostart',
    'WantedBy=default.target',
    'ln -sf ../vpn-control.service',
]
for snippet in forbidden_systemd_autostart:
    if snippet in text:
        print("arch_install.sh must not install user systemd GUI autostart entries.", file=sys.stderr)
        print(f"found forbidden snippet: {snippet}", file=sys.stderr)
        sys.exit(1)

forbidden_cross_user_cleanup = [
    'sudo rm -f "$service" "$wants"',
    'systemctl --user disable --now vpn-control.service',
]
for snippet in forbidden_cross_user_cleanup:
    if snippet in text:
        print("arch_install.sh must not directly remove or stop another user's legacy autostart.", file=sys.stderr)
        print(f"found forbidden snippet: {snippet}", file=sys.stderr)
        sys.exit(1)

current_cleanup = text.rfind("\ncleanup_legacy_user_systemd_autostart\n")
other_user_report = text.rfind("\nreport_legacy_systemd_autostart_for_other_users\n")
if current_cleanup < 0 or other_user_report < 0 or other_user_report < current_cleanup:
    print("arch_install.sh must clean the current user and then report other-user legacy autostart entries.", file=sys.stderr)
    sys.exit(1)

stop_call = text.rfind("\nstop_running_instance\n")
install_call = text.find('sudo rm -rf "$install_dir"')
start_call = text.rfind("start_installed_app")
success_call = text.find('echo "[vpn-control] installed successfully"')
if stop_call < 0 or install_call < 0 or stop_call > install_call:
    print("arch_install.sh must stop the running instance before replacing install_dir.", file=sys.stderr)
    sys.exit(1)
if start_call < 0 or success_call < 0 or start_call < success_call:
    print("arch_install.sh must start the newly installed app after a successful install.", file=sys.stderr)
    sys.exit(1)

tun_call = text.find("ensure_linux_tun_available")
setcap_call = text.find('sudo setcap cap_net_admin,cap_net_raw+ep "$installed_sing_box"')
if tun_call < 0 or setcap_call < 0 or tun_call > setcap_call:
    print("arch_install.sh must validate TUN support before declaring install capabilities complete.", file=sys.stderr)
    sys.exit(1)
PY

echo "[vpn-control] arch install hygiene passed"
