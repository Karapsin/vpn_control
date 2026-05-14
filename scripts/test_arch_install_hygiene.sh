#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

script="scripts/arch_install.sh"

bash -n "$script"

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
