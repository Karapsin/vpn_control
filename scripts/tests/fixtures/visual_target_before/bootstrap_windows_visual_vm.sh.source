#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_dir="$repo_root/.runtime/visual-vms/windows"
disk_path="$runtime_dir/vpn-control-win11.qcow2"
iso_path="${VPN_CONTROL_WINDOWS_ISO:-}"

command -v qemu-img >/dev/null || {
  echo "QEMU is required. On macOS install it with: brew install qemu" >&2
  exit 1
}
command -v qemu-system-aarch64 >/dev/null || command -v qemu-system-x86_64 >/dev/null || {
  echo "A QEMU system emulator is required." >&2
  exit 1
}
if [[ -f "$disk_path" ]]; then
  echo "[vpn-control] Windows visual VM disk already exists at $disk_path"
  echo "[vpn-control] It remains unavailable for capture until scripts/mark_windows_visual_vm_ready.sh --agent-confirmed succeeds."
  exit 0
fi
if [[ -z "$iso_path" || ! -f "$iso_path" ]]; then
  echo "Set VPN_CONTROL_WINDOWS_ISO to an official Windows 11 client ISO." >&2
  echo "The agent must obtain explicit user authorization before downloading media or accepting Windows license terms." >&2
  exit 1
fi

mkdir -p "$runtime_dir"
qemu-img create -f qcow2 "$disk_path" 96G
cat <<EOF
[vpn-control] Created $disk_path.
[vpn-control] Start the installer with scripts/start_windows_visual_vm.sh --install "$iso_path".
[vpn-control] Set VPN_CONTROL_WINDOWS_DRIVER_ISO to the UTM Windows guest-tools ISO for ARM64 VirtIO drivers and unattended setup support.
[vpn-control] The coding agent must complete Windows setup in the isolated VM, install and verify the capture prerequisites, then run:
[vpn-control] scripts/mark_windows_visual_vm_ready.sh --agent-confirmed
EOF
