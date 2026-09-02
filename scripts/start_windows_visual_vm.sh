#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_dir="$repo_root/.runtime/visual-vms/windows"
disk_path="$runtime_dir/vpn-control-win11.qcow2"
install_iso=""
if [[ "${1:-}" == "--install" ]]; then
  install_iso="${2:-}"
fi
[[ -f "$disk_path" ]] || { echo "Run scripts/bootstrap_windows_visual_vm.sh first." >&2; exit 1; }

machine="q35"
cpu="max"
qemu_binary="$(command -v qemu-system-x86_64 || true)"
if [[ "$(uname -m)" == arm64 ]]; then
  qemu_binary="$(command -v qemu-system-aarch64 || true)"
  machine="virt"
  cpu="host"
fi
[[ -n "$qemu_binary" ]] || { echo "No matching QEMU system emulator found." >&2; exit 1; }

args=(
  -machine "$machine,accel=hvf"
  -cpu "$cpu"
  -smp 6
  -m 8192
  -drive "file=$disk_path,if=virtio,format=qcow2"
  -device virtio-vga
  -display cocoa
  -qmp "unix:$runtime_dir/qmp.sock,server=on,wait=off"
  -name vpn-control-win11
)
if [[ -n "$install_iso" ]]; then
  [[ -f "$install_iso" ]] || { echo "Windows ISO not found: $install_iso" >&2; exit 1; }
  args+=( -cdrom "$install_iso" -boot d )
fi
exec "$qemu_binary" "${args[@]}"
