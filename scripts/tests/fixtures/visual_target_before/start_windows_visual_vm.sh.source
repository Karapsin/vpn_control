#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_dir="$repo_root/.runtime/visual-vms/windows"
disk_path="$runtime_dir/vpn-control-win11.qcow2"
uefi_vars="$runtime_dir/edk2-arm-vars.fd"
guest_agent_socket="$runtime_dir/qga.sock"
install_iso=""
driver_iso=""
if [[ "${1:-}" == "--install" ]]; then
  install_iso="${2:-}"
  driver_iso="${VPN_CONTROL_WINDOWS_DRIVER_ISO:-}"
elif [[ "${1:-}" == "--provision-drivers" ]]; then
  driver_iso="${2:-}"
fi
[[ -f "$disk_path" ]] || { echo "Run scripts/bootstrap_windows_visual_vm.sh first." >&2; exit 1; }
if command -v lsof >/dev/null 2>&1; then
  disk_users="$(lsof -t -- "$disk_path" 2>/dev/null | sort -u || true)"
  [[ -z "$disk_users" ]] || {
    echo "Managed Windows visual disk is already in use by PID(s): ${disk_users//$'\n'/, }." >&2
    echo "Use scripts/visual_platform.py stop --platform windows before starting another VM." >&2
    exit 1
  }
fi

machine_options="q35,accel=hvf"
cpu="max"
memory_mb=8192
graphics_args=(-device "virtio-gpu-pci,id=visual-display,xres=1280,yres=800")
system_boot_index=0
qemu_binary="$(command -v qemu-system-x86_64 || true)"
if [[ "$(uname -m)" == arm64 ]]; then
  qemu_binary="$(command -v qemu-system-aarch64 || true)"
  machine_options="virt,accel=hvf,highmem=off,gic-version=3,acpi=on"
  cpu="host"
  memory_mb=3072
  if [[ -n "$driver_iso" ]]; then
    graphics_args=(-device "ramfb,id=boot-display" -device "virtio-gpu-pci,id=visual-display,xres=1280,yres=800")
  fi
  if [[ -n "$install_iso" ]]; then
    system_boot_index=2
  fi
fi
[[ -n "$qemu_binary" ]] || { echo "No matching QEMU system emulator found." >&2; exit 1; }

args=(
  -machine "$machine_options"
  -cpu "$cpu"
  -smp 6
  -m "$memory_mb"
  -drive "file=$disk_path,if=none,format=qcow2,id=system"
  -device "nvme,drive=system,serial=VPNCONTROL,bootindex=$system_boot_index"
  "${graphics_args[@]}"
  -device "qemu-xhci,id=xhci"
  -device "usb-kbd,bus=xhci.0"
  -device "usb-tablet,bus=xhci.0"
  -device "virtio-serial-pci"
  -chardev "socket,path=$guest_agent_socket,server=on,wait=off,id=qga0"
  -device "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"
  -device "virtio-net-pci,netdev=network"
  -netdev "user,id=network,hostfwd=tcp:127.0.0.1:2299-:22"
  -rtc "base=localtime"
  -display none
  -vnc 127.0.0.1:5
  -qmp "unix:$runtime_dir/qmp.sock,server=on,wait=off"
  -name vpn-control-win11
)
if [[ "$(uname -m)" == arm64 ]]; then
  qemu_share="${VPN_CONTROL_QEMU_FIRMWARE_DIR:-$(cd "$(dirname "$qemu_binary")/../share/qemu" && pwd)}"
  uefi_code="$qemu_share/edk2-aarch64-code.fd"
  uefi_template="$qemu_share/edk2-arm-vars.fd"
  [[ -f "$uefi_code" && -f "$uefi_template" ]] || {
    echo "QEMU AArch64 UEFI firmware was not found under $qemu_share." >&2
    exit 1
  }
  if [[ ! -f "$uefi_vars" ]]; then
    cp "$uefi_template" "$uefi_vars"
    chmod u+w "$uefi_vars"
  fi
  args+=(
    -drive "if=pflash,format=raw,readonly=on,file=$uefi_code"
    -drive "if=pflash,format=raw,file=$uefi_vars"
  )
fi
if [[ -n "$install_iso" ]]; then
  [[ -f "$install_iso" ]] || { echo "Windows ISO not found: $install_iso" >&2; exit 1; }
  [[ -n "$driver_iso" && -f "$driver_iso" ]] || {
    echo "Set VPN_CONTROL_WINDOWS_DRIVER_ISO to the UTM Windows guest-tools ISO." >&2
    exit 1
  }
  args+=(
    -drive "file=$install_iso,media=cdrom,readonly=on,if=none,id=installer"
    -device "usb-storage,bus=xhci.0,drive=installer,bootindex=0"
    -boot "menu=on"
  )
fi
if [[ -n "$driver_iso" ]]; then
  [[ -f "$driver_iso" ]] || { echo "Windows guest-tools ISO not found: $driver_iso" >&2; exit 1; }
  args+=(
    -drive "file=$driver_iso,media=cdrom,readonly=on,if=none,id=drivers"
    -device "usb-storage,bus=xhci.0,drive=drivers"
  )
fi
exec "$qemu_binary" "${args[@]}"
