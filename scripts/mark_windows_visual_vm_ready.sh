#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_dir="$repo_root/.runtime/visual-vms/windows"
disk_path="$runtime_dir/vpn-control-win11.qcow2"
ready_path="$runtime_dir/READY"

if [[ "${1:-}" != "--agent-confirmed" ]]; then
  echo "Usage: $0 --agent-confirmed" >&2
  echo "Run this only after the coding agent has booted the isolated Windows client, checked the 1280x800/100% visual profile, and confirmed its capture driver." >&2
  exit 2
fi
[[ -f "$disk_path" ]] || { echo "Managed Windows disk is missing: $disk_path" >&2; exit 1; }
command -v qemu-img >/dev/null || { echo "qemu-img is required to inspect the managed disk." >&2; exit 1; }
python3 "$repo_root/scripts/capture_visual_windows_qemu.py" --probe
virtual_size="$(qemu-img info --force-share --output=json "$disk_path" | python3 -c 'import json,sys; print(int(json.load(sys.stdin).get("virtual-size", 0)))')"
(( virtual_size >= 64 * 1024 * 1024 * 1024 )) || {
  echo "Managed Windows disk is unexpectedly small; refusing to mark it ready." >&2
  exit 1
}
cat > "$ready_path" <<EOF
schema_version=1
confirmed_by=coding-agent
canonical_environment=windows11-client-1280x800
EOF
echo "[vpn-control] Marked the isolated Windows visual VM ready: $ready_path"
