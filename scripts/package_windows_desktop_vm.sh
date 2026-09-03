#!/usr/bin/env bash
set -euo pipefail

vm_name="vpn-control-win11"
host_ip=""
port="8771"
output_dir="dist/windows-vm"
skip_tests=false
skip_package_regression_tests=false
skip_installed_package_regression_tests=false
guest_work_root='C:\Users\Public\vpn-control-vm-package'
timeout_seconds=7200

usage() {
  cat <<'EOF'
Usage: scripts/package_windows_desktop_vm.sh [options]

Build Windows EXE/MSI installers inside the local Windows VM.

Options:
  --vm-name NAME                         libvirt VM name (default: vpn-control-win11)
  --host-ip IP                           host IP reachable from VM (default: virbr0 IPv4 or 192.168.122.1)
  --port PORT                            temporary host HTTP bridge port (default: 8771)
  --output-dir DIR                       host output directory (default: dist/windows-vm)
  --guest-work-root PATH                 Windows work directory (default: C:\Users\Public\vpn-control-vm-package)
  --timeout-seconds SECONDS              guest build timeout (default: 7200)
  --skip-tests                           skip Gradle desktop tests inside VM
  --skip-package-regression-tests        skip MSI/EXE package regression tests inside VM
  --skip-installed-package-regression-tests
                                          skip installed MSI smoke tests inside VM
  -h, --help                             show this help

The script starts the VM if needed, waits for QEMU guest agent, sends the current
working tree snapshot to Windows, runs scripts/package_windows_desktop.ps1 there,
and copies dist/windows outputs back to the host output directory.
EOF
}

while (($#)); do
  case "$1" in
    --vm-name)
      vm_name="${2:?missing --vm-name value}"
      shift 2
      ;;
    --host-ip)
      host_ip="${2:?missing --host-ip value}"
      shift 2
      ;;
    --port)
      port="${2:?missing --port value}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:?missing --output-dir value}"
      shift 2
      ;;
    --guest-work-root)
      guest_work_root="${2:?missing --guest-work-root value}"
      shift 2
      ;;
    --timeout-seconds)
      timeout_seconds="${2:?missing --timeout-seconds value}"
      shift 2
      ;;
    --skip-tests)
      skip_tests=true
      shift
      ;;
    --skip-package-regression-tests)
      skip_package_regression_tests=true
      shift
      ;;
    --skip-installed-package-regression-tests)
      skip_installed_package_regression_tests=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

./scripts/check_release_hygiene.sh

if [[ -z "$host_ip" ]]; then
  host_ip="$(ip -4 addr show virbr0 2>/dev/null | awk '/inet / { sub("/.*", "", $2); print $2; exit }')"
  host_ip="${host_ip:-192.168.122.1}"
fi

runtime_dir="$repo_root/.runtime/windows-vm-package"
upload_dir="$runtime_dir/upload"
repo_zip="$runtime_dir/repo.zip"
result_zip="$upload_dir/windows-package-result.zip"
bridge_log="$runtime_dir/vm-file-bridge.log"
host_output_dir="$repo_root/$output_dir"
host_base_url="http://$host_ip:$port"

mkdir -p "$runtime_dir" "$upload_dir" "$host_output_dir"
rm -f "$repo_zip" "$result_zip" "$bridge_log"

cleanup() {
  if [[ -n "${bridge_pid:-}" ]] && kill -0 "$bridge_pid" 2>/dev/null; then
    kill "$bridge_pid" 2>/dev/null || true
    wait "$bridge_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

log() {
  printf '[vpn-control] %s\n' "$*"
}

sudo_cmd() {
  if [[ -n "${VPN_CONTROL_SUDO_PASSWORD:-}" ]]; then
    printf '%s\n' "$VPN_CONTROL_SUDO_PASSWORD" | sudo -S "$@"
  else
    sudo "$@"
  fi
}

virsh_json() {
  sudo_cmd virsh qemu-agent-command "$vm_name" "$1" --timeout "${2:-30}"
}

wait_for_guest_agent() {
  local deadline=$((SECONDS + 300))
  while ((SECONDS < deadline)); do
    if virsh_json '{"execute":"guest-ping"}' 10 >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "Timed out waiting for QEMU guest agent in VM '$vm_name'" >&2
  return 1
}

guest_exec_powershell() {
  local script_file="$1"
  local payload
  payload="$(python3 - "$script_file" <<'PY'
import base64
import json
import pathlib
import sys

script = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
print(json.dumps({
    "execute": "guest-exec",
    "arguments": {
        "path": "powershell.exe",
        "arg": ["-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        "capture-output": False,
    },
}))
PY
)"
  virsh_json "$payload" 30
}

wait_for_guest_exec() {
  local pid="$1"
  local deadline=$((SECONDS + timeout_seconds))
  local status_file="$runtime_dir/guest-status.json"
  while ((SECONDS < deadline)); do
    python3 - "$pid" > "$runtime_dir/status-command.json" <<'PY'
import json
import sys
print(json.dumps({"execute": "guest-exec-status", "arguments": {"pid": int(sys.argv[1])}}))
PY
    if virsh_json "$(cat "$runtime_dir/status-command.json")" 30 > "$status_file"; then
      if python3 - "$status_file" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], encoding="utf-8"))["return"]
raise SystemExit(0 if data.get("exited") else 1)
PY
      then
        python3 - "$status_file" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], encoding="utf-8"))["return"]
print(data.get("exitcode", 1))
PY
        return 0
      fi
    fi
    sleep 5
  done
  echo "Timed out waiting for Windows VM build process pid=$pid" >&2
  return 1
}

log "creating repo snapshot from current working tree"
python3 - "$repo_zip" <<'PY'
import pathlib
import subprocess
import sys
import zipfile

repo_zip = pathlib.Path(sys.argv[1])
files_raw = subprocess.check_output(
    ["git", "ls-files", "-co", "--exclude-standard", "-z"],
)
paths = [path for path in files_raw.decode("utf-8").split("\0") if path]
with zipfile.ZipFile(repo_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in paths:
        source = pathlib.Path(path)
        if source.is_file():
            archive.write(source, path.replace("\\", "/"))
print(f"wrote {repo_zip} with {len(paths)} entries")
PY

log "ensuring VM '$vm_name' is running"
sudo_cmd -v
vm_state="$(sudo_cmd virsh domstate "$vm_name" 2>/dev/null || true)"
if [[ "$vm_state" != *running* ]]; then
  if ! sudo_cmd virsh start "$vm_name" >/dev/null; then
    vm_state="$(sudo_cmd virsh domstate "$vm_name" 2>/dev/null || true)"
    if [[ "$vm_state" != *running* ]]; then
      echo "Failed to start VM '$vm_name'" >&2
      exit 1
    fi
  fi
fi

log "waiting for QEMU guest agent"
wait_for_guest_agent

log "starting temporary file bridge at $host_base_url"
python3 "$repo_root/scripts/vm_file_bridge.py" \
  --bind "$host_ip" \
  --port "$port" \
  --repo-zip "$repo_zip" \
  --upload-dir "$upload_dir" \
  > "$bridge_log" 2>&1 &
bridge_pid=$!
sleep 1
if ! kill -0 "$bridge_pid" 2>/dev/null; then
  cat "$bridge_log" >&2 || true
  echo "file bridge failed to start" >&2
  exit 1
fi

bootstrap_ps="$runtime_dir/bootstrap.ps1"
python3 - "$bootstrap_ps" "$host_base_url" "$guest_work_root" "$skip_tests" "$skip_package_regression_tests" "$skip_installed_package_regression_tests" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
host_base_url = sys.argv[2]
work_root = sys.argv[3]
skip_tests = "$true" if sys.argv[4] == "true" else "$false"
skip_package_regression_tests = "$true" if sys.argv[5] == "true" else "$false"
skip_installed_package_regression_tests = "$true" if sys.argv[6] == "true" else "$false"
script = f'''
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$HostBaseUrl = "{host_base_url}"
$WorkRoot = "{work_root}"
$RepoRoot = Join-Path $WorkRoot "repo"
$RepoZip = Join-Path $WorkRoot "repo.zip"
if (Test-Path $WorkRoot) {{
    Remove-Item -Path $WorkRoot -Recurse -Force
}}
New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
Invoke-WebRequest -Uri "$HostBaseUrl/repo.zip" -OutFile $RepoZip -UseBasicParsing
Expand-Archive -Path $RepoZip -DestinationPath $RepoRoot -Force
& (Join-Path $RepoRoot "scripts\\windows_vm_package_worker.ps1") `
    -HostBaseUrl $HostBaseUrl `
    -WorkRoot $WorkRoot `
    -RepoRoot $RepoRoot `
    -SkipTests:{skip_tests} `
    -SkipPackageRegressionTests:{skip_package_regression_tests} `
    -SkipInstalledPackageRegressionTests:{skip_installed_package_regression_tests}
exit $LASTEXITCODE
'''
path.write_text(script, encoding="utf-8")
PY

log "starting Windows package build inside VM"
guest_response="$(guest_exec_powershell "$bootstrap_ps")"
guest_pid="$(python3 - "$guest_response" <<'PY'
import json
import sys
print(json.loads(sys.argv[1])["return"]["pid"])
PY
)"
log "guest build pid: $guest_pid"

guest_exit_code="$(wait_for_guest_exec "$guest_pid")"
log "guest build exit code: $guest_exit_code"

if [[ ! -f "$result_zip" ]]; then
  log "file bridge log:"
  cat "$bridge_log" >&2 || true
  echo "Windows VM did not upload result zip: $result_zip" >&2
  exit 1
fi

extract_dir="$runtime_dir/result"
rm -rf "$extract_dir"
mkdir -p "$extract_dir"
python3 - "$result_zip" "$extract_dir" <<'PY'
import pathlib
import sys
import zipfile

zip_path = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
with zipfile.ZipFile(zip_path) as archive:
    for info in archive.infolist():
        normalized = pathlib.PurePosixPath(info.filename.replace("\\", "/"))
        if normalized.is_absolute() or ".." in normalized.parts:
            raise RuntimeError(f"unsafe zip entry: {info.filename}")
        if info.is_dir():
            (target / normalized).mkdir(parents=True, exist_ok=True)
            continue
        destination = target / normalized
        destination.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as source, destination.open("wb") as output:
            output.write(source.read())
PY

rm -rf "$host_output_dir"
mkdir -p "$host_output_dir"
if [[ -d "$extract_dir/dist/windows" ]]; then
  cp -a "$extract_dir/dist/windows/." "$host_output_dir/"
fi
cp -f "$extract_dir/summary.txt" "$host_output_dir/summary.txt"
cp -f "$extract_dir/windows-package-build.log" "$host_output_dir/windows-package-build.log"

if [[ "$guest_exit_code" != "0" ]]; then
  log "Windows VM build failed; build log tail:"
  tail -n 120 "$host_output_dir/windows-package-build.log" >&2 || true
  exit "$guest_exit_code"
fi

if ! find "$host_output_dir" -maxdepth 1 -type f \( -name '*.exe' -o -name '*.msi' \) | grep -q .; then
  echo "Windows VM build completed but no EXE/MSI artifacts were copied to $host_output_dir" >&2
  exit 1
fi

log "Windows VM package artifacts copied to: $host_output_dir"
find "$host_output_dir" -maxdepth 1 -type f | sort | sed 's/^/[vpn-control]  - /'
