"""Public owned launch adapter; never imports or invokes Tart or a VM."""
import json
from pathlib import Path
import resource
import sys
import time


assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
root = Path(__file__).parent
with (root / "adapter-calls.jsonl").open("a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
if sys.argv[1:] == ["list", "--format", "json"]:
    print(json.dumps([{"Name": "vpn-tool-recovery-tart-macos-root-identity", "State": "stopped"}]))
else:
    assert sys.argv[1:6] == ["run", "vpn-tool-recovery-tart-macos-root-identity", "--no-graphics",
                              "--vnc-experimental", "--suspendable"]
    # Keep the actual child alive while the owner records its kernel generation.
    time.sleep(.15)
    print("guest has stopped the virtual machine", flush=True)
