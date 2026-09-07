"""Generate checkout-local Codex MCP configuration without tracked absolute paths."""
import argparse
import json
from pathlib import Path
import shutil
import time


def configure(root: Path, bash: str, *, replace: bool = False) -> Path:
    root = root.resolve()
    template = (root / "agent_tools/codex-config.toml.in").read_text(encoding="utf-8")
    values = {"@BASH@": bash, "@LAUNCHER@": str(root / "agent_tools/mcp_server.sh"),
              "@ROOT@": str(root)}
    for token, value in values.items():
        template = template.replace(token, json.dumps(value, ensure_ascii=False))
    destination = root / ".codex/config.toml"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_text(encoding="utf-8") == template:
            return destination
        if not replace:
            raise FileExistsError("Local config exists; use --replace to back it up and regenerate.")
        backup = destination.with_name(f"config.backup-{time.time_ns()}.toml")
        with backup.open("x", encoding="utf-8") as stream:
            stream.write(destination.read_text(encoding="utf-8"))
        backup.chmod(0o600)
    temporary = destination.with_name(f"config.generated-{time.time_ns()}.toml")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(template)
        temporary.chmod(0o600)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replace", action="store_true", help="Back up existing local settings before regeneration")
    args = parser.parse_args()
    bash = shutil.which("bash")
    if bash is None:
        parser.error("bash is required")
    print(configure(Path(__file__).resolve().parent.parent, bash, replace=args.replace))


if __name__ == "__main__":
    main()
