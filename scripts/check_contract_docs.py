#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "agent_docs/contracts.md"
ID_PATTERN = re.compile(r"^- \*\*([A-Z0-9]+-[0-9]{3})\s+—", re.MULTILINE)


def main() -> int:
    errors: list[str] = []
    text = CONTRACTS.read_text(encoding="utf-8")
    identifiers = ID_PATTERN.findall(text)
    if len(identifiers) != len(set(identifiers)):
        duplicates = sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1})
        errors.append("duplicate contract IDs: " + ", ".join(duplicates))
    domains = {identifier.split("-", 1)[0] for identifier in identifiers}
    required_domains = {
        "PRODUCT", "UI", "STATE", "PLATFORM", "DESKTOP", "CONFIG", "L10N", "ARTIFACT", "VISUAL", "RELEASE",
    }
    missing_domains = sorted(required_domains - domains)
    if missing_domains:
        errors.append("missing contract domains: " + ", ".join(missing_domains))
    for domain in domains:
        numbers = sorted(int(identifier.rsplit("-", 1)[1]) for identifier in identifiers if identifier.startswith(domain + "-"))
        if numbers != list(range(1, len(numbers) + 1)):
            errors.append(f"{domain} contract IDs must be contiguous from 001: {numbers}")
    for path in sorted((ROOT / "agent_docs").glob("*.md")):
        if path == CONTRACTS:
            continue
        local_ids = ID_PATTERN.findall(path.read_text(encoding="utf-8"))
        if local_ids:
            errors.append(f"{path.relative_to(ROOT)} defines contract entries outside contracts.md: {', '.join(local_ids)}")
    legacy = ROOT / "agent_docs/sing-box-contract.md"
    if legacy.exists():
        errors.append("legacy sing-box-contract.md must remain consolidated into contracts.md")
    for path in [ROOT / "AGENTS.md", *(ROOT / "agent_docs").glob("*.md"), ROOT / "agent_tools/README.md"]:
        if path.is_file() and "sing-box-contract.md" in path.read_text(encoding="utf-8"):
            errors.append(f"legacy contract reference remains in {path.relative_to(ROOT)}")
    for required_reference in (ROOT / "AGENTS.md", ROOT / "agent_docs/README.md", ROOT / "agent_tools/README.md"):
        if "contracts.md" not in required_reference.read_text(encoding="utf-8"):
            errors.append(f"{required_reference.relative_to(ROOT)} must route product invariants to contracts.md")
    if errors:
        print("Contract documentation hygiene failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print(f"[vpn-control] contract documentation passed ({len(identifiers)} contract IDs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
