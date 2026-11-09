"""The location links the product's own parser takes, read from its Kotlin source.

`locations add --input` reaches LocationConfigs.parseLocationInput, and a link goes to
ProxyLinkParser.parseProxyLink, which dispatches the trimmed text on its scheme,
ignoring case; anything else is an error the owner answers INVALID_ARGUMENT
(DesktopAppService.saveControlLocation). The fake products of these tests refuse what
it refuses, so a tool that publishes another scheme fails offline as it failed on a
guest. The schemes are read from the source at every call, never copied, so a fake
cannot drift from the product. A JSON profile, which the product also takes, is not
modelled: no tool publishes one.
"""
from pathlib import Path
import re

PARSER = Path(__file__).resolve().parents[2] / "shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/data/ProxyLinkParser.kt"
BRANCH = re.compile(r'trimmed\.startsWith\("([a-z0-9+.-]+://)", ignoreCase = true\) -> parse[A-Za-z]+Link\(trimmed\)')


def schemes():
    """The prefixes parseProxyLink dispatches; a branch of any other shape stops the caller."""
    text = PARSER.read_text(encoding="utf-8")
    found = re.search(r"\n    fun parseProxyLink\(link: String\): ProxyProfile \{\n(.*?)\n    \}\n", text, re.S)
    if found is None:
        raise AssertionError("ProxyLinkParser.parseProxyLink is not where the fake products read it")
    branches = [line.strip() for line in found.group(1).splitlines() if "->" in line]
    if not branches or not branches[-1].startswith("else -> error("):
        raise AssertionError("parseProxyLink no longer ends in its refusing else branch")
    prefixes = []
    for line in branches[:-1]:
        branch = BRANCH.fullmatch(line)
        if branch is None:
            raise AssertionError("parseProxyLink has a branch the fake products do not read: " + line)
        prefixes.append(branch.group(1))
    if not prefixes:
        raise AssertionError("parseProxyLink dispatches no scheme")
    return tuple(prefixes)


def dispatched(link):
    """Whether parseProxyLink takes this link: Kotlin's trim, then a prefix compared ignoring case."""
    trimmed = link.strip()
    return any(trimmed[:len(prefix)].lower() == prefix for prefix in schemes())
