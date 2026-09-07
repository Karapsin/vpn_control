"""Extract domain-sequence evidence from the two public routing result shapes.

This verifies domains only, not every routing setting or installation identity.
Missing fields must never become a successful zero-domain observation.
"""
import hashlib


def routing_domain_evidence(response):
    if (not isinstance(response, dict) or response.get("ok") is not True or
            response.get("final") is not True or response.get("code") != "OK"):
        raise ValueError("Routing evidence requires a final successful response")
    data = response.get("data")
    if not isinstance(data, dict):
        raise ValueError("Routing response has no data object")
    mutation, inspection = "direct-domains" in data, "routing" in data
    if mutation == inspection:
        raise ValueError("Missing or ambiguous routing response shape")
    if mutation:
        domains = data["direct-domains"]
    else:
        routing = data["routing"]
        rules = routing.get("rules") if isinstance(routing, dict) else None
        if not isinstance(rules, dict) or "direct_domain_suffixes" not in rules:
            raise ValueError("Routing inspection has no domain list")
        domains = rules["direct_domain_suffixes"]
    if not isinstance(domains, list) or any(not isinstance(domain, str) for domain in domains):
        raise ValueError("Routing domains must be a list of strings")
    digest = hashlib.sha256()
    for index, domain in enumerate(domains):
        if index:
            digest.update(b"\n")
        digest.update(domain.encode("utf-8", errors="strict"))
    return {"count": len(domains), "newlineSha256": digest.hexdigest()}
