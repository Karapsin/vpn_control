import hashlib
import unittest
from android_routing_evidence import routing_domain_evidence


def reply(data):
    return {"ok": True, "final": True, "code": "OK", "configurationRevision": 0, "data": data}


class RoutingEvidenceTest(unittest.TestCase):
    def test_mutation_and_cold_show_envelopes_prove_identical_domains(self):
        domains = ["one.example", "two.example", "two.example"]
        mutation = reply({"direct-domains": domains})
        cold = reply({"routing": {"version": 7, "rules": {"direct_domain_suffixes": domains}}})
        expected = {"count": 3, "newlineSha256": hashlib.sha256("\n".join(domains).encode()).hexdigest()}
        self.assertEqual(expected, routing_domain_evidence(mutation))
        self.assertEqual(expected, routing_domain_evidence(cold))

    def test_absent_or_ambiguous_fields_are_not_reported_as_empty_routing(self):
        for data in [{}, {"routing": {}}, {"routing": {"rules": {}}},
                     {"direct-domains": [], "routing": {"rules": {"direct_domain_suffixes": []}}}]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                routing_domain_evidence(reply(data))

    def test_explicit_empty_list_is_valid(self):
        for data in [{"direct-domains": []}, {"routing": {"rules": {"direct_domain_suffixes": []}}}]:
            self.assertEqual({"count": 0, "newlineSha256": hashlib.sha256(b"").hexdigest()},
                             routing_domain_evidence(reply(data)))

    def test_failed_pending_and_malformed_results_are_rejected(self):
        for response in [None, [], {}, {**reply({"direct-domains": []}), "ok": False},
                         {**reply({"direct-domains": []}), "final": False},
                         {**reply({"direct-domains": []}), "code": "ACCEPTED"},
                         reply({"direct-domains": "domain"}), reply({"direct-domains": [1]}),
                         reply({"direct-domains": ["bad\ud800"]})]:
            with self.subTest(response=response), self.assertRaises(ValueError):
                routing_domain_evidence(response)


if __name__ == "__main__":
    unittest.main()
