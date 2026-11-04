"""Tests for pivot_out.py. Run with:  python3 -m unittest

No network: the lookups are swapped for fake ones, so these run in a second
and never touch crt.sh, RDAP, or VirusTotal. All domains are made up
(.example is reserved for exactly this) and IPs are from documentation ranges,
except the Cloudflare one, which has to be a real Cloudflare address.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pivot_out as p  # noqa: E402


class Helpers(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(p.defang("evil.example"), "evil[.]example")
        self.assertEqual(p.defang("203.0.113.7"), "203.0.113[.]7")
        self.assertEqual(p.defang("Let's Encrypt"), "Let's Encrypt")

    def test_refang(self):
        self.assertEqual(p.refang("hxxps://evil[.]example/login"), "evil.example")
        self.assertEqual(p.refang("evil(.)example:8443"), "evil.example")

    def test_valid_domain(self):
        for good in ["evil.example", "www.evil-sso.example", "xn--80ak6aa92e.com"]:
            self.assertTrue(p.is_valid_domain(good), good)
        # SANs and hostnames are attacker-controlled, so junk has to be rejected
        for bad in ["evil", "-evil.example", "evil.example/x", "a b.example", '"><img>.example', ""]:
            self.assertFalse(p.is_valid_domain(bad), bad)

    def test_csv_safe(self):
        self.assertEqual(p.csv_safe("=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")")
        self.assertEqual(p.csv_safe("evil[.]example"), "evil[.]example")

    def test_shared_network(self):
        self.assertEqual(p.shared_network("104.21.94.1"), "Cloudflare")
        self.assertIsNone(p.shared_network("203.0.113.7"))
        self.assertIsNone(p.shared_network("not an ip"))

    def test_days_apart(self):
        self.assertEqual(p.days_apart("2026-09-26", "2026-09-28"), 2)
        self.assertIsNone(p.days_apart(None, "2026-09-28"))


def fake_cert(serial, sans):
    return {"crtsh_id": serial, "serial": serial, "issuer": "C=US, O=Let's Encrypt", "not_before": "2026-09-11",
            "not_after": "2026-12-10", "sans": sans, "query": "https://crt.sh/?q=x"}


class Pivot(unittest.TestCase):
    """The whole loop, with fake data shaped like the start-hub[.]beer case from Part 3."""

    def run_pivot(self, certs, resolutions, neighbors, **kwargs):
        with mock.patch.object(p, "lookup_registration", return_value=None), \
             mock.patch.object(p, "lookup_certs", side_effect=lambda d: certs.get(d, [])), \
             mock.patch.object(p, "lookup_resolutions", side_effect=lambda d, k: resolutions.get(d, [])), \
             mock.patch.object(p, "lookup_ip_neighbors", side_effect=lambda ip, k: neighbors.get(ip, [])) as nb, \
             mock.patch("sys.stderr"):
            findings = p.pivot("start.example", rounds=kwargs.pop("rounds", 1), max_domains=25,
                               vt_key="fake", **kwargs)
        return findings, nb

    def test_cloudflare_trap_and_same_week_neighbor(self):
        resolutions = {"start.example": [
            {"ip": "104.21.94.1", "date": "2026-09-11", "query": "vt"},  # Cloudflare: the trap
            {"ip": "203.0.113.7", "date": "2026-09-28", "query": "vt"},  # a real lead
        ]}
        neighbors = {"203.0.113.7": [
            {"host": "start.example", "date": "2026-09-28", "query": "vt"},
            {"host": "friend.example", "date": "2026-09-26", "query": "vt"},
            {"host": "old.example", "date": "2025-01-01", "query": "vt"},
        ]}
        findings, nb = self.run_pivot({}, resolutions, neighbors)

        nb.assert_called_once_with("203.0.113.7", "fake")  # never spent a lookup on Cloudflare
        cf = [f for f in findings if f["value"] == "104.21.94.1"][0]
        self.assertIn("Cloudflare", cf["note"])
        notes = {f["value"]: f["note"] for f in findings if f["type"] == "ip_neighbor"}
        self.assertTrue(notes["friend.example"].startswith("SAME WEEK"))
        self.assertIn("days apart", notes["old.example"])
        self.assertNotIn("start.example", notes)  # don't list the domain as its own neighbor

    def test_busy_ip_is_not_listed(self):
        resolutions = {"start.example": [{"ip": "203.0.113.9", "date": "2026-09-28", "query": "vt"}]}
        crowd = [{"host": f"site{i}.example", "date": "2026-09-28", "query": "vt"} for i in range(40)]
        findings, _ = self.run_pivot({}, resolutions, {"203.0.113.9": crowd})
        self.assertEqual([f["type"] for f in findings], ["resolution", "busy_ip"])

    def test_san_loop_skips_junk_and_giant_certs(self):
        certs = {
            "start.example": [fake_cert("1", ["start.example", "sso.example", "bad name.example"])],
            "sso.example": [fake_cert("2", ["sso.example"] + [f"cdn{i}.example" for i in range(60)])],
        }
        findings, _ = self.run_pivot(certs, {}, {}, rounds=2)
        types = [(f["type"], f["value"]) for f in findings]
        self.assertIn(("san", "sso.example"), types)
        self.assertIn(("skipped", "bad name.example"), types)
        # the 60-SAN cert gets recorded, but its SANs never get queued for another round
        checked = {f["related_to"] for f in findings if f["type"] == "certificate"}
        self.assertEqual(checked, {"start.example", "sso.example"})


if __name__ == "__main__":
    unittest.main()
