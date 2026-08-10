import hashlib
import unittest

import dns_exfil as de


class HelperTests(unittest.TestCase):
    def test_split_query(self):
        self.assertEqual(de.split_query("a.b.evil.example.com"), ("example.com", "a.b.evil"))
        self.assertEqual(de.split_query("example.com"), ("example.com", ""))

    def test_entropy(self):
        self.assertLess(de.shannon_entropy("aaaaaaaa"), 1.0)
        self.assertGreater(de.shannon_entropy("0123456789abcdef"), 3.5)


class DetectTests(unittest.TestCase):
    def setUp(self):
        benign = ["www.google.com"] * 100 + ["api.github.com"] * 50 + ["mail.example.org"] * 30
        exfil = [hashlib.sha256(str(i).encode()).hexdigest() + ".evil.example" for i in range(30)]
        self.stats = de.analyze(benign + exfil)
        self.findings = de.detect(self.stats)

    def test_flags_tunnel(self):
        flagged = {f["domain"] for f in self.findings}
        self.assertIn("evil.example", flagged)

    def test_ignores_benign(self):
        flagged = {f["domain"] for f in self.findings}
        self.assertNotIn("google.com", flagged)
        self.assertNotIn("github.com", flagged)

    def test_tunnel_is_high(self):
        tunnel = next(f for f in self.findings if f["domain"] == "evil.example")
        self.assertEqual(tunnel["severity"], "high")
        self.assertGreaterEqual(tunnel["unique_subdomains"], 20)


if __name__ == "__main__":
    unittest.main()
