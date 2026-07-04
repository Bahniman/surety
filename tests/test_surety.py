"""Surety test suite.  Run:  python -m unittest discover tests -v"""
import time
import unittest

from surety.crypto import (Ed25519Signer, ed25519_publickey, ed25519_sign,
                           ed25519_verify)
from surety import certificate as cert_mod
from surety.guard import Guard
from surety.store import Store
from surety.verifier import verify_action


def make_cert(signer=None, **over):
    signer = signer or Ed25519Signer()
    kw = dict(
        budget_total=250000,
        allowed_tools={"saas_renewal": "software", "book_travel": "travel"},
        allowed_domains=["*.figma.com", "*.makemytrip.com"],
        budget_categories={"travel": 60000, "software": 170000},
        active_hours=(0, 24),
        max_actions_per_hour=30,
        require_approval_over=50000,
        ttl_hours=24,
    )
    kw.update(over)
    return signer, cert_mod.issue(signer, "cfo@x.example", "agent-1", **kw)


class TestEd25519(unittest.TestCase):
    def test_rfc8032_vector_1(self):
        # RFC 8032, section 7.1, TEST 1 (empty message)
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pub_expected = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig_expected = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        pub = ed25519_publickey(seed)
        self.assertEqual(pub, pub_expected)
        sig = ed25519_sign(b"", seed, pub)
        self.assertEqual(sig, sig_expected)
        self.assertTrue(ed25519_verify(sig, b"", pub))

    def test_rfc8032_vector_2(self):
        # RFC 8032, section 7.1, TEST 2 (one-byte message 0x72)
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        pub_expected = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        sig_expected = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
        pub = ed25519_publickey(seed)
        self.assertEqual(pub, pub_expected)
        sig = ed25519_sign(b"\x72", seed, pub)
        self.assertEqual(sig, sig_expected)
        self.assertTrue(ed25519_verify(sig, b"\x72", pub))

    def test_wrong_message_fails(self):
        s = Ed25519Signer()
        sig = s.sign(b"hello")
        self.assertTrue(Ed25519Signer.verify(b"hello", sig, s.public_hex))
        self.assertFalse(Ed25519Signer.verify(b"hellO", sig, s.public_hex))

    def test_wrong_key_fails(self):
        s1, s2 = Ed25519Signer(), Ed25519Signer()
        sig = s1.sign(b"msg")
        self.assertFalse(Ed25519Signer.verify(b"msg", sig, s2.public_hex))


class TestCertificate(unittest.TestCase):
    def test_verify_roundtrip(self):
        _, cert = make_cert()
        self.assertTrue(cert_mod.verify(cert))

    def test_tamper_detected(self):
        _, cert = make_cert()
        cert["scope"]["budget_total"] = 9_999_999
        self.assertFalse(cert_mod.verify(cert))

    def test_tool_category(self):
        _, cert = make_cert()
        self.assertEqual(cert_mod.tool_category(cert, "book_travel"), "travel")
        self.assertIsNone(cert_mod.tool_category(cert, "buy_ads"))


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.signer, self.cert = make_cert()
        self.store = Store()
        self.guard = Guard(self.cert, self.store)

    def test_allow_in_scope(self):
        d = self.guard.request("saas_renewal", domain="www.figma.com", amount=38400)
        self.assertEqual(d.verdict, "ALLOW")
        self.assertEqual(self.guard.spent, 38400)

    def test_block_unknown_tool(self):
        d = self.guard.request("buy_ads", domain="www.figma.com", amount=100)
        self.assertEqual(d.verdict, "BLOCK")
        self.assertIn("not in the mandate", d.reason)

    def test_block_bad_domain(self):
        d = self.guard.request("saas_renewal", domain="evil.biz", amount=100)
        self.assertEqual(d.verdict, "BLOCK")
        self.assertIn("not allow-listed", d.reason)

    def test_block_category_budget(self):
        self.guard.request("book_travel", domain="www.makemytrip.com", amount=45000)
        d = self.guard.request("book_travel", domain="www.makemytrip.com", amount=20000)
        self.assertEqual(d.verdict, "BLOCK")
        self.assertIn("category 'travel' budget", d.reason)

    def test_block_total_budget(self):
        # third tool has no category cap, so only the total can stop it
        _, cert = make_cert(
            allowed_tools={"saas_renewal": "software", "book_travel": "travel",
                           "order_supplies": "supplies"},
            allowed_domains=["*"], require_approval_over=None)
        g = Guard(cert, Store())
        g.request("saas_renewal", domain="www.figma.com", amount=160000)
        g.request("book_travel", domain="www.makemytrip.com", amount=55000)
        # spent 215k of 250k; supplies has no category cap
        d = g.request("order_supplies", domain="shop.example", amount=40000)
        self.assertEqual(d.verdict, "BLOCK")
        self.assertIn("total budget", d.reason)

    def test_escrow_over_threshold_then_approve(self):
        d = self.guard.request("saas_renewal", domain="www.figma.com", amount=118000)
        self.assertEqual(d.verdict, "ESCROW")
        self.assertIsNotNone(d.escrow_id)
        self.assertEqual(self.guard.spent, 0)
        d2 = self.guard.approve(d.escrow_id, "cfo@x.example")
        self.assertEqual(d2.verdict, "ALLOW")
        self.assertEqual(self.guard.spent, 118000)

    def test_escrow_deny(self):
        d = self.guard.request("saas_renewal", domain="www.figma.com", amount=118000)
        d2 = self.guard.deny(d.escrow_id, "cfo@x.example", "not this quarter")
        self.assertEqual(d2.verdict, "BLOCK")
        self.assertEqual(self.guard.spent, 0)

    def test_escrow_expires(self):
        g = Guard(self.cert, Store(), escrow_ttl_s=0.01)
        d = g.request("saas_renewal", domain="www.figma.com", amount=118000)
        time.sleep(0.05)
        d2 = g.approve(d.escrow_id, "cfo@x.example")
        self.assertEqual(d2.verdict, "BLOCK")
        self.assertIn("expired", d2.reason)

    def test_escrow_recheck_catches_changed_conditions(self):
        d = self.guard.request("saas_renewal", domain="www.figma.com", amount=118000)
        # meanwhile the agent burns the software category
        self.guard.request("saas_renewal", domain="www.figma.com", amount=49000)
        self.guard.request("saas_renewal", domain="www.figma.com", amount=49000)
        self.guard.request("saas_renewal", domain="www.figma.com", amount=49000)
        # software spent = 147k; approving 118k would exceed 170k cap
        d2 = self.guard.approve(d.escrow_id, "cfo@x.example")
        self.assertEqual(d2.verdict, "BLOCK")
        self.assertIn("conditions changed", d2.reason)

    def test_rate_limit(self):
        _, cert = make_cert(max_actions_per_hour=3, require_approval_over=None)
        g = Guard(cert, Store())
        for _ in range(3):
            self.assertEqual(
                g.request("saas_renewal", domain="www.figma.com", amount=10).verdict,
                "ALLOW")
        d = g.request("saas_renewal", domain="www.figma.com", amount=10)
        self.assertEqual(d.verdict, "BLOCK")
        self.assertIn("rate limit", d.reason)

    def test_active_hours(self):
        # long-lived cert valid from epoch so the fixed test date is in-window
        _, cert = make_cert(active_hours=(9, 18), valid_from=0.0,
                            ttl_hours=24 * 365 * 10)
        g = Guard(cert, Store())
        # 03:30 local on an arbitrary day
        t = time.mktime((2026, 7, 6, 3, 30, 0, 0, 0, -1))
        d = g.request("saas_renewal", domain="www.figma.com", amount=10, now=t)
        self.assertEqual(d.verdict, "BLOCK")
        self.assertIn("active hours", d.reason)

    def test_expiry(self):
        _, cert = make_cert(ttl_hours=0.0001)
        g = Guard(cert, Store())
        time.sleep(0.4)
        d = g.request("saas_renewal", domain="www.figma.com", amount=10)
        self.assertEqual(d.verdict, "BLOCK")
        self.assertIn("expired", d.reason)

    def test_revocation(self):
        self.guard.revoke()
        d = self.guard.request("saas_renewal", domain="www.figma.com", amount=10)
        self.assertEqual(d.verdict, "BLOCK")
        self.assertIn("revoked", d.reason)


class TestAudit(unittest.TestCase):
    def test_chain_intact_and_tamper_detected(self):
        store = Store()
        _, cert = make_cert()
        g = Guard(cert, store)
        g.request("saas_renewal", domain="www.figma.com", amount=100)
        g.request("buy_ads", amount=5)
        ok, bad = store.verify_chain()
        self.assertTrue(ok)
        # tamper directly in SQLite
        store.db.execute(
            "UPDATE audit SET body = replace(body, 'BLOCK', 'ALLOW') WHERE seq=2")
        store.db.commit()
        ok, bad = store.verify_chain()
        self.assertFalse(ok)
        self.assertEqual(bad, 2)


class TestPersistence(unittest.TestCase):
    def test_state_survives_reopen(self):
        import os
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "surety_test.db")
        signer, cert = make_cert()
        g1 = Guard(cert, Store(path))
        g1.request("saas_renewal", domain="www.figma.com", amount=1000)
        g1.revoke()
        # reopen fresh
        store2 = Store(path)
        self.assertTrue(store2.is_revoked(cert["id"]))
        self.assertEqual(store2.spent_total(cert["id"]), 1000)
        ok, _ = store2.verify_chain()
        self.assertTrue(ok)


class TestMerchantVerifier(unittest.TestCase):
    def test_offline_verify(self):
        _, cert = make_cert()
        res = verify_action(cert, tool="book_travel",
                            domain="www.makemytrip.com", amount=2100)
        self.assertTrue(res["authentic"])
        self.assertTrue(res["in_scope"])

    def test_offline_verify_rejects_tampered(self):
        _, cert = make_cert()
        cert["scope"]["budget_total"] = 10**9
        res = verify_action(cert, tool="book_travel",
                            domain="www.makemytrip.com", amount=2100)
        self.assertFalse(res["authentic"])

    def test_offline_verify_out_of_scope_tool(self):
        _, cert = make_cert()
        res = verify_action(cert, tool="wire_transfer", amount=10)
        self.assertTrue(res["authentic"])
        self.assertFalse(res["in_scope"])


if __name__ == "__main__":
    unittest.main()
