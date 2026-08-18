"""Tests for the provenance ledger. Standard library only: python test_ledger.py"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from ledger import GENESIS, Ledger, payload_hash
from merkle import inclusion_proof, merkle_root, verify_inclusion


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "ledger.jsonl")
        self.ledger = Ledger(self.path)

    def tearDown(self):
        self.dir.cleanup()

    def test_empty_ledger_verifies(self):
        ok, _ = self.ledger.verify()
        self.assertTrue(ok)

    def test_append_chains_records(self):
        r1 = self.ledger.append("human.a", "approve", {"case": 1})
        r2 = self.ledger.append("human.a", "approve", {"case": 2})
        self.assertEqual(r1["prev_hash"], GENESIS)
        self.assertEqual(r2["prev_hash"], r1["record_hash"])
        ok, msg = self.ledger.verify()
        self.assertTrue(ok, msg)

    def test_payload_hash_is_deterministic_and_order_free(self):
        self.assertEqual(payload_hash({"a": 1, "b": 2}), payload_hash({"b": 2, "a": 1}))
        self.assertNotEqual(payload_hash({"a": 1}), payload_hash({"a": 2}))

    def test_tampered_payload_detected(self):
        self.ledger.append("human.a", "approve", {"case": 1})
        self.ledger.append("human.a", "refuse", {"case": 2})
        lines = open(self.path, encoding="utf-8").readlines()
        rec = json.loads(lines[1])
        rec["payload_hash"] = payload_hash({"case": 2, "quietly": "changed"})
        lines[1] = json.dumps(rec, sort_keys=True) + "\n"
        open(self.path, "w", encoding="utf-8").writelines(lines)
        ok, msg = self.ledger.verify()
        self.assertFalse(ok)
        self.assertIn("seq 2", msg)

    def test_deleted_record_breaks_chain(self):
        self.ledger.append("human.a", "approve", {"case": 1})
        self.ledger.append("human.a", "approve", {"case": 2})
        self.ledger.append("human.a", "approve", {"case": 3})
        lines = open(self.path, encoding="utf-8").readlines()
        del lines[1]  # silently drop the middle record
        open(self.path, "w", encoding="utf-8").writelines(lines)
        ok, _ = self.ledger.verify()
        self.assertFalse(ok)

    def test_checkpoint_commits_to_history(self):
        for i in range(5):
            self.ledger.append("human.a", "approve", {"case": i})
        c1 = self.ledger.checkpoint()
        self.assertEqual(c1["records"], 5)
        self.ledger.append("human.a", "approve", {"case": 99})
        c2 = self.ledger.checkpoint()
        self.assertNotEqual(c1["merkle_root"], c2["merkle_root"])
        self.assertNotEqual(c1["chain_head"], c2["chain_head"])


class MerkleTests(unittest.TestCase):
    def _leaves(self, n):
        import hashlib
        return [hashlib.sha256(str(i).encode()).hexdigest() for i in range(n)]

    def test_root_of_empty_is_genesis(self):
        self.assertEqual(merkle_root([]), GENESIS)

    def test_root_of_single_leaf_is_leaf(self):
        leaves = self._leaves(1)
        self.assertEqual(merkle_root(leaves), leaves[0])

    def test_inclusion_proofs_verify_for_every_leaf(self):
        for n in (1, 2, 3, 4, 5, 8, 13):
            leaves = self._leaves(n)
            root = merkle_root(leaves)
            for i in range(n):
                proof = inclusion_proof(leaves, i)
                self.assertTrue(verify_inclusion(leaves[i], proof, root),
                                f"n={n} leaf={i}")

    def test_wrong_leaf_fails_inclusion(self):
        leaves = self._leaves(8)
        root = merkle_root(leaves)
        proof = inclusion_proof(leaves, 3)
        self.assertFalse(verify_inclusion(leaves[4], proof, root))


if __name__ == "__main__":
    unittest.main(verbosity=2)
