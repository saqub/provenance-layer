"""Adversarial tests for the dependency-free provenance-layer PoC."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest

from ledger import (
    GENESIS,
    Ledger,
    LedgerFormatError,
    LedgerIntegrityError,
    commitment_matches,
    payload_commitment,
    payload_hash,
    record_digest,
)
from merkle import PROOF_SCHEMA, inclusion_proof, merkle_root, verify_inclusion


WRITER_KEY = bytes.fromhex("11" * 32)
WRONG_KEY = bytes.fromhex("22" * 32)


class LedgerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "ledger.jsonl")
        self.ledger = Ledger(self.path, writer_key=WRITER_KEY)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def append_records(self, count: int = 3) -> list[dict]:
        for index in range(count):
            self.ledger.append("human.a", "approve", {"case": index})
        return self.ledger.read_all()

    def write_records(self, records: list[dict]) -> None:
        with open(self.path, "w", encoding="utf-8", newline="\n") as stream:
            for record in records:
                stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


class LedgerStructureTests(LedgerTestCase):
    def test_empty_ledger_verifies(self) -> None:
        ok, message = self.ledger.verify(require_auth=True)
        self.assertTrue(ok, message)

    def test_append_creates_strict_sequence_and_one_ledger_identity(self) -> None:
        records = self.append_records(3)
        self.assertEqual([record["seq"] for record in records], [1, 2, 3])
        self.assertEqual(len({record["ledger_id"] for record in records}), 1)
        self.assertEqual(records[0]["prev_hash"], GENESIS)
        self.assertEqual(records[1]["prev_hash"], records[0]["record_hash"])

    def test_authenticated_ledger_verifies_with_correct_key(self) -> None:
        self.append_records()
        ok, message = self.ledger.verify(require_auth=True)
        self.assertTrue(ok, message)
        self.assertIn("writer authenticated", message)

    def test_wrong_key_fails_authentication(self) -> None:
        self.append_records()
        ok, message = Ledger(self.path, writer_key=WRONG_KEY).verify(require_auth=True)
        self.assertFalse(ok)
        self.assertIn("wrong writer key", message)

    def test_keyless_reader_can_check_chain_but_not_authenticate(self) -> None:
        self.append_records()
        ok, message = Ledger(self.path).verify()
        self.assertTrue(ok, message)
        self.assertIn("not authenticated", message)

    def test_keyless_append_cannot_downgrade_authenticated_ledger(self) -> None:
        self.ledger.append("human.a", "approve", {"case": 1})
        with self.assertRaisesRegex(LedgerIntegrityError, "authentication mode|writer key"):
            Ledger(self.path).append("human.b", "approve", {"case": 2})
        self.assertEqual(len(self.ledger.read_all()), 1)
        ok, message = self.ledger.verify(require_auth=True)
        self.assertTrue(ok, message)

    def test_public_verifier_rejects_authentication_downgrade(self) -> None:
        records = self.append_records(1)
        salt = "ab" * 16
        body = {
            "schema": records[0]["schema"],
            "ledger_id": records[0]["ledger_id"],
            "seq": 2,
            "ts": records[0]["ts"],
            "actor": "human.b",
            "event": "approve",
            "payload_commitment": payload_commitment({"case": 2}, salt),
            "payload_salt": salt,
            "prev_hash": records[0]["record_hash"],
            "writer_key_id": None,
        }
        records.append({**body, "record_hash": record_digest(body)})
        self.write_records(records)
        ok, message = Ledger(self.path).verify()
        self.assertFalse(ok)
        self.assertIn("authentication mode changed", message)

    def test_non_string_hex_field_is_rejected(self) -> None:
        records = self.append_records(1)
        records[0]["payload_salt"] = 11111111111111111111111111111111
        body = {
            key: value
            for key, value in records[0].items()
            if key not in {"record_hash", "writer_mac"}
        }
        records[0]["record_hash"] = record_digest(body)
        self.write_records(records)
        ok, message = Ledger(self.path).verify()
        self.assertFalse(ok)
        self.assertIn("invalid payload_salt", message)

    def test_non_nfc_record_returns_format_failure(self) -> None:
        records = self.append_records(1)
        records[0]["actor"] = "e\u0301"
        self.write_records(records)
        ok, message = Ledger(self.path).verify()
        self.assertFalse(ok)
        self.assertIn("canonical record invalid", message)

    def test_invalid_sequence_fails(self) -> None:
        records = self.append_records()
        records[1]["seq"] = 99
        self.write_records(records)
        ok, message = self.ledger.verify()
        self.assertFalse(ok)
        self.assertIn("sequence error", message)

    def test_boolean_is_not_accepted_as_a_sequence_number(self) -> None:
        records = self.append_records(1)
        records[0]["seq"] = True
        body = {
            key: value
            for key, value in records[0].items()
            if key not in {"record_hash", "writer_mac"}
        }
        records[0]["record_hash"] = record_digest(body)
        self.write_records(records)
        ok, message = Ledger(self.path).verify()
        self.assertFalse(ok)
        self.assertIn("sequence error", message)

    def test_unknown_field_fails(self) -> None:
        records = self.append_records(1)
        records[0]["surprise"] = True
        self.write_records(records)
        ok, message = self.ledger.verify()
        self.assertFalse(ok)
        self.assertIn("unknown surprise", message)

    def test_malformed_json_returns_failure(self) -> None:
        with open(self.path, "w", encoding="utf-8") as stream:
            stream.write('{"partial":')
        ok, message = self.ledger.verify()
        self.assertFalse(ok)
        self.assertIn("invalid JSON", message)

    def test_duplicate_json_key_returns_failure(self) -> None:
        with open(self.path, "w", encoding="utf-8") as stream:
            stream.write('{"schema":"one","schema":"two"}\n')
        ok, message = self.ledger.verify()
        self.assertFalse(ok)
        self.assertIn("duplicate JSON key", message)

    def test_append_refuses_a_corrupt_ledger(self) -> None:
        records = self.append_records(2)
        records[0]["payload_commitment"] = "0" * 64
        self.write_records(records)
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.append("human.a", "approve", {"case": 3})


class CommitmentTests(LedgerTestCase):
    def test_payload_hash_is_deterministic_and_order_independent(self) -> None:
        self.assertEqual(payload_hash({"a": 1, "b": 2}), payload_hash({"b": 2, "a": 1}))
        self.assertNotEqual(payload_hash({"a": 1}), payload_hash({"a": 2}))

    def test_salted_commitments_differ_and_open(self) -> None:
        payload = {"case": "low-entropy"}
        first = payload_commitment(payload, "00" * 16)
        second = payload_commitment(payload, "11" * 16)
        self.assertNotEqual(first, second)
        self.assertTrue(commitment_matches(payload, "00" * 16, first))
        self.assertFalse(commitment_matches({"case": "other"}, "00" * 16, first))

    def test_append_uses_a_fresh_salt(self) -> None:
        records = self.append_records(2)
        self.assertNotEqual(records[0]["payload_salt"], records[1]["payload_salt"])

    def test_floats_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.ledger.append("human.a", "measure", {"score": 1.25})

    def test_non_string_keys_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.ledger.append("human.a", "measure", {1: "value"})


class AdversarialLedgerTests(LedgerTestCase):
    def test_naive_payload_commitment_edit_is_detected(self) -> None:
        records = self.append_records()
        records[1]["payload_commitment"] = "0" * 64
        self.write_records(records)
        ok, message = self.ledger.verify(require_auth=True)
        self.assertFalse(ok)
        self.assertIn("tamper detected", message)

    def test_deleted_middle_record_breaks_chain(self) -> None:
        records = self.append_records(3)
        del records[1]
        self.write_records(records)
        ok, _ = self.ledger.verify()
        self.assertFalse(ok)

    def test_recomputed_chain_passes_public_hash_check_but_fails_auth(self) -> None:
        records = self.append_records(4)
        records[1]["payload_commitment"] = "f" * 64
        for index in range(1, len(records)):
            records[index]["prev_hash"] = records[index - 1]["record_hash"]
            body = {
                key: value
                for key, value in records[index].items()
                if key not in {"record_hash", "writer_mac"}
            }
            records[index]["record_hash"] = record_digest(body)
        self.write_records(records)

        public_ok, _ = Ledger(self.path).verify()
        auth_ok, message = self.ledger.verify(require_auth=True)
        self.assertTrue(public_ok)
        self.assertFalse(auth_ok)
        self.assertIn("writer_mac mismatch", message)


class CheckpointTests(LedgerTestCase):
    def test_checkpoint_commits_to_verified_history(self) -> None:
        self.append_records(5)
        receipt = self.ledger.checkpoint(require_auth=True)
        ok, message = self.ledger.verify_checkpoint(receipt, require_auth=True)
        self.assertTrue(ok, message)
        self.assertEqual(receipt["record_count"], 5)
        self.assertEqual(receipt["anchor_status"], "UNPUBLISHED")

    def test_checkpoint_changes_after_append(self) -> None:
        self.append_records(2)
        first = self.ledger.checkpoint(require_auth=True)
        self.ledger.append("human.a", "approve", {"case": 3})
        second = self.ledger.checkpoint(require_auth=True)
        self.assertNotEqual(first["receipt_hash"], second["receipt_hash"])
        self.assertNotEqual(first["merkle_root"], second["merkle_root"])

    def test_checkpoint_refuses_invalid_ledger(self) -> None:
        records = self.append_records(2)
        records[0]["payload_commitment"] = "0" * 64
        self.write_records(records)
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.checkpoint(require_auth=True)

    def test_keyless_checkpoint_cannot_downgrade_authenticated_ledger(self) -> None:
        self.append_records(2)
        with self.assertRaisesRegex(LedgerIntegrityError, "authentication mode|writer key"):
            Ledger(self.path).checkpoint()

    def test_tail_truncation_needs_retained_checkpoint_to_detect(self) -> None:
        records = self.append_records(4)
        receipt = self.ledger.checkpoint(require_auth=True)
        self.write_records(records[:-1])

        local_ok, _ = Ledger(self.path).verify()
        checkpoint_ok, message = Ledger(self.path).verify_checkpoint(receipt)
        self.assertTrue(local_ok)
        self.assertFalse(checkpoint_ok)
        self.assertIn("record_count", message)

    def test_modified_receipt_fails_its_digest(self) -> None:
        self.append_records(2)
        receipt = self.ledger.checkpoint(require_auth=True)
        receipt["record_count"] = 99
        ok, message = self.ledger.verify_checkpoint(receipt, require_auth=True)
        self.assertFalse(ok)
        self.assertIn("receipt_hash mismatch", message)

    def test_unknown_checkpoint_field_fails(self) -> None:
        self.append_records(1)
        receipt = self.ledger.checkpoint(require_auth=True)
        receipt["surprise"] = True
        ok, message = self.ledger.verify_checkpoint(receipt)
        self.assertFalse(ok)
        self.assertIn("unknown fields", message)

    def test_checkpoint_cannot_claim_external_publication(self) -> None:
        self.append_records(1)
        receipt = self.ledger.checkpoint(require_auth=True)
        receipt["anchor_status"] = "ANCHORED"
        ok, message = self.ledger.verify_checkpoint(receipt)
        self.assertFalse(ok)
        self.assertIn("unsupported anchor_status", message)


class MerkleTests(unittest.TestCase):
    @staticmethod
    def leaves(count: int) -> list[str]:
        return [hashlib.sha256(str(index).encode()).hexdigest() for index in range(count)]

    def test_root_of_empty_is_genesis(self) -> None:
        self.assertEqual(merkle_root([]), GENESIS)

    def test_root_of_single_leaf_is_leaf(self) -> None:
        leaves = self.leaves(1)
        self.assertEqual(merkle_root(leaves), leaves[0])

    def test_inclusion_proofs_verify_for_every_leaf(self) -> None:
        for count in (1, 2, 3, 4, 5, 8, 13):
            leaves = self.leaves(count)
            root = merkle_root(leaves)
            for index, leaf in enumerate(leaves):
                proof = inclusion_proof(leaves, index)
                self.assertTrue(verify_inclusion(leaf, proof, root), f"n={count} leaf={index}")

    def test_wrong_leaf_fails(self) -> None:
        leaves = self.leaves(8)
        proof = inclusion_proof(leaves, 3)
        self.assertFalse(verify_inclusion(leaves[4], proof, merkle_root(leaves)))

    def test_invalid_side_fails_closed(self) -> None:
        leaves = self.leaves(4)
        proof = inclusion_proof(leaves, 1)
        proof["path"][0]["side"] = "bogus"
        self.assertFalse(verify_inclusion(leaves[1], proof, merkle_root(leaves)))

    def test_wrong_tree_size_fails(self) -> None:
        leaves = self.leaves(5)
        proof = inclusion_proof(leaves, 4)
        proof["tree_size"] = 4
        self.assertFalse(verify_inclusion(leaves[4], proof, merkle_root(leaves)))

    def test_boolean_index_and_tree_size_fail(self) -> None:
        leaves = self.leaves(1)
        with self.assertRaises(TypeError):
            inclusion_proof(leaves, True)
        proof = inclusion_proof(leaves, 0)
        proof["leaf_index"] = False
        self.assertFalse(verify_inclusion(leaves[0], proof, merkle_root(leaves)))
        proof = inclusion_proof(leaves, 0)
        proof["tree_size"] = True
        self.assertFalse(verify_inclusion(leaves[0], proof, merkle_root(leaves)))

    def test_wrong_schema_fails(self) -> None:
        leaves = self.leaves(2)
        proof = inclusion_proof(leaves, 0)
        self.assertEqual(proof["schema"], PROOF_SCHEMA)
        proof["schema"] = "unknown"
        self.assertFalse(verify_inclusion(leaves[0], proof, merkle_root(leaves)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
