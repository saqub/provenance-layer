"""Small, inspectable building blocks for tamper-evident AI event records.

This module is a proof of concept, not a production custody system. It shows
four separate properties which are often blurred together:

1. a hash chain makes accidental or naive edits visible;
2. an HMAC can authenticate a cooperative writer that holds a shared key;
3. a Merkle checkpoint commits a retained snapshot of the ledger; and
4. an external anchor *could* timestamp that checkpoint later.

It does not publish a checkpoint, protect keys in an HSM, establish
non-repudiation, or make a local file immutable. See THREAT_MODEL.md.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
import unicodedata
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

GENESIS = "0" * 64
RECORD_SCHEMA = "provenance-layer/record/v2"
CHECKPOINT_SCHEMA = "provenance-layer/checkpoint/v2"

_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_RECORD_DOMAIN = b"provenance-layer/record/v2\x00"
_PAYLOAD_DOMAIN = b"provenance-layer/payload/v1\x00"
_CHECKPOINT_DOMAIN = b"provenance-layer/checkpoint/v2\x00"
_MAC_DOMAIN = b"provenance-layer/hmac/v1\x00"


class LedgerError(RuntimeError):
    """Base error for ledger operations."""


class LedgerIntegrityError(LedgerError):
    """Raised when an operation is attempted against an invalid ledger."""


class LedgerFormatError(LedgerError):
    """Raised when JSONL cannot be decoded into ledger records."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LedgerFormatError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_json_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError(f"{path}: strings must be Unicode NFC-normalised")
        return
    if isinstance(value, float):
        raise TypeError(f"{path}: floats are not supported by this canonical profile")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path}: JSON object keys must be strings")
            _validate_json_value(key, f"{path}.<key>")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise TypeError(f"{path}: unsupported JSON value type {type(value).__name__}")


def _canonical(obj: Any) -> bytes:
    """Return the one JSON representation hashed by this PoC.

    This rejects NaN and infinity. It is deterministic for supported Python
    JSON values, but it is not claimed as a full RFC 8785 implementation or a
    cross-language canonicalisation standard.
    """

    _validate_json_value(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def payload_hash(payload: Any) -> str:
    """Return a deterministic, unsalted payload hash for comparisons.

    Do not use this alone for low-entropy or sensitive values: guesses can be
    hashed offline. Ledger.append uses payload_commitment with a random salt.
    """

    return _sha256_hex(_PAYLOAD_DOMAIN + _canonical(payload))


def payload_commitment(payload: Any, salt: str) -> str:
    """Commit to a payload with a per-record public salt."""

    if not _HEX_32.fullmatch(salt):
        raise ValueError("salt must be 16 bytes encoded as 32 lowercase hex characters")
    return _sha256_hex(_PAYLOAD_DOMAIN + bytes.fromhex(salt) + _canonical(payload))


def commitment_matches(payload: Any, salt: str, expected: str) -> bool:
    """Verify a disclosed payload against its stored commitment."""

    if not _HEX_64.fullmatch(expected):
        return False
    return hmac.compare_digest(payload_commitment(payload, salt), expected)


def record_digest(body: dict[str, Any]) -> str:
    """Hash the canonical body of one record with domain separation."""

    return _sha256_hex(_RECORD_DOMAIN + _canonical(body))


def _checkpoint_digest(body: dict[str, Any]) -> str:
    return _sha256_hex(_CHECKPOINT_DOMAIN + _canonical(body))


def _normalise_key(writer_key: bytes | bytearray | None) -> bytes | None:
    if writer_key is None:
        return None
    key = bytes(writer_key)
    if len(key) < 32:
        raise ValueError("writer_key must contain at least 32 bytes")
    return key


def key_id(writer_key: bytes) -> str:
    """Return a non-secret identifier for a writer key."""

    return _sha256_hex(b"provenance-layer/key-id/v1\x00" + writer_key)[:16]


def _mac(digest: str, writer_key: bytes) -> str:
    return hmac.new(writer_key, _MAC_DOMAIN + bytes.fromhex(digest), hashlib.sha256).hexdigest()


@contextmanager
def _cooperative_file_lock(path: str, timeout_seconds: float = 5.0) -> Iterator[None]:
    """Cross-platform advisory lock for cooperating writers."""

    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(lock_path)), exist_ok=True)
    handle = open(lock_path, "a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        deadline = time.monotonic() + timeout_seconds

        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out waiting for ledger lock: {lock_path}")
                    time.sleep(0.025)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out waiting for ledger lock: {lock_path}")
                    time.sleep(0.025)

        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


class Ledger:
    """Append-only-by-API JSONL ledger for a single cooperative writer key."""

    def __init__(self, path: str, writer_key: bytes | bytearray | None = None):
        self.path = os.path.abspath(path)
        self.writer_key = _normalise_key(writer_key)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def _read_all_unlocked(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        out: list[dict[str, Any]] = []
        line_number = 0
        try:
            with open(self.path, encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    value = json.loads(line, object_pairs_hook=_object_without_duplicate_keys)
                    if not isinstance(value, dict):
                        raise LedgerFormatError(f"line {line_number}: record must be a JSON object")
                    out.append(value)
        except json.JSONDecodeError as exc:
            raise LedgerFormatError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
        return out

    def read_all(self) -> list[dict[str, Any]]:
        """Read and decode all records. This does not imply verification."""

        return self._read_all_unlocked()

    def append(self, actor: str, event: str, payload: Any) -> dict[str, Any]:
        """Seal one event after verifying the current ledger under the lock."""

        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty string")
        if not isinstance(event, str) or not event.strip():
            raise ValueError("event must be a non-empty string")
        _canonical(payload)

        with _cooperative_file_lock(self.path):
            records = self._read_all_unlocked()
            ok, message = self._verify_records(records, require_auth=self.writer_key is not None)
            if not ok:
                raise LedgerIntegrityError(f"refusing append: {message}")

            if records:
                ledger_id = records[0]["ledger_id"]
                previous = records[-1]["record_hash"]
            else:
                ledger_id = str(uuid.uuid4())
                previous = GENESIS

            salt = secrets.token_hex(16)
            body: dict[str, Any] = {
                "schema": RECORD_SCHEMA,
                "ledger_id": ledger_id,
                "seq": len(records) + 1,
                "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                "actor": actor.strip(),
                "event": event.strip(),
                "payload_commitment": payload_commitment(payload, salt),
                "payload_salt": salt,
                "prev_hash": previous,
                "writer_key_id": key_id(self.writer_key) if self.writer_key else None,
            }
            digest = record_digest(body)
            record = {**body, "record_hash": digest}
            if self.writer_key:
                record["writer_mac"] = _mac(digest, self.writer_key)

            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as stream:
                stream.write(_canonical(record).decode("utf-8") + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            return record

    def _verify_records(
        self,
        records: list[dict[str, Any]],
        *,
        require_auth: bool,
    ) -> tuple[bool, str]:
        previous = GENESIS
        expected_ledger_id: str | None = None
        authenticated = 0
        macs_not_checked = 0

        for expected_seq, record in enumerate(records, start=1):
            label = f"seq {record.get('seq', '?')}"
            required = {
                "schema",
                "ledger_id",
                "seq",
                "ts",
                "actor",
                "event",
                "payload_commitment",
                "payload_salt",
                "prev_hash",
                "writer_key_id",
                "record_hash",
            }
            missing = sorted(required - set(record))
            if missing:
                return False, f"format error at {label}: missing {', '.join(missing)}"
            allowed = required | {"writer_mac"}
            unknown = sorted(set(record) - allowed)
            if unknown:
                return False, f"format error at {label}: unknown {', '.join(unknown)}"
            if record["schema"] != RECORD_SCHEMA:
                return False, f"format error at {label}: unsupported schema"
            if type(record["seq"]) is not int or record["seq"] != expected_seq:
                return False, f"sequence error at {label}: expected seq {expected_seq}"
            if not _valid_timestamp(record["ts"]):
                return False, f"format error at {label}: invalid timestamp"
            if not isinstance(record["actor"], str) or not record["actor"].strip():
                return False, f"format error at {label}: actor is empty"
            if not isinstance(record["event"], str) or not record["event"].strip():
                return False, f"format error at {label}: event is empty"
            if not _HEX_32.fullmatch(str(record["payload_salt"])):
                return False, f"format error at {label}: invalid payload_salt"
            if not _HEX_64.fullmatch(str(record["payload_commitment"])):
                return False, f"format error at {label}: invalid payload_commitment"
            if not _HEX_64.fullmatch(str(record["prev_hash"])):
                return False, f"format error at {label}: invalid prev_hash"
            if not _HEX_64.fullmatch(str(record["record_hash"])):
                return False, f"format error at {label}: invalid record_hash"

            try:
                parsed_ledger_id = str(uuid.UUID(str(record["ledger_id"])))
            except ValueError:
                return False, f"format error at {label}: invalid ledger_id"
            if expected_ledger_id is None:
                expected_ledger_id = parsed_ledger_id
            elif parsed_ledger_id != expected_ledger_id:
                return False, f"ledger identity changed at {label}"

            if record["prev_hash"] != previous:
                return False, f"chain break at {label}: prev_hash mismatch"

            body = {k: v for k, v in record.items() if k not in {"record_hash", "writer_mac"}}
            claimed_digest = record["record_hash"]
            if not hmac.compare_digest(record_digest(body), claimed_digest):
                return False, f"tamper detected at {label}: record_hash mismatch"

            record_key_id = record["writer_key_id"]
            record_mac = record.get("writer_mac")
            if record_key_id is None:
                if record_mac is not None:
                    return False, f"format error at {label}: MAC present without writer_key_id"
                if require_auth:
                    return False, f"authentication missing at {label}"
            else:
                if not isinstance(record_key_id, str) or not re.fullmatch(r"[0-9a-f]{16}", record_key_id):
                    return False, f"format error at {label}: invalid writer_key_id"
                if not _HEX_64.fullmatch(str(record_mac)):
                    return False, f"format error at {label}: invalid writer_mac"
                if self.writer_key is None:
                    if require_auth:
                        return False, f"authentication key required at {label}"
                    macs_not_checked += 1
                else:
                    if not hmac.compare_digest(record_key_id, key_id(self.writer_key)):
                        return False, f"authentication failed at {label}: wrong writer key"
                    if not hmac.compare_digest(record_mac, _mac(claimed_digest, self.writer_key)):
                        return False, f"authentication failed at {label}: writer_mac mismatch"
                    authenticated += 1

            previous = claimed_digest

        if not records:
            return True, "empty ledger: no records to verify"
        if authenticated == len(records):
            return True, f"verified {len(records)} records: chain intact and writer authenticated"
        if macs_not_checked:
            return True, (
                f"verified {len(records)} records: chain intact; "
                f"{macs_not_checked} writer MACs present but not authenticated (no key supplied)"
            )
        return True, f"verified {len(records)} records: chain intact; records are unauthenticated"

    def verify(self, *, require_auth: bool = False) -> tuple[bool, str]:
        """Verify structure, sequence, chain hashes, and optionally writer HMACs."""

        try:
            records = self._read_all_unlocked()
        except LedgerFormatError as exc:
            return False, str(exc)
        return self._verify_records(records, require_auth=require_auth)

    def checkpoint(self, *, require_auth: bool = False) -> dict[str, Any]:
        """Create an explicitly UNPUBLISHED receipt for the current history."""

        from merkle import merkle_root

        records = self._read_all_unlocked()
        ok, message = self._verify_records(records, require_auth=require_auth)
        if not ok:
            raise LedgerIntegrityError(f"refusing checkpoint: {message}")

        leaves = [record["record_hash"] for record in records]
        body: dict[str, Any] = {
            "schema": CHECKPOINT_SCHEMA,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "ledger_id": records[0]["ledger_id"] if records else None,
            "record_count": len(records),
            "chain_head": leaves[-1] if leaves else GENESIS,
            "merkle_root": merkle_root(leaves),
            "anchor_status": "UNPUBLISHED",
            "writer_key_id": key_id(self.writer_key) if self.writer_key else None,
        }
        digest = _checkpoint_digest(body)
        receipt = {**body, "receipt_hash": digest}
        if self.writer_key:
            receipt["receipt_mac"] = _mac(digest, self.writer_key)
        return receipt

    def verify_checkpoint(
        self,
        receipt: dict[str, Any],
        *,
        require_auth: bool = False,
    ) -> tuple[bool, str]:
        """Compare this ledger with a separately retained checkpoint receipt."""

        from merkle import merkle_root

        if not isinstance(receipt, dict):
            return False, "checkpoint must be a JSON object"
        required = {
            "schema",
            "created_at",
            "ledger_id",
            "record_count",
            "chain_head",
            "merkle_root",
            "anchor_status",
            "writer_key_id",
            "receipt_hash",
        }
        missing = sorted(required - set(receipt))
        if missing:
            return False, f"checkpoint missing fields: {', '.join(missing)}"
        allowed = required | {"receipt_mac"}
        unknown = sorted(set(receipt) - allowed)
        if unknown:
            return False, f"checkpoint has unknown fields: {', '.join(unknown)}"
        receipt_hash = receipt.get("receipt_hash")
        if not _HEX_64.fullmatch(str(receipt_hash)):
            return False, "checkpoint has an invalid receipt_hash"
        body = {k: v for k, v in receipt.items() if k not in {"receipt_hash", "receipt_mac"}}
        if body.get("schema") != CHECKPOINT_SCHEMA:
            return False, "checkpoint has an unsupported schema"
        if body.get("anchor_status") != "UNPUBLISHED":
            return False, "checkpoint has an unsupported anchor_status"
        if not _valid_timestamp(body.get("created_at")):
            return False, "checkpoint has an invalid created_at timestamp"
        if type(body.get("record_count")) is not int or body["record_count"] < 0:
            return False, "checkpoint has an invalid record_count"
        if not _HEX_64.fullmatch(str(body.get("chain_head"))):
            return False, "checkpoint has an invalid chain_head"
        if not _HEX_64.fullmatch(str(body.get("merkle_root"))):
            return False, "checkpoint has an invalid merkle_root"
        if body.get("ledger_id") is not None:
            try:
                uuid.UUID(str(body["ledger_id"]))
            except ValueError:
                return False, "checkpoint has an invalid ledger_id"
        if not hmac.compare_digest(_checkpoint_digest(body), receipt_hash):
            return False, "checkpoint receipt_hash mismatch"

        receipt_key_id = body.get("writer_key_id")
        receipt_mac = receipt.get("receipt_mac")
        if receipt_key_id is not None:
            if self.writer_key is None:
                if require_auth:
                    return False, "checkpoint authentication key required"
            else:
                if not hmac.compare_digest(str(receipt_key_id), key_id(self.writer_key)):
                    return False, "checkpoint authentication failed: wrong writer key"
                if not _HEX_64.fullmatch(str(receipt_mac)) or not hmac.compare_digest(
                    receipt_mac, _mac(receipt_hash, self.writer_key)
                ):
                    return False, "checkpoint authentication failed: receipt_mac mismatch"
        elif require_auth:
            return False, "checkpoint is unauthenticated"

        try:
            records = self._read_all_unlocked()
        except LedgerFormatError as exc:
            return False, str(exc)
        ok, message = self._verify_records(records, require_auth=require_auth)
        if not ok:
            return False, message

        leaves = [record["record_hash"] for record in records]
        expected = {
            "ledger_id": records[0]["ledger_id"] if records else None,
            "record_count": len(records),
            "chain_head": leaves[-1] if leaves else GENESIS,
            "merkle_root": merkle_root(leaves),
        }
        for field, value in expected.items():
            if body.get(field) != value:
                return False, f"checkpoint mismatch: {field} differs from retained receipt"
        return True, f"checkpoint matches {len(records)} verified records"
