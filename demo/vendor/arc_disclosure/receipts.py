"""D6: verifiable disclosure history. One receipt per outbound request, written BEFORE the bytes leave.

Each receipt names what was disclosed (fact references + categories, never values), to whom
(recipient + endpoint), under which grant and purpose, and the SHA-256 and length of the EXACT bytes
handed to the transport. Receipts form a hash chain (prev_sha256), so deletion, reordering or edits
are detectable; outcome records (sent / transport_error) and block records join the same chain.

Fact references are HMAC-SHA256(ledger key, source|text)[:24]: stable for the custodian, but a
receipt shown to an examiner does not let them confirm a guessed withheld fact without the key.
The key lives beside the ledger (custody-local) and is created on first use.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets as _secrets
import time
import uuid
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple

from .canon import canon, sha256_hex

GENESIS = "0" * 64
_KEY_LOCK = __import__("threading").Lock()


class ReceiptError(RuntimeError):
    """The ledger could not be written: the request must not be sent (fail closed)."""


class ReceiptLedger:
    def __init__(self, path: str, key_path: Optional[str] = None):
        self.path = path
        self.key_path = key_path or (path + ".key")
        self._key: Optional[bytes] = None

    # ---- keyed references ------------------------------------------------------------------
    def _k(self) -> bytes:
        """The custody-local HMAC key. Created atomically (write a temp file, then link it into place),
        so concurrent first uses converge on ONE key and nobody reads a half-written key."""
        if self._key is None:
            with _KEY_LOCK:
                if self._key is None:
                    self._key = self._load_or_create_key()
        return self._key

    def _load_or_create_key(self) -> bytes:
        try:
            with open(self.key_path, "rb") as fh:
                key = fh.read()
            if len(key) == 32:
                return key
            raise ReceiptError("ledger key is malformed")
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ReceiptError("ledger key not readable: %s" % type(exc).__name__) from exc
        tmp = "%s.%s.tmp" % (self.key_path, uuid.uuid4().hex)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(_secrets.token_bytes(32))
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(tmp, self.key_path)          # atomic; fails if another writer won the race
            except FileExistsError:
                pass
        except OSError as exc:
            raise ReceiptError("ledger key not writable: %s" % type(exc).__name__) from exc
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        with open(self.key_path, "rb") as fh:
            key = fh.read()
        if len(key) != 32:
            raise ReceiptError("ledger key is malformed")
        return key

    def ref(self, source: str, text: str) -> str:
        return hmac.new(self._k(), (source + "|" + text).encode("utf-8"), hashlib.sha256).hexdigest()[:24]

    # ---- reading -----------------------------------------------------------------------------
    def records(self) -> List[dict]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return [json.loads(l) for l in fh if l.strip()]
        except FileNotFoundError:
            return []

    def history_categories(self, recipients: Optional[Iterable[str]], since: float) -> FrozenSet[str]:
        """Categories disclosed (receipts whose request was sent or may have been sent) since `since`.
        recipients=None means every external recipient (collusion-conservative)."""
        want = None if recipients is None else set(recipients)
        cats = set()
        for r in self.records():
            if r.get("type") != "receipt" or r.get("created_at", 0) < since:
                continue
            if want is not None and r.get("recipient") not in want:
                continue
            for d in r.get("disclosed", []):
                cats |= set(d.get("categories", []))
            cats |= set(r.get("request_categories", []))
        return frozenset(cats)

    # ---- writing (append + fsync under an exclusive lock) ------------------------------------
    def _append(self, body: dict) -> dict:
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        except OSError as exc:
            raise ReceiptError("receipt ledger not writable: %s" % type(exc).__name__) from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with open(self.path, "r", encoding="utf-8") as fh:
                lines = [l for l in fh if l.strip()]
            prev = json.loads(lines[-1])["record_sha256"] if lines else GENESIS
            rec = dict(body, seq=len(lines), prev_sha256=prev)
            rec["record_sha256"] = sha256_hex(canon(rec))
            data = (json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
            if os.write(fd, data) != len(data):
                raise ReceiptError("short write to the receipt ledger")
            os.fsync(fd)
            return rec
        except OSError as exc:
            raise ReceiptError("receipt ledger write failed: %s" % type(exc).__name__) from exc
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def write_ahead(self, *, recipient: str, endpoint: str, actor: str, grant_id: str, purpose: str, level: str,
                    disclosed: List[dict], withheld: List[dict], request_categories: Iterable[str], substitutions: int,
                    body: bytes, grant_store_sha256: str) -> dict:
        return self._append({
            "type": "receipt", "schema": "arc-disclosure-receipt/v1", "receipt_id": uuid.uuid4().hex,
            "created_at": time.time(), "recipient": recipient, "endpoint": endpoint, "actor": actor,
            "grant_id": grant_id, "purpose": purpose, "level": level, "disclosed": disclosed, "withheld": withheld,
            "request_categories": sorted(set(request_categories)), "substitutions": substitutions,
            "bytes_sha256": sha256_hex(body), "bytes_len": len(body), "grant_store_sha256": grant_store_sha256})

    def outcome(self, receipt_id: str, status: str, detail: str = "") -> dict:
        return self._append({"type": "outcome", "receipt_id": receipt_id, "status": status, "detail": detail[:200],
                             "created_at": time.time()})

    def block(self, *, recipient: str, actor: str, purpose: str, reason: str, detail: List[str] = ()) -> dict:
        return self._append({"type": "block", "recipient": recipient, "actor": actor, "purpose": purpose,
                             "reason": reason, "detail": list(detail)[:20], "created_at": time.time()})


def anchor_of(records: List[dict]) -> Tuple[int, str]:
    """(count, head record_sha256): keep it OUTSIDE the ledger file (a GMAP card, the turn log, a printout).
    Without an anchor the chain cannot reveal a rewritten-and-rehashed or truncated tail (model cx
    cx_d6_limit_unanchored_tail_rehash_undetected)."""
    return len(records), (records[-1]["record_sha256"] if records else GENESIS)


def verify_chain(records: List[dict], anchor: Optional[Tuple[int, str]] = None) -> Tuple[bool, str]:
    """Model: model/pos/d6_receipts.bend verify(); with an anchor every edit, rehash or truncation is detected."""
    if anchor is not None and (len(records) < anchor[0]):
        return False, "truncated: %d records, anchor says %d" % (len(records), anchor[0])
    prev = GENESIS
    for i, r in enumerate(records):
        body = {k: v for k, v in r.items() if k != "record_sha256"}
        if r.get("seq") != i:
            return False, "seq %d out of order" % i
        if r.get("prev_sha256") != prev:
            return False, "chain broken at seq %d" % i
        if sha256_hex(canon(body)) != r.get("record_sha256"):
            return False, "record %d altered" % i
        prev = r["record_sha256"]
        if anchor is not None and i + 1 == anchor[0] and prev != anchor[1]:
            return False, "head at seq %d does not match the anchor" % i
    return True, "%d records chained" % len(records) + (" (anchored at %d)" % anchor[0] if anchor is not None else "")


def verify_bytes(receipt: dict, body: bytes) -> bool:
    """True iff `body` is exactly the request the receipt describes."""
    return receipt.get("bytes_sha256") == sha256_hex(body) and receipt.get("bytes_len") == len(body)
