"""The only path by which bytes leave custody for a model provider.

send(): (a) refuses a blocked plan (recording a block), (b) serializes the request ONCE, (c) final byte
gate: scans the exact bytes for protected values (D2) and re-reads the grant (D3), (d) writes the
receipt with the SHA-256 of those exact bytes BEFORE sending (D6; ledger failure = no send), (e) hands
the SAME bytes object to the transport, (f) records the outcome.
"""
from __future__ import annotations

import time
from typing import Any, Callable, List, Optional, Tuple

from .boundary import Plan
from .grants import MemoryGrantStore
from .receipts import ReceiptLedger
from .secrets import SecretRegistry


class DisclosureBlocked(RuntimeError):
    def __init__(self, reason: str, detail: List[str] = ()):
        super().__init__(reason)
        self.reason = reason
        self.detail = list(detail)


class Egress:
    def __init__(self, ledger: ReceiptLedger, registry: SecretRegistry, grants: MemoryGrantStore):
        self.ledger = ledger
        self.registry = registry
        self.grants = grants

    def prepare(self, plan: Plan, endpoint: str, build_body: Callable[[List[dict]], bytes],
                now: Optional[float] = None) -> Tuple[bytes, dict]:
        """Steps (a)-(d): returns (the exact bytes to send, the write-ahead receipt). The caller MUST send exactly
        these bytes (e.g. an async/streaming client) and then call finish(). Nothing may be sent if this raises."""
        if plan.blocked:
            self.ledger.block(recipient=plan.recipient, actor=plan.actor, purpose=plan.purpose, reason=plan.reason)
            raise DisclosureBlocked(plan.reason)
        body = build_body(plan.messages)
        if not isinstance(body, (bytes, bytearray)):
            raise TypeError("build_body must return bytes")
        body = bytes(body)
        findings = self.registry.scan(body.decode("utf-8", "replace"))
        if findings:
            detail = sorted({"%s via %s" % (f.source, f.transform) for f in findings})
            self.ledger.block(recipient=plan.recipient, actor=plan.actor, purpose=plan.purpose,
                              reason="protected_value_in_bytes", detail=detail)
            raise DisclosureBlocked("protected_value_in_bytes", detail)
        grant, store_sha = self.grants.get(plan.grant_id, time.time() if now is None else now)
        if grant is None:
            self.ledger.block(recipient=plan.recipient, actor=plan.actor, purpose=plan.purpose, reason="grant_not_live_at_send")
            raise DisclosureBlocked("grant_not_live_at_send")
        receipt = self.ledger.write_ahead(
            recipient=plan.recipient, endpoint=endpoint, actor=plan.actor, grant_id=plan.grant_id, purpose=plan.purpose,
            level=plan.level, disclosed=plan.disclosed, withheld=plan.withheld, request_categories=plan.request_categories,
            substitutions=plan.substitutions, body=body, grant_store_sha256=store_sha)
        return body, receipt

    def finish(self, receipt: dict, status: str = "sent", detail: str = "") -> None:
        """Step (f): record the outcome of the request whose receipt prepare() wrote."""
        self.ledger.outcome(receipt["receipt_id"], status, detail)

    def refuse(self, *, recipient: str, actor: str, purpose: str, reason: str) -> None:
        """Record a refusal for a path that is not routed (D8): nothing is sent, the refusal is in the ledger."""
        self.ledger.block(recipient=recipient, actor=actor, purpose=purpose, reason=reason)

    def send(self, plan: Plan, endpoint: str, build_body: Callable[[List[dict]], bytes],
             transport: Callable[[bytes], Any], now: Optional[float] = None) -> Tuple[Any, dict]:
        body, receipt = self.prepare(plan, endpoint, build_body, now)
        try:
            result = transport(body)
        except Exception as exc:
            self.finish(receipt, "transport_error", type(exc).__name__)
            raise
        self.finish(receipt, "sent")
        return result, receipt
