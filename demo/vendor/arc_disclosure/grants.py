"""Contextual authorization (actor / recipient / purpose / time / grant) and revocation (D1, D3).

GrantStore re-reads its file on EVERY lookup (no cache), so a revocation written by the owner takes
effect before the next outbound request: the boundary looks the grant up when it plans the request
and again at the egress gate, immediately before the bytes leave (egress.py).
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Tuple

from .canon import canon, sha256_hex


@dataclass(frozen=True)
class Grant:
    grant_id: str
    actor: str
    recipient: str
    purposes: FrozenSet[str]
    categories: FrozenSet[str]
    expires_at: Optional[float] = None
    revoked: bool = False
    allow_targets: FrozenSet[str] = frozenset()   # sensitive inference targets this grant explicitly allows (D5)

    def live(self, now: float) -> bool:
        return not self.revoked and (self.expires_at is None or now < self.expires_at)

    def matches(self, actor: str, recipient: str, purpose: str) -> bool:
        return (self.actor in ("*", actor) and self.recipient in ("*", recipient) and purpose in self.purposes)

    @staticmethod
    def from_json(d: dict) -> "Grant":
        return Grant(grant_id=str(d["grant_id"]), actor=str(d.get("actor", "*")), recipient=str(d.get("recipient", "*")),
                     purposes=frozenset(d.get("purposes", [])), categories=frozenset(d.get("categories", [])),
                     expires_at=d.get("expires_at"), revoked=bool(d.get("revoked", False)),
                     allow_targets=frozenset(d.get("allow_targets", [])))

    def to_json(self) -> dict:
        return {"grant_id": self.grant_id, "actor": self.actor, "recipient": self.recipient, "purposes": sorted(self.purposes),
                "categories": sorted(self.categories), "expires_at": self.expires_at, "revoked": self.revoked,
                "allow_targets": sorted(self.allow_targets)}


class MemoryGrantStore:
    """In-process store (tests, embedding). Same semantics as the file store."""

    def __init__(self, grants: List[Grant] = ()):
        self._grants = list(grants)

    def snapshot(self) -> Tuple[List[Grant], str]:
        return list(self._grants), sha256_hex(canon([g.to_json() for g in self._grants]))

    def revoke(self, grant_id: str) -> None:
        self._grants = [Grant(**{**g.__dict__, "revoked": True}) if g.grant_id == grant_id else g for g in self._grants]

    def find(self, actor: str, recipient: str, purpose: str, now: Optional[float] = None) -> Tuple[Optional[Grant], str]:
        now = time.time() if now is None else now
        grants, digest = self.snapshot()
        for g in grants:
            if g.matches(actor, recipient, purpose) and g.live(now):
                return g, digest
        return None, digest

    def get(self, grant_id: str, now: Optional[float] = None) -> Tuple[Optional[Grant], str]:
        now = time.time() if now is None else now
        grants, digest = self.snapshot()
        for g in grants:
            if g.grant_id == grant_id:
                return (g if g.live(now) else None), digest
        return None, digest


class FileGrantStore(MemoryGrantStore):
    """{"grants": [...]} JSON file, re-read on every call. A missing or unreadable file means NO grants
    (fail closed)."""

    def __init__(self, path: str):
        self.path = path

    def snapshot(self) -> Tuple[List[Grant], str]:
        try:
            with open(self.path, "rb") as fh:
                raw = fh.read()
            data = json.loads(raw.decode("utf-8"))
            return [Grant.from_json(d) for d in data.get("grants", [])], sha256_hex(raw)
        except (OSError, ValueError, KeyError, TypeError):
            return [], "unreadable"

    def write(self, grants: List[Grant]) -> None:
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".grants-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(json.dumps({"grants": [g.to_json() for g in grants]}, indent=1, sort_keys=True).encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def revoke(self, grant_id: str) -> None:
        grants, _ = self.snapshot()
        self.write([Grant(**{**g.__dict__, "revoked": True}) if g.grant_id == grant_id else g for g in grants])
