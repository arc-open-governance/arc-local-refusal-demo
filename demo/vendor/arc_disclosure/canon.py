"""Canonical JSON and digests used by every receipt and plan."""
import hashlib
import json
from typing import Any


def canon(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no spaces, UTF-8 (not ASCII-escaped)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
