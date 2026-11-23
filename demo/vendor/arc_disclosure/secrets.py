"""D2: forbidden values and reconstructable secrets, including encodings and partials.

A SecretRegistry holds the values that must never leave custody (account numbers, credentials,
identity numbers, the home address...). They are held LOCALLY; the registry never returns a value,
only findings of the form (secret_id or detector, transform).

scan(text) looks for every secret, and for pattern detectors, in many views of the text:
raw, case-folded, NFKC + zero-width stripped, JSON/HTML/URL unescaped, number words -> digits,
alnum-only, numeric clusters, reversed, ROT13, leetspeak-folded, and recursively inside base64,
base32 and hex tokens. A secret matches if ANY window of `min_window` consecutive normalized
characters of the secret appears in a view: that covers full values, partials (e.g. "ending 2297"),
and halves split across one payload. Shorter fragments are a documented limit (DISCLOSURE-LAW.md A4).
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set, Tuple

_ZW = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
_NUMWORDS = {"zero": "0", "oh": "0", "o": "0", "one": "1", "two": "2", "three": "3", "four": "4",
             "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9", "niner": "9"}
_NUMWORD_RE = re.compile(r"\b(?:" + "|".join(sorted(_NUMWORDS, key=len, reverse=True)) + r")\b", re.I)
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{8,}={0,2}")
_B32_TOKEN = re.compile(r"[A-Z2-7]{8,}={0,6}")
_HEX_TOKEN = re.compile(r"(?:0x)?[0-9a-fA-F]{8,}")
# digits joined by short non-alphanumeric separators ("7302 9184-6650.2297") form one numeric cluster
_NUM_CLUSTER = re.compile(r"\d(?:[\s\-\.\,_/\\:]{0,3}\d)+")


def _alnum(s: str) -> str:
    return re.sub(r"[^0-9a-z]", "", s.casefold())


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _numwords(s: str) -> str:
    return _NUMWORD_RE.sub(lambda m: _NUMWORDS[m.group(0).lower()], s)


def _unescape(s: str) -> str:
    out = s
    for _ in range(3):
        prev = out
        out = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), out)
        out = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), out)
        out = html.unescape(out)
        out = urllib.parse.unquote_plus(out)
        if out == prev:
            break
    return out


def _decode_tokens(s: str) -> List[str]:
    """Plausible decodings of base64 / base64url / base32 / hex tokens found in s."""
    outs: List[str] = []
    for m in _B64_TOKEN.finditer(s):
        tok = m.group(0)
        for alt in (tok, tok.replace("-", "+").replace("_", "/")):
            pad = alt + "=" * (-len(alt.rstrip("=")) % 4)
            try:
                raw = base64.b64decode(pad.rstrip("=") + "=" * (-len(pad.rstrip("=")) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            txt = raw.decode("utf-8", "ignore")
            if txt and sum(c.isprintable() for c in txt) >= 0.8 * len(txt):
                outs.append(txt)
    for m in _B32_TOKEN.finditer(s):
        tok = m.group(0)
        try:
            raw = base64.b32decode(tok + "=" * (-len(tok) % 8))
        except (binascii.Error, ValueError):
            continue
        txt = raw.decode("utf-8", "ignore")
        if txt and sum(c.isprintable() for c in txt) >= 0.8 * len(txt):
            outs.append(txt)
    for m in _HEX_TOKEN.finditer(s):
        tok = m.group(0)
        tok = tok[2:] if tok.lower().startswith("0x") else tok
        if len(tok) % 2:
            tok = tok[:-1]
        try:
            txt = bytes.fromhex(tok).decode("utf-8", "ignore")
        except ValueError:
            continue
        if txt and sum(c.isprintable() for c in txt) >= 0.8 * len(txt):
            outs.append(txt)
    return outs


def views(text: str, depth: int = 2) -> List[Tuple[str, str]]:
    """(transform name, view) pairs. Recursion into decoded tokens is bounded by `depth`."""
    base = unicodedata.normalize("NFKC", text).translate(_ZW)
    un = _unescape(base)
    words = _numwords(un)
    vs: List[Tuple[str, str]] = [
        ("raw", text), ("nfkc", base), ("unescaped", un), ("numwords", words),
        ("rot13", codecs.encode(un, "rot13")), ("leet", un.casefold().translate(_LEET)),
        ("reversed", un[::-1]), ("numwords_reversed", words[::-1]),
    ]
    if depth > 0:
        for d in _decode_tokens(un):
            vs += [("decoded:" + n, v) for n, v in views(d, depth - 1)]
    return vs


@dataclass(frozen=True)
class Secret:
    secret_id: str
    kind: str              # account_number | routing_number | identity_number | credential | api_key | home_address | other
    value: str = field(repr=False)
    min_window: int = 0    # 0 -> default by kind

    def normalized(self) -> Tuple[str, str]:
        return _alnum(self.value), _digits(self.value)

    def window(self) -> int:
        if self.min_window:
            return self.min_window
        return {"account_number": 4, "routing_number": 5, "identity_number": 4, "card_number": 4,
                "credential": 6, "api_key": 8, "home_address": 8}.get(self.kind, 6)


@dataclass(frozen=True)
class Finding:
    source: str        # secret id, or "detector:<name>"
    kind: str
    transform: str     # which view revealed it ("raw", "decoded:raw", "numwords", ...)
    partial: bool      # True when only a window (not the whole value) matched


_DETECTORS = [
    # (name, kind, regex over a view). These need no registry and run for unknown values too.
    ("card_luhn", "card_number", re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")),
    ("long_digit_run", "account_number", re.compile(r"(?<!\d)\d(?:[ \-\.]?\d){8,}(?!\d)")),
    ("ssn", "identity_number", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    ("credential_label", "credential", re.compile(
        r"\b(?:password|passcode|passphrase|pin|api[ _-]?key|secret[ _-]?key|access[ _-]?token|bearer)\b\s*(?:is|=|:)\s*\S{4,}", re.I)),
    ("private_key", "credential", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("iban", "account_number", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}\b")),
]


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


class SecretRegistry:
    """Locally held forbidden values + pattern detectors. Never exposes a value."""

    def __init__(self, secrets: Iterable[Secret] = (), detectors: bool = True):
        self._secrets = list(secrets)
        self.detectors = detectors

    def __len__(self) -> int:
        return len(self._secrets)

    def ids(self) -> List[str]:
        return [s.secret_id for s in self._secrets]

    def add(self, secret: Secret) -> None:
        self._secrets.append(secret)

    def scan(self, text: str) -> List[Finding]:
        found: List[Finding] = []
        seen: Set[Tuple[str, str]] = set()
        vlist = views(text)
        for tname, view in vlist:
            a = _alnum(view)
            clusters = [_digits(m.group(0)) for m in _NUM_CLUSTER.finditer(view)]
            folded = _alnum(view.casefold().translate(_LEET))
            for s in self._secrets:
                if (s.secret_id, tname) in seen:
                    continue
                sa, sd = s.normalized()
                w = s.window()
                hit, partial = self._match(sa, sd, w, a, clusters, folded, _alnum(s.value.casefold().translate(_LEET)))
                if hit:
                    seen.add((s.secret_id, tname))
                    found.append(Finding(s.secret_id, s.kind, tname, partial))
            if self.detectors:
                for name, kind, rx in _DETECTORS:
                    key = ("detector:" + name, tname)
                    if key in seen:
                        continue
                    for m in rx.finditer(view):
                        if name == "card_luhn" and not _luhn_ok(_digits(m.group(0))):
                            continue
                        seen.add(key)
                        found.append(Finding("detector:" + name, kind, tname, False))
                        break
        return found

    @staticmethod
    def _match(sa: str, sd: str, w: int, a: str, clusters: List[str], folded: str, sfold: str) -> Tuple[bool, bool]:
        # whole value
        if sa and sa in a:
            return True, False
        if sd and len(sd) >= max(4, w) and any(sd in c for c in clusters):
            return True, False
        if sfold and sfold in folded:
            return True, False
        # any window of w consecutive normalized characters (partials, split halves)
        numeric = bool(sd) and len(sd) == len(sa)
        if numeric:
            for i in range(0, len(sd) - w + 1):
                win = sd[i:i + w]
                if any(win in c for c in clusters):
                    return True, True
            return False, False
        if len(sa) >= w:
            for i in range(0, len(sa) - w + 1):
                if sa[i:i + w] in a:
                    return True, True
            for i in range(0, len(sfold) - w + 1):
                if sfold[i:i + w] in folded:
                    return True, True
        return False, False
