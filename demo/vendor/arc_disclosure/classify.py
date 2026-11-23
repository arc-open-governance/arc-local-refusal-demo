"""Multi-label category classifier for unstructured text (memory lines, conversation context, documents).

Structured records (AMP/Field relations) should carry their categories; this classifier exists for
unstructured memory, which is what the Noetica runner reads today. It is deliberately conservative:
a line gets EVERY category whose pattern matches, and a fact is disclosed only if ALL of its
categories are permitted (boundary.py). A line that matches nothing is "general".
Heuristic classification is a documented limit (DISCLOSURE-LAW.md A3): a sensitive fact phrased so
that no pattern matches is "general", and the registry (secrets.py) is the backstop for values.
"""
from __future__ import annotations

import re
from typing import Dict, FrozenSet, Iterable, List, Optional, Pattern, Tuple

_MONEY = r"(?:\$\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s?(?:dollars|usd))"
DEFAULT_PATTERNS: Dict[str, List[str]] = {
    "finance_account": [r"\baccount\s*(?:number|no\.?|#)", r"\brouting\b", r"\biban\b", r"\bcard\s*(?:number|ending)", r"\bending\s+(?:in\s+)?\d{4}\b",
                        r"\b(?:checking|savings)\s+account\b", r"\bjoint\s+account\b"],
    "finance_balance": [r"\bbalance\b", r"\bdiscretionary\b", r"\bincome\b", r"\bsalary\b", r"\bfunds?\b", r"\bnet\s+worth\b", r"\bsavings\b.*" + _MONEY,
                        r"\breserve\b"],
    "finance_transaction": [r"\b(?:paid|charged|purchase[d]?|withdrew|deposit(?:ed)?|transaction|refund(?:ed)?)\b.*" + _MONEY],
    "finance_policy": [r"\b(?:savings|household)\s+(?:policy|rule|goal)\b", r"\brequired\s+reserve\b", r"\breserve\s+policy\b"],
    "credential": [r"\bpassword\b", r"\bpasscode\b", r"\bpassphrase\b", r"\bpin\b", r"\bapi[ _-]?key\b", r"\b(?:access|bearer|auth)[ _-]?token\b",
                   r"\bsecret[ _-]?key\b", r"\blog[ -]?in\b.*\b(?:is|:)", r"PRIVATE KEY"],
    "identity_number": [r"\bssn\b", r"\bsocial\s+security\b", r"\bpassport\b", r"\bdriver'?s?\s+licen[cs]e\b", r"\b\d{3}-\d{2}-\d{4}\b"],
    "home_address": [r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s+){1,4}(?:Street|St|Lane|Ln|Avenue|Ave|Road|Rd|Drive|Dr|Court|Ct|Boulevard|Blvd|Way|Place|Pl|Terrace|Circle)\b",
                     r"\bhome\s+address\b", r"\b(?:we|i|they)\s+live\s+(?:at|on)\b", r"\b\d{5}(?:-\d{4})?\b(?=[^\n]*\b[A-Z]{2}\b)"],
    "contact": [r"[\w.+-]+@[\w-]+\.[\w.]+", r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"],
    "health": [r"\ballerg(?:y|ies|ic)\b", r"\bdiagnos", r"\bclinic\b", r"\bmedication\b", r"\bprescri", r"\bpediatric", r"\btherapy\b", r"\bdoctor\b|\bdr\.\s",
               r"\bsurgery\b", r"\basthma\b", r"\bdiabet"],
    "family": [r"\b(?:daughter|son|wife|husband|spouse|partner|child|children|kid|kids|mother|father|mom|dad|sister|brother|grandm\w+|grandf\w+)\b"],
    "child_school": [r"\b(?:elementary|middle\s+school|high\s+school|preschool|daycare|kindergarten|school)\b"],
    "workplace": [r"\bworks?\s+(?:at|for)\b", r"\bemployer\b", r"\b(?:office|job)\s+(?:at|is)\b", r"\bshift\s+at\b", r"\bemployed\b"],
    "schedule": [r"\b(?:every|each)\s+(?:weekday|morning|evening|monday|tuesday|wednesday|thursday|friday|saturday|sunday|day)\b",
                 r"\b(?:drop(?:s|ped)?[ -]off|pick(?:s|ed)?[ -]up)\b", r"\b\d{1,2}:\d{2}\s*(?:am|pm)?\b", r"\bweekdays?\b", r"\broutine\b"],
    "neighborhood": [r"\blives?\s+(?:near|in|by)\b", r"\bneighbo(?:u)?rhood\b", r"\bdistrict\b", r"\bnear\s+\w+\s+park\b"],
    "commute": [r"\bcommute[sd]?\b", r"\b(?:bus|train|metro)\s+(?:route|line|stop)\b", r"\bdrives?\s+(?:to|via)\b", r"\bparks?\s+(?:at|on)\b"],
    "instruction_like": [r"\bignore\s+(?:all|any|previous|your|prior)\b", r"\b(?:system|developer)\s*:", r"\byou\s+must\b", r"\bpre-?approved\b",
                         r"\bdisregard\b", r"\binclude\s+the\s+full\b"],
}


class Classifier:
    def __init__(self, patterns: Optional[Dict[str, Iterable[str]]] = None,
                 pseudonyms: Iterable[Tuple[str, str]] = ()):
        pats = DEFAULT_PATTERNS if patterns is None else patterns
        self._rx: List[Tuple[str, List[Pattern]]] = [
            (cat, [re.compile(p, re.I) if cat not in ("home_address",) else re.compile(p) for p in ps]) for cat, ps in pats.items()]
        self._names = [(re.compile(r"\b" + re.escape(v) + r"\b", re.I), cat) for v, cat in pseudonyms if v.strip()]

    def categories(self, text: str) -> FrozenSet[str]:
        cats = set()
        for cat, rxs in self._rx:
            if any(r.search(text) for r in rxs):
                cats.add(cat)
        for rx, cat in self._names:
            if rx.search(text):
                cats.add(cat)
        return frozenset(cats) if cats else frozenset({"general"})
