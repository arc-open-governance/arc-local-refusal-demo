"""Local predicate computation: the model gets the abstract decision problem, not the records.

A handler runs INSIDE custody over the raw local facts (which may include withheld ones: computing
locally is not disclosure) and returns derived statements. Only the derived statements may be
disclosed, and only if the grant allows the category "derived_predicate" (or "derived_minimized").

household_savings (the founder's $500 example):
  level "predicate": the provider learns only that a proposed transfer was checked locally against
                     the declared household savings policy and the result (PASS / FAIL / UNKNOWN);
  level "minimized": the provider additionally learns the three policy numbers (discretionary funds,
                     required reserve, proposed amount), as in the founder's illustrative request.
Either way the statement says the answer is an assessment only; execution is separate (KORE/GMAP).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

_MONEY = re.compile(r"\$\s?(\d[\d,]*(?:\.\d+)?)")


def _amount(text: str) -> Optional[float]:
    m = _MONEY.search(text)
    return float(m.group(1).replace(",", "")) if m else None


@dataclass(frozen=True)
class Derived:
    text: str
    category: str


def household_savings(user_text: str, local_texts: Sequence[str], level: str) -> List[Derived]:
    transfer = None
    m = re.search(r"\b(?:move|transfer|put|save)\b[^$]*(\$\s?\d[\d,]*(?:\.\d+)?)", user_text, re.I)
    if m:
        transfer = _amount(m.group(1))
    discretionary = reserve = None
    for t in local_texts:
        low = t.lower()
        if discretionary is None and "discretionary" in low:
            discretionary = _amount(t)
        if reserve is None and "reserve" in low and ("policy" in low or "required" in low or "keep" in low):
            reserve = _amount(t)
    if None in (transfer, discretionary, reserve):
        verdict = "UNKNOWN (the local records needed for the check are not all present)"
    else:
        verdict = "PASS" if discretionary - reserve >= transfer else "FAIL"
    base = ("A proposed household savings transfer was checked locally against the household's declared savings "
            "policy (transfer must fit within discretionary funds after the required reserve). Locally computed result: %s. "
            "Explain this assessment briefly in plain words. Trip affordability was not evaluated: no trip cost is on record. "
            "Do not execute anything; any transfer is authorized separately." % verdict)
    if level == "minimized" and None not in (transfer, discretionary, reserve):
        base += (" Policy numbers: available discretionary funds $%s; required reserve $%s; proposed transfer $%s."
                 % (f"{discretionary:,.0f}", f"{reserve:,.0f}", f"{transfer:,.0f}"))
        return [Derived(base, "derived_minimized")]
    return [Derived(base, "derived_predicate")]


HANDLERS: Dict[str, Callable[[str, Sequence[str], str], List[Derived]]] = {"household_savings": household_savings}

# Words a host can use to gather the LOCAL records a handler needs. These records feed the local computation
# only; they are never rendered into a request.
HANDLER_KEYWORDS: Dict[str, str] = {"household_savings": "household savings policy discretionary funds reserve transfer"}
