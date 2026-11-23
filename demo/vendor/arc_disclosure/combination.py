"""D5: combination / derived-inference control for a DECLARED sensitive set.

A sensitive target (e.g. home_address) is protected two ways:
  * directly: a fact carrying the target's own category is never disclosed unless allowed;
  * by inference: each InferenceRule names a set of categories whose co-disclosure to the provider
    reveals the target (workplace + child_school + schedule -> home_address).
Co-disclosure is CUMULATIVE: categories already disclosed to the provider (from the receipt ledger,
within the window) and categories the user's own message discloses count as disclosed.

select() walks candidate facts in relevance order and admits a fact only if, after adding its
categories, no rule's category set is fully disclosed (for a target the grant does not allow).
It is greedy: a withheld fact is one whose admission at that point would complete a rule.
Model: model/pos/d5_combination.bend (laws d5_*), negatives n_fieldwise_redaction,
n_per_turn_only. Limit: only the declared rules are enforced (DISCLOSURE-LAW.md A5).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Sequence, Set, Tuple


@dataclass(frozen=True)
class InferenceRule:
    target: str
    requires: FrozenSet[str]


class SensitiveSet:
    def __init__(self, rules: Iterable[InferenceRule] = (), direct: Dict[str, str] = None):
        self.rules = list(rules)
        self.direct = dict(direct or {})          # target -> category that IS the target

    def targets_completed(self, cats: FrozenSet[str]) -> Set[str]:
        out = {t for t, c in self.direct.items() if c in cats}
        out |= {r.target for r in self.rules if r.requires <= cats}
        return out

    def select(self, history: FrozenSet[str], candidates: Sequence[Tuple[str, FrozenSet[str]]],
               allowed_targets: FrozenSet[str] = frozenset()) -> Tuple[List[str], List[Tuple[str, str]], FrozenSet[str]]:
        """-> (admitted refs, withheld [(ref, reason)], categories disclosed incl. history)."""
        acc: Set[str] = set(history)
        admitted: List[str] = []
        withheld: List[Tuple[str, str]] = []
        for ref, cats in candidates:
            trial = frozenset(acc | set(cats))
            bad = sorted(t for t in self.targets_completed(trial) if t not in allowed_targets)
            if bad:
                withheld.append((ref, "combination:" + ",".join(bad)))
            else:
                admitted.append(ref)
                acc |= set(cats)
        return admitted, withheld, frozenset(acc)


DEFAULT_SENSITIVE = SensitiveSet(
    rules=[InferenceRule("home_address", frozenset({"workplace", "child_school", "schedule"})),
           InferenceRule("home_address", frozenset({"neighborhood", "schedule", "commute"})),
           InferenceRule("child_health_identity", frozenset({"family", "child_school", "health"}))],
    direct={"home_address": "home_address"})
