"""Policy: purposes (which categories each purpose may use, and at what disclosure level), the declared
sensitive set (D5), the history window, and collusion-conservative history across recipients."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional

from .combination import DEFAULT_SENSITIVE, InferenceRule, SensitiveSet


@dataclass(frozen=True)
class PurposeSpec:
    categories: FrozenSet[str]
    level: str = "raw"                 # raw | minimized | predicate
    handler: Optional[str] = None      # predicates.HANDLERS key for minimized/predicate


@dataclass
class Policy:
    purposes: Dict[str, PurposeSpec]
    sensitive: SensitiveSet = field(default_factory=lambda: DEFAULT_SENSITIVE)
    window_s: float = 86400.0
    collusion_conservative: bool = True
    pseudonymize_operator: bool = True          # founder decision 1 (2026-11-21 10:34 AM PT): STRICT
    operator_placeholder: str = "the operator"
    vision_mode: str = "refuse"                 # founder decision 3 (2026-11-21 10:44 AM PT): refuse until routed


CONVERSATION_DEFAULT = frozenset({"general", "task", "runner_note", "document", "schedule", "workplace", "family",
                                  "child_school", "neighborhood", "commute", "finance_policy"})


def default_policy() -> Policy:
    return Policy(purposes={
        "conversation": PurposeSpec(CONVERSATION_DEFAULT, "raw"),
        "household_savings_check": PurposeSpec(frozenset({"task", "runner_note", "derived_predicate"}), "predicate", "household_savings"),
    })


def policy_from_json(d: dict) -> Policy:
    purposes = {name: PurposeSpec(frozenset(p.get("categories", [])), p.get("level", "raw"), p.get("handler"))
                for name, p in d.get("purposes", {}).items()}
    sens = d.get("sensitive")
    sensitive = DEFAULT_SENSITIVE if sens is None else SensitiveSet(
        [InferenceRule(r["target"], frozenset(r["requires"])) for r in sens.get("rules", [])], sens.get("direct", {}))
    ident = d.get("identity", {})
    return Policy(purposes, sensitive, float(d.get("window_s", 86400)), bool(d.get("collusion_conservative", True)),
                  bool(ident.get("pseudonymize_operator", True)), str(ident.get("placeholder", "the operator")),
                  str(d.get("vision", {}).get("mode", "refuse")))


# The STRICT defaults (founder decision 1, 2026-11-21 10:34 AM PT). Categories that must never be granted to the
# conversation purpose by a strict policy, and the checks a strict policy must pass.
STRICT_CONVERSATION_FORBIDDEN = frozenset({"finance_balance", "finance_account", "finance_transaction", "credential",
                                           "identity_number", "identity_name"})


def strict_violations(policy: Policy) -> list:
    """[] iff the policy satisfies the STRICT defaults decision."""
    out = []
    conv = policy.purposes.get("conversation")
    if conv is None:
        out.append("no conversation purpose")
    else:
        bad = sorted(conv.categories & STRICT_CONVERSATION_FORBIDDEN)
        if bad:
            out.append("conversation grants forbidden categories: " + ",".join(bad))
    for name, spec in policy.purposes.items():
        if "identity_name" in spec.categories:
            out.append("purpose %s discloses identity_name" % name)
    if not policy.pseudonymize_operator or policy.operator_placeholder != "the operator":
        out.append("operator name not replaced with 'the operator'")
    if not policy.collusion_conservative:
        out.append("combination mode is not collusion-conservative")
    if policy.window_s != 86400:
        out.append("combination window is not 24 hours")
    if policy.vision_mode != "refuse":       # decision 3: no image leaves custody until a routed path exists
        out.append("vision is not refused (decision 3: refuse until routed through the boundary)")
    return out


def load_policy(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        return policy_from_json(json.load(fh))
