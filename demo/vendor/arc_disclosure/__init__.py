"""ARC Disclosure Boundary (working name): provider-minimized disclosure for model requests.

"ARC separates intelligence from authority, and reasoning from custody."
This package is the custody-side boundary: grants, protected values, combination control, local
predicates, exact-bytes receipts. It is a PROTOTYPE (2026-11-21): see DISCLOSURE-LAW.md and the
proof report for what is demonstrated and what is not. It makes no compliance claim.
"""
from .boundary import BOUNDARY_NOTE, DATA_NOTICE, DisclosureBoundary, Fact, Plan
from .classify import Classifier, DEFAULT_PATTERNS
from .combination import DEFAULT_SENSITIVE, InferenceRule, SensitiveSet
from .egress import DisclosureBlocked, Egress
from .grants import FileGrantStore, Grant, MemoryGrantStore
from .predicates import HANDLER_KEYWORDS, HANDLERS
from .policy import (STRICT_CONVERSATION_FORBIDDEN, Policy, PurposeSpec, default_policy, load_policy, policy_from_json,
                     strict_violations)
from .receipts import ReceiptError, ReceiptLedger, anchor_of, verify_bytes, verify_chain
from .secrets import Finding, Secret, SecretRegistry

__version__ = "0.1.0"
__all__ = [n for n in dir() if not n.startswith("_")]
