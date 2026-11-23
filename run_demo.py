"""Local refusal demonstration v0.1: a five-minute governed tool action.

A synthetic tool, digest.send, proposes to send the operator's weekly
digest. The real Disclosure Boundary (vendored byte-identical under
demo/vendor/) decides what the tool may receive, and the real redaction
layer builds the tool-facing view. All values are synthetic
(demo/persona.json); the tool is simulated by a fixed reply function.
No live model, live service, live grant, or live machine is touched.
No network, no credential, no key beyond the fixed demo ledger key below.

What the run shows, in order:
  (a) an AUTHORIZED tool action succeeds: the boundary discloses only
      the in-scope facts (workplace + proposal), the tool sends the
      digest from the redacted view, and both crossings are receipted;
  (b) an UNAUTHORIZED ask refuses uniformly -- the tool asks for the
      commute category (outside the narrow grant) and for a withheld
      fact's category (child_school), and both refusals are byte-identical
      {"status": "refused", "reason": "not_available"}, receipted with
      their true internal rules in the ledger;
  (c) the one in-scope escalation grant (schedule) is granted once,
      refused on second use, and still refused after a simulated
      restart rebuilds the authority from the store file -- a spent
      grant stays spent;
  (d) a tool action that would need a withheld fact (the commute)
      gets a view with no commute record, and its result says the
      information is absent.

Determinism (why two cold runs are byte-identical): the demo pins its
own clock, its UUID source, and its ledger HMAC key, so the receipts
carry no wall-clock time, no random ids, and no random key. These pins
are DEMO fixtures, documented in README.md; production receipts carry
real timestamps, random ids, and a random per-ledger key. The pins
change nothing about the boundary's decisions -- only the bytes that
record them.

Run from this directory:
  python3 run_demo.py [--out DIR]
Exit 0 iff all expectations match. Evidence: output/ (default) or DIR.
Verify with: python3 verify_demo.py [--out DIR]
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import shutil
import sys
import time
import uuid

# ---- determinism pins (demo fixtures; see README.md) -----------------------
FIXED_TIME = 1780000000.0
FIXED_KEY = hashlib.sha256(
    b"local-refusal-demo-v0.1: synthetic demo ledger key, never real").digest()
_uuid_counter = itertools.count(1)


def _fixed_uuid4():
    return uuid.UUID(int=next(_uuid_counter))


time.time = lambda: FIXED_TIME  # noqa: E731
uuid.uuid4 = _fixed_uuid4

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "demo", "vendor"))
sys.path.insert(0, os.path.join(HERE, "demo"))

from arc_disclosure import (  # noqa: E402
    DisclosureBoundary,
    Fact,
    FileGrantStore,
    Secret,
    SecretRegistry,
    anchor_of,
    load_policy,
    strict_violations,
    verify_chain,
)
from redaction import (  # noqa: E402
    MODEL_REFUSAL,
    EscalationGrant,
    PersistentEscalationAuthority,
    RedactionLedger,
    RedactionSchema,
    redacted_model_turn,
    request_more,
    write_grant_store,
)

NARROW_CATEGORIES = ["general", "schedule", "task", "workplace"]
PSEUDONYMS = [("Jordan Ellis", "the operator"), ("Maya", "the child")]


def canon_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def main(argv) -> int:
    if argv and argv[0] != "--out":
        print("usage: python3 run_demo.py [--out DIR]")
        return 2
    if argv and len(argv) != 2:
        print("usage: python3 run_demo.py [--out DIR]")
        return 2
    out = argv[1] if argv else None
    out = out or os.path.join(HERE, "output")
    persona = json.load(open(os.path.join(HERE, "demo", "persona.json"),
                             encoding="utf-8"))
    actor = persona["actor"]
    recipient = persona["recipient"]
    purpose = persona["purpose"]
    task_name = persona["task"]["name"]

    # Fresh state every run: a rerun must not inherit a spent grant or a
    # longer ledger from the last run.
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out, exist_ok=True)
    work = os.path.join(out, "work")
    os.makedirs(work, exist_ok=True)

    # The fixed demo ledger key, seeded before the ledger is constructed,
    # so the HMAC fact refs are stable across runs. Production keys are
    # random per ledger; this one is a documented demo fixture.
    key_path = os.path.join(out, "receipts.jsonl.key")
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(FIXED_KEY)

    # 1. Stage the narrow boundary grant and the one in-scope escalation grant.
    narrow_grant = persona["narrow_grant"]
    grants_path = os.path.join(work, "grants.json")
    with open(grants_path, "w", encoding="utf-8") as fh:
        json.dump({"grants": [narrow_grant]}, fh, indent=1, sort_keys=True)
    esc = persona["escalation_grant"]
    esc_store_path = os.path.join(work, "escalation-grants.json")
    write_grant_store(esc_store_path, [EscalationGrant(
        esc["grant_id"], esc["category"], esc["actor"], esc["recipient"],
        esc["purpose"], float(esc["expires_at"]))])

    policy = load_policy(os.path.join(HERE, "demo", "policy.json"))
    bad = strict_violations(policy)
    if bad:
        raise SystemExit("POLICY REFUSED: " + "; ".join(bad))
    registry = SecretRegistry([Secret(s["secret_id"], s["kind"], s["value"])
                               for s in persona["secrets"]])
    ledger = RedactionLedger(os.path.join(out, "receipts.jsonl"))
    boundary = DisclosureBoundary(policy, FileGrantStore(grants_path), registry, ledger)
    authority = PersistentEscalationAuthority(esc_store_path)
    schema = RedactionSchema(task=task_name,
                             input_categories=frozenset(NARROW_CATEGORIES),
                             result_fields=tuple(persona["task"]["result_fields"]),
                             escalatable_categories=frozenset(
                                 persona["task"]["escalatable_categories"]))
    facts = [Fact(f["text"], f["source"], f["ref"]) for f in persona["facts"]]
    texts = {f["ref"]: f["text"] for f in persona["facts"]}
    failures = []

    def check(label, got, want):
        ok = got == want
        print(("  PASS " if ok else "  FAIL ") + label + ": got " + repr(got) + ", want " + repr(want))
        if not ok:
            failures.append(label)

    # (a) The authorized tool action: digest.send sends the weekly digest.
    plan = boundary.plan(actor=actor, recipient=recipient, purpose=purpose,
                         system_prompt=persona["system_prompt"],
                         user_text=persona["user_text"], facts=facts,
                         pseudonyms=[tuple(p) for p in persona["pseudonyms"]])
    check("authorized plan is not blocked", plan.blocked, False)
    check("authorized plan discloses only in-scope facts",
          sorted(d["ref"] for d in plan.disclosed), ["fact-proposal", "fact-works-at"])
    check("authorized plan withholds the out-of-scope facts",
          sorted(w["ref"] for w in plan.withheld),
          ["fact-address", "fact-dropoff", "fact-income", "fact-project", "fact-school"])
    seen = []

    def call_tool(view_text):
        seen.append(view_text)
        return persona["stub_reply"]

    result, report = redacted_model_turn(
        plan, schema, registry, ledger, call_tool,
        task_instruction=persona["task"]["instruction"], texts=texts,
        pseudonyms=PSEUDONYMS,
        shape_reply=lambda r: {"summary": r, "suggested_times": []})
    with open(os.path.join(out, "view.json"), "w", encoding="utf-8") as fh:
        fh.write(seen[0])
    with open(os.path.join(out, "raw-tool-reply.txt"), "w", encoding="utf-8") as fh:
        fh.write(persona["stub_reply"] + "\n")
    with open(os.path.join(out, "filtered-result.json"), "wb") as fh:
        fh.write(canon_bytes(result))
    with open(os.path.join(out, "view-report.json"), "w", encoding="utf-8") as fh:
        json.dump(report["view"], fh, indent=1, sort_keys=True)
    view = json.loads(seen[0])
    check("tool view holds only the granted facts",
          [r["ref"] for r in view["records"]], ["fact-works-at", "fact-proposal"])
    check("tool view has no secret value",
          [s["secret_id"] for s in persona["secrets"] if s["value"] in seen[0]], [])
    check("filtered result is the tool reply shaped to the schema",
          result, {"summary": persona["stub_reply"], "suggested_times": []})
    check("filtered result has no secret value",
          [s["secret_id"] for s in persona["secrets"] if s["value"] in json.dumps(result)], [])

    # (b) Escalation asks: outside the grant, and for a withheld fact's category.
    transcript = []

    def ask(category):
        resp = request_more(ledger, authority, schema, actor=actor, recipient=recipient,
                            purpose=purpose, category=category)
        rec = [r for r in ledger.records() if r.get("type") == "escalation"][-1]
        transcript.append({"ask": category, "granted": rec["granted"],
                           "internal_rule": rec["internal_rule"], "model_response": resp})
        return resp, rec

    resp, rec = ask("commute")
    check("commute ask outside the grant is refused uniformly",
          resp, dict(MODEL_REFUSAL))
    check("commute refusal's true rule is no_live_grant",
          rec["internal_rule"], "no_live_grant")
    resp, rec = ask("child_school")
    check("child_school ask for a withheld fact is refused uniformly",
          resp, dict(MODEL_REFUSAL))
    check("child_school refusal's true rule is outside_escalatable_scope",
          rec["internal_rule"], "outside_escalatable_scope")

    # The one in-scope escalation grant: granted once, then spent.
    resp, rec = ask("schedule")
    check("schedule ask inside the scope is granted once",
          resp, {"status": "granted", "category": "schedule",
                 "grant_id": "esc-demo-schedule-001"})
    check("schedule grant's true rule is granted", rec["internal_rule"], "granted")
    resp, rec = ask("schedule")
    check("second schedule ask is refused uniformly", resp, dict(MODEL_REFUSAL))
    check("second schedule refusal's true rule is grant_already_used",
          rec["internal_rule"], "grant_already_used")
    # Simulated restart: rebuild the authority from the store file.
    authority2 = PersistentEscalationAuthority(esc_store_path)
    resp = request_more(ledger, authority2, schema, actor=actor, recipient=recipient,
                        purpose=purpose, category="schedule")
    rec = [r for r in ledger.records() if r.get("type") == "escalation"][-1]
    transcript.append({"ask": "schedule-after-restart", "granted": rec["granted"],
                       "internal_rule": rec["internal_rule"], "model_response": resp})
    check("schedule ask after restart is still refused uniformly",
          resp, dict(MODEL_REFUSAL))
    check("schedule refusal after restart is grant_already_used",
          rec["internal_rule"], "grant_already_used")
    with open(os.path.join(out, "escalation-transcript.json"), "w", encoding="utf-8") as fh:
        json.dump(transcript, fh, indent=1, sort_keys=True)

    # (c) A tool action that would need a withheld fact: the commute.
    commute_facts = facts + [Fact(persona["commute_fact_text"], "memory", "fact-commute")]
    commute_texts = dict(texts)
    commute_texts["fact-commute"] = persona["commute_fact_text"]
    commute_schema = RedactionSchema(task="commute-question-demo",
                                     input_categories=frozenset(NARROW_CATEGORIES),
                                     result_fields=("summary",),
                                     escalatable_categories=frozenset(
                                         persona["task"]["escalatable_categories"]))
    commute_plan = boundary.plan(actor=actor, recipient=recipient, purpose=purpose,
                                 system_prompt="",
                                 user_text=persona["commute_user_text"],
                                 facts=commute_facts,
                                 pseudonyms=[tuple(p) for p in persona["pseudonyms"]])
    check("commute plan is not blocked", commute_plan.blocked, False)
    check("commute plan withholds the commute fact",
          "fact-commute" in [w["ref"] for w in commute_plan.withheld], True)
    commute_seen = []

    def call_tool_commute(view_text):
        commute_seen.append(view_text)
        return persona["commute_stub_reply"]

    commute_result, commute_report = redacted_model_turn(
        commute_plan, commute_schema, registry, ledger, call_tool_commute,
        task_instruction="Answer the commute question from the records given.",
        texts=commute_texts, pseudonyms=PSEUDONYMS,
        shape_reply=lambda r: {"summary": r})
    with open(os.path.join(out, "commute-turn-view.json"), "w", encoding="utf-8") as fh:
        fh.write(commute_seen[0])
    with open(os.path.join(out, "commute-turn-report.json"), "w", encoding="utf-8") as fh:
        json.dump(commute_report["view"], fh, indent=1, sort_keys=True)
    with open(os.path.join(out, "commute-turn-result.json"), "wb") as fh:
        fh.write(canon_bytes(commute_result))
    with open(os.path.join(out, "commute-turn-plan-withheld.json"), "w", encoding="utf-8") as fh:
        json.dump(commute_plan.withheld, fh, indent=1, sort_keys=True)
    commute_view = json.loads(commute_seen[0])
    check("commute turn view carries no commute record",
          [r["ref"] for r in commute_view["records"] if "commute" in r["ref"]], [])
    check("commute turn result says the information is absent",
          commute_result, {"summary": persona["commute_stub_reply"]})
    check("commute turn result has no secret value",
          [s["secret_id"] for s in persona["secrets"] if s["value"] in json.dumps(commute_result)], [])

    # The spent grant's store file, as it stands after the run.
    with open(os.path.join(out, "escalation-grants.json"), "w", encoding="utf-8") as fh:
        json.dump(json.load(open(esc_store_path, encoding="utf-8")), fh, indent=1, sort_keys=True)
    with open(os.path.join(out, "grants.json"), "w", encoding="utf-8") as fh:
        json.dump({"grants": [narrow_grant]}, fh, indent=1, sort_keys=True)

    records = ledger.records()
    count, head = anchor_of(records)
    ok, msg = verify_chain(records, (count, head))
    print("receipt chain: " + msg + " ok=" + str(ok))
    check("receipt chain verifies against its anchor", ok, True)
    check("ledger holds four redaction records",
          len([r for r in records if r.get("type") == "redaction"]), 4)
    check("ledger holds five escalation records",
          len([r for r in records if r.get("type") == "escalation"]), 5)
    check("ledger holds exactly one granted escalation",
          len([r for r in records if r.get("type") == "escalation" and r.get("granted")]), 1)

    lines = ["# Local refusal demonstration v0.1: run report", "",
             "A synthetic tool, digest.send, proposes to send the operator's",
             "weekly digest. The Disclosure Boundary authorizes the in-scope",
             "facts and withholds the rest; the tool receives only the",
             "redacted view. An ask outside the narrow grant refuses",
             "uniformly, and the one in-scope escalation grant is spent on",
             "first use and stays spent across a restart. All values are",
             "synthetic (demo/persona.json). The tool is simulated by a",
             "fixed reply; no live model, live service, live grant, or live",
             "machine was called. The receipts are deterministic: the demo",
             "pins its clock, UUID source, and ledger key (README.md), so a",
             "cold run reproduces these bytes exactly.", "",
             "## (a) The authorized tool action", "",
             "Task: " + task_name + ". The boundary disclosed only",
             "fact-works-at (workplace) and fact-proposal (general) and",
             "withheld fact-school, fact-dropoff, fact-address, fact-income,",
             "and fact-project. The view (view.json) holds exactly those two",
             "records; the filtered result (filtered-result.json) is the tool",
             "reply shaped to summary and suggested_times.", "",
             "## (b) The asks", "",
             "commute (outside the grant): refused, true rule no_live_grant.",
             "child_school (a withheld fact's category): refused, true rule",
             "outside_escalatable_scope. schedule (the one in-scope grant):",
             "granted once, then refused as grant_already_used, and refused",
             "again after a simulated restart rebuilds the authority from",
             "the store file. Every refusal the tool saw is byte-identical:",
             '{"status": "refused", "reason": "not_available"}.',
             "Full decisions: escalation-transcript.json.", "",
             "## (c) The tool action that would need a withheld fact", "",
             "A commute question with a commute fact in the facts: the",
             "boundary withholds fact-commute (commute is not in the narrow",
             "grant), the view (commute-turn-view.json) carries no commute",
             "record, and the result says the information is absent.",
             "The plan's withheld list: commute-turn-plan-withheld.json.", "",
             "## Receipt chain", "",
             "Records: " + str(count), "anchor: " + str(count) + " " + head,
             "Chain verification: " + msg, "",
             "## Expectations", "",
             ("ALL EXPECTATIONS MATCH" if not failures else "MISMATCHES: " + ", ".join(failures))]
    with open(os.path.join(out, "RUN-REPORT.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("anchor: " + str(count) + " " + head)
    print("evidence: " + out)
    if failures:
        print("RESULT: MISMATCH: " + ", ".join(failures))
        return 1
    print("RESULT: ALL EXPECTATIONS MATCH")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
