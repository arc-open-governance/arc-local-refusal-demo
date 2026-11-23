"""Independent verifier for the local refusal demonstration v0.1.

Run from this directory:
  python3 verify_demo.py [--out DIR]

It checks, using the REAL receipt code vendored in demo/vendor/:
  1. MANIFEST.json: every shipped file exists with the listed SHA-256
     and byte count, and no shipped file is unlisted.
  2. The receipt chain in output/receipts.jsonl verifies against the
     anchor in EXPECTED.json, and the ledger file's bytes match.
  3. Every output file's SHA-256 matches EXPECTED.json (this is what
     makes a cold run byte-identical, not just behaviorally equal).
  4. The view holds only the granted facts and no secret value; the
     filtered result is exactly the expected bytes with only the
     declared fields and no secret value; no receipt names a secret.
  5. All refusals are byte-identical and exactly
     {"status": "refused", "reason": "not_available"}; exactly one
     escalation granted (schedule), with the true internal rules.
  6. The spent grant stays spent (consumed=true) in the store file.
  7. The commute-turn view carries no commute record, and the plan's
     withheld list names fact-commute.

Then it runs the NEGATIVE CONTROLS: four deliberately broken copies
of the output, each of which the same checks must REJECT. A control
that cannot fail proves nothing, so the verifier exits nonzero if any
control is not rejected:
  - tampered-receipt: one receipt field altered (chain must fail);
  - reused-grant: a second schedule escalation marked granted
    (exactly-one-grant must fail);
  - mutated-payload: one byte of the filtered result changed (the
    result receipt must stop binding the bytes);
  - truncated-ledger: the last receipt dropped (anchor must mismatch).

The controls run on temp copies and never touch the real output/.
The verifier reads only the shipped files and output/; it needs no
key, no credential, and no network.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "demo", "vendor"))

from arc_disclosure import verify_chain  # noqa: E402

NARROW_CATEGORIES = {"general", "schedule", "task", "workplace"}
UNIFORM_REFUSAL = {"status": "refused", "reason": "not_available"}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def check_output(outdir, expected, persona):
    """Every EXPECTED check on one output directory. Returns the list of
    failure labels (empty means the output matches EXPECTED exactly)."""
    failures = []

    def check(label, ok, detail=""):
        if not ok:
            failures.append(label)
        print(("  PASS " if ok else "  FAIL ") + label + ((": " + detail) if detail else ""))

    receipts_path = os.path.join(outdir, "receipts.jsonl")
    try:
        records = [json.loads(line) for line in
                   open(receipts_path, encoding="utf-8") if line.strip()]
        records_ok = True
    except (OSError, ValueError) as exc:
        records = []
        records_ok = False
        check("receipts.jsonl parses as JSONL", False, type(exc).__name__)
    anchor = (expected["anchor"][0], expected["anchor"][1])
    if records_ok:
        ok, msg = verify_chain(records, anchor)
        check("receipt chain verifies against the published anchor", ok, msg)
        check("receipts.jsonl matches EXPECTED.json bytes",
              sha256_hex(open(receipts_path, "rb").read()) == expected["receipts_sha256"])
        red = [r for r in records if r.get("type") == "redaction"]
        esc = [r for r in records if r.get("type") == "escalation"]
        check("ledger holds four redaction records",
              len(red) == expected["counts"]["redaction"], str(len(red)))
        check("ledger holds five escalation records",
              len(esc) == expected["counts"]["escalation"], str(len(esc)))
        granted = [r for r in esc if r.get("granted")]
        check("exactly one escalation granted (schedule)",
              len(granted) == 1 and granted[0].get("category") == "schedule"
              and granted[0].get("grant_id") == "esc-demo-schedule-001", str(len(granted)))
        rules = {(r.get("category"), r.get("internal_rule")) for r in esc}
        check("commute refusal records no_live_grant",
              ("commute", "no_live_grant") in rules)
        check("child_school refusal records outside_escalatable_scope",
              ("child_school", "outside_escalatable_scope") in rules)
        check("repeat schedule refusals record grant_already_used",
              sum(1 for r in esc if r.get("internal_rule") == "grant_already_used") == 2)

    for name, want in expected["files"].items():
        path = os.path.join(outdir, name)
        try:
            data = open(path, "rb").read()
            check(name + " matches EXPECTED.json",
                  sha256_hex(data) == want, "sha256 " + sha256_hex(data))
        except OSError:
            check(name + " matches EXPECTED.json", False, "missing")

    key_path = os.path.join(outdir, "receipts.jsonl.key")
    try:
        check("ledger key is the fixed demo key",
              sha256_hex(open(key_path, "rb").read()) == expected["key_sha256"])
    except OSError:
        check("ledger key is the fixed demo key", False, "missing")

    secrets = [s["value"] for s in persona["secrets"]]
    try:
        view = open(os.path.join(outdir, "view.json"), "rb").read()
        vobj = json.loads(view)
        check("tool view holds only the granted facts",
              [r["ref"] for r in vobj["records"]] == expected["view_refs"])
        vtext = view.decode("utf-8", "replace")
        leaked = [s["secret_id"] for s in persona["secrets"] if s["value"] in vtext]
        check("tool view contains no registered secret value", not leaked,
              "leaked: " + ",".join(leaked))
        view_recs = [r for r in records if r.get("type") == "redaction"
                     and r.get("task") == "weekly-digest-send"]
        check("one view redaction record exists", len(view_recs) == 1, str(len(view_recs)))
        if view_recs:
            check("view receipt binds the exact view bytes",
                  view_recs[0].get("view_sha256") == sha256_hex(view)
                  and view_recs[0].get("view_len") == len(view))
    except (OSError, ValueError) as exc:
        check("tool view checks", False, type(exc).__name__)

    try:
        result = open(os.path.join(outdir, "filtered-result.json"), "rb").read()
        robj = json.loads(result)
        check("filtered result is exactly the expected bytes",
              robj == expected["result_exact"])
        check("filtered result has only the declared fields",
              set(robj) <= set(expected["result_fields"]))
        rtext = result.decode("utf-8", "replace")
        leaked = [s["secret_id"] for s in persona["secrets"] if s["value"] in rtext]
        check("filtered result contains no registered secret value", not leaked,
              "leaked: " + ",".join(leaked))
        result_recs = [r for r in records if r.get("type") == "redaction"
                       and r.get("task") == "weekly-digest-send:result"]
        check("one result redaction record exists", len(result_recs) == 1,
              str(len(result_recs)))
        if result_recs:
            check("result receipt binds the exact filtered bytes",
                  result_recs[0].get("view_sha256") == sha256_hex(result)
                  and result_recs[0].get("view_len") == len(result))
    except (OSError, ValueError) as exc:
        check("filtered result checks", False, type(exc).__name__)

    try:
        transcript = load_json(os.path.join(outdir, "escalation-transcript.json"))
        refusals = [t["model_response"] for t in transcript
                    if t["model_response"].get("status") == "refused"]
        check("four refusals in the transcript",
              len(refusals) == expected["counts"]["refusals"], str(len(refusals)))
        check("all refusals are byte-identical",
              len({json.dumps(r, sort_keys=True) for r in refusals}) == 1)
        check("every refusal says exactly not_available",
              all(r == UNIFORM_REFUSAL for r in refusals))
    except (OSError, ValueError) as exc:
        check("escalation transcript checks", False, type(exc).__name__)

    try:
        store = load_json(os.path.join(outdir, "escalation-grants.json"))["grants"]
        spent = [g for g in store if g.get("grant_id") == "esc-demo-schedule-001"]
        check("spent grant is still in the store", len(spent) == 1, str(len(spent)))
        if spent:
            check("spent grant stays spent (consumed=true)",
                  spent[0].get("consumed") is True,
                  "consumed: " + repr(spent[0].get("consumed")))
    except (OSError, ValueError) as exc:
        check("escalation store checks", False, type(exc).__name__)

    try:
        grants = load_json(os.path.join(outdir, "grants.json"))["grants"]
        check("one narrow boundary grant staged", len(grants) == 1, str(len(grants)))
        if grants:
            check("narrow grant carries only the four categories",
                  set(grants[0].get("categories", [])) == NARROW_CATEGORIES)
            check("narrow grant is g-demo-digest",
                  grants[0].get("grant_id") == "g-demo-digest")
    except (OSError, ValueError) as exc:
        check("boundary grant checks", False, type(exc).__name__)

    try:
        cview = json.loads(open(os.path.join(outdir, "commute-turn-view.json"),
                                encoding="utf-8").read())
        check("commute-turn view carries no commute record",
              [r["ref"] for r in cview["records"] if "commute" in r["ref"]] == [])
        withheld = load_json(os.path.join(outdir, "commute-turn-plan-withheld.json"))
        check("commute-turn plan withholds fact-commute",
              "fact-commute" in [w["ref"] for w in withheld])
        cresult = open(os.path.join(outdir, "commute-turn-result.json"),
                       encoding="utf-8").read()
        check("commute-turn result contains no registered secret value",
              not [s["secret_id"] for s in persona["secrets"] if s["value"] in cresult])
    except (OSError, ValueError) as exc:
        check("commute-turn checks", False, type(exc).__name__)

    if records_ok:
        rec_text = json.dumps(records)
        leaked = [s["secret_id"] for s in persona["secrets"] if s["value"] in rec_text]
        check("no receipt names a secret value", not leaked, "leaked: " + ",".join(leaked))

    try:
        report = open(os.path.join(outdir, "RUN-REPORT.md"), encoding="utf-8").read()
        check("run report carries the anchor",
              ("anchor: %d %s" % (anchor[0], anchor[1])) in report)
    except OSError:
        check("run report carries the anchor", False, "missing")

    return failures


def check_manifest():
    """SHA-256 and byte count of every shipped file; no shipped file unlisted."""
    failures = []
    manifest = load_json(os.path.join(HERE, "MANIFEST.json"))
    listed = {e["path"]: e for e in manifest["files"]}

    def check(label, ok, detail=""):
        if not ok:
            failures.append(label)
        print(("  PASS " if ok else "  FAIL ") + label + ((": " + detail) if detail else ""))

    for path, entry in sorted(listed.items()):
        full = os.path.join(HERE, path)
        try:
            data = open(full, "rb").read()
            check("manifest: " + path,
                  sha256_hex(data) == entry["sha256"] and len(data) == entry["bytes"],
                  "sha256 " + sha256_hex(data) + " bytes " + str(len(data)))
        except OSError:
            check("manifest: " + path, False, "missing")
    found = set()
    for root, dirs, files in os.walk(HERE):
        dirs[:] = [d for d in dirs if d not in ("output", "__pycache__")]
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, HERE)
            if rel == "MANIFEST.json":
                continue
            found.add(rel)
    check("every shipped file is listed in the manifest",
          found <= set(listed), "unlisted: " + ",".join(sorted(found - set(listed))))
    check("no listed file is missing from the tree",
          set(listed) <= found, "missing: " + ",".join(sorted(set(listed) - found)))
    return failures


def run_control(name, mutate, want_label, outdir, expected, persona):
    """Copy the output, break it as described, and require check_output
    to reject it with the expected failure label. Returns True iff the
    control was correctly rejected."""
    tmp = tempfile.mkdtemp(prefix="local-refusal-control-")
    try:
        copy = os.path.join(tmp, "out")
        shutil.copytree(outdir, copy)
        mutate(copy)
        print("  -- negative control " + name + " --")
        failures = check_output(copy, expected, persona)
        ok = want_label in failures
        print(("  PASS " if ok else "  FAIL ") + "negative control " + name
              + (" correctly rejected (" + "; ".join(failures) + ")" if ok
                 else " NOT rejected: expected failure '" + want_label
                 + "' absent; failures were: " + "; ".join(failures)))
        return ok
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _mutate_receipt_record(path, seq, **changes):
    lines = open(path, encoding="utf-8").read().splitlines()
    rec = json.loads(lines[seq])
    rec.update(changes)
    lines[seq] = json.dumps(rec, sort_keys=True, ensure_ascii=False)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv) -> int:
    out = os.path.join(HERE, "output")
    if argv and argv[0] == "--out" and len(argv) == 2:
        out = argv[1]
    elif argv:
        print("usage: python3 verify_demo.py [--out DIR]")
        return 2
    expected = load_json(os.path.join(HERE, "EXPECTED.json"))
    persona = load_json(os.path.join(HERE, "demo", "persona.json"))

    print("== manifest ==")
    failures = check_manifest()
    print("== output vs EXPECTED.json ==")
    failures += check_output(out, expected, persona)

    print("== negative controls ==")
    controls = []

    def c_tampered(copy):
        _mutate_receipt_record(os.path.join(copy, "receipts.jsonl"), 4,
                               internal_rule="grantedX")

    controls.append(run_control(
        "tampered-receipt", c_tampered,
        "receipt chain verifies against the published anchor",
        out, expected, persona))

    def c_reused(copy):
        _mutate_receipt_record(os.path.join(copy, "receipts.jsonl"), 5,
                               granted=True, internal_rule="granted",
                               grant_id="esc-demo-schedule-001")

    controls.append(run_control(
        "reused-grant", c_reused,
        "exactly one escalation granted (schedule)",
        out, expected, persona))

    def c_mutated(copy):
        path = os.path.join(copy, "filtered-result.json")
        data = open(path, encoding="utf-8").read()
        open(path, "w", encoding="utf-8").write(data.replace("Meridian", "MeridiaX", 1))

    controls.append(run_control(
        "mutated-payload", c_mutated,
        "result receipt binds the exact filtered bytes",
        out, expected, persona))

    def c_truncated(copy):
        path = os.path.join(copy, "receipts.jsonl")
        lines = open(path, encoding="utf-8").read().splitlines()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines[:-1]) + "\n")

    controls.append(run_control(
        "truncated-ledger", c_truncated,
        "receipt chain verifies against the published anchor",
        out, expected, persona))

    if not all(controls):
        print("RESULT: FAIL: a negative control was NOT rejected -- "
              "the check cannot detect that tampering")
        return 1
    print("RESULT: all 4 negative controls correctly rejected")
    if failures:
        print("RESULT: FAIL: " + ", ".join(failures))
        return 1
    print("RESULT: ALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
