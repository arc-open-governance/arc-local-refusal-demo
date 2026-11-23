# Local refusal demonstration v0.1

A five-minute, fully offline demonstration of a governed tool action.
A synthetic tool, `digest.send`, proposes to send the operator's weekly
digest. The real Disclosure Boundary decides what the tool may receive,
and the real redaction layer builds the tool-facing view. An unauthorized
ask is refused uniformly, and every crossing is receipted into one
verifiable hash chain.

## Quick start (no install, no network, no account)

```bash
python3 run_demo.py
python3 verify_demo.py
```

Both commands run in under a second on an ordinary machine. `run_demo.py`
writes its evidence to `output/`; `verify_demo.py` re-checks that evidence
independently and runs the negative controls. Exit 0 from both means the
demonstration behaved exactly as specified.

## What the run shows

1. **An authorized tool action succeeds.** The boundary discloses only
   the in-scope facts (workplace + proposal) and withholds the rest
   (school, dropoff, address, income, project). The tool sends the
   digest from the redacted view only. Both crossings are receipted.
2. **An unauthorized ask refuses uniformly.** The tool asks for the
   commute category (outside the narrow grant) and for a withheld
   fact's category (child_school). Both refusals are byte-identical:
   `{"status": "refused", "reason": "not_available"}`. The ledger
   records the true internal rules (`no_live_grant`,
   `outside_escalatable_scope`); the tool never sees them.
3. **A one-shot grant is spent on first use.** The `schedule`
   escalation grant is granted once, refused on second use
   (`grant_already_used`), and still refused after a simulated restart
   rebuilds the authority from the store file. A restart cannot
   resurrect a spent grant.
4. **A tool action that would need a withheld fact gets nothing.**
   The commute turn's view carries no commute record, and its result
   says the information is absent.
5. **The receipts form a verifiable hash chain.** `output/receipts.jsonl`
   holds 9 records (4 redaction, 5 escalation) chained to the anchor
   in `EXPECTED.json` and `output/RUN-REPORT.md`.

## What is proven here, and what is not

**Proven by this demo:** the specified boundary behaves as claimed on
these synthetic inputs — least-privilege disclosure, uniform refusal,
one-shot grant consumption across a restart, and a verifiable receipt
chain. The boundary and redaction code are the real modules, vendored
byte-identical (see `demo/vendor/VENDORED.md`), not reimplementations.

**Not proven:** this is a sandbox demonstration, not proof of universal
protection. The tool is simulated by a fixed reply function; no real
tool is executed through a protected route, and no real agent is
governed. A plugin that can observe a tool call but cannot prevent an
alternate route from executing is not sufficient evidence of complete
mediation. The acceptance gate for protected-execution claims remains
**AUTH-01** (arc-open-governance/arc-open-governance issue 57): an
authentic Field/DSL → protected KORE → independently observed sandbox
effect. This demo is milestone 1 of 3 (five-minute local refusal);
milestones 2 (bring your own agent, with real protected execution) and
3 (break the boundary, adversarial examination) are separate work.

## Determinism: why two cold runs are byte-identical

`run_demo.py` pins its own clock (fixed epoch), its UUID source
(deterministic counter), and its ledger HMAC key (a fixed demo key,
`SHA-256("local-refusal-demo-v0.1: synthetic demo ledger key, never
real")`, seeded into `output/receipts.jsonl.key` before the ledger is
constructed). The pins are **demo fixtures**: production receipts carry
real timestamps, random ids, and a random per-ledger key. The pins
change nothing about the boundary's decisions, only the bytes that
record them — so a cold run from a fresh copy reproduces the exact
bytes in `EXPECTED.json`. Copy the whole directory (minus `output/`)
anywhere and run it; the outputs will match.

## Layout

| Path | What it is |
|---|---|
| `run_demo.py` | The entry point. Stdlib only. Writes `output/`. |
| `verify_demo.py` | The independent verifier. Checks the manifest, re-checks every output against `EXPECTED.json` with the real receipt code, and runs the negative controls. |
| `MANIFEST.json` | SHA-256 and byte count of every shipped file (itself excepted: a manifest cannot hash itself). |
| `EXPECTED.json` | The exact expected outputs: anchor, file hashes, counts, refusal bytes, grant state, view refs, result bytes. |
| `demo/persona.json` | The synthetic persona: facts, secrets, grants, stub tool replies. All values invented; no real person. |
| `demo/policy.json` | The STRICT disclosure policy, byte-identical to the vendored harness copy. |
| `demo/vendor/arc_disclosure/` | The Disclosure Boundary, vendored byte-identical from the disclosure-experiment harness (which vendors it from `cos/presence-disclosure-routing-20261121`, branch head `9b6daea5`). |
| `demo/vendor/redaction.py` | The redaction layer, vendored byte-identical from the same harness. |
| `demo/vendor/VENDORED.md` | Vendoring provenance, including the repo blob SHA-1s. |
| `output/` | Generated by the run. Not shipped, not in the manifest. |

## Negative controls

`verify_demo.py` runs four deliberately broken cases against temp
copies of the output and requires each one to be **rejected**:

1. `tampered-receipt` — one field of one receipt altered: the chain
   must fail.
2. `reused-grant` — a second schedule escalation marked granted: the
   exactly-one-grant check must fail.
3. `mutated-payload` — one byte of the filtered result changed: the
   result receipt must no longer bind the bytes.
4. `truncated-ledger` — the last receipt dropped: the anchor must
   mismatch.

A control that cannot fail proves nothing, so the verifier exits
nonzero if any control is **not** rejected, and prints each control's
rejection. The controls never touch the real `output/`.

## What remains

- **Outside-examiner cold run.** No independent examiner has yet run
  this from a fresh copy. That is the next verification step, and the
  artifact is built for it: one directory, no install, no network.
- **Scope.** Milestones 2 and 3 (a real supported agent integration
  with protected execution, and adversarial examination) are not in
  this artifact.

## License

Apache License 2.0. See `LICENSE`.
