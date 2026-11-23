# Vendored boundary provenance

The code in `vendor/arc_disclosure/` is an exact copy, never rewritten, of the deployed
Disclosure Boundary on branch `cos/presence-disclosure-routing-20261121` of
Syzygy-research/Agentic-Org-Workflow.

- **Source branch** `cos/presence-disclosure-routing-20261121`
- **Branch head at vendoring** `9b6daea5` (2026-11-21T22:44:53Z, presence redesign v6 frontend;
  commit message states "backend + Disclosure Boundary untouched")
- **Boundary code commit** `d40fe4d0` (deploy) and `95f75e9f` (Bend law commit, parent of 9b6daea5)
- **Source path in the repo** `work-atoms/jarvis-loop-20261111/noetica-loop/app/vendor/arc_disclosure/`
- **Vendored digest** (repo `app/vendor/VENDORED.sha256`) `b43546705c5bc90b8e3ceb444c1fc0e28ff9e0cb99e05bd02e32d4c4c6fb2b7c`

## Correction to the build brief

The build brief described the boundary as a JavaScript implementation and asked for a
Node harness driving it. That is wrong. There is no JavaScript boundary module in the
repo. A code search for `DisclosureBoundary` returns 0 results, and the boundary is
Python (`app/vendor/arc_disclosure/`, plus `app/disclosure_route.py` and
`app/disclosure_policy.json`). The harness in this directory is therefore Python and
drives the real Python boundary. Nothing is mocked and nothing is re-implemented.

## File-by-file verification (git blob SHA-1, repo vs this copy)

| File | Repo blob | This copy |
| --- | --- | --- |
| `__init__.py` | `4bc1bdc2c36c` | matches |
| `boundary.py` | `da89672bd8b8` | matches |
| `canon.py` | `6ff0d16c53bf` | matches |
| `classify.py` | `c7ebad25901f` | matches |
| `combination.py` | `166f77b79d4c` | matches |
| `egress.py` | `becd09bf4438` | matches |
| `grants.py` | `011ad5498b26` | matches |
| `policy.py` | `13f6ba489373` | matches |
| `predicates.py` | `26466893315a` | matches |
| `receipts.py` | `4082a710e5f1` | matches |
| `secrets.py` | `8e996ed522fb` | matches |
| `disclosure_policy.json` | `5996df8f1eec` | matches |

The local names in `~/workspace/disclosure-facts/` (`arc_boundary.py` and so on) are the
same files under a local prefix; the copies here use the package's own module names.
`disclosure_policy.json` is the bundled STRICT policy from the same branch and commit.
