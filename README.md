# AuthTrace: safe API authorization testing + local RAG starter

This is a student-project starter, not a production security scanner. It demonstrates:
- a local synthetic invoice API with `vulnerable` and `fixed` modes;
- deterministic authorization tests using HTTPX + pytest;
- a JSON policy and sanitized evidence report;
- optional local RAG retrieval using Sentence Transformers;
- optional local explanation generation through Ollama.

## Safety boundaries
- The demo API binds to `127.0.0.1` by default.
- The test runner refuses non-loopback hosts unless `AUTHTRACE_ALLOW_STAGING=1` is set.
- Use only systems you own or have explicit written authorization to test.
- Use synthetic fixtures; do not put tokens or private response bodies in reports.
- The current authorization demo and seeded checks are read-only; write/tenant-isolation coverage is not yet implemented.
- `POLICY_MISMATCH` means observed behavior differs from the submitted policy; `SECURITY_REGRESSION` means an explicit security invariant was violated. Neither a pass nor an absence of findings proves the whole API is secure.

## 1. Setup

Python 3.11+ recommended.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

The core install contains the API, HTTP client, and test runner only. Optional local RAG dependencies are separate:

```bash
pip install -r requirements-rag.txt
```

## 2. Start the demo API

In terminal 1:

```bash
uvicorn demo_api:app --host 127.0.0.1 --port 8000
```

The demo has fixed mode by default. To demonstrate a seeded flaw, stop the server and restart it with:

**Windows PowerShell**
```powershell
$env:AUTH_TRACE_MODE="vulnerable"
uvicorn demo_api:app --host 127.0.0.1 --port 8000
```

**macOS/Linux**
```bash
AUTH_TRACE_MODE=vulnerable uvicorn demo_api:app --host 127.0.0.1 --port 8000
```

Synthetic bearer tokens:
- `token-user-a`
- `token-user-b`
- `token-admin`

Do not reuse these demo tokens anywhere else.

## 3. Run the policy-aware regression tests

Start the API in fixed mode (the default) in terminal 1:

```bash
uvicorn demo_api:app --host 127.0.0.1 --port 8000
```

In terminal 2, run the test suite:

```bash
python -m pytest -q
```

The tests compare actual HTTP outcomes with policy expectations and independently enforce the cross-user invoice access invariant. Do not set an environment variable to force vulnerable behavior to pass: a foreign invoice returned to a non-owner is reported as a security regression.

## 4. Run the dashboard workflow end to end

Keep the demo API running, then start the control center in a second terminal:

```bash
uvicorn control_center:app --host 127.0.0.1 --port 8010
```

Open [http://127.0.0.1:8010](http://127.0.0.1:8010) and follow these steps:

1. Open **Policy Diff** and edit the proposed policy JSON.
2. Select **Validate policy** to see actionable schema errors before saving.
3. Select **Submit policy**. The validated proposal is saved to `policy.proposed.json`; `policy.json` remains the immutable baseline.
4. Select **Compare policies** to review added, removed, and modified rules with before/after values and policy hashes.
5. Open **Regression Planner** to review selected pytest node IDs, selection rationale, and unmapped rules.
6. Select **Run Selected Tests**. Only tests mapped to changed policy rules are executed against the local demo API.
7. Open **Test Runs** or **Evidence Explorer** to inspect the run-specific report, expected versus observed outcomes, status classifications, policy hashes, and sanitized evidence.

The checked-in `policy.v2.json` is an illustrative proposal that changes cross-user invoice access from `deny` to `allow`. Against the fixed API, that proposal produces a **policy mismatch** because the API correctly denies the request. To demonstrate a genuine security regression, stop the API and restart it in vulnerable mode:

**Windows PowerShell**
```powershell
$env:AUTH_TRACE_MODE="vulnerable"
uvicorn demo_api:app --host 127.0.0.1 --port 8000
```

**macOS/Linux**
```bash
AUTH_TRACE_MODE=vulnerable uvicorn demo_api:app --host 127.0.0.1 --port 8000
```

Run the selected regression again. If the API returns User B's invoice to User A, AuthTrace reports a **security regression** even when the submitted policy says `allow`, because the separate cross-user access invariant still forbids that behavior. Restart in fixed mode when finished.

For a terminal-only run using the same diff/validation/mapping/execution pipeline as the dashboard:

```bash
python authtrace_pipeline.py --execute --report reports/latest_pipeline.json --dashboard reports/dashboard.html
```

The compatibility command `python run_checks.py` uses that same pipeline and writes the latest report to `reports/latest.json`.

## 5. Local RAG

Install the optional retrieval dependencies:

```bash
pip install -r requirements-rag.txt
python rag_assistant.py --question "Why is cross-user invoice access a BOLA risk?"
```

The first run may download an embedding model. If you need fully offline operation, pre-download the model and point `RAG_EMBED_MODEL` at the local model directory.

Documents in `knowledge_base/` are illustrative curated notes. Replace/expand them with properly sourced OWASP/CERT-In documentation and preserve source URL/title/section metadata. Retrieval is evidence support, not a vulnerability detector.

### Optional Ollama generation
Install and run Ollama separately, then pull a local model, for example:

```bash
ollama pull llama3.2
ollama serve
python rag_assistant.py --question "Explain this test result" --use-ollama
```

The assistant sends only the question and retrieved knowledge snippets to Ollama, not authorization tokens. Do not send unredacted logs or production data.

## 6. Project structure

```text
demo_api.py             Local synthetic API (vulnerable/fixed modes)
policy.json             Human-reviewed policy source of truth
test_authorization.py   Deterministic pytest checks
run_checks.py           HTTPX runner + sanitized JSON report
rag_assistant.py        Local retrieval + optional Ollama explanation
knowledge_base/         Curated source notes
reports/                Generated reports
```

## 7. Policy-change pipeline

See [`README_POLICY_PIPELINE.md`](README_POLICY_PIPELINE.md) for policy diffing, deterministic risk-ranked test selection, mapping validation, report generation, and CI behavior. The pipeline validates that mapped rule IDs exist in at least one of the compared policy versions and records stable SHA-256 policy hashes. Planned checks are not the same as executed checks.

## 8. Known limitations

- The demo currently covers synthetic invoice reads. Write authorization, denied-write integrity, and broader tenant-isolation scenarios are outside this competition-focused implementation.
- A green planner test run validates policy-diff mechanics, not the security of a running API.
- JSON evidence includes run timestamps and run IDs, so byte-for-byte report output is not identical across runs; policy hashes and test selection are stable for identical inputs.

## 9. Suggested implementation milestones
1. Run fixed mode and confirm own-object access passes and cross-user access is denied.
2. Run vulnerable mode and confirm the cross-user check detects the seeded issue.
3. Add negative controls (admin allowed; User A own invoice allowed).
4. Add retrieval source citations to every generated explanation.
5. Measure seeded-flaw recall, false-positive rate, evidence completeness, and repeatability.
6. Only then add BFLA, property-level authorization, or carefully isolated write tests.


## 10. AuthTrace Security Control Center

The new local-first dashboard connects the existing demo API, sanitized authorization runner, policy-diff pipeline, and persisted run history. It is a student-project workbench, not a production scanner.

### Start the dashboard

Install the core dependencies as above, then start two services in separate terminals from the repository root.

**Terminal 1 — synthetic demo API**
```bash
uvicorn demo_api:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — control center**
```bash
uvicorn control_center:app --host 127.0.0.1 --port 8010
```

Open http://127.0.0.1:8010 in your browser. The API documentation is available at http://127.0.0.1:8010/docs.

On Windows PowerShell, the same `uvicorn` commands work after activating the virtual environment.

### Implemented dashboard functionality

- Live overview metrics and recent runs from the local SQLite database.
- Guided execution of the existing three read-only synthetic invoice authorization checks, with an explicit local-target confirmation.
- Persistent run status, duration, sanitized report data, and error records.
- Policy diff backed by `authtrace_pipeline.py`, including changed fields, SHA-256 policy hashes, risk heuristic, and rationale.
- Regression plan preview with mapped tests, deduplication, unmapped rules, and missing test-file checks. The plan is explicitly labeled as not executed.
- Finding status persistence for a cross-user invoice-access finding detected by a run.
- Evidence/run detail view and JSON report download.
- Local target scope screen, implemented test catalog, appearance toggle, responsive layout, and empty/error states.

### Verify the control center

```bash
python -m unittest tests.test_authtrace_pipeline tests.test_control_center -v
pytest -v
```

The control-center run endpoint executes the fixed `run_checks.py` command using an argument list, without a shell, and applies a 30-second timeout. It only permits the local demo target `http://127.0.0.1:8000`; it does not enable arbitrary external target testing. Run history is stored in `reports/authtrace.db`, and the latest sanitized runner report is `reports/latest.json`.

### Current limitations

- BFLA role/action matrices, write authorization, ownership-field tampering, and broader property-level authorization are not implemented.
- The policy regression planner is a preview only in the dashboard; the dashboard does not launch its selected arbitrary pytest node IDs.
- The demo API's fixed/vulnerable mode is configured when the demo server starts. A finding is created when the runner observes the seeded cross-user access violation.
- The control center uses a local SQLite file and is intended for local development, not multi-user deployment. Do not expose it to a public network.
- Browser-to-demo connection status is separate from a security test result; a connection failure is not reported as a passed check.
