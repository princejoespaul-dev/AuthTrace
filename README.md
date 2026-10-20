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
run_checks.py           Compatibility CLI for the policy-driven selected-test runner
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

## 9. Competition verification checklist

1. Start the fixed demo API and run `python -m pytest -q`.
2. Submit a proposal that changes `INV-READ-OTHER.expected` to `allow`; fixed mode should report a policy mismatch because the API denies cross-user access.
3. Restart the demo in vulnerable mode and run the selected regression plan; returning User B's invoice to User A must produce a security-regression finding.
4. Inspect the saved run in Test Runs / Evidence Explorer and confirm its run ID, policy hashes, selected rule IDs, and sanitized expected-versus-observed evidence.
5. Keep both services bound to loopback. The control center is a local development tool, not a multi-user production deployment.

## 10. AuthTrace Security Control Center

The dashboard connects policy submission, strict validation, deterministic diffing, test mapping, selected pytest execution, sanitized evidence, and SQLite run history. It is a competition-focused workbench, not a production scanner.

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

Open [http://127.0.0.1:8010](http://127.0.0.1:8010). The API documentation is available at [http://127.0.0.1:8010/docs](http://127.0.0.1:8010/docs).

### Implemented dashboard functionality

- Read-only baseline policy view and editable proposal editor.
- Strict policy validation and proposal submission to `policy.proposed.json`; `policy.json` remains the baseline.
- Exact added, removed, and modified rules, changed fields, before/after values, and canonical SHA-256 hashes.
- Deduplicated regression plan with selection rationale, unmapped rule coverage gaps, and missing test-path checks.
- Run Selected Tests action that executes only mapped tests for changed rules, with bounded subprocess timeouts and safe argument lists.
- Run-specific SQLite history containing policy hashes, changed rules, selected tests, expected/observed evidence, status classifications, and sanitized diagnostics.
- Security-regression classification that is independent from whether observed behavior matches the submitted policy.
- Loopback-only target enforcement; no external target is enabled by default.

### Verify the control center

```bash
python -m pytest -q tests/test_authtrace_pipeline.py
python -m pytest -q tests/test_control_center.py
python -m pytest -q
```

CI also starts the local fixed and vulnerable demo API modes and verifies that a real cross-user response in vulnerable mode is classified as a security regression. Run history is stored in `reports/authtrace.db`, and the latest sanitized report is written to `reports/latest.json`. Keep the control center bound to `127.0.0.1`; authentication is not implemented.
