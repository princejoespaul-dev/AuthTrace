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
- `PASS`, `FAIL`, and `INCONCLUSIVE` describe the declared policy/test, not whether an entire API is secure.

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

## 3. Run deterministic tests

In terminal 2, from this directory:

```bash
pytest -v
```

The suite expects the **fixed** API by default. For vulnerable-mode demonstration:

**Windows PowerShell**
```powershell
$env:AUTH_TRACE_EXPECT_VULNERABLE="1"
pytest -v
```

**macOS/Linux**
```bash
AUTH_TRACE_EXPECT_VULNERABLE=1 pytest -v
```

The cross-user test should fail in fixed mode only if the API unexpectedly exposes User B's invoice. In vulnerable mode, set the expectation variable so the seeded flaw is detected as expected. Do not interpret a successful test run against vulnerable mode as a secure result; it means the test correctly recognized the seeded flaw.

## 4. Generate an evidence report

```bash
python run_checks.py
```

Set `AUTH_TRACE_EXPECT_VULNERABLE=1` for vulnerable mode. The runner uses a local target by default and writes `reports/latest.json`. Reports contain no token values or full response bodies.

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

- The demo currently covers invoice reads; write authorization, denied-write integrity, tenant isolation, and a full vulnerable/fixed/regression automation are not implemented yet.
- A green planner test run validates policy-diff mechanics, not the security of a running API.
- JSON evidence includes run timestamps and run IDs, so byte-for-byte report output is not identical across runs; policy hashes and test selection are stable for identical inputs.

## 9. Suggested implementation milestones
1. Run fixed mode and confirm own-object access passes and cross-user access is denied.
2. Run vulnerable mode and confirm the cross-user check detects the seeded issue.
3. Add negative controls (admin allowed; User A own invoice allowed).
4. Add retrieval source citations to every generated explanation.
5. Measure seeded-flaw recall, false-positive rate, evidence completeness, and repeatability.
6. Only then add BFLA, property-level authorization, or carefully isolated write tests.
