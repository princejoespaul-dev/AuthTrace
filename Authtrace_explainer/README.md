# AuthTrace AI Explainer

Optional, non-authoritative explainer for sanitized AuthTrace JSON reports. It adds plain-language explanations and code-aware authorization analysis using the OpenAI API. Deterministic test verdicts remain the source of truth.

## Features

- Explains expected-versus-observed authorization behavior.
- Selects relevant source snippets from explicitly supplied demo API files.
- Requests structured analysis: likely root cause, evidence basis, potential impact, recommended fix, verification steps, confidence, missing information, and source references.
- Validates model output before including it in the report.
- Keeps AI output separate from `checks[*].verdict` and top-level `overall`.
- Falls back to deterministic explanations if the API key is missing or the response is unavailable/invalid.
- Does not execute code or automatically apply fixes.

## Privacy and safety

The OpenAI API is hosted. Selected source snippets and sanitized test fields are sent to OpenAI when AI mode is enabled. Review provider data-handling terms before using proprietary source. Do not provide production secrets, credentials, personal data, or real customer data.

- Set `OPENAI_API_KEY` in your environment; never hardcode it or commit it.
- Common secret-bearing report fields are omitted, common credential patterns are redacted, and `.env`, secrets, credentials, `.git`, dependency, build, and virtual-environment directories are excluded.
- Only explicitly supplied source files/directories are considered; source selection is relevance-ranked and bounded.
- Model findings are advisory and unverified. They cannot change deterministic verdicts.
- Use synthetic data in the local demo.

## Run from the AuthTrace repository root

Generate the deterministic report with the demo API running:

```bash
python run_checks.py
```

Set your API key in your shell:

macOS/Linux:

```bash
export OPENAI_API_KEY="your-api-key"
```

PowerShell:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
```

### Rules-only mode

```bash
python -m Authtrace_explainer.main
```

### OpenAI explanation mode

```bash
python -m Authtrace_explainer.main --use-openai
```

### OpenAI code-aware mode

Pass the directory or exact files containing demo API authorization logic. Change `app` to the actual source directory in your checkout.

```bash
python -m Authtrace_explainer.main --use-openai --source app
```

Or pass files explicitly:

```bash
python -m Authtrace_explainer.main --use-openai --source app/main.py --source app/routes/invoices.py
```

Defaults: input `reports/latest.json`; output `reports/explained_latest.json`.

## Configuration

- `OPENAI_API_KEY` — required for hosted analysis.
- `AUTHTRACE_OPENAI_MODEL` — optional model override; defaults to `gpt-4.1-mini`.
- `AUTHTRACE_OPENAI_BASE_URL` — optional compatible endpoint override; defaults to OpenAI Chat Completions API.

Local Ollama remains available with `--use-ollama`.

## Tests

```bash
python -m pytest Authtrace_explainer/tests -q
```
