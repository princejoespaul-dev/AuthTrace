# Authtrace_explainer

An optional, non-authoritative explainer for the AuthTrace starter repository. It consumes the sanitized JSON report created by `run_checks.py` and annotates each check with a plain-language explanation. It does **not** run security tests, calculate verdicts, or change `checks[*].verdict` or `overall`.

## Safety model

- The existing deterministic test runner remains the sole source of verdicts.
- Rules-only mode is the default and requires no extra dependencies.
- Optional Ollama generation changes explanation wording only; invalid/unavailable model output falls back to rules.
- Evidence is bounded and common credential formats are redacted before being sent to Ollama.
- Use only the synthetic local demo data. This is a student-project helper, not a production security scanner.

## Run from the repository root

First generate the existing report with the demo API running:

```bash
python run_checks.py
```

Then run the rules-based explainer:

```bash
python -m Authtrace_explainer.main
```

It reads `reports/latest.json` and writes `reports/explained_latest.json`. To specify paths:

```bash
python -m Authtrace_explainer.main --input reports/latest.json --output reports/explained_latest.json
```

## Optional local Ollama wording

Start Ollama and pull a model first, for example `ollama pull llama3.2`. Then:

```bash
python -m Authtrace_explainer.main --use-ollama
```

Optional environment variables:

- `AUTHTRACE_EXPLAINER_MODEL` (default `llama3.2`)
- `AUTHTRACE_EXPLAINER_OLLAMA_URL` (default `http://127.0.0.1:11434/api/generate`)

The program makes a bounded request to the configured local Ollama endpoint. Do not point it at an untrusted service or send production reports. If Ollama is unavailable or its response fails validation, rules-based wording is used.

## Tests

Run from the repository root:

```bash
python -m pytest Authtrace_explainer/tests -q
```

The package uses only the Python standard library at runtime; pytest is already a dependency of the parent project.
