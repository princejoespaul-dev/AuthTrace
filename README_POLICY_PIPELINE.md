# AuthTrace policy-change pipeline

AuthTrace validates policy JSON, compares stable rule IDs, maps changed rules to pytest
node IDs, runs only selected tests, and stores sanitized expected-versus-observed evidence.
Security invariants are evaluated separately from submitted policy expectations.

## Files

- `policy.json`: immutable baseline during normal dashboard use.
- `policy.v2.json`: checked-in example proposal; it changes `INV-READ-OTHER.expected`
  from `deny` to `allow` to demonstrate a policy mismatch against fixed API behavior.
- `policy.proposed.json`: created only after a valid proposal is submitted in the dashboard.
  When present, it is the default proposal for the CLI pipeline.
- `test_mapping.json`: human-reviewed policy rule IDs to pytest node IDs.
- `authtrace_pipeline.py`: strict validation, diff, planner, bounded selected-test runner,
  JSON evidence, and static HTML report.
- `control_center.py`: local dashboard API, policy submission, selected-plan execution, and
  run-specific SQLite history.
- `.github/workflows/authtrace-policy-check.yml`: unit, dashboard syntax, fixed API, and
  vulnerable API regression checks.

## Validate and compare without execution

```bash
python authtrace_pipeline.py --fail-on-unmapped
```

This creates `reports/latest_pipeline.json` and `reports/dashboard.html`. A planned run is
not evidence of execution. Changed rules without mappings are listed as coverage gaps;
`--fail-on-unmapped` makes those gaps a non-zero exit. Policy validation rejects missing or
duplicate rule IDs, missing required fields, invalid outcomes, unsupported role/action/resource/
condition values, unsupported policy structures, malformed JSON, invalid mappings, and missing
or path-traversing test references.

## Submit through the dashboard

Start the synthetic API and control center on loopback:

```bash
uvicorn demo_api:app --host 127.0.0.1 --port 8000
uvicorn control_center:app --host 127.0.0.1 --port 8010
```

Open [http://127.0.0.1:8010](http://127.0.0.1:8010), select **Policy Diff**, edit the proposal,
choose **Validate policy**, then **Submit policy**. Submission writes `policy.proposed.json`
only after validation; `policy.json` is not overwritten. Compare Policies displays added,
removed, and modified rules with exact before/after values and policy hashes.

## Execute only selected tests

Start the local synthetic API first, then run:

```bash
python authtrace_pipeline.py --execute --fail-on-unmapped
```

The CLI uses `policy.proposed.json` when it exists, otherwise it uses `policy.v2.json`.
The dashboard uses the same diff, mapping, and selected-test runner. Tests are invoked with
argument lists, no shell interpolation, and a bounded timeout. Each result records the mapped
rule IDs, expected outcome, observed decision, sanitized evidence, duration, and error class.
No bearer token or full response body is written to the report.

The runner distinguishes `POLICY_MISMATCH`, `SECURITY_REGRESSION`, `ERROR`, `TIMEOUT`,
and ordinary assertion failures. A changed policy is not automatically a vulnerability. The
cross-user invoice invariant remains separately enforced: if User A receives User B's invoice,
the result is a security regression even when the submitted policy expects `allow`.

The runner blocks non-loopback targets unless `AUTHTRACE_ALLOW_STAGING=1` is explicitly set.
The control center itself pins runs to `http://127.0.0.1:8000`. Keep the unauthenticated
control center bound to loopback; it is not intended for public or multi-user deployment.

## Tests and CI

```bash
python -m pytest -q tests/test_authtrace_pipeline.py
python -m pytest -q tests/test_control_center.py
python -m pytest -q
```

CI validates the dashboard's inline JavaScript, starts the fixed demo API and runs the full
suite, then starts the vulnerable demo API on a separate loopback port and verifies that the
selected cross-user test produces a `SECURITY_REGRESSION` classification from actual HTTP
behavior. A passing unit/planner suite alone is not proof that an arbitrary API is secure.
