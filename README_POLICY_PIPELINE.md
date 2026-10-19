# AuthTrace policy-change pipeline

This extension adds deterministic policy JSON comparison, rule-to-test mapping, risk-ranked
selection, optional selected-test execution, sanitized JSON evidence, a static HTML dashboard,
and CI checks. Policy analysis is authoritative; any AI explanation is advisory only.

## Files

- `policy.json`: baseline policy.
- `policy.v2.json`: illustrative proposed policy. It intentionally changes
  `INV-READ-OTHER.expected` from `deny` to `allow` to demonstrate a high-risk authorization change.
- `test_mapping.json`: human-reviewed policy rule IDs to pytest node IDs.
- `authtrace_pipeline.py`: validation, diff, planner, optional runner, JSON evidence, dashboard.
- `.github/workflows/authtrace-policy-check.yml`: offline planner/unit-test job.

## Plan without contacting an API

```bash
python authtrace_pipeline.py --fail-on-unmapped
```

This creates `reports/latest_pipeline.json` and `reports/dashboard.html`. A plan is not
evidence of execution: the report uses `PLANNED` when no target tests ran. Changed rules
without mappings are listed under `coverage_gaps.unmapped_rules`; CI can fail on these with
`--fail-on-unmapped`. The pipeline also checks that mapped test files exist before execution.

## Risk model and selection

Rules are compared by stable rule ID. Changes are classified as `added`, `removed`, or
`modified`; modified rules include their changed fields. The transparent heuristic assigns
higher scores to deny-to-allow changes and changes to actor/action/resource/condition. Scores
are review priorities, not probabilities. Selected pytest node IDs are deduplicated while
preserving risk priority. Each plan item includes a short risk explanation and the mapping
rationale.

A policy change with no mapping is a coverage gap, not a successful security validation.
An invalid mapping, malformed policy, or nonexistent test file is treated as a configuration
error. Keep mapping IDs aligned with real pytest node IDs, for example
`test_authorization.py::test_cross_user_access_matches_declared_mode`.

## Execute only selected tests

Start the synthetic API locally first, then run:

```bash
python authtrace_pipeline.py --execute --fail-on-unmapped
```

The runner defaults to `http://127.0.0.1:8000`, validates that mapped test files exist, and
executes each selected pytest node ID using an argument list rather than a shell command.
Each selected test has a timeout. The JSON report records status, return code, duration, and
whether tests actually ran; it does not persist pytest output, credentials, or response bodies.
An empty selection is an execution error rather than a passing run. Missing pytest node IDs,
timeouts, and collection/runner errors are represented as `ERROR`, distinct from assertion
failures (`FAIL`).

The runner blocks non-loopback targets unless `AUTOTRACE_ALLOW_STAGING=1` is set. This
override is only for explicitly authorized staging systems. Do not weaken the guard to make a
test pass. The included demo is synthetic and read-only.

For the intentionally vulnerable demo, set `AUTH_TRACE_EXPECT_VULNERABLE=1` only when
running the suite against a server deliberately started in vulnerable mode. A test pass in
that mode means the expected seeded flaw was observed; it is not a security pass.

## Tests and CI

Run the planner tests:

```bash
python -m pytest -q tests/test_authtrace_pipeline.py
```

The suite covers policy diffs, risk direction, deterministic/deduplicated selection, malformed
policy/mapping input, nonexistent and path-traversing test references, loopback restrictions,
and HTML escaping. The GitHub Actions workflow runs these unit tests and creates a plan without
contacting a target API, then uploads the JSON report and dashboard.

A green planner CI job does not prove the application is secure or that target API tests ran.
Review policy changes and mappings manually, and treat unmapped rules as explicit coverage gaps.
