# AuthTrace policy-change pipeline

This extension adds policy JSON comparison, rule-to-test mapping, risk-ranked selection,
selective pytest execution, sanitized evidence reporting, a static HTML dashboard, and CI checks.

## Files

- \`policy.json\`: baseline policy.
- \`policy.v2.json\`: illustrative proposed policy. It intentionally changes
  \`INV-READ-OTHER.expected\` from \`deny\` to \`allow\` to demonstrate high-risk detection.
- \`test_mapping.json\`: human-reviewed policy rule ID to pytest node ID mapping.
- \`authtrace_pipeline.py\`: diff, planner, optional runner, JSON evidence, and dashboard.
- \`.github/workflows/authtrace-policy-check.yml\`: offline CI planner/unit-test job.

## Plan without contacting an API

\`\`\`bash
python authtrace_pipeline.py
\`\`\`

This creates \`reports/latest_pipeline.json\` and \`reports/dashboard.html\`. A plan is not
evidence of execution; the report marks the run as \`PLANNED\`.

## Execute only selected tests

Start the synthetic API locally first, then run:

\`\`\`bash
python authtrace_pipeline.py --execute
\`\`\`

The runner defaults to \`http://127.0.0.1:8000\`, executes only mapped pytest node IDs, and
does not save pytest output, credentials, or response bodies in the report. The selected
tests still use the project's \`AUTH_TRACE_EXPECT_VULNERABLE\` setting; set it only when
intentionally demonstrating the seeded vulnerable mode.

The runner blocks non-loopback targets unless \`AUTHTRACE_ALLOW_STAGING=1\` is set. Use that
override only for explicitly authorized staging systems. This project is designed for
synthetic, read-only authorization checks.

## CI gate

The workflow runs deterministic unit tests and generates a policy impact plan without
contacting a target API. \`--fail-on-unmapped\` causes CI to fail if a changed rule has no
test mapping. The CI artifact includes JSON evidence and the HTML dashboard.

## Risk model and limitations

Risk scores are an explainable heuristic, not a probability. A deny-to-allow change scores
high because it can broaden access. Review the diff and mapping manually. A green CI job means
the planner and unit tests passed; it does not prove the application is secure or that target
API tests ran.
