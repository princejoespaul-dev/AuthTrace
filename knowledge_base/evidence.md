# Evidence and verdict discipline

The expected authorization decision must come from an explicit, reviewed policy. A deterministic engine compares that expected decision with the observed response and any relevant state change. An LLM should not be the final pass/fail judge.

A report should identify the test ID, policy rule, actor label, object fixture, action, expected decision, observed behavior, status code, and sanitized evidence. Never include bearer tokens, session cookies, or unnecessary private response bodies.

Use INCONCLUSIVE or human review required when policy is missing, ambiguous, or evidence is insufficient. A clean result means only that the tested cases passed; it is not proof that the whole API is secure.
