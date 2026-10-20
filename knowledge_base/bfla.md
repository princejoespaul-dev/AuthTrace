# Broken Function Level Authorization (BFLA)

BFLA occurs when a caller can invoke a function or endpoint that their role is not permitted to use. For example, a standard user may be able to invoke an administrator-only operation. The test must define the intended roles and allowed/denied actions before making a request.

Use a positive control as well as a negative control: the administrator should retain legitimate access while the standard user is denied. Do not infer the intended policy from a status code alone.

Source note: Curated starter summary based on the AuthTrace project assessment and OWASP API Security Top 10 guidance. Replace this note with the official source URL, publication/version, and section before presenting it as a formal citation.
