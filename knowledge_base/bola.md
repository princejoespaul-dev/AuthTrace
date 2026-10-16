# Broken Object Level Authorization (BOLA)

BOLA occurs when an API fails to verify that the authenticated actor is permitted to access the specific object requested. Authentication alone does not grant access to every object. For example, User A may be allowed to read Invoice A but must not read Invoice B owned by User B unless an explicit policy grants that access.

For an authorization test, use synthetic fixtures and two distinct test identities. Compare the observed behavior with a human-reviewed policy. A status code alone is not always sufficient evidence: some applications use HTTP 404 as a denial response to avoid disclosing object existence. Where appropriate, verify response semantics and relevant state changes.

Source note: Curated starter summary based on the AuthTrace project assessment and OWASP API Security Top 10 guidance. Replace this note with the official source URL, publication/version, and section before presenting it as a formal citation.
