"""Policy-aware authorization tests for the local synthetic invoice API."""
from __future__ import annotations

import json
import os

import httpx

BASE_URL = os.getenv("AUTH_TRACE_BASE_URL", "http://127.0.0.1:8000")
EXPECTED_OUTCOMES = json.loads(os.getenv("AUTH_TRACE_EXPECTED_OUTCOMES", "{}"))
RULE_OWN = "INV-READ-OWN"
RULE_OTHER = "INV-READ-OTHER"
RULE_ADMIN = "INV-READ-ADMIN"


def request_invoice(token: str, invoice_id: str) -> httpx.Response:
    """Call the demo API without persisting credentials or complete response bodies."""
    with httpx.Client(base_url=BASE_URL, timeout=3.0, follow_redirects=False) as client:
        return client.get(
            f"/api/invoices/{invoice_id}",
            headers={"Authorization": f"Bearer {token}"},
        )


def _observe(response: httpx.Response, expected: str, *, cross_user: bool = False) -> dict:
    """Record a sanitized outcome and independently evaluate the security invariant."""
    observed_allow = response.status_code == 200
    owner_id = None
    if observed_allow:
        try:
            body = response.json()
            owner_id = body.get("owner_id") if isinstance(body, dict) else None
        except (ValueError, json.JSONDecodeError):
            owner_id = "malformed-response"
    observed = "allow" if observed_allow else "deny"
    invariant_violated = bool(cross_user and observed_allow and owner_id == "user-b")
    matches_policy = observed == expected and not (observed_allow and owner_id == "malformed-response")
    classification = (
        "SECURITY_REGRESSION" if invariant_violated
        else "POLICY_MISMATCH" if not matches_policy
        else "POLICY_MATCH"
    )
    evidence = {
        "expected": expected,
        "observed": observed,
        "http_status": response.status_code,
        "returned_owner_id": owner_id,
        "policy_match": matches_policy,
        "security_invariant_violated": invariant_violated,
        "classification": classification,
    }
    print("AUTHTRACE_EVIDENCE=" + json.dumps(evidence, sort_keys=True))
    return evidence


def _assert_policy(evidence: dict) -> None:
    assert evidence["policy_match"], (
        f"Policy mismatch: expected {evidence['expected']}, observed {evidence['observed']} "
        f"(HTTP {evidence['http_status']})"
    )
    assert not evidence["security_invariant_violated"], (
        "SECURITY_REGRESSION: non-owner received another user's invoice"
    )


def test_user_can_read_own_invoice():
    response = request_invoice("token-user-a", "inv-a")
    expected = EXPECTED_OUTCOMES.get(RULE_OWN, "allow")
    evidence = _observe(response, expected)
    assert response.status_code == 200, "Owner should be able to read their own invoice."
    assert evidence["returned_owner_id"] == "user-a"
    _assert_policy(evidence)


def test_admin_can_read_other_users_invoice():
    response = request_invoice("token-admin", "inv-b")
    expected = EXPECTED_OUTCOMES.get(RULE_ADMIN, "allow")
    evidence = _observe(response, expected)
    assert response.status_code == 200, "Administrator should be able to read the fixture invoice."
    assert evidence["returned_owner_id"] == "user-b"
    _assert_policy(evidence)


def test_cross_user_access_matches_declared_mode():
    response = request_invoice("token-user-a", "inv-b")
    expected = EXPECTED_OUTCOMES.get(RULE_OTHER, "deny")
    evidence = _observe(response, expected, cross_user=True)
    _assert_policy(evidence)
