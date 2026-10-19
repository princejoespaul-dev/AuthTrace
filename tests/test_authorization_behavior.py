"""Unit tests for classifying observed API responses without a live server."""
import httpx

from test_authorization import _observe


def test_server_error_is_not_mistaken_for_authorization_denial():
    evidence = _observe(httpx.Response(500, json={"detail": "server error"}), "deny")
    assert evidence["observed"] == "error"
    assert evidence["classification"] == "API_ERROR"
    assert not evidence["policy_match"]


def test_malformed_success_response_is_not_a_policy_pass():
    evidence = _observe(httpx.Response(200, content=b"not-json"), "allow")
    assert evidence["classification"] == "MALFORMED_RESPONSE"
    assert not evidence["policy_match"]


def test_foreign_invoice_identifier_violates_invariant_even_without_owner_field():
    evidence = _observe(httpx.Response(200, json={"id": "inv-b"}), "allow", cross_user=True)
    assert evidence["security_invariant_violated"] is True
    assert evidence["classification"] == "SECURITY_REGRESSION"


def test_standard_denial_status_matches_deny_policy():
    evidence = _observe(httpx.Response(404, json={"detail": "Not found"}), "deny", cross_user=True)
    assert evidence["observed"] == "deny"
    assert evidence["classification"] == "POLICY_MATCH"
    assert evidence["security_invariant_violated"] is False
