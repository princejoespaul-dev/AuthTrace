import copy

from Authtrace_explainer.explainer import explain_check, explain_report


def sample_report():
    return {
        "tool": "AuthTrace starter",
        "overall": "VULNERABILITY_DETECTED",
        "checks": [
            {
                "test_id": "TC-CROSS-USER",
                "policy_id": "INV-READ-OTHER",
                "expected": "deny",
                "observed": "allow",
                "verdict": "FAIL",
                "http_status": 200,
                "evidence": {"returned_owner_matches_fixture": True, "token_redacted": True},
            },
            {"test_id": "TC-OWN-READ", "expected": "allow", "observed": "allow", "verdict": "PASS"},
            {"test_id": "TC-TIMEOUT", "expected": "deny", "observed": "unknown", "verdict": "ERROR"},
            {"test_id": "TC-UNKNOWN", "expected": "deny", "observed": "unexpected", "verdict": "INCONCLUSIVE"},
        ],
    }


def test_report_verdicts_and_overall_are_unchanged():
    report = sample_report()
    before = copy.deepcopy(report)
    result = explain_report(report)
    assert result["overall"] == before["overall"]
    assert [x["verdict"] for x in result["checks"]] == [x["verdict"] for x in before["checks"]]
    assert [x["verdict"] for x in report["checks"]] == [x["verdict"] for x in before["checks"]]
    assert all("explanation" in check for check in result["checks"])


def test_fail_deny_observed_allow_gets_cautious_explanation():
    result = explain_check({"test_id": "TC-CROSS-USER", "expected": "deny", "observed": "allow", "verdict": "FAIL"})
    assert "authorization-policy failure" in result["summary"]
    assert "hypothesis" in result["likely_cause"]
    assert result["source"] == "rules"


def test_pass_does_not_claim_entire_api_is_secure():
    result = explain_check({"test_id": "TC-OWN-READ", "expected": "allow", "observed": "allow", "verdict": "PASS"})
    assert result["verdict"] if "verdict" in result else True
    assert "does not prove the entire API is secure" in result["limitations"][0]


def test_error_not_claimed_to_be_vulnerability():
    result = explain_check({"test_id": "TC-TIMEOUT", "verdict": "ERROR", "observed": "unknown"})
    assert "not proof" in result["limitations"][0]


def test_malformed_report_rejected():
    try:
        explain_report({"overall": "INCONCLUSIVE"})
    except ValueError as exc:
        assert "checks list" in str(exc)
    else:
        raise AssertionError("Expected malformed report to be rejected")
