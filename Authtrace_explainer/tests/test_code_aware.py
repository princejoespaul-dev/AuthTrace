import copy

from Authtrace_explainer.explainer import collect_source_context, explain_report, _valid_code_analysis


def test_source_context_selects_relevant_code_and_ignores_secret_files(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("def read_invoice(invoice_id, current_user):\n    invoice = db.get(invoice_id)\n    return invoice\n", encoding="utf-8")
    secret = tmp_path / ".env"
    secret.write_text("API_KEY=should-not-be-read", encoding="utf-8")
    result = collect_source_context([str(tmp_path)], {"test_id": "TC-CROSS-USER", "expected": "deny", "observed": "allow"})
    assert result
    assert all(".env" not in item["path"] for item in result)
    assert "return invoice" in result[0]["source"]
    assert "should-not-be-read" not in repr(result)


def test_code_analysis_schema_is_strict():
    valid = {
        "likely_root_cause": "The route returns the invoice without an ownership guard.",
        "evidence_basis": ["app.py: read_invoice has no visible owner comparison"],
        "impact_if_confirmed": "A caller may read another user's invoice.",
        "recommended_fix": "Check invoice.owner_id against authenticated principal before returning it.",
        "verification_steps": ["Re-run cross-user deny test"],
        "confidence": "medium",
        "missing_information": ["Need to inspect the auth dependency and data model"],
        "source_references": ["app.py:read_invoice"],
    }
    assert _valid_code_analysis(valid)
    valid["confidence"] = "certain"
    assert not _valid_code_analysis(valid)


def test_source_paths_do_not_change_deterministic_report(tmp_path):
    source = tmp_path / "api.py"
    source.write_text("def read_invoice(invoice_id):\n    return invoice_id\n", encoding="utf-8")
    report = {"overall": "VULNERABILITY_DETECTED", "checks": [{"test_id": "TC-CROSS-USER", "expected": "deny", "observed": "allow", "verdict": "FAIL"}]}
    before = copy.deepcopy(report)
    result = explain_report(report, source_paths=[str(source)])
    assert result["overall"] == before["overall"]
    assert result["checks"][0]["verdict"] == "FAIL"
    assert report == before
    assert result["checks"][0]["explanation"]["code_analysis"]["status"] == "not_run"
