import copy
import json

from Authtrace_explainer import explainer


def test_openai_provider_missing_key_keeps_deterministic_verdict(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    report = {"overall": "VULNERABILITY_DETECTED", "checks": [{"test_id": "TC-CROSS-USER", "expected": "deny", "observed": "allow", "verdict": "FAIL"}]}
    result = explainer.explain_report(report, use_openai=True)
    assert result["overall"] == report["overall"]
    assert result["checks"][0]["verdict"] == "FAIL"
    assert result["checks"][0]["explanation"]["ai_status"]["status"] == "missing_api_key"


def test_openai_code_analysis_is_advisory_and_does_not_change_verdict(monkeypatch, tmp_path):
    source = tmp_path / "routes.py"
    source.write_text("def read_invoice(invoice, current_user):\n    return invoice\n", encoding="utf-8")
    analysis = {
        "likely_root_cause": "The shown route returns an invoice without a visible ownership check.",
        "evidence_basis": ["routes.py:2 returns invoice directly."],
        "impact_if_confirmed": "A caller could read another user's invoice if no guard exists elsewhere.",
        "recommended_fix": "Check invoice ownership against the authenticated principal before returning it.",
        "verification_steps": ["Re-run the cross-user denial test."],
        "confidence": "medium",
        "missing_information": ["Any authorization dependency or middleware not shown."],
        "source_references": ["routes.py:1-2"],
    }
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    monkeypatch.setattr(explainer, "_openai_code_analysis", lambda *args, **kwargs: copy.deepcopy(analysis))
    report = {"overall": "VULNERABILITY_DETECTED", "checks": [{"test_id": "TC-CROSS-USER", "expected": "deny", "observed": "allow", "verdict": "FAIL"}]}
    before = copy.deepcopy(report)
    result = explainer.explain_report(report, use_openai=True, source_paths=[str(source)])
    assert result["overall"] == before["overall"]
    assert result["checks"][0]["verdict"] == before["checks"][0]["verdict"]
    assert result["checks"][0]["explanation"]["code_analysis"]["confidence"] == "medium"
    assert report == before


def test_openai_response_parser_uses_json_chat_response(monkeypatch):
    class FakeResponse:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self):
            return json.dumps({"choices": [{"message": {"content": '{"summary":"ok"}'}}]}).encode()
    captured = {}
    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["headers"] = request.headers
        captured["payload"] = json.loads(request.data.decode())
        return FakeResponse()
    monkeypatch.setattr(explainer.urllib.request, "urlopen", fake_urlopen)
    parsed = explainer._openai_json("prompt", "gpt-4.1-mini", "dummy")
    assert parsed == {"summary": "ok"}
    assert captured["url"] == "https://api.openai.com/v1/chat/completions"
    assert captured["payload"]["response_format"] == {"type": "json_object"}
    assert captured["headers"]["Authorization"] == "Bearer dummy"


def test_model_payload_sanitizer_omits_secret_fields():
    safe = explainer._sanitize_value({
        "api_key": "should-not-be-sent",
        "accessToken": "also-secret",
        "evidence": {"returned_owner_matches_fixture": True},
    })
    assert safe["api_key"] == "[OMITTED]"
    assert safe["accessToken"] == "[OMITTED]"
    assert safe["evidence"]["returned_owner_matches_fixture"] is True
