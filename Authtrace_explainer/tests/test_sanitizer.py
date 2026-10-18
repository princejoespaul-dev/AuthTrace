from Authtrace_explainer.sanitizer import redact


def test_bearer_token_redacted():
    assert "my-secret-token" not in redact("Authorization: Bearer my-secret-token")


def test_password_redacted():
    assert "dont-log-me" not in redact("password=dont-log-me")


def test_output_is_bounded():
    assert len(redact("x" * 5000, limit=100)) == 100


def test_nested_secrets_are_omitted_before_model_request():
    from Authtrace_explainer.explainer import _sanitize_value

    value = _sanitize_value({
        "evidence": {"note": "Authorization: Bearer nested-token", "password": "hidden"}
    })
    assert "nested-token" not in str(value)
    assert value["evidence"]["password"] == "[OMITTED]"
