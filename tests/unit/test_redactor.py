from cerberus.proxy.redactor import SecretRedactor

def test_secret_redaction():
    text = "Authorization: Bearer sk-ant-api03-abcdefghijklmn9876543210"
    redacted, modified = SecretRedactor.redact_text(text)
    assert modified is True
    assert "[REDACTED_SECRET]" in redacted

    data = {"api_key": "secret12345678", "normal": "hello"}
    d_red, fields = SecretRedactor.redact_dict(data)
    assert "api_key" in fields
    assert d_red["api_key"] == "[REDACTED_SECRET]"
