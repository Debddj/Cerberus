from hypothesis import given, settings
from hypothesis import strategies as st

from cerberus.proxy.redactor import SecretRedactor

# Strategy for arbitrary JSON-like dictionaries
json_primitives = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text()
)
json_values = st.recursive(
    json_primitives,
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(st.text(max_size=20), children, max_size=5)
    ),
    max_leaves=15,
)


@given(st.dictionaries(st.text(max_size=20), json_values, max_size=5))
@settings(max_examples=50, deadline=None)
def test_fuzz_secret_redactor_never_crashes(payload):
    """Ensure arbitrary nested structures never crash redactor."""
    redacted, modified_fields = SecretRedactor.redact_dict(payload)
    assert isinstance(redacted, dict)
    assert isinstance(modified_fields, list)


@given(st.text())
@settings(max_examples=50, deadline=None)
def test_fuzz_secret_redactor_text_idempotence(text):
    """Redacting twice produces identical result."""
    first_pass, _ = SecretRedactor.redact_text(text)
    second_pass, _ = SecretRedactor.redact_text(first_pass)
    assert first_pass == second_pass


@given(
    st.text(min_size=1, max_size=50),
    st.sampled_from(
        [
            "sk-proj-abcdefghijklmnopqrstuvwxyz12345678901234567890",
            "ghp_123456789012345678901234567890123456",
            "AKIAIOSFODNN7EXAMPLE",
        ]
    ),
)
@settings(max_examples=30, deadline=None)
def test_fuzz_secret_redactor_catches_injected_secrets(prefix, secret):
    """Injected high-entropy tokens must never survive redaction."""
    text = f"{prefix} token: {secret} more text"
    redacted, modified = SecretRedactor.redact_text(text)
    assert modified is True
    assert secret not in redacted
    assert "[REDACTED_SECRET]" in redacted
