from hypothesis import given, settings
from hypothesis import strategies as st

from cerberus.scanner.trifecta import LethalTrifectaDetector


@given(st.lists(st.text(max_size=30), max_size=20))
@settings(max_examples=50, deadline=None)
def test_fuzz_trifecta_never_crashes(tool_sequence):
    """Arbitrary tool call sequences must evaluate without throwing."""
    is_trifecta, breakdown = LethalTrifectaDetector.check_session_tools(tool_sequence)
    assert isinstance(is_trifecta, bool)
    assert isinstance(breakdown, dict)


@given(
    st.sampled_from(list(LethalTrifectaDetector.PRIVATE_DATA_KEYWORDS)),
    st.sampled_from(list(LethalTrifectaDetector.UNTRUSTED_CONTENT_KEYWORDS)),
    st.sampled_from(list(LethalTrifectaDetector.EXTERNAL_EGRESS_KEYWORDS)),
    st.lists(st.text(max_size=20), max_size=10),
)
@settings(max_examples=50, deadline=None)
def test_fuzz_trifecta_guaranteed_detection(t_priv, t_untrust, t_egress, noise):
    """Any session containing all 3 keyword matches in any order must be detected."""
    import random

    combined = [t_priv, t_untrust, t_egress] + noise
    random.shuffle(combined)

    is_trifecta, breakdown = LethalTrifectaDetector.check_session_tools(combined)
    assert is_trifecta is True
    assert breakdown["private_data"] is not None
    assert breakdown["untrusted_content"] is not None
    assert breakdown["external_egress"] is not None
