from cerberus.scanner.trifecta import LethalTrifectaDetector

def test_lethal_trifecta_detection():
    safe_tools = ["read_file", "write_file", "search_code"]
    is_trifecta, _ = LethalTrifectaDetector.check_session_tools(safe_tools)
    assert not is_trifecta
    
    dangerous_tools = ["read_file", "fetch_inbox", "http_post"]
    is_trifecta, breakdown = LethalTrifectaDetector.check_session_tools(dangerous_tools)
    assert is_trifecta
    assert len(breakdown["private_data"]) == 1
    assert len(breakdown["untrusted_content"]) == 1
    assert len(breakdown["external_egress"]) == 1
