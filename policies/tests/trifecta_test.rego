package cerberus.trifecta

test_allow_safe_agent if {
    allow with input as {
        "static_scan": {"lethal_trifecta": false},
        "config": {"trifecta_override": false}
    }
}

test_deny_trifecta if {
    deny with input as {
        "static_scan": {"lethal_trifecta": true},
        "config": {"trifecta_override": false}
    }
}

test_allow_trifecta_override if {
    not deny with input as {
        "static_scan": {"lethal_trifecta": true},
        "config": {"trifecta_override": true}
    }
}
