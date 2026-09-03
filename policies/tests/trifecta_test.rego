package cerberus.trifecta

test_allow_safe_agent {
    allow with input as {
        "static_scan": {"lethal_trifecta": false},
        "config": {"trifecta_override": false}
    }
}

test_deny_trifecta {
    deny with input as {
        "static_scan": {"lethal_trifecta": true},
        "config": {"trifecta_override": false}
    }
}

test_allow_trifecta_override {
    not deny with input as {
        "static_scan": {"lethal_trifecta": true},
        "config": {"trifecta_override": true}
    }
}
