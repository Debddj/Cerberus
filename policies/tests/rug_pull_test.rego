package cerberus.rug_pull

test_allow_when_no_drift {
    allow with input as {
        "static_scan": {"schema_drift": false},
        "config": {"schema_pin_mode": "enforce"}
    }
}

test_deny_when_drift_in_enforce_mode {
    deny with input as {
        "static_scan": {"schema_drift": true},
        "config": {"schema_pin_mode": "enforce"}
    }
}
