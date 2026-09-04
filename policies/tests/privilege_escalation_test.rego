package cerberus.privilege_escalation

test_allow_in_scope if {
    allow with input as {
        "static_scan": {"out_of_scope": false}
    }
}

test_deny_out_of_scope if {
    deny with input as {
        "static_scan": {"out_of_scope": true}
    }
}
