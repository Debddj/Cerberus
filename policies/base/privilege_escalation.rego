package cerberus.privilege_escalation

default allow = true

# Deny if tool called is outside declared agent scope
deny {
    input.static_scan.out_of_scope == true
}

reason = "Privilege escalation: Tool invoked is outside agent's authorized capability scope" {
    deny
}
