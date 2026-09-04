package cerberus.trifecta

default allow := true

# Deny if lethal trifecta is present without override
deny if {
    input.static_scan.lethal_trifecta == true
    not input.config.trifecta_override
}

reason := "Lethal trifecta detected: Agent possesses private data access, untrusted content exposure, and external egress" if {
    deny
}
