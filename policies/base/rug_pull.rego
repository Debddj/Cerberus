package cerberus.rug_pull

default allow := true

# Deny if static scanner detected schema drift and mode is enforce
deny if {
    input.static_scan.schema_drift == true
    input.config.schema_pin_mode == "enforce"
}

reason := "Schema drift detected: Tool description hash mismatch (potential rug pull attack)" if {
    deny
}
