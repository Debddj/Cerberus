package cerberus.behavioral

default decision := "allow"

decision := "quarantine" if {
    input.risk_score >= 0.9
}

decision := "block" if {
    input.risk_score >= 0.7
    input.risk_score < 0.9
}

decision := "flag" if {
    input.risk_score >= 0.4
    input.risk_score < 0.7
}
