package cerberus.behavioral

default decision = "allow"

decision = "quarantine" {
    input.risk_score >= 0.9
}

decision = "block" {
    input.risk_score >= 0.7
    input.risk_score < 0.9
}

decision = "flag" {
    input.risk_score >= 0.4
    input.risk_score < 0.7
}
