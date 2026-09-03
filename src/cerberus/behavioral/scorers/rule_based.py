from cerberus.proxy.models import RuleFeatures

class RuleBasedScorer:
    """Pre-baseline floor and lexical anomaly heuristic detector."""
    
    @staticmethod
    def score(features: RuleFeatures) -> tuple[float, list[str]]:
        factors = []
        score = 0.0
        
        # Check: Read private data then immediate egress
        if len(features.prev_tools) >= 1:
            prev = features.prev_tools[-1].lower()
            curr = features.tool_name.lower()
            if any(p in prev for p in ["read", "query", "fetch"]) and any(e in curr for e in ["post", "send", "webhook"]):
                score = max(score, 0.95)
                factors.append("Sequence Pattern: Private data access directly followed by external egress")
                
        # Check: Cold-start immediate novel egress
        if features.sequence_position == 0 and features.destination_novelty > 0.85 and any(e in features.tool_name.lower() for e in ["post", "send", "webhook"]):
            score = max(score, 0.85)
            factors.append(f"Cold-Start Anomaly: External egress tool '{features.tool_name}' invoked on initial call without baseline")

        # Check: First-time novel destination with significant payload
        if features.destination_novelty > 0.85 and features.param_size_bytes > 5000:
            score = max(score, 0.80)
            factors.append(f"Novel Destination ({features.destination_domain}) with high payload ({features.param_size_bytes}B)")
            
        # Check: High entropy parameter spike
        if features.param_entropy > 6.8:
            score = max(score, 0.65)
            factors.append(f"High parameter entropy ({features.param_entropy:.2f} bits) indicating possible encoded payload")
            
        return score, factors
