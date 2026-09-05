from cerberus.proxy.models import RuleFeatures


class RuleBasedScorer:
    """Pre-baseline floor and lexical anomaly heuristic detector."""

    @staticmethod
    def score(features: RuleFeatures) -> tuple[float, list[str]]:
        factors = []
        score = 0.0

        # Check: Privilege escalation - admin/destructive tool invoked outside authorized scope
        if any(
            p in features.tool_name.lower()
            for p in ["admin", "drop_db", "drop_table", "drop_database", "sudo", "exec_root"]
        ):
            score = max(score, 0.90)
            factors.append(
                f"Privilege Escalation Anomaly: High-privilege administrative tool '{features.tool_name}' invoked outside authorized scope"
            )

        # Check: Read private data then immediate external egress to novel/external destination
        if len(features.prev_tools) >= 1:
            prev = features.prev_tools[-1].lower()
            curr = features.tool_name.lower()
            is_private_read = any(
                p in prev
                for p in [
                    "read_file",
                    "read_private",
                    "query_db",
                    "get_secret",
                    "database",
                    "credentials",
                ]
            )
            is_egress = any(e in curr for e in ["post", "webhook", "upload"]) or (
                "send" in curr and "email" not in curr and "reply" not in curr
            )
            if (
                is_private_read
                and is_egress
                and (
                    features.destination_novelty > 0.5
                    or features.tool_novelty > 0.5
                    or (
                        features.destination_domain
                        and not features.destination_domain.endswith((".internal", ".local"))
                    )
                )
            ):
                score = max(score, 0.95)
                factors.append(
                    f"Sequence Pattern: Private data access directly followed by external egress to '{features.destination_domain or 'external endpoint'}'"
                )

        # Check: Cold-start immediate novel egress
        if (
            features.sequence_position == 0
            and features.destination_novelty > 0.85
            and any(e in features.tool_name.lower() for e in ["post", "send", "webhook"])
        ):
            score = max(score, 0.85)
            factors.append(
                f"Cold-Start Anomaly: External egress tool '{features.tool_name}' invoked on initial call without baseline"
            )

        # Check: First-time novel destination with significant payload
        if features.destination_novelty > 0.85 and features.param_size_bytes > 5000:
            score = max(score, 0.80)
            factors.append(
                f"Novel Destination ({features.destination_domain}) with high payload ({features.param_size_bytes}B)"
            )

        # Check: Cumulative exfiltration drip - sustained egress burst across sequence
        if (
            features.sequence_position >= 10
            and any(e in features.tool_name.lower() for e in ["post", "send", "webhook"])
            and (features.destination_novelty > 0.5 or features.destination_domain)
        ):
            score = max(score, 0.75)
            factors.append(
                f"Cumulative Egress Drip: High sequence position ({features.sequence_position}) sustained egress burst to external destination"
            )

        # Check: High entropy parameter spike
        if features.param_entropy > 6.8:
            score = max(score, 0.65)
            factors.append(
                f"High parameter entropy ({features.param_entropy:.2f} bits) indicating possible encoded payload"
            )

        return score, factors
