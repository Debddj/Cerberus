import numpy as np


def calculate_tpr(tp: int, fn: int) -> float:
    return float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0


def calculate_fpr(fp: int, tn: int) -> float:
    return float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0


def calculate_latency_percentiles(latencies_ms: list[float]) -> dict[str, float]:
    if not latencies_ms:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
    arr = np.array(latencies_ms)
    return {
        "p50": round(float(np.percentile(arr, 50)), 2),
        "p95": round(float(np.percentile(arr, 95)), 2),
        "p99": round(float(np.percentile(arr, 99)), 2),
    }
