def calculate_tpr(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) > 0 else 0.0


def calculate_fpr(fp: int, tn: int) -> float:
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0
