from collections import defaultdict, deque

import numpy as np


class RunningScaler:
    """Maintains running statistics using sliding window Median and Median Absolute Deviation (MAD)
    for robust z-scaling with a 50% breakdown point against adversarial outliers."""

    def __init__(self, window_size: int = 500):
        self.window_size = window_size
        self.buffers: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=window_size))
        self.stats: dict[
            str, dict
        ] = {}  # key -> {"count": n, "mean": m, "M2": m2} for Welford backward-compatibility

    def update(self, key: str, value: float):
        self.buffers[key].append(float(value))

        if key not in self.stats:
            self.stats[key] = {"count": 0, "mean": 0.0, "M2": 0.0}

        s = self.stats[key]
        s["count"] += 1
        delta = float(value) - s["mean"]
        s["mean"] += delta / s["count"]
        delta2 = float(value) - s["mean"]
        s["M2"] += delta * delta2

    def get_robust_stats(self, key: str) -> tuple[float, float]:
        """Calculates Median and Median Absolute Deviation (MAD) with 1.4826 consistency scale factor.

        If scale < 1e-4, safely falls back to scale = 1.0 (zero-MAD fallback).
        """
        buf = self.buffers.get(key)
        if not buf or len(buf) < 2:
            return 0.0, 1.0
        arr = np.array(buf, dtype=float)
        median = float(np.median(arr))
        mad = float(np.median(np.abs(arr - median)))
        scale = 1.4826 * mad
        if scale < 1e-4:
            scale = 1.0
        return median, scale

    def get_mean_std(self, key: str) -> tuple[float, float]:
        """Backward-compatible interface: returns robust statistics (median, scale)."""
        return self.get_robust_stats(key)
