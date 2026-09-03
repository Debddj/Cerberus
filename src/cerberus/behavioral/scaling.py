class RunningScaler:
    """Maintains running statistics (mean and standard deviation) for robust z-scaling."""
    
    def __init__(self):
        self.stats: dict[str, dict] = {} # key -> {"count": n, "mean": m, "M2": m2}

    def update(self, key: str, value: float):
        if key not in self.stats:
            self.stats[key] = {"count": 0, "mean": 0.0, "M2": 0.0}
            
        s = self.stats[key]
        s["count"] += 1
        delta = value - s["mean"]
        s["mean"] += delta / s["count"]
        delta2 = value - s["mean"]
        s["M2"] += delta * delta2

    def get_mean_std(self, key: str) -> tuple[float, float]:
        if key not in self.stats or self.stats[key]["count"] < 2:
            return 0.0, 1.0
        s = self.stats[key]
        variance = s["M2"] / (s["count"] - 1)
        return s["mean"], variance ** 0.5
