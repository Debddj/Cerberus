from cerberus.behavioral.scaling import RunningScaler


def test_running_scaler():
    scaler = RunningScaler()
    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    for v in values:
        scaler.update("test_metric", v)
    mean, std = scaler.get_mean_std("test_metric")
    assert mean == 30.0
    assert std > 0


def test_robust_scaler_median_mad():
    scaler = RunningScaler()
    normal_values = [10.0, 11.0, 12.0, 10.0, 11.0]
    for v in normal_values:
        scaler.update("feat", v)

    median_before, scale_before = scaler.get_robust_stats("feat")
    assert median_before == 11.0
    assert abs(scale_before - 1.4826) < 1e-3

    # Add massive adversarial outlier
    scaler.update("feat", 1_000_000.0)

    median_after, scale_after = scaler.get_robust_stats("feat")
    # Median of [10, 10, 11, 11, 12, 1000000] is 11.0, MAD is 1.0
    assert median_after == 11.0
    assert abs(scale_after - 1.4826) < 1e-3

    # get_mean_std also returns robust stats
    r_med, r_scale = scaler.get_mean_std("feat")
    assert r_med == median_after
    assert r_scale == scale_after


def test_robust_scaler_zero_mad_fallback():
    scaler = RunningScaler()
    for _ in range(5):
        scaler.update("constant_feat", 5.0)

    median, scale = scaler.get_robust_stats("constant_feat")
    assert median == 5.0
    # MAD is 0.0, fallback scale is 1.0
    assert scale == 1.0

    # Ensure no division by zero when calculating z-score
    z_score = (5.0 - median) / scale
    assert z_score == 0.0
