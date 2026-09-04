from cerberus.behavioral.scaling import RunningScaler


def test_running_scaler():
    scaler = RunningScaler()
    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    for v in values:
        scaler.update("test_metric", v)
    mean, std = scaler.get_mean_std("test_metric")
    assert mean == 30.0
    assert std > 0
