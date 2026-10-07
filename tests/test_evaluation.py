"""Tests for evaluation metrics and ground truth compliance."""
from sentinelgraph.evaluation.metrics import compute_metrics, safe_div


def test_safe_div():
    assert safe_div(10, 2) == 5.0
    assert safe_div(0, 0, default=1.0) == 1.0
    assert safe_div(5, 0, default=0.0) == 0.0


def test_compute_metrics():
    evals = [
        {"tp": 1, "fp": 0, "tn": 0, "fn": 0, "is_benign": False, "inc_tp": 1, "inc_fp": 0, "inc_fn": 0, "stage_coverage": 1.0},
        {"tp": 0, "fp": 0, "tn": 1, "fn": 0, "is_benign": True, "inc_tp": 0, "inc_fp": 0, "inc_fn": 0, "stage_coverage": 1.0}
    ]
    m = compute_metrics(evals)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1_score == 1.0
    assert m.false_positive_rate == 0.0
    assert m.clean_log_false_positive_count == 0
