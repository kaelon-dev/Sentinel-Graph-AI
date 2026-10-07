"""Automated detection evaluation against ground truth specifications."""
import json
from pathlib import Path
from typing import Any, Dict, List
from sentinelgraph.pipeline import SentinelPipeline
from sentinelgraph.evaluation.metrics import compute_metrics, EvaluationMetrics


def evaluate_all() -> EvaluationMetrics:
    """Evaluate detection pipeline against all ground truth datasets."""
    gt_path = Path("data/generated/ground_truth.json")
    if not gt_path.exists():
        raise FileNotFoundError(f"Ground truth file not found at {gt_path}")

    ground_truth = json.loads(gt_path.read_text(encoding="utf-8"))
    dataset_evals: List[Dict[str, Any]] = []

    print("=" * 80)
    print("SENTINELGRAPH AI -- BENCHMARK EVALUATION ENGINE")
    print("=" * 80)

    for filename, gt in ground_truth.items():
        if filename.endswith(".json"):
            continue
        file_path = Path("data/generated") / filename
        if not file_path.exists():
            print(f"Skipping missing file: {filename}")
            continue

        use_ext = gt.get("requires_extended_window", False)
        # Execute pipeline
        result = SentinelPipeline.analyze_file(
            file_path=file_path,
            use_extended_window=use_ext
        )

        is_benign = gt.get("is_benign", False)
        expected_inc_count = gt.get("expected_incident_count", 0)
        expected_stages = set(gt.get("expected_stages", []))
        expected_sev_range = gt.get("expected_severity_range", [])
        max_allowed_sev = gt.get("max_severity_allowed", "CRITICAL")

        # Extract detected incidents
        incidents = result.incidents
        high_crit_incidents = [inc for inc in incidents if inc.severity in ("HIGH", "CRITICAL")]

        tp = 0
        fp = 0
        tn = 0
        fn = 0
        inc_tp = 0
        inc_fp = 0
        inc_fn = 0

        timeline_ordered = True
        for inc in incidents:
            ts_list = [item.timestamp for item in inc.evidence_items]
            if ts_list != sorted(ts_list):
                timeline_ordered = False

        if is_benign:
            # Benign dataset evaluation
            if high_crit_incidents:
                # False alarm on clean/benign data
                fp += len(high_crit_incidents)
                inc_fp += len(high_crit_incidents)
                passed = False
                status_msg = f"FAIL: {len(high_crit_incidents)} unexpected HIGH/CRITICAL incident(s)"
            else:
                tn += 1
                passed = True
                status_msg = "PASS: Zero HIGH/CRITICAL false alarms"
        else:
            # Attack dataset evaluation
            if not incidents:
                fn += 1
                inc_fn += 1
                passed = False
                status_msg = "FAIL: Attack was not detected (0 incidents)"
            else:
                main_inc = incidents[0]
                stage_match = True
                if expected_stages:
                    detected_stages = {s.stage_name for s in main_inc.attack_stages if s.status == "confirmed"}
                    stage_match = expected_stages.issubset(detected_stages) or len(detected_stages.intersection(expected_stages)) >= 1

                sev_match = True
                if expected_sev_range:
                    sev_match = main_inc.severity in expected_sev_range

                if sev_match and stage_match:
                    tp += 1
                    inc_tp += 1
                    passed = True
                    status_msg = f"PASS: Detected {main_inc.incident_id} ({main_inc.severity}, Risk: {main_inc.risk_score})"
                else:
                    fn += 1
                    inc_fn += 1
                    passed = False
                    status_msg = f"FAIL: Severity {main_inc.severity} or stages did not match expected ground truth"

        # Calculate stage coverage for attack datasets
        stage_cov = 1.0
        if not is_benign and incidents:
            confirmed_with_evd = sum(
                1 for s in incidents[0].attack_stages if s.status == "confirmed" and len(s.evidence_event_ids) > 0
            )
            total_confirmed = sum(1 for s in incidents[0].attack_stages if s.status == "confirmed")
            stage_cov = (confirmed_with_evd / total_confirmed) if total_confirmed > 0 else 1.0

        eval_entry = {
            "dataset": filename,
            "is_benign": is_benign,
            "events_analyzed": result.valid_event_count,
            "incidents_found": len(incidents),
            "top_severity": incidents[0].severity if incidents else "NONE",
            "top_risk": incidents[0].risk_score if incidents else 0.0,
            "passed": passed,
            "status": status_msg,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "inc_tp": inc_tp,
            "inc_fp": inc_fp,
            "inc_fn": inc_fn,
            "stage_coverage": round(stage_cov, 4),
            "timeline_ordered": timeline_ordered
        }
        dataset_evals.append(eval_entry)

        status_symbol = "[PASS]" if passed else "[FAIL]"
        print(f"{status_symbol:<6} {filename:<36} | {status_msg}")

    # Compute overall metrics
    metrics = compute_metrics(dataset_evals)

    # Persist evaluation reports
    out_dir = Path("outputs/sample_reports")
    out_dir.mkdir(parents=True, exist_ok=True)

    json_report_path = out_dir / "evaluation_report.json"
    json_report_path.write_text(metrics.model_dump_json(indent=2), encoding="utf-8")

    # Generate Markdown Report
    md_content = f"""# SentinelGraph AI — Detection Quality Evaluation Benchmark

**Datasets Evaluated:** {metrics.total_datasets_evaluated}  
**Precision:** **{metrics.precision * 100:.1f}%**  
**Recall:** **{metrics.recall * 100:.1f}%**  
**F1-Score:** **{metrics.f1_score * 100:.1f}%**  
**False Positive Rate:** **{metrics.false_positive_rate * 100:.2f}%**  
**Clean-Log False Positive Count:** **{metrics.clean_log_false_positive_count}**  
**Stage-Level Evidence Coverage:** **{metrics.stage_level_evidence_coverage * 100:.1f}%**  
**Timeline Ordering Accuracy:** **{metrics.timeline_ordering_accuracy * 100:.1f}%**  
**Entity-Link Accuracy:** **{metrics.entity_link_accuracy * 100:.1f}%**

---

## Detailed Dataset Results

| Dataset | Type | Events | Incidents | Top Severity | Risk | Stage Coverage | Status |
|---|---|---|---|---|---|---|---|
"""
    for d in dataset_evals:
        dtype = "Benign" if d["is_benign"] else "Attack"
        res_badge = "PASSED" if d["passed"] else "FAILED"
        md_content += f"| `{d['dataset']}` | {dtype} | {d['events_analyzed']} | {d['incidents_found']} | `{d['top_severity']}` | {d['top_risk']} | {int(d['stage_coverage']*100)}% | **{res_badge}** |\n"

    md_report_path = out_dir / "evaluation_report.md"
    md_report_path.write_text(md_content, encoding="utf-8")

    print("\n" + "=" * 80)
    print("BENCHMARK SUMMARY RESULTS:")
    print(f"Precision:                     {metrics.precision * 100:.1f}%")
    print(f"Recall:                        {metrics.recall * 100:.1f}%")
    print(f"F1-Score:                      {metrics.f1_score * 100:.1f}%")
    print(f"False Positive Rate:           {metrics.false_positive_rate * 100:.2f}%")
    print(f"Clean-Log False Positives:     {metrics.clean_log_false_positive_count}")
    print(f"Stage Evidence Coverage:       {metrics.stage_level_evidence_coverage * 100:.1f}%")
    print(f"Timeline Order Accuracy:       {metrics.timeline_ordering_accuracy * 100:.1f}%")
    print(f"Reports saved to {out_dir}")
    print("=" * 80)

    return metrics


if __name__ == "__main__":
    evaluate_all()
