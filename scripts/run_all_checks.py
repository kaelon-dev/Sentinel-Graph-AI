"""Master automated check orchestrator running all tests, smoke tests, and benchmarks."""
import subprocess
import sys
from pathlib import Path


def run_step(step_name: str, cmd: list) -> None:
    print(f"\n>>> [RUNNING] {step_name}...")
    proc = subprocess.run(cmd, stdout=sys.stdout, stderr=sys.stderr)
    if proc.returncode != 0:
        print(f"\n[FAIL] Step '{step_name}' failed with exit code {proc.returncode}.")
        sys.exit(proc.returncode)
    print(f">>> [PASS] {step_name} completed successfully.\n")


def main():
    python_exe = sys.executable
    print("=" * 80)
    print("SENTINELGRAPH AI -- MASTER VERIFICATION SUITE")
    print(f"Python: {python_exe}")
    print("=" * 80)

    # 1. Dataset Generation
    run_step("1. Synthetic Data Generation", [python_exe, "scripts/generate_sample_data.py"])

    # 2. Pytest Test Suite
    run_step("2. Unit & Integration Test Suite", [python_exe, "-m", "pytest", "-q"])

    # 3. End-to-end Smoke Test
    run_step("3. End-to-End Pipeline Smoke Test", [python_exe, "scripts/smoke_test.py"])

    # 4. Benchmark Detection Evaluation
    run_step("4. Detection Quality Benchmark Evaluation", [python_exe, "scripts/evaluate_detection.py"])

    print("=" * 80)
    print("ALL SENTINELGRAPH AI CHECKS PASSED PERFECTLY!")
    print("=" * 80)


if __name__ == "__main__":
    main()
