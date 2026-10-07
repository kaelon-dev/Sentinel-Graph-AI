# SentinelGraph AI — Troubleshooting & Common Issues Guide

### 1. Windows Console Encoding Error (`cp1252` UnicodeEncodeError)
- **Symptom:** Scripts crash with `UnicodeEncodeError: 'charmap' codec can't encode character '\u2713'`.
- **Cause:** Default Windows PowerShell console code page (`cp1252`) cannot render certain Unicode symbols.
- **Resolution:** All SentinelGraph AI scripts use safe ASCII markers (`[PASS]`, `[FAIL]`, `--`). Alternatively, force UTF-8 in PowerShell by running:
  ```powershell
  $OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
  ```

### 2. ModuleNotFoundError: No module named 'sentinelgraph'
- **Symptom:** Running python scripts yields `ModuleNotFoundError: No module named 'sentinelgraph'`.
- **Cause:** Package is not installed in editable development mode in the virtual environment.
- **Resolution:** Run:
  ```powershell
  & ".\.venv\Scripts\python.exe" -m pip install -e . --no-deps
  ```

### 3. Starlette / TestClient Deprecation Warning in Pytest
- **Symptom:** Warning emitted during test run: `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated`.
- **Cause:** Informational warning from newer FastAPI/Starlette versions.
- **Impact:** Harmless; tests pass completely. Configured in `pyproject.toml` with `--tb=short`.

### 4. Slow-Burn Attack Appears as Two Incidents
- **Symptom:** Multi-day attack sequence does not merge under default analysis.
- **Cause:** Default correlation window is strictly 60 minutes to prevent alert contamination.
- **Resolution:** Pass `--extended-window` via CLI or set `use_extended_window=True` in API/Dashboard. This activates the 72-hour window with temporal proximity decay.
