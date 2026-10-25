# Public Sample Evaluation (generated 2026-10-25T09:34:46.926749+00:00)

Comparison source: `dataset/sample_output.csv`; predictions are not trained or copied from sample labels.

| Metric | Measured |
|---|---|
| Cases compared | 32 |
| Case-level status accuracy | 100.00% |
| Step-level precision | 100.00% |
| Step-level recall | 100.00% |
| Step-level F1 | 100.00% |
| Field-level accuracy (aligned steps) | 100.00% |
| Full-sequence accuracy | 100.00% |

## Additional Team Cases

- **A: non-deletion instruction.** Data-access request with explicit "do not delete" must be `NOT_APPLICABLE`, `[]`. Test: `test_engine.py::test_non_deletion`. 
- **B: preservation plus redaction.** A tombstone retains its stable user reference but direct identifiers require `REDACT_RECORD`; security retention requires `VERIFY_RECORD_PRESENT`. Test: `test_engine.py::test_tombstone_and_retention`.
- **C: resurrection prevention.** Active sync and unblocked backup must be disabled/blocked before deleting a still-present profile. Test: `test_engine.py::test_resurrection_path`.
- **D: temporal boundary.** Evidence captured later than `audit_at` must not justify earlier status. Test: `test_engine.py::test_temporal_boundary`.

## Failures and corrections

Corrections built into code: do not rely on reported workflow success; prohibit stale future evidence; bind historical identifiers; separate retention from deletion; deterministic ordering and conservative unknown-state handling.

Current mismatches (first 25):

No mismatches on the public sample.
