# Ghost Data Still Exists: Evidential Deletion Agent

A local-first, read-only deletion-audit system that builds a temporal evidence graph, resolves historic identifiers, interprets heterogeneous records, applies the **provided** `deletion_rules.csv`, and writes deterministic HackerRank predictions. Evidence and policy remain authoritative; an optional local LLM supports ambiguous multilingual request intent only. The algorithm does not train on, or hardcode, sample labels, case IDs, or oracle outputs.

## Install inside the official repository

Clone `https://github.com/interviewstreet/hackerrank-orchestrate-october26` (if you haven't already). Replace the starter `code/` directory with this `code/` folder, **without copying the dataset into the final zip**. Run the commands from the repository root.

Python 3.10+ is required. Standard library handles CSV, JSON, SQL, identity graph, sorting and policy rules. For optional PDFs and screenshots:

```shell
python -m pip install pymupdf pillow pytesseract
```

For screenshots, also install the **Tesseract OCR engine** separately so `pytesseract` can find it. If OCR is unavailable, the engine skips the image, never hallucinates its content; this reduces expected accuracy and should be flagged in an evaluation review.

## Run

```shell
python code/main.py --sample
python code/evaluation/evaluate.py --expected dataset/sample_output.csv --predicted sample_prediction.csv
python code/evaluation/test_engine.py
python code/main.py
python code/evaluation/validate_output.py --dataset dataset --output output.csv
```

Predictions are written to `output.csv` at repository root. The main entry point requires the *complete* official `dataset/` directory and raises if the 518-row final count is not met. The `code/evaluation/usage_report.md` is updated on the full run with actual model calls, token counts, SHA-256 and costs. The sample evaluator updates the evaluation report with exact measured status, step, field, and sequence metrics. Do not submit the evaluation placeholders without running the full corpus.

## Optional local AI

Set `OLLAMA_MODEL` to the exact model already available on your local Ollama server, for example `gemma3:4b`. It makes structured, temperature-zero requests only when deterministic authorization detection did not identify an unambiguous deletion instruction. Default: no outbound model calls. If a model is unavailable, it falls back to conservative offline classification.

PowerShell:

```powershell
$env:OLLAMA_MODEL='gemma3:4b'
python code/main.py
```

No API credentials are required. Recorded input/output tokens use Ollama's own `prompt_eval_count` and `eval_count`. Costs are reported as $0.00 API spend for local inference, excluding electricity/hardware. Local inputs may contain fictional identity information from the supplied dataset. Treat any switch to an external API as a separate privacy review.

## Architecture

1. **Authorization gate:** request_text, including explicit negative instructions and major supported languages. Workflow `reported_status` is never used to decide authorization.
2. **Identity graph:** stable user ID plus current email/name/phone/hash, old/new values from every identity audit event, and exact token matching.
3. **Evidence adapters:** SQL snapshots executed in isolated in-memory SQLite, recursive JSON snapshots, structured/trace-correlated log readbacks, pipe-delimited handover reports, and optional PDF text / image OCR. Every observation has source evidence ID and observation timestamp.
4. **Temporal state reduction:** enforce `audit_at` and manifest capture time, group evidence by system/resource, prioritize the latest observed state. A same-timestamp live replica outweighs a conflicting absent copy.
5. **Policy engine:** apply the configured category action (DELETE / REDACT / ANONYMIZE / RETAIN), treat backups as restore risk and live connectors as resurrection risk. Tombstones preserve stable reference but not direct fields.
6. **Safe plan:** findings → disable flows and block restores → deletions/redactions/anonymization → verification. Stable ordering follows the challenge's operation priority then system/resource. Remediation is a proposal, never executed.
7. **Evaluation:** canonical public sample comparison and original synthetic edge cases. The validator checks JSON, allowed states, order, evidence provenance, and coverage.

## Limits / safety

An absence claim is not inferred from a failed deletion workflow. The system operates only on supplied participant files and does not delete or alter any records. Empty/inaccessible/unparsed evidence is not proof of a completed deletion. Some images need OCR; some identity conflicts need human review. The model does not invent evidence IDs. The result is an audit recommendation, not a legally conclusive certified deletion receipt.

The challenge allows evidence IDs referencing manifest `file_id`, `system_activity.activity_id`, or `user_audit_log.audit_id`; the implementation primarily cites actual evidence files because they're preferred over uncorroborated activity outcomes. Human review should precede any real-world remediation. Avoid posting input records or private identifiers to third-party model APIs.

## Submission

From the official repository root, after the full run and validation:

```powershell
Compress-Archive -Path code -DestinationPath code.zip -Force
```

Upload the three artifacts separately: `code.zip`, root-level `output.csv`, and the root-level `log.txt` from an AGENTS.md-aware coding-agent session. Do not include `dataset/`, private keys, `__pycache__`, `.venv`, logs other than the required transcript, or nested archives in the code zip.
