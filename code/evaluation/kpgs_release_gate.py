"""KPGS/GSMB read-only release audit for HackerRank Ghost Data Still Exists.

Usage (from challenge repository root):
    python code/evaluation/kpgs_release_gate.py
    python code/evaluation/kpgs_release_gate.py --deep

Never modifies output.csv, source records, or the evaluation corpus.
This is a review gate, not an inference-time dependency or official judge.
"""
from __future__ import annotations

import argparse
import ast
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

PHASE = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATIONS = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT", 0),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT", 1),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE", 2),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE", 3),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED", 0),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED", 1),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT", 2),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED", 3),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED", 4),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT", 0),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT", 1),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED", 2),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED", 3),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED", 4),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED", 5),
}
REMEDIATION_ACTION = {
    "DELETE_RECORD": "DELETE", "REDACT_RECORD": "REDACT",
    "ANONYMIZE_RECORD": "ANONYMIZE",
}


def csvrows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def audit(root: Path, deep: bool = False) -> dict:
    ds = root / "dataset"
    source = root / "code" / "ghost.py"
    output = root / "output.csv"
    blockers: list[str] = []
    warnings: list[str] = []
    facts: dict = {}

    requirements = [ds / "deletion_requests.csv", ds / "evidence_files.csv",
                    ds / "system_activity.csv", ds / "user_audit_log.csv",
                    ds / "deletion_rules.csv", output, source]
    for p in requirements:
        if not p.exists():
            blockers.append(f"Required file unavailable: {p.relative_to(root)}")
    if blockers:
        return dict(facts=facts, blockers=blockers, warnings=warnings)

    requests = csvrows(ds / "deletion_requests.csv")
    predictions = csvrows(output)
    request_index = {r["case_id"]: r for r in requests}
    evidence_cutoff: dict[str, str] = {}
    for fn, eid, timefield in [
        ("evidence_files.csv", "file_id", "captured_at"),
        ("system_activity.csv", "activity_id", "event_time"),
        ("user_audit_log.csv", "audit_id", "event_time"),
    ]:
        for e in csvrows(ds / fn):
            evidence_cutoff[e[eid]] = e[timefield]

    counts = Counter()
    zero_incomplete: list[str] = []
    all_steps = 0
    requested_ids = sorted(request_index)
    predicted_ids = [p["case_id"] for p in predictions]
    if predicted_ids != requested_ids:
        blockers.append("Output case IDs are not the exact sorted request ID set")

    step_cache: list[tuple[dict, dict]] = []
    for row in predictions:
        cid = row["case_id"]
        request = request_index.get(cid)
        if request is None:
            blockers.append(f"Extraneous prediction: {cid}")
            continue
        status = row["deletion_status"]
        counts[status] += 1
        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            blockers.append(f"{cid}: invalid deletion status {status!r}")
        try:
            steps = json.loads(row["steps_json"])
        except (ValueError, TypeError):
            blockers.append(f"{cid}: invalid steps_json")
            continue
        if not isinstance(steps, list):
            blockers.append(f"{cid}: steps_json must be array")
            continue
        if status == "NOT_APPLICABLE" and steps:
            blockers.append(f"{cid}: non-deletion authorizes no steps")
        if status == "COMPLETE" and (not steps or any(s.get("phase") != "VERIFICATION" for s in steps)):
            blockers.append(f"{cid}: COMPLETE lacks verification-only proof")
        if status == "INCOMPLETE" and not steps:
            zero_incomplete.append(cid)
        sort_keys = []
        all_steps += len(steps)
        for index, step in enumerate(steps, 1):
            if set(step) != {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}:
                blockers.append(f"{cid}: malformed step fields at position {index}")
                continue
            if step["step_no"] != index:
                blockers.append(f"{cid}: nonsequential step number at {index}")
            op = step["operation"]
            spec = OPERATIONS.get(op)
            if not spec:
                blockers.append(f"{cid}: unsupported operation {op}")
                continue
            if (step["phase"], step["state"]) != spec[:2]:
                blockers.append(f"{cid}: phase/state incompatible with {op}")
            sort_keys.append((PHASE.get(step["phase"], 99), spec[2], step["system_id"], step["resource_id"]))
            ref = step["evidence_id"]
            if ref:
                bound = evidence_cutoff.get(ref)
                if not bound:
                    blockers.append(f"{cid}: unknown evidence ID {ref}")
                elif bound > request["audit_at"]:
                    blockers.append(f"{cid}: evidence {ref} created after audit_at")
            if (step["phase"] == "FINDING" or (status == "COMPLETE" and step["phase"] == "VERIFICATION")) and not ref:
                blockers.append(f"{cid}: finding/current verification lacks source evidence")
            if (step["phase"] == "REMEDIATION" or (status == "INCOMPLETE" and step["phase"] == "VERIFICATION")) and ref:
                blockers.append(f"{cid}: future work wrongly cites existing evidence")
            step_cache.append((row, step))
        if sort_keys != sorted(sort_keys):
            blockers.append(f"{cid}: step ordering differs from contract")

    if zero_incomplete:
        warnings.append(f"{len(zero_incomplete)} INCOMPLETE cases contain no actionable or verification steps: {', '.join(zero_incomplete[:25])}")

    # AST examines only the active inference code, not the sample evaluation module.
    source_text = source.read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    named_exceptions = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and re.fullmatch(
            r"(?:case|user|account|audit_record)_\d+", n.value):
            named_exceptions.append((n.lineno, n.value))
    if named_exceptions:
        blockers.append("Runtime contains sample-style literal IDs: " + ", ".join(
            f"ghost.py:{lineno}={value}" for lineno, value in named_exceptions[:30]))
    if "^user_0*([1-9]|10)$" in source_text:
        warnings.append("Runtime contains special user_01–10 account-number shortcut; justify or generalize")
    if "engine.policy_event.get(e.resource)" in source_text:
        warnings.append("Runtime passes worker-event action into policy disposition; verify rules cannot be overridden")
    if "retained_later(" in source_text:
        warnings.append("retained_later() examines post-audit observations; prove no future-state leakage")

    facts = {
        "request_rows": len(requests), "prediction_rows": len(predictions),
        "status_counts": dict(counts), "steps": all_steps,
        "incomplete_without_steps": len(zero_incomplete),
        "literal_ids_in_runtime": named_exceptions,
    }
    if deep:
        sys.path.insert(0, str(root / "code"))
        from ghost import EvidenceEngine  # Existing engine; read-only dataset parsing
        engine = EvidenceEngine(ds)
        rules = {r["data_category"]: r["required_action"] for r in csvrows(ds / "deletion_rules.csv")}
        cutoff = {r["case_id"]: r["audit_at"] for r in requests}
        mismatches = []
        for row, step in step_cache:
            action = REMEDIATION_ACTION.get(step["operation"])
            if not action:
                continue
            cid = row["case_id"]
            resource = step["resource_id"]
            kinds = {e.kind for e in engine.evidence
                     if e.resource == resource and e.timestamp <= cutoff[cid]
                     and (not e.evidence_id or evidence_cutoff.get(e.evidence_id, "") <= cutoff[cid])}
            if not kinds:
                continue
            actions = {rules[k] for k in kinds if k in rules}
            # Multiple categories can legitimately exist, e.g. a support-message attachment.
            if actions and action not in actions:
                mismatches.append((cid, resource, step["operation"], ",".join(sorted(kinds)), ",".join(sorted(actions))))
        facts["policy_action_conflicts_needing_review"] = len(mismatches)
        facts["policy_action_conflict_examples"] = mismatches[:20]
        if mismatches:
            blockers.append(f"{len(mismatches)} remediation action(s) conflict with observed category rules; examples: "
                            + "; ".join(f"{cid}/{rid} {op} vs {actions} ({kind})"
                                        for cid, rid, op, kind, actions in mismatches[:12]))
        import importlib.util
        import shutil
        media = [m for m in csvrows(ds / "evidence_files.csv") if Path(m["file_path"]).suffix.lower() in (".png", ".jpg", ".jpeg", ".webp", ".pdf")]
        facts["media_manifest_files"] = len(media)
        if any(Path(m["file_path"]).suffix.lower() in (".png", ".jpg", ".jpeg", ".webp") for m in media) and not shutil.which("tesseract"):
            warnings.append("Tesseract executable not on PATH; screenshot evidence may be silently skipped")
        if any(Path(m["file_path"]).suffix.lower() == ".pdf" for m in media) and importlib.util.find_spec("fitz") is None:
            warnings.append("PyMuPDF missing; PDF evidence may be silently skipped")
    return dict(facts=facts, blockers=blockers, warnings=warnings)


def main() -> int:
    p = argparse.ArgumentParser(description="KPGS read-only deletion audit release gate")
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument("--deep", action="store_true", help="Also reconcile predicted actions against source evidence and policy")
    args = p.parse_args()
    report = audit(args.root.resolve(), args.deep)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 2 if report["blockers"] else 0


if __name__ == "__main__":
    sys.exit(main())
