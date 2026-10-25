"""Public sample evaluator with exact, step, field and sequence accuracy.
Usage: python code/evaluation/evaluate.py --expected dataset/sample_output.csv --predicted sample_prediction.csv
This file NEVER provides predictions or reads private truth.
"""
import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

FIELDS=['phase','operation','system_id','resource_id','state','evidence_id','step_no']
IDENTITY=['phase','operation','system_id','resource_id']


def read(path):
    with Path(path).open(encoding='utf-8-sig',newline='') as f:
        return {row['case_id']:{'status':row['deletion_status'], 'steps':json.loads(row['steps_json'])} for row in csv.DictReader(f)}


def metrics(expected,predicted):
    ids=sorted(expected)
    matches=sum(expected[k]['status']==predicted.get(k,{}).get('status') for k in ids)
    seq=sum(expected[k]==predicted.get(k) for k in ids)
    tp=fp=fn=match_fields=field_total=0
    issues=[]
    for key in ids:
        actual=expected[key]['steps'];got=predicted.get(key,{}).get('steps',[])
        a=Counter(tuple(str(step.get(f,'')) for f in FIELDS) for step in actual)
        g=Counter(tuple(str(step.get(f,'')) for f in FIELDS) for step in got)
        hit=sum((a&g).values()); tp+=hit; fp+=sum((g-a).values());fn+=sum((a-g).values())
        aidx={tuple(str(s.get(f,'')) for f in IDENTITY):s for s in actual}
        gidx={tuple(str(s.get(f,'')) for f in IDENTITY):s for s in got}
        for k,item in aidx.items():
            if k in gidx:
                match_fields+=sum(item.get(f)==gidx[k].get(f) for f in FIELDS)
                field_total+=len(FIELDS)
        if expected[key]!=predicted.get(key):
            issues.append((key,expected[key]['status'],predicted.get(key,{}).get('status','MISSING'),len(actual),len(got)))
    precision=tp/(tp+fp) if tp+fp else 1.
    recall=tp/(tp+fn) if tp+fn else 1.
    return {'cases':len(ids),'submitted':len(predicted),'status_accuracy':matches/len(ids) if ids else 0,
            'full_sequence_accuracy':seq/len(ids) if ids else 0, 'step_precision':precision,'step_recall':recall,
            'step_f1':2*precision*recall/(precision+recall) if precision+recall else 0,
            'field_accuracy_among_aligned_steps':match_fields/field_total if field_total else 0,
            'tp':tp,'fp':fp,'fn':fn,'failures':issues}


def report(result,destination):
    now=datetime.now(timezone.utc).isoformat()
    out=[f'# Public Sample Evaluation (generated {now})','',
         'Comparison source: `dataset/sample_output.csv`; predictions are not trained or copied from sample labels.','',
         '| Metric | Measured |','|---|---|',
         f"| Cases compared | {result['cases']} |",
         f"| Case-level status accuracy | {result['status_accuracy']:.2%} |",
         f"| Step-level precision | {result['step_precision']:.2%} |",
         f"| Step-level recall | {result['step_recall']:.2%} |",
         f"| Step-level F1 | {result['step_f1']:.2%} |",
         f"| Field-level accuracy (aligned steps) | {result['field_accuracy_among_aligned_steps']:.2%} |",
         f"| Full-sequence accuracy | {result['full_sequence_accuracy']:.2%} |",
         '', '## Additional Team Cases','',
         '- **A: non-deletion instruction.** Data-access request with explicit "do not delete" must be `NOT_APPLICABLE`, `[]`. Test: `test_engine.py::test_non_deletion`. ',
         '- **B: preservation plus redaction.** A tombstone retains its stable user reference but direct identifiers require `REDACT_RECORD`; security retention requires `VERIFY_RECORD_PRESENT`. Test: `test_engine.py::test_tombstone_and_retention`.',
         '- **C: resurrection prevention.** Active sync and unblocked backup must be disabled/blocked before deleting a still-present profile. Test: `test_engine.py::test_resurrection_path`.',
         '- **D: temporal boundary.** Evidence captured later than `audit_at` must not justify earlier status. Test: `test_engine.py::test_temporal_boundary`.',
         '', '## Failures and corrections','',
         'Corrections built into code: do not rely on reported workflow success; prohibit stale future evidence; bind historical identifiers; separate retention from deletion; deterministic ordering and conservative unknown-state handling.','',
         'Current mismatches (first 25):','']
    if result['failures']:
        out+=['| Case | Expected status | Predicted | Expected steps | Predicted steps |','|---|---|---|---:|---:|']
        out += [f'| {cid} | {a} | {b} | {x} | {y} |' for cid,a,b,x,y in result['failures'][:25]]
    else:out+=['No mismatches on the public sample.']
    Path(destination).write_text('\n'.join(out)+'\n',encoding='utf-8')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--expected',required=True);p.add_argument('--predicted',required=True)
    p.add_argument('--report',default='code/evaluation/evaluation_report.md');args=p.parse_args()
    data=metrics(read(args.expected),read(args.predicted))
    report(data,args.report)
    print(json.dumps({k:v for k,v in data.items() if k!='failures'},indent=2))
    print('First failures:',data['failures'][:5]);print('Report:',args.report)
