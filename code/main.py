"""Ghost Data Still Exists: evidence-grounded deletion audit.

Run: python code/main.py [--dataset dataset] [--output output.csv]
This program never modifies source records or executes remediations.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
from ghost import EvidenceEngine, audit_case


def load_rows(path: Path):
    with path.open('r', encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--dataset', default=None)
    parser.add_argument('--output', default=None)
    parser.add_argument('--sample', action='store_true')
    args=parser.parse_args()
    root=Path(__file__).resolve().parent.parent
    dataset=Path(args.dataset) if args.dataset else root/'dataset'
    dataset=dataset.resolve()
    requests=load_rows(dataset/('sample_deletion_requests.csv' if args.sample else 'deletion_requests.csv'))
    output=Path(args.output).resolve() if args.output else root/('sample_prediction.csv' if args.sample else 'output.csv')
    sample_file=dataset/'sample_deletion_requests.csv'
    eval_file=dataset/'deletion_requests.csv'
    all_cases=[]
    if sample_file.exists():all_cases.extend(load_rows(sample_file))
    if eval_file.exists():all_cases.extend(load_rows(eval_file))
    engine=EvidenceEngine(dataset)
    engine.assign_links(all_cases if all_cases else requests)
    results=[]
    for case in sorted(requests,key=lambda r:r['case_id']):
        result=audit_case(case,engine)
        results.append({'case_id':case['case_id'],'deletion_status':result['deletion_status'],
                        'steps_json':json.dumps(result['steps'],ensure_ascii=False,separators=(',',':'))})
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['case_id','deletion_status','steps_json']);writer.writeheader();writer.writerows(results)
    print(f'Wrote {len(results)} cases to {output}')
    print('Statuses:',{s:sum(x['deletion_status']==s for x in results) for s in ['COMPLETE','INCOMPLETE','NOT_APPLICABLE']})
    manifest=hashlib.sha256(output.read_bytes()).hexdigest()
    print('Output sha256:',manifest)
    if not args.sample:
        model=engine.intent_model
        calls=model.calls if model else 0
        inp=model.input_tokens if model else 0
        out=model.output_tokens if model else 0
        desc=model.model if model and model.model else 'None (offline rules and evidence graph)'
        usage=(f'# Final Full-Dataset Token and Cost Report\n\n'
            f'- Generated output SHA-256: `{manifest}`\n'
            f'- Requests processed: {len(results)}\n'
            f'- Provider: {"Ollama (local)" if calls else "none"}\n'
            f'- Model: {desc}\n'
            f'- Model calls: {calls}\n'
            f'- Input tokens: {inp}\n'
            f'- Output tokens: {out}\n'
            f'- Total tokens: {inp+out}\n'
            f'- Average tokens per request: {(inp+out)/len(results):.2f}\n'
            f'- Estimated total API cost: $0.00 (self-hosted Ollama or no API)\n'
            f'- Estimated cost per request: $0.00 (excludes local compute)\n'
            f'- Model call failures: {model.failures if model else 0}\n\n'
            'Deterministic evidence extraction, identifier matching, SQLite queries, '
            'policy enforcement, sorting and CSV writing use no billable LLM tokens. '
            'Optional local LLM calls only resolve ambiguous deletion intent.\n')
        report=root/'code'/'evaluation'/'usage_report.md'
        report.parent.mkdir(parents=True,exist_ok=True)
        report.write_text(usage,encoding='utf-8')
    if not args.sample and len(results)!=518:
        raise ValueError(f'Expected 518 data rows, got {len(results)}')

if __name__=='__main__': main()
