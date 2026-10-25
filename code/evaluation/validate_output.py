"""Validate submission rows, ordered actions and grounded evidence citations."""
import argparse
import csv
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ghost import ORDER,PHASE_ORDER

STATES={
 'REPORT_REMAINING_RECORD':'PRESENT','REPORT_EXPOSED_PII':'PRESENT',
 'REPORT_ACTIVE_DATA_FLOW':'ACTIVE','REPORT_RESTORE_RISK':'ACTIVE',
 'DISABLE_DATA_FLOW':'DISABLED','BLOCK_RESTORE':'BLOCKED','DELETE_RECORD':'ABSENT',
 'REDACT_RECORD':'REDACTED','ANONYMIZE_RECORD':'ANONYMIZED',
 'VERIFY_RECORD_ABSENT':'ABSENT','VERIFY_RECORD_PRESENT':'PRESENT',
 'VERIFY_RECORD_REDACTED':'REDACTED','VERIFY_RECORD_ANONYMIZED':'ANONYMIZED',
 'VERIFY_DATA_FLOW_DISABLED':'DISABLED','VERIFY_RESTORE_BLOCKED':'BLOCKED'}


def read(path):
    with Path(path).open(encoding='utf-8-sig',newline='') as f:
        r=csv.DictReader(f)
        return r.fieldnames,list(r)


def validate(dataset,output,expected_count=518):
    req_head,req=read(dataset/'deletion_requests.csv')
    head,rows=read(output)
    problems=[]
    if head!=['case_id','deletion_status','steps_json']:problems.append('Invalid CSV header')
    ids=[r['case_id'] for r in rows]
    req_ids=sorted(r['case_id'] for r in req)
    if len(rows)!=expected_count:problems.append(f'Expected {expected_count} rows, got {len(rows)}')
    if ids!=req_ids:problems.append('Missing, duplicate or unsorted case IDs')
    manifest={r['file_id'] for r in read(dataset/'evidence_files.csv')[1]}
    manifest|={r['activity_id'] for r in read(dataset/'system_activity.csv')[1]}
    manifest|={r['audit_id'] for r in read(dataset/'user_audit_log.csv')[1]}
    fields={'step_no','phase','system_id','resource_id','operation','state','evidence_id'}
    for row in rows:
        cid=row['case_id'];status=row['deletion_status']
        if status not in ('COMPLETE','INCOMPLETE','NOT_APPLICABLE'):problems.append(f'{cid}: invalid status')
        try:steps=json.loads(row['steps_json'])
        except ValueError:problems.append(f'{cid}: invalid JSON');continue
        if not isinstance(steps,list):problems.append(f'{cid}: steps not array');continue
        if status=='NOT_APPLICABLE' and steps:problems.append(f'{cid}: unauthorized steps')
        if status=='COMPLETE' and any(x.get('phase')!='VERIFICATION' for x in steps):problems.append(f'{cid}: complete with non-verification')
        order=[]
        for i,s in enumerate(steps,1):
            if set(s)!=fields:problems.append(f'{cid}: step {i} wrong fields')
            if s.get('step_no')!=i:problems.append(f'{cid}: step {i} numbering')
            if s.get('phase') not in PHASE_ORDER:problems.append(f'{cid}: step {i} phase');continue
            op=s.get('operation')
            if op not in STATES or s.get('state')!=STATES.get(op):problems.append(f'{cid}: step {i} operation/state')
            order.append((PHASE_ORDER[s['phase']],ORDER.get(op,99),s.get('system_id',''),s.get('resource_id','')))
            ev=s.get('evidence_id','')
            if s['phase']=='FINDING' or (status=='COMPLETE' and s['phase']=='VERIFICATION'):
                if ev not in manifest:problems.append(f'{cid}: step {i} invalid evidence {ev}')
            else:
                if ev!='':problems.append(f'{cid}: step {i} future evidence must be empty')
        if order!=sorted(order):problems.append(f'{cid}: unsorted steps')
    return problems

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--dataset',default='dataset');p.add_argument('--output',default='output.csv')
    a=p.parse_args();problems=validate(Path(a.dataset),Path(a.output))
    for prob in problems[:100]:print('ERROR:',prob)
    print(f'Errors: {len(problems)}')
    if problems:sys.exit(1)
    print('PASS: exact schema, case coverage, step ordering, states, and evidence-ID validity')
