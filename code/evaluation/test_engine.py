"""Synthetic regression fixtures. These are original fictional data, NOT golden test labels."""
import csv
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ghost import EvidenceEngine,audit_case,classify_intent


def putcsv(path,rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)


def fixture(events):
    temp=TemporaryDirectory();p=Path(temp.name)
    putcsv(p/'deletion_rules.csv',[
        dict(rule_id='r1',data_category='USER_PROFILE',condition='Always',required_action='DELETE'),
        dict(rule_id='r2',data_category='ACCOUNT_TOMBSTONE',condition='stable ref',required_action='REDACT'),
        dict(rule_id='r3',data_category='SECURITY_AUDIT_LOG',condition='retention',required_action='RETAIN')])
    putcsv(p/'user_identities.csv',[dict(user_id='user_999',name='Synthetic Person',email='new@example.test',phone='+1 555 0011',email_hash='abcdabcd',updated_at='2026-01-01T00:00:00Z')])
    putcsv(p/'user_audit_log.csv',[dict(audit_id='audit_999',user_id='user_999',event_time='2025-01-01T00:00:00Z',field_name='email',old_value='old@example.test',new_value='new@example.test')])
    putcsv(p/'system_activity.csv',[dict(activity_id='activity_999',event_time='2026-01-01T00:00:00Z',event_type='LINK_RESOURCE_IDENTITY',source_system='a',target_system='b',resource_id='account_999',reported_result='SUCCESS',details='user_999')])
    putcsv(p/'evidence_files.csv',[dict(file_id='evidence_999',file_path='evidence/records/fixture.json',origin='regression',captured_at='2026-01-15T12:00:00Z')])
    dest=p/'evidence/records/fixture.json';dest.parent.mkdir(parents=True)
    dest.write_text(json.dumps({'exported_at':'2026-01-15T12:00:00Z','records':events},indent=2))
    return temp,p


def case(**overrides):
    d=dict(case_id='case_test',email='old@example.test',audit_at='2026-01-20T12:00:00Z',
           requested_at='2026-01-10T12:00:00Z',request_text='Please delete my account and data.')
    d.update(overrides);return d


def test_non_deletion():
    assert classify_intent('Please export my data; do not delete my account.') is False
    assert classify_intent('Please permanently erase my profile') is True


def test_tombstone_and_retention():
    events=[dict(resource_id='tombstone_999',system='account_service',record_type='ACCOUNT_TOMBSTONE',
                 subject_reference='user_999',email='old@example.test',result='IDENTIFIABLE',recorded_at='2026-01-15T12:00:00Z'),
            dict(resource_id='audit_record_999',system='security_service',record_type='SECURITY_AUDIT_LOG',
                 subject_reference='user_999',result='FOUND',recorded_at='2026-01-15T12:00:00Z')]
    temp,p=fixture(events)
    try:
        s=audit_case(case(),EvidenceEngine(p))
        ops=[v['operation'] for v in s['steps']]
        assert s['deletion_status']=='INCOMPLETE'
        assert 'REDACT_RECORD' in ops and 'VERIFY_RECORD_PRESENT' in ops
        assert 'DELETE_RECORD' not in ops
    finally:temp.cleanup()


def test_resurrection_path():
    events=[dict(resource_id='account_999',system='account_service',record_type='USER_PROFILE',
                 email='new@example.test',result='FOUND',recorded_at='2026-01-15T12:00:00Z'),
            dict(resource_id='data_flow_999',system='integration_service',record_type='DATA_FLOW',
                 subject_reference='user_999',enabled=True,recorded_at='2026-01-15T12:00:00Z'),
            dict(resource_id='backup_999',system='backup_service',record_type='BACKUP_ARCHIVE',
                 subject_reference='user_999',restore_allowed=True,recorded_at='2026-01-15T12:00:00Z')]
    temp,p=fixture(events)
    try:
        s=audit_case(case(),EvidenceEngine(p))
        rem=[x['operation'] for x in s['steps'] if x['phase']=='REMEDIATION']
        assert rem==['DISABLE_DATA_FLOW','BLOCK_RESTORE','DELETE_RECORD'],rem
    finally:temp.cleanup()


def test_temporal_boundary():
    events=[dict(resource_id='account_999',system='account_service',record_type='USER_PROFILE',
                 email='old@example.test',result='FOUND',recorded_at='2026-01-15T12:00:00Z')]
    temp,p=fixture(events)
    try:
        e=EvidenceEngine(p)
        assert e.observed('user_999','2026-01-14T12:00:00Z')==[]
        assert len(e.observed('user_999','2026-01-20T12:00:00Z'))==1
    finally:temp.cleanup()


def test_historical_identity():
    events=[dict(resource_id='account_999',system='account_service',record_type='USER_PROFILE',
                 email='old@example.test',result='FOUND',recorded_at='2026-01-15T12:00:00Z')]
    temp,p=fixture(events)
    try:
        e=EvidenceEngine(p)
        assert e.subject_for('old@example.test')=='user_999'
        assert audit_case(case(),e)['deletion_status']=='INCOMPLETE'
    finally:temp.cleanup()


def test_policy_supremacy_over_worker_delete():
    events=[dict(resource_id='support_999',system='support_platform',record_type='SUPPORT_MESSAGE',
                 email='old@example.test',result='IDENTIFIABLE',recorded_at='2026-01-15T12:00:00Z')]
    temp,p=fixture(events)
    putcsv(p/'deletion_rules.csv',[
        dict(rule_id='r1',data_category='USER_PROFILE',condition='Always',required_action='DELETE'),
        dict(rule_id='r5',data_category='SUPPORT_MESSAGE',condition='Shared context',required_action='REDACT')])
    putcsv(p/'system_activity.csv',[
        dict(activity_id='act_worker',event_time='2026-01-16T12:00:00Z',event_type='DELETE_RECORD',
             source_system='deletion_worker',target_system='support_platform',resource_id='support_999',
             reported_result='SUCCESS',details='user_999')])
    try:
        e=EvidenceEngine(p)
        s=audit_case(case(),e)
        rem=[x['operation'] for x in s['steps'] if x['phase']=='REMEDIATION']
        assert 'REDACT_RECORD' in rem, f"Expected REDACT_RECORD from policy, got {rem}"
        assert 'DELETE_RECORD' not in rem, "Worker DELETE must not override policy REDACT"
    finally:temp.cleanup()


def test_temporal_noninterference():
    events=[dict(resource_id='account_999',system='account_service',record_type='USER_PROFILE',
                 email='old@example.test',result='FOUND',recorded_at='2026-01-25T12:00:00Z')]
    temp,p=fixture([])
    putcsv(p/'evidence_files.csv',[
        dict(file_id='evidence_future',file_path='evidence/records/future.json',origin='regression',captured_at='2026-01-25T12:00:00Z')])
    dest=p/'evidence/records/future.json';dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps({'exported_at':'2026-01-25T12:00:00Z','records':events},indent=2))
    try:
        e=EvidenceEngine(p)
        obs=e.observed('user_999','2026-01-20T12:00:00Z')
        assert obs==[], f"Future evidence must be quarantined, got {obs}"
    finally:temp.cleanup()


def test_worker_success_never_proves_absence():
    temp,p=fixture([])
    putcsv(p/'system_activity.csv',[
        dict(activity_id='act_worker',event_time='2026-01-16T12:00:00Z',event_type='DELETE_RECORD',
             source_system='deletion_worker',target_system='account_service',resource_id='account_999',
             reported_result='SUCCESS',details='user_999')])
    try:
        e=EvidenceEngine(p)
        s=audit_case(case(),e)
        assert s['deletion_status']=='INCOMPLETE'
    finally:temp.cleanup()


if __name__=='__main__':
    for t in (test_non_deletion,test_tombstone_and_retention,test_resurrection_path,
              test_temporal_boundary,test_historical_identity,
              test_policy_supremacy_over_worker_delete,test_temporal_noninterference,
              test_worker_success_never_proves_absence):
        t();print('PASS',t.__name__)
