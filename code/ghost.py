"""Temporal, policy-driven, multimodal evidence graph for deletion investigations.

Uses only dataset/ participant files. Reported workflow outcomes are not ground truth.
Stable internal references remain permitted for retained security records and tombstones.
"""
from __future__ import annotations
import csv
import hashlib
import json
import re
import shlex
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ORDER={
 'REPORT_REMAINING_RECORD':0,'REPORT_EXPOSED_PII':1,'REPORT_ACTIVE_DATA_FLOW':2,'REPORT_RESTORE_RISK':3,
 'DISABLE_DATA_FLOW':0,'BLOCK_RESTORE':1,'DELETE_RECORD':2,'REDACT_RECORD':3,'ANONYMIZE_RECORD':4,
 'VERIFY_RECORD_ABSENT':0,'VERIFY_RECORD_PRESENT':1,'VERIFY_RECORD_REDACTED':2,'VERIFY_RECORD_ANONYMIZED':3,
 'VERIFY_DATA_FLOW_DISABLED':4,'VERIFY_RESTORE_BLOCKED':5}
PHASE_ORDER={'FINDING':0,'REMEDIATION':1,'VERIFICATION':2}
DIRECT_KEYS={'email','name','full_name','phone','email_hash','requester_email','requester_name','requester_phone',
             'customer_email','owner_email','owner_phone','contact_email','display_name','message_text','matched_value'}
CATEGORIES={'account_':'USER_PROFILE','tombstone_':'ACCOUNT_TOMBSTONE','search_':'SEARCH_INDEX_ENTRY',
 'support_':'SUPPORT_MESSAGE','analytics_':'ANALYTICS_PROFILE','telemetry_':'PRODUCT_TELEMETRY',
 'export_':'USER_EXPORT','marketing_':'MARKETING_PROFILE','audit_record_':'SECURITY_AUDIT_LOG',
 'backup_':'BACKUP_ARCHIVE','data_flow_':'DATA_FLOW','cache_':'CACHE_ENTRY','identifier_':'SECONDARY_IDENTIFIER',
 'delivery_':'EMAIL_DELIVERY_LOG'}
SYSTEM_CATEGORIES={'account_service':'USER_PROFILE','search_service':'SEARCH_INDEX_ENTRY',
 'analytics_platform':'ANALYTICS_PROFILE','support_platform':'SUPPORT_MESSAGE','security_service':'SECURITY_AUDIT_LOG',
 'backup_service':'BACKUP_ARCHIVE','integration_service':'DATA_FLOW','export_service':'USER_EXPORT',
 'marketing_service':'MARKETING_PROFILE'}
SYSTEM_BY_PREFIX={'account_':'account_service','search_':'search_service','support_':'support_platform',
  'analytics_':'analytics_platform','telemetry_':'analytics_platform','export_':'export_service','data_flow_':'integration_service',
  'backup_':'backup_service','audit_record_':'security_service','tombstone_':'identity_service','marketing_':'marketing_platform'}
ACTION_BY_EVENT={'DELETE_RECORD':'DELETE','REDACT_RECORD':'REDACT','ANONYMIZE_RECORD':'ANONYMIZE'}
ABSENT={'NOT_FOUND','ABSENT','DELETED','MISSING','ZERO_RESULTS'}
PRESENT={'PRESENT','FOUND','ACTIVE','IDENTIFIABLE','EXISTS','UNREDACTED'}


def records(path):
    if not path.exists(): return []
    with path.open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))


def norm(x): return str(x or '').strip().casefold()

def utc(x): return str(x or '')[:20]

def iso_min(*values): return min((v for v in values if v),default='')

def normalize_state(value):
    v=norm(value)
    if v in ('false','off','stopped','disabled','inactive'):return 'DISABLED'
    if v in ('true','on','enabled','running'):return 'ACTIVE'
    if v in ('blocked','deny','denied'):return 'BLOCKED'
    if v in ('unblocked','allowed'):return 'ACTIVE'
    if v in ('hit','hits','present','found','exists','rows=1','identifiable'):return 'PRESENT' if v!='identifiable' else 'IDENTIFIABLE'
    if v in ('not_found','not found','none','null','deleted','absent','missing','miss','0','rows=0'):return 'ABSENT'
    if v in ('redacted','anonymized','disabled','active','blocked'):return v.upper()
    return ''


def category(resource,system,explicit=''):
    if explicit: return str(explicit).upper()
    for prefix,kind in sorted(CATEGORIES.items(),key=lambda x:-len(x[0])):
        if (resource or '').startswith(prefix):return kind
    return SYSTEM_CATEGORIES.get(system or '', '')


def has_direct(v):
    """Inspect direct identifiers recursively; allow stable reference on tombstones."""
    if isinstance(v,dict):
        for k,val in v.items():
            if k.casefold() in DIRECT_KEYS and val not in ('',None,'[REDACTED]','REDACTED','null','NULL'):
                return True
            if isinstance(val,(dict,list)) and has_direct(val): return True
        return False
    if isinstance(v,list):return any(has_direct(x) for x in v)
    return False


def identity_values(obj):
    if isinstance(obj,dict):
        for k,v in obj.items():
            if k in ('resource_id','trace_id','audit_id','activity_id'):continue
            yield from identity_values(v)
    elif isinstance(obj,list):
        for v in obj:yield from identity_values(v)
    elif isinstance(obj,str):
        yield norm(obj)


@dataclass
class Evidence:
    system:str
    resource:str
    kind:str
    state:str
    timestamp:str
    evidence_id:str
    content:Any
    text:str
    direct:bool=False
    score:int=0


class EvidenceEngine:
    def __init__(self,folder:Path):
        self.folder=folder
        self.rules={r['data_category']:r['required_action'] for r in records(folder/'deletion_rules.csv')}
        self.identities=records(folder/'user_identities.csv')
        self.history=records(folder/'user_audit_log.csv')
        self.activity=records(folder/'system_activity.csv')
        self.media_status={}
        try:
            from models import IntentModel
            self.intent_model=IntentModel()
        except ImportError:
            self.intent_model=None
        self.manifest=records(folder/'evidence_files.csv')
        self.subjects=defaultdict(set)
        self.by_token=defaultdict(set)
        for row in self.identities:
            u=row['user_id'];self.subjects[u].add(norm(u))
            for k in ('email','name','phone','email_hash'):
                if row.get(k):self.subjects[u].add(norm(row[k]))
        for row in self.history:
            u=row['user_id']
            for k in ('old_value','new_value'):
                if row.get(k):self.subjects[u].add(norm(row[k]))
        for u,vals in self.subjects.items():
            for v in vals:
                if v and len(v)>3:self.by_token[v].add(u)
        self.evidence=[]
        self.sql_scopes=[]
        self.resource_users=defaultdict(set)
        self._load_evidence()
        self._link_resources()
        self.user_evidence_files = defaultdict(set)
        for u in self.subjects:
            self.user_evidence_files[u] = {e.evidence_id for e in self.evidence if u in self.resource_users.get(e.resource, ()) and e.evidence_id}
        self.resource_evidence_files = defaultdict(set)
        for e in self.evidence:
            if e.evidence_id:
                self.resource_evidence_files[e.resource].add(e.evidence_id)

    def _append(self,system,resource,kind,state,when,file_id,obj,raw='',score=2):
        if not resource:return
        for prefix,canonical in SYSTEM_BY_PREFIX.items():
            if str(resource).startswith(prefix):system=canonical;break
        if not system:return
        state=normalize_state(state) or state
        kind=category(resource,system,kind)
        self.evidence.append(Evidence(system,resource,kind,state,utc(when),file_id,obj,raw or json.dumps(obj,ensure_ascii=False,default=str),has_direct(obj),score))

    def _collect_json(self,data,file_id,manifest_time):
        if isinstance(data,dict) and 'snapshots' in data:
            for s in data['snapshots']:
                if s.get('data_store')=='account_service':
                    res_set={str(r.get('resource_id')) for r in s.get('records',[]) if r.get('resource_id')}
                    self.sql_scopes.append((file_id,utc(manifest_time),{'profiles_primary':res_set}))
        def walk(node,ctx):
            if isinstance(node,list):
                for child in node:walk(child,ctx)
                return
            if not isinstance(node,dict):return
            system=node.get('system') or node.get('origin_system') or node.get('data_store') or ctx.get('system','')
            kind=node.get('record_type') or ctx.get('kind','')
            ts=utc(node.get('observed_at') or node.get('recorded_at') or node.get('captured_at') or node.get('updated_at') or ctx.get('time') or manifest_time)
            if node.get('resource_id'):
                if node.get('tombstone') is True or norm(node.get('account_status')) in ('tombstone','deleted_tombstone'):
                    kind='ACCOUNT_TOMBSTONE'
                state=self._from_structured(node,kind)
                self._append(system,str(node['resource_id']),kind,state,ts,file_id,node,score=3)
            nxt={'system':system,'kind':kind,'time':ts}
            for key,v in node.items():
                if key=='service_exports' and isinstance(v,dict):
                    for sys,items in v.items():walk(items,{**nxt,'system':sys})
                elif key in ('snapshots','records','entries','exports','connectors','profiles','documents','restore_entries','messages','user_profiles','data','data_records'):
                    walk(v,nxt)
                elif isinstance(v,(dict,list)) and key not in ('metrics','recent_activity','record_json'):
                    walk(v,nxt)
        walk(data,{'system':'','kind':'','time':utc(manifest_time)})

    def _from_structured(self,v,kind):
        if v.get('status_code')==404 or ('profile' in v and v['profile'] is None):return 'ABSENT'
        if 'download_available' in v:return 'PRESENT' if v['download_available'] else 'ABSENT'
        if kind=='ACCOUNT_TOMBSTONE' or v.get('tombstone') is True or str(v.get('resource_id','')).startswith('tombstone_'):
            return 'IDENTIFIABLE' if has_direct(v) else 'REDACTED'
        if 'enabled' in v:return 'ACTIVE' if str(v['enabled']).lower() in ('true','1') else 'DISABLED'
        if 'restore_allowed' in v:return 'ACTIVE' if str(v['restore_allowed']).lower() in ('true','1') else 'BLOCKED'
        if 'deletion_block' in v:return 'BLOCKED' if str(v['deletion_block']).lower() in ('true','1') else 'ACTIVE'
        for k in ('result','status','state','record_state','account_status','deletion_state'):
            if k in v and v[k] not in (None,''):
                state=normalize_state(v[k]);
                if state:return state
        if kind in ('ANALYTICS_PROFILE','PRODUCT_TELEMETRY') or str(v.get('resource_id','')).startswith(('analytics_','telemetry_')):
            return 'IDENTIFIABLE' if has_direct(v) or v.get('user_id') else 'ANONYMIZED'
        if kind in ('SUPPORT_MESSAGE','EMAIL_DELIVERY_LOG') or str(v.get('resource_id','')).startswith('support_'):
            return 'IDENTIFIABLE' if has_direct(v) else 'REDACTED'
        if kind=='BACKUP_ARCHIVE':return 'ACTIVE' if str(v.get('restore_allowed','')).lower() in ('true','1') else 'BLOCKED'
        return 'PRESENT'

    def _collect_sql(self,text,file_id,file_time):
        # The supplied exports are SQLite-compatible. Only execute trusted challenge fixtures.
        connection=sqlite3.connect(':memory:');connection.row_factory=sqlite3.Row
        try:
            connection.executescript(text)
            tables=connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
            captured={}
            for table_row in tables:
                table=table_row['name'].replace('"','""')
                captured[table]=set()
                for row in connection.execute('SELECT * FROM "'+table+'"'):
                    d=dict(row)
                    if 'record_json' in d:
                        try:record=json.loads(d['record_json'])
                        except (ValueError,TypeError):record={}
                    else:record=d
                    resource=d.get('resource_id') or record.get('resource_id')
                    if resource:captured[table].add(str(resource))
                    system=d.get('origin_system') or record.get('system') or table
                    # A database row's updated_at is mutation time, not snapshot observation time.
                    when=file_time
                    kind=record.get('record_type') or category(resource,system)
                    state=self._from_structured(record,kind)
                    self._append(system,resource,kind,state,when,file_id,record,score=3)
            self.sql_scopes.append((file_id,utc(file_time),captured))
        except sqlite3.Error:
            # Fallback never marks missing data as deleted.
            pass
        finally:connection.close()

    def _collect_text(self,txt,file_id,file_time):
        # Parse 'timestamp | system | resource | category | status | identifier' records.
        for line in txt.splitlines():
            if ' | ' in line:
                fields=[v.strip(' -') for v in line.split('|')]
                if len(fields)>=5 and re.match(r'20\d\d-',fields[0]):
                    if fields[1] not in ('DEBUG','INFO','WARN','ERROR'):
                        ts,sys,res,cat,state=fields[:5]
                        self._append(sys,res,cat,state,ts,file_id,{'subject_reference':fields[5] if len(fields)>5 else '',
                                      'resource_id':res,'record_type':cat,'result':state},raw=line,score=3)
        # Parse trace correlated diagnostic reads. A "started" line only supplies identity,
        # while a "completed" line supplies the terminal resource state.
        traces=defaultdict(list)
        for line in txt.splitlines():
            tid = None
            if 'trace_id' in line:
                m_json=re.search(r'(\{.*\})',line)
                if m_json:
                    try:
                        d=json.loads(m_json.group(1))
                        tid=d.get('trace_id')
                    except (ValueError,TypeError):pass
                if not tid:
                    token=re.search(r'\btrace_id=([^\s]+)',line)
                    if token:tid=token.group(1).strip('"\'')
            if not tid and ' | ' in line:
                parts=[p.strip(' -') for p in line.split('|')]
                if len(parts)>=4 and parts[1] in ('DEBUG','INFO','WARN','ERROR'):
                    tid=parts[3].strip()
            if not tid:
                m_sys=re.search(r'\b(tr-[a-zA-Z0-9_-]+|rb-[a-zA-Z0-9_-]+)\b',line)
                if m_sys:
                    tid=m_sys.group(1)
            if tid:
                traces[tid].append(line)
        for trace,lines in traces.items():
            extra=' '.join(lines)
            for line in lines:
                if 'resource_id' not in line:continue
                d=self._kv(line)
                event=d.get('event','')
                state=''
                if d.get('rows')=='0' or d.get('http_status')=='404' or d.get('result') in ('miss','not_found'):state='ABSENT'
                elif d.get('result') in ('hit','found') or int(d.get('rows','0') or '0')>0:state='PRESENT'
                elif 'pii_scan' in event:state='IDENTIFIABLE'
                elif d.get('enabled') is not None:state='ACTIVE' if str(d.get('enabled')).lower() in ('true','1') else 'DISABLED'
                elif d.get('restore_allowed') is not None:state='ACTIVE' if str(d.get('restore_allowed')).lower() in ('true','1') else 'BLOCKED'
                elif d.get('deletion_block') is not None:state='BLOCKED' if str(d.get('deletion_block')).lower() in ('true','1') else 'ACTIVE'
                elif event=='restore_candidate_evaluated':state='ACTIVE' if str(d.get('eligible','')).lower() in ('true','1') else 'BLOCKED'
                elif event.endswith('_completed') and d.get('resource_id'):state='PRESENT'
                if event=='analytics_profile_read_completed':
                    state='IDENTIFIABLE' if any(d.get(k) not in ('null','',None) for k in ('customer_reference','email','phone','email_hash')) else 'ANONYMIZED'
                if event=='support_ticket_read_completed':
                    state='IDENTIFIABLE' if any(d.get(k) not in ('null','',None) for k in ('requester_email','requester_phone','requester_name')) else 'REDACTED'
                if event=='audit_record_read_completed' and (str(d.get('rows'))=='1' or d.get('integrity_check')=='passed'):state='PRESENT'
                if not state:continue
                evidence_content={**d,'trace_context':extra}
                service=d.get('service') or d.get('system') or ''
                if not service and ' | ' in line:
                    parts=[p.strip(' -') for p in line.split('|')]
                    if len(parts)>=4 and parts[1] in ('DEBUG','INFO','WARN','ERROR'):
                        service=parts[2].strip()
                if not service and '<' in line and '>' in line:
                    m_sys_srv=re.search(r'<\d+>\d\s+\S+\s+(\w+)\s+(tr-[^\s]+)',line)
                    if m_sys_srv:
                        service=m_sys_srv.group(1)
                self._append(service,d.get('resource_id'),'',state,d.get('timestamp') or line[:20],file_id,
                             evidence_content,extra,score=4)
        # Some unstructured logs carry terminal readback without a trace_id.
        for line in txt.splitlines():
            if 'trace_id' in line or 'resource_id' not in line:continue
            d=self._kv(line)
            if d.get('event','').endswith('_completed'):
                s='ABSENT' if d.get('rows')=='0' else 'PRESENT' if d.get('rows')=='1' else ''
                if s:self._append(d.get('service'),d.get('resource_id'),'',s,line[:20],file_id,d,line,score=2)

    def _kv(self,line):
        m=re.search(r'(\{.*\})',line)
        if m:
            try:
                d=json.loads(m.group(1))
                if 'timestamp' not in d and re.match(r'20\d\d-',line):
                    d['timestamp']=line[:20].strip()
                return d
            except (ValueError,TypeError):pass
        d={'timestamp':line[:20] if re.match(r'20\d\d-',line) else ''}
        if ' | ' in line:
            parts=[p.strip(' -') for p in line.split('|')]
            if len(parts)>=5 and parts[1] in ('DEBUG','INFO','WARN','ERROR'):
                d['service']=parts[2]
                d['trace_id']=parts[3]
                d['event']=parts[4]
                rest=parts[5] if len(parts)>5 else ''
                try:subparts=shlex.split(rest)
                except ValueError:subparts=rest.split()
                for p in subparts:
                    if '=' in p:
                        k,v=p.split('=',1);d[k]=v
                return d
        try:parts=shlex.split(line)
        except ValueError:parts=line.split()
        for p in parts:
            if '=' in p:
                k,v=p.split('=',1);d[k]=v
        return d

    def _extract_media(self,path):
        if not path.exists():
            self.media_status[path.name]='unavailable'
            return ''
        ext=path.suffix.lower()
        if ext=='.pdf':
            try:
                import fitz
            except ImportError:
                self.media_status[path.name]='failed (fitz missing)'
                return ''
            try:
                with fitz.open(path) as doc:
                    text='\n'.join(p.get_text() for p in doc).strip()
                self.media_status[path.name]='parsed' if text else 'empty'
                return text
            except Exception as err:
                self.media_status[path.name]=f'failed ({type(err).__name__})'
                return ''
        if ext in ('.png','.jpeg','.jpg','.webp'):
            try:
                import pytesseract
                from PIL import Image,ImageOps,ImageEnhance
                import shutil
                if not shutil.which('tesseract'):
                    self.media_status[path.name]='failed (tesseract missing)'
                    return ''
                with Image.open(path) as im:
                    im=ImageOps.grayscale(im)
                    text=pytesseract.image_to_string(ImageEnhance.Contrast(im).enhance(1.7)).strip()
                self.media_status[path.name]='parsed' if text else 'empty'
                return text
            except Exception as err:
                self.media_status[path.name]=f'failed ({type(err).__name__})'
                return ''
        return ''

    def _load_evidence(self):
        for ent in self.manifest:
            path=self.folder/ent['file_path'];fid=ent['file_id'];captured=ent['captured_at']
            if not path.exists():continue
            ext=path.suffix.lower()
            if ext=='.json':
                try:self._collect_json(json.loads(path.read_text(encoding='utf-8')),fid,captured)
                except (ValueError,UnicodeError):pass
            elif ext=='.sql':self._collect_sql(path.read_text(encoding='utf-8',errors='replace'),fid,captured)
            elif ext in ('.log','.txt'):
                self._collect_text(path.read_text(encoding='utf-8',errors='replace'),fid,captured)
            elif ext in ('.pdf','.png','.jpg','.jpeg','.webp'):
                content=self._extract_media(path)
                if content:self._collect_document(content,fid,captured)
        # Add operational activity as low-confidence context and links, never alone
        # assume a workflow SUCCESS means deletion actually occurred.
        self.activity_by_resource=defaultdict(list)
        for a in sorted(self.activity,key=lambda r:r['event_time']):
            self.activity_by_resource[a['resource_id']].append(a)

    def _collect_document(self,txt,file_id,when):
        """PDF/image text: pipe records plus any resource ids named in the document.
        A document describing an uploaded attachment is a SUPPORT_ATTACHMENT (own rule)."""
        self._collect_text(txt,file_id,when)
        low=txt.casefold()
        attachment=('attachment' in low and any(w in low for w in ('uploader','checksum','upload history','uploaded')))
        for rid in sorted(set(re.findall(r'\b(?:support|export|search|analytics|account|backup|data_flow|marketing)_\d+\b',low))):
            if any(x.resource==rid and x.evidence_id==file_id for x in self.evidence):continue
            kind='SUPPORT_ATTACHMENT' if attachment and rid.startswith('support_') else ''
            self._append('',rid,kind,'PRESENT',when,file_id,{'resource_id':rid},raw=txt,score=3)

    def _link_resources(self):
        # Strong exact identity matching. Later anonymized records are linked via their
        # prior identifiable resource_id, without leaking a direct identifier again.
        token_order=sorted(self.by_token,key=len,reverse=True)
        for e in self.evidence:
            raw=e.text.casefold()
            values=set(identity_values(e.content))
            for val in values:
                for u in self.by_token.get(val,[]):self.resource_users[e.resource].add(u)
            # Text values in logs/messages, including old emails that are not standalone fields.
            for match in re.finditer(r'(?<![\w.+-])[\w.+-]+@[\w.-]+\.[a-z]{2,}(?![\w.-])',raw):
                for u in self.by_token.get(match.group(),[]):self.resource_users[e.resource].add(u)
            for match in re.finditer(r'(?<![a-z_])user_\d+(?!\d)',raw):
                if match.group() in self.subjects:self.resource_users[e.resource].add(match.group())
        # Activity references are useful for correlation, not as final-state proof.
        for r,rows in self.activity_by_resource.items():
            for a in rows:
                d=a.get('details','').casefold()
                for t in re.findall(r'(?<![\w.+-])[\w.+-]+@[\w.-]+\.[a-z]{2,}',d):
                    self.resource_users[r].update(self.by_token.get(t,()))
                for t in re.findall(r'\buser_\d+\b',d):
                    if t in self.subjects:self.resource_users[r].add(t)

    def subject_for(self,email):
        n=norm(email)
        candidates=self.by_token.get(n,set())
        if len(candidates)==1:return next(iter(candidates))
        return ''

    WORKER_RESULTS={'COMPLETE':('SUCCESS',),'PARTIALLY_COMPLETE':('SUCCESS','PARTIAL'),'NOT_STARTED':('FAILED',)}

    LINK_KINDS={'account':('DELETE_RECORD','account_service',True,False),
                'analytics':('ANONYMIZE_RECORD','analytics_platform',False,True)}

    @staticmethod
    def _parse(x):
        from datetime import datetime
        try:return datetime.fromisoformat(utc(x).replace('Z','+00:00'))
        except ValueError:return None

    def seen_resources(self,limit):
        """Resource ids present in evidence that is citable at `limit` (cached per cutoff)."""
        cache=self.__dict__.setdefault('_seen_cache',{})
        if limit not in cache:
            captured=self.__dict__.setdefault('_captured',{m['file_id']:utc(m['captured_at']) for m in self.manifest})
            cache[limit]={e.resource for e in self.evidence
                          if (not e.timestamp or e.timestamp<=limit) and (not captured.get(e.evidence_id) or captured[e.evidence_id]<=limit)}
        return cache[limit]

    def link_candidates(self,case,uid,kind):
        """Rank deletion-worker events that could belong to this case (participant data only).

        Worker events carry no identity, so a candidate must (a) follow the request, (b) fall just
        before/at reported_at, (c) not be positively identified with another user, and (d) for
        accounts carry the worker result implied by reported_status, for anonymized records be
        corroborated by a record in evidence captured at/before audit_at. Rank: result match,
        co-location, corroboration, chronological event order."""
        event,system,use_result,need_seen=self.LINK_KINDS[kind]
        rep=self._parse(case.get('reported_at'));req=self._parse(case.get('requested_at'))
        if not rep:return []
        allowed=self.WORKER_RESULTS.get(case.get('reported_status',''),())
        limit=utc(case.get('audit_at'))
        seen=self.seen_resources(limit)
        ufiles = self.user_evidence_files.get(uid, set()) if hasattr(self, 'user_evidence_files') else set()
        rfiles_map = getattr(self, 'resource_evidence_files', {})
        scored=[]
        for a in self.activity:
            if a.get('source_system')!='deletion_worker' or a.get('target_system')!=system or a.get('event_type')!=event:continue
            when=self._parse(a['event_time'])
            if not when:continue
            delta=(rep-when).total_seconds()
            if delta<-900 or delta>4*3600 or (req and when<req):continue
            matched=a['resource_id'] in seen
            if need_seen and not matched:continue
            if use_result and allowed and a.get('reported_result') not in allowed:continue
            owners=self.resource_users.get(a['resource_id'],set())
            if uid and owners and uid not in owners:continue

            rep_status = case.get('reported_status', '')
            if use_result:
                if rep_status == 'PARTIALLY_COMPLETE':
                    res_rank = 0 if a.get('reported_result') == 'PARTIAL' else 1
                elif rep_status == 'COMPLETE':
                    res_rank = 0 if a.get('reported_result') == 'SUCCESS' else 1
                elif rep_status == 'NOT_STARTED':
                    res_rank = 0 if a.get('reported_result') == 'FAILED' else 1
                else:
                    res_rank = 0 if (not allowed or a.get('reported_result') in allowed) else 1
            else:
                res_rank = 0

            rfiles = rfiles_map.get(a['resource_id'], set())
            coloc = bool(ufiles & rfiles)
            coloc_rank = 0 if coloc else 1
            seen_rank = 0 if matched else 1
            scored.append(((res_rank, coloc_rank, seen_rank, when), a['resource_id']))
        scored.sort()
        return scored

    def infer_account_from_activity(self,case,uid=''):
        ranked=self.link_candidates(case,uid,'account')
        return ranked[0][1] if ranked else ''

    def assign_links(self,cases):
        """Global one-to-one matching of worker events to cases (greedy by rank)."""
        self.assigned=defaultdict(dict)
        triples=[]
        for case in cases:
            if not classify_intent(case.get('request_text','')):continue
            uid=self.subject_for(case['email'])
            if not uid:continue
            linked=self.observed(uid,case['audit_at'])
            for kind in self.LINK_KINDS:
                if any(e.system==('account_service' if kind=='account' else 'analytics_platform') for e in linked):continue
                if kind == 'analytics' and any(e.system in ('account_service', 'search_service', 'support_platform', 'export_service') and e.state in ('PRESENT', 'IDENTIFIABLE', 'ACTIVE') for e in linked):
                    continue
                for rank,res in self.link_candidates(case,uid,kind):
                    sort_key = (rank, kind, case.get('requested_at', ''), case.get('email', ''), case['case_id'], res)
                    triples.append(sort_key)
        used=set();done=set()
        for item in sorted(triples):
            rank, kind = item[0], item[1]
            cid, res = item[-2], item[-1]
            if (kind,cid) in done or res in used:continue
            self.assigned[cid][kind]=res;used.add(res);done.add((kind,cid))

    def infer_sql_absence(self,resource,audit_at):
        # A readback absence can be proven only in an explicit account-primary/replica
        # snapshot, never from arbitrary sparse evidence bundles.
        candidates=[]
        for fid,when,tables in self.sql_scopes:
            if when>utc(audit_at):continue
            if not any('profiles_primary' in t or 'profiles_failover_replica' in t for t in tables):continue
            if resource in set().union(*tables.values()):continue
            candidates.append((when,fid))
        if not candidates:return None
        when,fid=max(candidates)
        return Evidence('account_service',resource,'USER_PROFILE','ABSENT',when,fid,{},'',False,3)

    def observed(self,uid,audit_at,extra=()):
        relevant=[]
        limit=utc(audit_at)
        captured={m['file_id']:utc(m['captured_at']) for m in self.manifest}
        for e in self.evidence:
            if uid not in self.resource_users.get(e.resource,()) and e.resource not in extra:continue
            if e.timestamp and e.timestamp>limit:continue
            # Files with capture dates later than the audit cut-off cannot be cited.
            man_time=captured.get(e.evidence_id,'')
            if man_time and man_time>limit:continue
            relevant.append(e)
        groups=defaultdict(list)
        for e in relevant:groups[(e.system,e.resource)].append(e)
        result=[]
        for _,items in groups.items():
            latest=max(e.timestamp for e in items)
            contenders=[x for x in items if x.timestamp==latest]
            # When same-time primary & replica disagree, treat a live copy as a violation.
            severity={'ACTIVE':8,'IDENTIFIABLE':7,'PRESENT':6,'REDACTED':4,'ANONYMIZED':4,
                      'BLOCKED':3,'DISABLED':3,'ABSENT':2}
            result.append(max(contenders,key=lambda e:(severity.get(e.state,5),e.score,e.evidence_id)))
        acc_absent=[e for e in result if e.system=='account_service' and e.kind=='USER_PROFILE' and e.state=='ABSENT']
        if len(acc_absent)>1:
            latest_acc=max(acc_absent,key=lambda e:e.timestamp)
            result=[e for e in result if not (e.system=='account_service' and e.kind=='USER_PROFILE' and e.state=='ABSENT' and e.resource!=latest_acc.resource)]
        return result


def classify_intent(text):
    """No status-label shortcuts. Deletion authorization is read from user language."""
    t=norm(text)
    # Stems with \w* suffix: 'deleted', 'erased', 'suppression', 'supprimer', 'gelöscht', ...
    deletes=[r'\b(delet|eras|remov|clos|wip|purg|forget|forgot|gone|suppress|supprim|effac|elimin|borr|apag|exclu|l[öo]sch|loesch|gel[öo]scht|entfern|slett|verwijder|cancell|cancel)\w*',
             r'削除|消去|退会|حذف|مسح|удал|삭제|탈퇴|إزالة|ลบ|抹消',
             r'\b(opt[- ]?out of data processing|right to be forgotten)\b']
    denied=[r'\b(do not|don.t|never|without|no need to|not asking (you )?to|please do not|rather than|instead of)\s+(\w+\s+){0,3}(delet|eras|remov|clos|wip)\w*',
            r'\b(not a deletion request|not requesting deletion|keep my account|leave (the|my) account (active|open|as it is))\b',
            r'\bnot (asking for|a request (to|for)|requesting|an? \w+ request (to|for))\s+(\w+\s+){0,3}(delet|eras|remov|clos|wip)\w*',
            r'\b(marketing|promotional|newsletter)\b.{0,60}\b(only|still (need|want))\b|\bonly\b.{0,40}\b(marketing|promotional|newsletter)\b|\b(stop|unsubscribe).{0,30}(promotional|marketing|newsletter)',
            r'\b(no (quiero|deseo) (borrar|eliminar)|ne (supprimez|effacez) pas|削除しないで|削除は希望しない)\b']
    if any(re.search(x,t,re.I) for x in denied):return False
    if any(re.search(x,t,re.I) for x in deletes):return True
    # Ambiguous requests are not authorized merely by a workflow status.
    return False


def disposition(e, rules):
    kind=e.kind
    if kind=='DATA_FLOW':return ('FLOW','ACTIVE' if e.state in ('ACTIVE','PRESENT') else 'DISABLED')
    if kind=='BACKUP_ARCHIVE':return ('RESTORE','ACTIVE' if e.state in ('ACTIVE','PRESENT') else 'BLOCKED')
    action=rules.get(kind)
    if not action:
        # A tombstone is a special retained account record with strict redaction.
        if kind=='ACCOUNT_TOMBSTONE':action='REDACT'
        else:return ('UNKNOWN','')
    if action=='DELETE':return ('DELETE','ABSENT' if e.state=='ABSENT' else 'PRESENT')
    if action=='REDACT':
        # Direct fields in a supposedly sanitized record override self-reported status.
        if e.direct and e.state in ('REDACTED','ANONYMIZED'):return ('REDACT','IDENTIFIABLE')
        if e.state=='ABSENT':return ('REDACT','ABSENT')
        if e.state in ('REDACTED','ANONYMIZED'):return ('REDACT','REDACTED')
        return ('REDACT','IDENTIFIABLE')
    if action=='ANONYMIZE':
        if e.direct and e.state=='ANONYMIZED':return ('ANONYMIZE','IDENTIFIABLE')
        if e.state=='ANONYMIZED':return ('ANONYMIZE','ANONYMIZED')
        return ('ANONYMIZE','IDENTIFIABLE')
    if action=='RETAIN':return ('RETAIN','PRESENT' if e.state!='ABSENT' else 'ABSENT')
    return ('UNKNOWN','')


def step(phase,operation,e,evidence_id=''):
    state={'REPORT_REMAINING_RECORD':'PRESENT','REPORT_EXPOSED_PII':'PRESENT',
           'REPORT_ACTIVE_DATA_FLOW':'ACTIVE','REPORT_RESTORE_RISK':'ACTIVE',
           'DISABLE_DATA_FLOW':'DISABLED','BLOCK_RESTORE':'BLOCKED','DELETE_RECORD':'ABSENT',
           'REDACT_RECORD':'REDACTED','ANONYMIZE_RECORD':'ANONYMIZED',
           'VERIFY_RECORD_ABSENT':'ABSENT','VERIFY_RECORD_PRESENT':'PRESENT','VERIFY_RECORD_REDACTED':'REDACTED',
           'VERIFY_RECORD_ANONYMIZED':'ANONYMIZED','VERIFY_DATA_FLOW_DISABLED':'DISABLED',
           'VERIFY_RESTORE_BLOCKED':'BLOCKED'}[operation]
    return {'phase':phase,'system_id':e.system,'resource_id':e.resource,
           'operation':operation,'state':state,'evidence_id':evidence_id}


def audit_case(case,engine:EvidenceEngine):
    intent=classify_intent(case.get('request_text',''))
    if not intent and engine.intent_model is not None:
        # AI only resolves ambiguous natural-language intent, never policy or evidence.
        hypothesis=engine.intent_model.classify(case.get('request_text',''))
        if hypothesis is True and not re.search(r'\b(do not|don.t|not requesting|not asking)\b',norm(case.get('request_text',''))):
            intent=True
    if not intent:
        return {'deletion_status':'NOT_APPLICABLE','steps':[]}
    uid=engine.subject_for(case['email'])
    evidence=[];extra=[]
    if uid:
        # Account resources already tied to this subject by identity-bearing evidence win;
        # otherwise use the deletion-worker links (see link_candidates / assign_links).
        assigned=getattr(engine,'assigned',None)
        if assigned is not None:links=dict(assigned.get(case.get('case_id'),{}))
        else:
            links={}
            linked=engine.observed(uid,case['audit_at'])
            if not any(e.system=='account_service' and e.kind=='USER_PROFILE' for e in linked):
                a=engine.infer_account_from_activity(case,uid)
                if a:links['account']=a
        extra=list(links.values())
        evidence=engine.observed(uid,case['audit_at'],extra=tuple(extra))
        account=links.get('account','')
        if account and not any(e.resource==account for e in evidence):
            absence=engine.infer_sql_absence(account,case['audit_at'])
            if absence:evidence.append(absence)
            else:evidence.append(Evidence('account_service',account,'USER_PROFILE','ABSENT',utc(case['audit_at']),'',{},'',False,0))
    findings=[];remediations=[];checks=[];unresolved_retention=False
    for e in evidence:
        kind,state=disposition(e,engine.rules)
        if kind=='UNKNOWN':continue
        violation=False
        if kind=='DELETE':
            if state=='PRESENT':
                findings.append(step('FINDING','REPORT_REMAINING_RECORD',e,e.evidence_id))
                remediations.append(step('REMEDIATION','DELETE_RECORD',e));violation=True
            checks.append(step('VERIFICATION','VERIFY_RECORD_ABSENT',e,e.evidence_id if not violation else ''))
        elif kind=='REDACT':
            if state=='IDENTIFIABLE':
                findings.append(step('FINDING','REPORT_EXPOSED_PII',e,e.evidence_id))
                remediations.append(step('REMEDIATION','REDACT_RECORD',e));violation=True
            checks.append(step('VERIFICATION','VERIFY_RECORD_REDACTED',e,e.evidence_id if not violation else ''))
        elif kind=='ANONYMIZE':
            if state=='IDENTIFIABLE':
                findings.append(step('FINDING','REPORT_EXPOSED_PII',e,e.evidence_id))
                remediations.append(step('REMEDIATION','ANONYMIZE_RECORD',e));violation=True
            checks.append(step('VERIFICATION','VERIFY_RECORD_ANONYMIZED',e,e.evidence_id if not violation else ''))
        elif kind=='RETAIN':
            if state=='ABSENT':
                # No allowed remediation can reconstruct a legally necessary audit record.
                # Treat as a blocker rather than fabricate a DELETE action.
                violation=True;unresolved_retention=True
            checks.append(step('VERIFICATION','VERIFY_RECORD_PRESENT',e,e.evidence_id if not violation else ''))
        elif kind=='FLOW':
            if state=='ACTIVE':
                findings.append(step('FINDING','REPORT_ACTIVE_DATA_FLOW',e,e.evidence_id))
                remediations.append(step('REMEDIATION','DISABLE_DATA_FLOW',e));violation=True
            checks.append(step('VERIFICATION','VERIFY_DATA_FLOW_DISABLED',e,e.evidence_id if not violation else ''))
        elif kind=='RESTORE':
            if state=='ACTIVE':
                findings.append(step('FINDING','REPORT_RESTORE_RISK',e,e.evidence_id))
                remediations.append(step('REMEDIATION','BLOCK_RESTORE',e));violation=True
            checks.append(step('VERIFICATION','VERIFY_RESTORE_BLOCKED',e,e.evidence_id if not violation else ''))
    # No certainty without positive current-state evidence. Fail closed for unknown subject.
    status='INCOMPLETE' if findings or unresolved_retention or not uid else 'COMPLETE'
    if status=='COMPLETE':
        # A COMPLETE verification must cite evidence; uncitable (assumed) checks are dropped.
        checks=[s for s in checks if s['evidence_id']]
        if not checks:status='INCOMPLETE'
    if status=='INCOMPLETE':
        f_res={s['resource_id'] for s in findings}
        checks=[{**s,'evidence_id':''} for s in checks
                if s['resource_id'] in f_res or s['system_id'] in ('account_service','security_service')]
        items=findings+remediations+checks
    else:items=checks
    # The official order is phase -> operation table -> system -> resource.
    items.sort(key=lambda s:(PHASE_ORDER[s['phase']],ORDER[s['operation']],s['system_id'],s['resource_id']))
    for i,s in enumerate(items,1):s['step_no']=i
    return {'deletion_status':status,'steps':items}
