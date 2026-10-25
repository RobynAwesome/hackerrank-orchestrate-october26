"""Per-case diagnostic diff against the PUBLIC sample labels (dataset/sample_output.csv).
Usage: python code/evaluation/diff_cases.py [predicted.csv] [-v]
Diagnostic only; never used for inference."""
import csv, json, sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
args = [a for a in sys.argv[1:] if not a.startswith('-')]
verbose = '-v' in sys.argv
pred_path = Path(args[0]) if args else root / 'sample_prediction.csv'


def read(p):
    with open(p, encoding='utf-8-sig', newline='') as f:
        return {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(f)}


exp = read(root / 'dataset' / 'sample_output.csv')
got = read(pred_path)
reqs = {r['case_id']: r for r in csv.DictReader(open(root / 'dataset' / 'sample_deletion_requests.csv', encoding='utf-8-sig', newline=''))}
K = lambda s: (s['phase'], s['operation'], s['system_id'], s['resource_id'], s['state'])
tot = dict(status=0, missing=0, extra=0, evid=0, order=0)
for cid in sorted(exp):
    es, esteps = exp[cid]
    gs, gsteps = got.get(cid, ('MISSING', []))
    ek = {K(s): s for s in esteps}
    gk = {K(s): s for s in gsteps}
    missing = [k for k in ek if k not in gk]
    extra = [k for k in gk if k not in ek]
    evid = [(k, ek[k]['evidence_id'], gk[k]['evidence_id']) for k in ek if k in gk and ek[k]['evidence_id'] != gk[k]['evidence_id']]
    order = (not missing and not extra and [K(s) for s in esteps] != [K(s) for s in gsteps])
    if es == gs and not (missing or extra or evid or order):
        continue
    tot['status'] += es != gs; tot['missing'] += len(missing); tot['extra'] += len(extra)
    tot['evid'] += len(evid); tot['order'] += order
    print(f'{cid}: exp={es} got={gs} missing={len(missing)} extra={len(extra)} evid_err={len(evid)} order_err={order}')
    if verbose:
        print('   text:', reqs[cid]['request_text'][:110].replace('\n', ' '), '| email:', reqs[cid]['email'])
        for k in missing: print('   MISSING', k, ek[k]['evidence_id'])
        for k in extra: print('   EXTRA  ', k, gk[k]['evidence_id'])
        for k, a, b in evid: print('   EVID   ', k, 'exp', a, 'got', b)
print(tot)
