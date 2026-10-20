import html
import json
from datetime import datetime,timezone
from pathlib import Path
from .domain import ROOT,score
from .classifier import metrics

def domain_evaluation():
    rows=json.loads((ROOT/'fixtures/observations.json').read_text())
    benign={'maybank2u.com.my','museum.example','boost-community.example','grap.example'}
    results=[]
    for row in rows:
        a=score(row,now=datetime(2026,10,19,tzinfo=timezone.utc))
        results.append({'domain':a['domain'],'truth':'benign' if row['domain'] in benign else 'suspicious','prediction':'suspicious' if a['score']>=40 else 'benign','score':a['score']})
    return {'threshold':40,'evaluation_time':'2026-10-19T00:00:00Z','label_provenance':'Authored synthetic scenario labels; no independent adjudication','metrics':metrics([(x['truth'],x['prediction']) for x in results]),'results':results}

def public_snapshot(db):
    rows=db.cases()
    items=''.join('<tr><td>'+html.escape(r['domain'].replace('.','[.]'))+'</td><td>'+html.escape(r['assessment']['brand'])+'</td><td>'+str(r['assessment']['score'])+'</td><td>'+('Synthetic' if r['latest'].get('synthetic') else 'Imported')+'</td><td>'+html.escape(r['status'])+'</td></tr>' for r in rows)
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Selat Watch public snapshot</title><style>body{font:16px/1.6 system-ui;max-width:1000px;margin:40px auto;padding:20px;color:#18384c}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #ccd8df;overflow-wrap:anywhere}@media(max-width:600px){table{font-size:12px}th,td{padding:6px}}</style><h1>Selat Watch</h1><p>Read-only local export. Scores are review priorities, not confirmed phishing. Domains are defanged. Private analyst notes, report references and attachments are excluded.</p><p>Generated '+datetime.now(timezone.utc).isoformat()+'</p><table><thead><tr><th>Domain</th><th>Brand resemblance</th><th>Score</th><th>Evidence</th><th>Workflow</th></tr></thead><tbody>'+items+'</tbody></table><p>No takedowns or external reports are claimed.</p></html>'
