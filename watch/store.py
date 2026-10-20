import base64
from contextlib import contextmanager
import csv
import hashlib
import io
import json
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from .domain import normalize, score, date_value
from .classifier import classify

def now(): return datetime.now(timezone.utc).isoformat()
def dump(value): return json.dumps(value,ensure_ascii=False,sort_keys=True)
def sha(data): return hashlib.sha256(data).hexdigest()

class Store:
    def __init__(self,path):
        self.path=str(path)
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS cases(domain TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, status TEXT DEFAULT 'new', verdict TEXT DEFAULT 'unknown', note TEXT DEFAULT '', assessment TEXT, latest TEXT);
            CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, domain TEXT, received TEXT, payload TEXT);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, domain TEXT, at TEXT, kind TEXT, payload TEXT);
            CREATE TABLE IF NOT EXISTS attachments(id TEXT PRIMARY KEY, domain TEXT, name TEXT, mime TEXT, captured_at TEXT, provenance TEXT, data BLOB);
            CREATE TABLE IF NOT EXISTS allowlist(domain TEXT PRIMARY KEY, reason TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, at TEXT, source TEXT, state TEXT, detail TEXT);
            ''')
    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.path,timeout=15); db.row_factory=sqlite3.Row
        try:
            with db: yield db
        finally: db.close()
    def allowlist(self):
        with self.connect() as db: return [dict(r) for r in db.execute('SELECT * FROM allowlist ORDER BY domain')]
    def log_run(self,source,state,detail):
        with self.connect() as db: db.execute('INSERT INTO runs(at,source,state,detail) VALUES(?,?,?,?)',(now(),source,state,str(detail)[:500]))
    def ingest(self,rows):
        if not isinstance(rows,list) or len(rows)>5000: raise ValueError('Import expects an array of at most 5000 observations')
        added=duplicates=0; errors=[]
        allow=[r['domain'] for r in self.allowlist()]
        with self.connect() as db:
            for index,raw in enumerate(rows):
                try:
                    if not isinstance(raw,dict): raise ValueError('Observation must be an object')
                    if len(dump(raw))>150000: raise ValueError('Observation exceeds 150 KB')
                    record=dict(raw); record['domain']=normalize(record['domain'])
                    record.setdefault('source','Manual import'); record.setdefault('synthetic',False)
                    if not isinstance(record['synthetic'],bool): raise ValueError('synthetic must be true or false')
                    if not isinstance(record['source'],str) or not record['source'].strip(): raise ValueError('source is required')
                    record.setdefault('observed_at',None); date_value(record['observed_at'])
                    if record.get('page_text') is not None and not isinstance(record['page_text'],str): raise ValueError('page_text must be text')
                    assessment=score(record,allow)
                    if record.get('page_text'): assessment['page_classification']=classify(record['page_text'])
                    payload=dump(record); identity=sha(payload.encode())
                    if db.execute('SELECT 1 FROM observations WHERE id=?',(identity,)).fetchone(): duplicates+=1; continue
                    stamp=now(); d=record['domain']
                    db.execute('INSERT INTO observations VALUES(?,?,?,?)',(identity,d,stamp,payload))
                    db.execute('INSERT INTO cases(domain,first_seen,last_seen,assessment,latest) VALUES(?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen,assessment=excluded.assessment,latest=excluded.latest',(d,stamp,stamp,dump(assessment),payload))
                    db.execute('INSERT INTO events(domain,at,kind,payload) VALUES(?,?,?,?)',(d,stamp,'observation',dump({'id':identity,'source':record['source']})))
                    added+=1
                except (ValueError,KeyError,TypeError) as e: errors.append({'row':index+1,'error':str(e)})
        self.log_run('import','partial' if errors else 'ok',dump({'added':added,'duplicates':duplicates,'errors':len(errors)}))
        return dict(added=added,duplicates=duplicates,errors=errors)
    def cases(self):
        with self.connect() as db:
            rows=[dict(r) for r in db.execute('SELECT * FROM cases')]
        for row in rows:
            row['assessment']=json.loads(row['assessment']); row['latest']=json.loads(row['latest'])
        return sorted(rows,key=lambda x:(-x['assessment']['score'],x['domain']))
    def detail(self,domain):
        domain=normalize(domain)
        row=next((r for r in self.cases() if r['domain']==domain),None)
        if row is None: raise KeyError('Case not found')
        with self.connect() as db:
            row['observations']=[dict(r) for r in db.execute('SELECT id,received,payload FROM observations WHERE domain=? ORDER BY received',(domain,))]
            for x in row['observations']: x['payload']=json.loads(x['payload'])
            row['events']=[dict(r) for r in db.execute('SELECT * FROM events WHERE domain=? ORDER BY id DESC',(domain,))]
            for x in row['events']: x['payload']=json.loads(x['payload'])
            row['attachments']=[dict(r) for r in db.execute('SELECT id,name,mime,captured_at,provenance FROM attachments WHERE domain=?',(domain,))]
        return row
    def review(self,domain,status,verdict,note):
        domain=normalize(domain)
        self.detail(domain)
        if status not in ('new','reviewing','escalated','closed') or verdict not in ('unknown','suspicious','benign'): raise ValueError('Invalid case state or verdict')
        if not isinstance(note,str) or len(note)>10000: raise ValueError('Note exceeds 10000 characters')
        if status in ('escalated','closed') and not note.strip(): raise ValueError('Add a reason before escalation or closure')
        with self.connect() as db:
            db.execute('UPDATE cases SET status=?,verdict=?,note=? WHERE domain=?',(status,verdict,note,domain))
            db.execute('INSERT INTO events(domain,at,kind,payload) VALUES(?,?,?,?)',(domain,now(),'review',dump(dict(status=status,verdict=verdict,note=note))))
    def report(self,domain,recipient,reference,note):
        domain=normalize(domain)
        self.detail(domain)
        if recipient not in ('Cyber999','Brand owner','Internal SOC'): raise ValueError('Unknown report destination')
        if not isinstance(reference,str) or not reference.strip() or len(reference)>500: raise ValueError('Enter a draft/reference identifier up to 500 characters')
        with self.connect() as db: db.execute('INSERT INTO events(domain,at,kind,payload) VALUES(?,?,?,?)',(domain,now(),'manual-report-log',dump(dict(recipient=recipient,reference=reference,note=str(note)[:5000],delivery='User-entered record; no message sent by this tool'))))
    def set_allow(self,domain,reason,remove=False):
        domain=normalize(domain)
        if not remove and (not isinstance(reason,str) or not reason.strip()): raise ValueError('Allowlist reason is required')
        with self.connect() as db:
            if remove: db.execute('DELETE FROM allowlist WHERE domain=?',(domain,))
            else: db.execute('INSERT OR REPLACE INTO allowlist VALUES(?,?,?)',(domain,reason[:1000],now()))
            db.execute('INSERT INTO events(domain,at,kind,payload) VALUES(?,?,?,?)',(domain,now(),'allowlist',dump({'removed':remove,'reason':reason})))
        self.rescore()
    def rescore(self):
        allow=[r['domain'] for r in self.allowlist()]
        with self.connect() as db:
            for c in self.cases():
                a=score(c['latest'],allow)
                if c['latest'].get('page_text'): a['page_classification']=classify(c['latest']['page_text'])
                db.execute('UPDATE cases SET assessment=? WHERE domain=?',(dump(a),c['domain']))
    def attach(self,domain,name,encoded,provenance,captured_at):
        domain=normalize(domain)
        self.detail(domain)
        if not provenance or not captured_at: raise ValueError('Capture time and provenance are required')
        date_value(captured_at)
        try: data=base64.b64decode(encoded,validate=True)
        except Exception as e: raise ValueError('Invalid base64 image') from e
        if len(data)>4*1024*1024: raise ValueError('Image limit is 4 MB')
        mime='image/png' if data.startswith(b'\x89PNG\r\n\x1a\n') else 'image/jpeg' if data.startswith(b'\xff\xd8\xff') else None
        if not mime: raise ValueError('Only PNG or JPEG evidence is accepted')
        name=Path(str(name)).name[:100]
        identity=sha(data)
        with self.connect() as db:
            # Same bytes can be attached to multiple cases without stealing an existing attachment.
            identity=sha((domain+identity).encode())
            db.execute('INSERT OR IGNORE INTO attachments VALUES(?,?,?,?,?,?,?)',(identity,domain,name,mime,captured_at,str(provenance)[:2000],data))
            db.execute('INSERT INTO events(domain,at,kind,payload) VALUES(?,?,?,?)',(domain,now(),'evidence-import',dump({'id':identity,'content_sha256':sha(data)})))
        return identity
    def attachment(self,identity):
        with self.connect() as db: r=db.execute('SELECT * FROM attachments WHERE id=?',(identity,)).fetchone()
        if r is None: raise KeyError('Evidence not found')
        return dict(r)
    def reports(self):
        with self.connect() as db:
            rows=[dict(r) for r in db.execute("SELECT * FROM events WHERE kind='manual-report-log' ORDER BY id DESC")]
        for row in rows: row['payload']=json.loads(row['payload'])
        return rows
    def runs(self):
        with self.connect() as db: return [dict(r) for r in db.execute('SELECT * FROM runs ORDER BY id DESC LIMIT 50')]
    def digest(self,date=None):
        day=date or datetime.now(ZoneInfo('Asia/Kuala_Lumpur')).date().isoformat()
        datetime.strptime(day,'%Y-%m-%d')
        rows=[r for r in self.cases() if date_value(r['last_seen']).astimezone(ZoneInfo('Asia/Kuala_Lumpur')).date().isoformat()==day]
        lines=[f'# Selat Watch daily digest — {day}','', 'Timezone: Asia/Kuala_Lumpur. Local review aid. Scores are prioritization signals, not confirmed phishing.',f'Cases observed: {len(rows)}; synthetic: {sum(r["latest"].get("synthetic",False) for r in rows)}.','']
        for r in rows: lines.append(f'- {r["domain"].replace(".","[.]")} | {r["assessment"]["score"]}/100 | {r["status"]} | analyst: {r["verdict"]}')
        if not rows: lines.append('No observations received for this date.')
        return '\n'.join(lines)+'\n'
    def pack(self,domain):
        c=self.detail(domain); files={}
        files['case.json']=dump(c).encode()
        files['report-draft.md']=(f'# Review draft: {domain.replace(".","[.]")}\n\nNot submitted. Analyst verification is required.\n\nSynthetic: {c["latest"].get("synthetic",False)}\nPriority score: {c["assessment"]["score"]}/100\nVerdict: {c["verdict"]}\n\nReasons:\n'+ '\n'.join('- '+x for x in c['assessment']['reasons'])+'\n\nAnalyst note:\n'+c['note']+'\n\nRegistration and hosting metadata are supplied observations, not independently verified. Certificate appearance does not prove maliciousness.\n').encode()
        for item in c['attachments']:
            a=self.attachment(item['id']); suffix='.png' if a['mime']=='image/png' else '.jpg'; files['evidence/'+a['id']+suffix]=a['data']
        files['manifest.json']=dump({'schema':'selat-evidence-1','generated_at':now(),'files':{name:sha(data) for name,data in files.items()},'custody':'Local import hashes; not independent forensic attestation'}).encode()
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
            for name,data in files.items(): z.writestr(name,data)
        return out.getvalue()
    def sigma(self):
        domains=[c['domain'] for c in self.cases() if c['verdict']=='suspicious' and c['assessment']['priority']!='allowlisted']
        return '\n'.join(['title: Analyst-reviewed Malaysian Brand Lookalike Domains','id: c4ac9901-c066-4405-b7c8-a3e5964bb103','status: experimental','description: Exact destination-host matches. Review synthetic examples before importing.','logsource:','  category: proxy','detection:','  selection:','    cs-host:']+['      - '+json.dumps(d) for d in domains]+(['      - "no-reviewed-cases.invalid"'] if not domains else [])+['  condition: selection','falsepositives:','  - Legitimate domain transfers or analyst misclassification','level: medium',''])
