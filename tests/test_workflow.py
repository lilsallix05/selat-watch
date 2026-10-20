import base64
import io
import json
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
import zipfile
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
from watch.store import Store,sha
from watch.domain import score
from watch.adapters import ct_records,enrich
from watch.classifier import evaluate,classify,metrics
from watch.server import Server

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.db=Store(Path(self.temp.name)/'test.db')
        self.record={'domain':'maybank-tebus.example','source':'Synthetic test','synthetic':True,'registered_at':'2026-10-17','observed_at':'2026-10-19T00:00:00Z'}
    def tearDown(self): self.temp.cleanup()
    def test_import_dedupe_and_bad_rows(self):
        self.assertEqual(self.db.ingest([self.record])['added'],1)
        self.assertEqual(self.db.ingest([self.record])['duplicates'],1)
        self.assertEqual(len(self.db.ingest([{},'bad',{'domain':'http://127.0.0.1'}])['errors']),3)
        self.assertEqual(len(self.db.cases()),1)
    def test_ct_reimport_is_idempotent(self):
        event={'message_type':'certificate_update','data':{'leaf_cert':{'all_domains':['*.maybank-tebus.example']},'cert_index':1}}
        records=ct_records(event,synthetic=True)
        self.assertEqual(self.db.ingest(records)['added'],1)
        self.assertEqual(self.db.ingest(records)['duplicates'],1)
    def test_reviews_persist_and_pack_hashes(self):
        self.db.ingest([self.record])
        self.db.review(self.record['domain'],'escalated','suspicious','Synthetic exercise, analyst review required')
        self.db.report(self.record['domain'],'Cyber999','DRAFT-01','Not sent')
        image=b'\x89PNG\r\n\x1a\nsynthetic bytes for import hash test'
        self.db.attach(self.record['domain'],'../../screen.png',base64.b64encode(image).decode(),'Test import, not a rendered screenshot','2026-10-19T00:00:00Z')
        restored=Store(self.db.path).detail(self.record['domain'])
        self.assertEqual(restored['status'],'escalated')
        self.assertEqual(restored['attachments'][0]['name'],'screen.png')
        with zipfile.ZipFile(io.BytesIO(self.db.pack(self.record['domain']))) as z:
            manifest=json.loads(z.read('manifest.json'))
            for name,digest in manifest['files'].items(): self.assertEqual(sha(z.read(name)),digest)
            self.assertIn(b'Not submitted',z.read('report-draft.md'))
        self.assertIn('maybank-tebus.example',self.db.sigma())
    def test_allowlist_exact_and_review_preserved(self):
        self.db.ingest([self.record,dict(self.record,domain='sub.maybank-tebus.example')])
        self.db.review(self.record['domain'],'reviewing','benign','Reviewed')
        self.db.set_allow(self.record['domain'],'Authorised exercise')
        self.assertEqual(self.db.detail(self.record['domain'])['assessment']['score'],0)
        self.assertGreater(self.db.detail('sub.maybank-tebus.example')['assessment']['score'],0)
        self.db.ingest([dict(self.record,source='Second source')])
        self.assertEqual(self.db.detail(self.record['domain'])['verdict'],'benign')
        self.db.set_allow(self.record['domain'],'',True)
        self.assertGreater(self.db.detail(self.record['domain'])['assessment']['score'],0)
    def test_dates_and_hosting_not_inferred(self):
        a=score(dict(self.record,registered_at='nonsense'),now=datetime(2026,10,19,tzinfo=timezone.utc))
        self.assertIsNone(a['age_days']); self.assertIn('Invalid registration date; age unknown',a['warnings'])
        b=score(dict(self.record,registered_at='2027-01-01')); self.assertIsNone(b['age_days'])
        self.assertNotIn('Registered',str(score({'domain':'maybank.example','certificate_not_before':'2026-10-19'})['reasons']))
    def test_validation_and_empty_states(self):
        self.db.ingest([self.record])
        with self.assertRaises(ValueError): self.db.review(self.record['domain'],'closed','benign','')
        with self.assertRaises(ValueError): self.db.attach(self.record['domain'],'x.svg',base64.b64encode(b'<svg/>').decode(),'test','2026-01-01')
        self.assertIn('No observations',self.db.digest('2000-01-01'))
        self.assertEqual(classify('<script>password</script>')['label'],'unknown')
    def test_classifier_evidence(self):
        e=evaluate();self.assertEqual(e['metrics']['n'],12);self.assertEqual(e['training_count'],12)
        self.assertEqual(e['metrics']['tp']+e['metrics']['fp']+e['metrics']['tn']+e['metrics']['fn'],12)
        self.assertIsNone(metrics([])['precision'])
    def test_malformed_ct_and_normalized_review(self):
        with self.assertRaises(ValueError): ct_records({'message_type':'certificate_update','data':None})
        self.db.ingest([self.record]);self.db.review('MAYBANK-TEBUS.EXAMPLE','reviewing','unknown','Normalized request')
        self.assertEqual(self.db.detail(self.record['domain'])['note'],'Normalized request')
    def test_provider_contracts(self):
        with patch.dict('os.environ',{'VT_API_KEY':'test-key','URLHAUS_AUTH_KEY':'test-key'}):
            with patch('watch.adapters.request',return_value={'data':{'type':'domain','id':'test.example','attributes':{'last_analysis_stats':{'malicious':2}}}}) as req:
                r=enrich('test.example','virustotal');self.assertEqual(r['last_analysis_stats']['malicious'],2)
                self.assertEqual(req.call_args.args[0],'https://www.virustotal.com/api/v3/domains/test.example')
            with patch('watch.adapters.request',return_value={'query_status':'no_results'}) as req:
                r=enrich('test.example','urlhaus');self.assertEqual(r['query_status'],'no_results')
                self.assertIn(b'host=test.example',req.call_args.args[2])
        with patch.dict('os.environ',{},clear=True):
            with self.assertRaises(ValueError): enrich('test.example','virustotal')

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.db=Store(Path(self.temp.name)/'test.db');self.server=Server(('127.0.0.1',0),self.db)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.url=f'http://127.0.0.1:{self.server.server_port}'
    def tearDown(self): self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()
    def request(self,path,data=None,headers=None):
        return urllib.request.urlopen(urllib.request.Request(self.url+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json',**(headers or {})}))
    def test_http_roundtrip(self):
        with self.request('/api/import',{'records':[{'domain':'cimb-verify.example','synthetic':True}]}) as r: self.assertEqual(json.load(r)['added'],1)
        with self.request('/api/cases') as r: self.assertEqual(json.load(r)[0]['domain'],'cimb-verify.example')
        with self.request('/api/review',{'domain':'cimb-verify.example','status':'reviewing','verdict':'unknown','note':'Browser equivalent'}) as r: self.assertTrue(json.load(r)['saved'])
        with self.request('/api/pack?domain=cimb-verify.example') as r: self.assertTrue(zipfile.is_zipfile(io.BytesIO(r.read())))
    def test_cross_origin_and_bad_payload(self):
        with self.assertRaises(urllib.error.HTTPError) as e: self.request('/api/import',{}, {'Origin':'https://outside.example'})
        self.assertEqual(e.exception.code,403); e.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as e: self.request('/api/import',{'records':'wrong'})
        self.assertEqual(e.exception.code,400); e.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as e: self.request('/api/cases',headers={'Host':'evil.example'})
        self.assertEqual(e.exception.code,403); e.exception.close()
        with self.request('/') as r: self.assertIn("default-src 'self'",r.headers['Content-Security-Policy'])

if __name__=='__main__': unittest.main()
