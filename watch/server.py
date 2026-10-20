import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
from .domain import ROOT, brands, permutations
from .classifier import classify, evaluate
from .adapters import ct_records

class Server(ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=64
    def __init__(self,address,store): self.store=store; super().__init__(address,Handler)

class Handler(BaseHTTPRequestHandler):
    def log_message(self,fmt,*args): pass
    @property
    def db(self): return self.server.store
    def send(self,data,status=200,mime='application/json',filename=None):
        if not isinstance(data,bytes): data=json.dumps(data,ensure_ascii=False).encode() if mime=='application/json' else str(data).encode()
        self.send_response(status)
        self.send_header('Content-Type',mime+'; charset=utf-8' if mime.startswith('text/') else mime)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if filename: self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
        self.end_headers(); self.wfile.write(data)
    def check_host(self):
        return self.headers.get('Host') in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}')
    def do_GET(self):
        if not self.check_host(): return self.send({'error':'Invalid host'},403)
        p=urlsplit(self.path); q=parse_qs(p.query); domain=q.get('domain',[''])[0]
        try:
            if p.path=='/api/cases': return self.send(self.db.cases())
            if p.path=='/api/case': return self.send(self.db.detail(domain))
            if p.path=='/api/brands': return self.send(brands())
            if p.path=='/api/allowlist': return self.send(self.db.allowlist())
            if p.path=='/favicon.ico': return self.send(b'',status=204,mime='image/x-icon')
            if p.path=='/api/reports': return self.send(self.db.reports())
            if p.path=='/api/runs': return self.send(self.db.runs())
            if p.path=='/api/evaluation': return self.send(evaluate())
            if p.path=='/api/permutations': return self.send(permutations(q.get('brand',[''])[0]))
            if p.path=='/api/digest': return self.send(self.db.digest(q.get('date',[None])[0]),mime='text/markdown',filename='daily-digest.md')
            if p.path=='/api/export': return self.send(self.db.cases(),filename='case-register.json')
            if p.path=='/api/pack': return self.send(self.db.pack(domain),mime='application/zip',filename='evidence-pack.zip')
            if p.path=='/api/sigma': return self.send(self.db.sigma(),mime='text/yaml',filename='reviewed-domains.yml')
            if p.path.startswith('/api/attachment/'):
                a=self.db.attachment(p.path.rsplit('/',1)[1]); return self.send(a['data'],mime=a['mime'])
            name='index.html' if p.path=='/' else p.path.lstrip('/')
            if name not in ('index.html','app.js','style.css'): return self.send({'error':'Not found'},404)
            return self.send((ROOT/'static'/name).read_bytes(),mime=mimetypes.guess_type(name)[0] or 'text/plain')
        except (ValueError,KeyError) as e: self.send({'error':str(e)},404 if isinstance(e,KeyError) else 400)
    def do_POST(self):
        origin=self.headers.get('Origin')
        allowed=(f'http://127.0.0.1:{self.server.server_port}',f'http://localhost:{self.server.server_port}')
        if not self.check_host() or (origin and origin not in allowed): return self.send({'error':'Cross-origin mutation rejected'},403)
        if self.headers.get('Content-Type','').split(';')[0]!='application/json': return self.send({'error':'JSON body required'},415)
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=6_000_000: raise ValueError('Request limit is 6 MB')
            data=json.loads(self.rfile.read(length))
            if not isinstance(data,dict): raise ValueError('JSON object required')
            path=urlsplit(self.path).path
            if path=='/api/import': result=self.db.ingest(data.get('records'))
            elif path=='/api/ct': result=self.db.ingest(ct_records(data.get('events'),synthetic=data.get('synthetic',False)))
            elif path=='/api/review': self.db.review(data['domain'],data['status'],data['verdict'],data.get('note','')); result={'saved':True}
            elif path=='/api/report': self.db.report(data['domain'],data['recipient'],data['reference'],data.get('note','')); result={'saved':True,'sent':False}
            elif path=='/api/allowlist': self.db.set_allow(data['domain'],data.get('reason',''),data.get('remove',False)); result={'saved':True}
            elif path=='/api/attachment': result={'id':self.db.attach(data['domain'],data['name'],data['data'],data['provenance'],data['captured_at'])}
            elif path=='/api/classify':
                if not isinstance(data.get('text'),str) or len(data['text'])>100000: raise ValueError('Page text limit is 100000 characters')
                result=classify(data['text'])
            elif path=='/api/rescore': self.db.rescore(); result={'saved':True}
            else: return self.send({'error':'Not found'},404)
            self.send(result)
        except (ValueError,KeyError,TypeError) as e: self.send({'error':str(e)},400)
