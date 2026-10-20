#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from watch.domain import ROOT,permutations
from watch.store import Store,now
from watch.adapters import ct_records,enrich,stream
from watch.classifier import evaluate,metrics
from watch.exports import domain_evaluation,public_snapshot
from watch.server import Server

def main():
    parser=argparse.ArgumentParser(description='Selat Watch: passive Malaysian brand investigation')
    parser.add_argument('--db',default=str(ROOT/'work/watch.db'))
    sub=parser.add_subparsers(dest='command',required=True)
    serve=sub.add_parser('serve'); serve.add_argument('--port',type=int,default=8765); serve.add_argument('--demo',action='store_true')
    imp=sub.add_parser('import'); imp.add_argument('file'); imp.add_argument('--ct',action='store_true'); imp.add_argument('--synthetic',action='store_true')
    perm=sub.add_parser('permutations'); perm.add_argument('brand')
    digest=sub.add_parser('digest'); digest.add_argument('--date')
    pack=sub.add_parser('pack'); pack.add_argument('domain'); pack.add_argument('output')
    en=sub.add_parser('enrich'); en.add_argument('domain'); en.add_argument('--provider',required=True,choices=['urlhaus','virustotal'])
    st=sub.add_parser('watch-ct'); st.add_argument('--url',required=True); st.add_argument('--seconds',type=int,default=60)
    sub.add_parser('evaluate-domains'); snap=sub.add_parser('snapshot'); snap.add_argument('output')
    sub.add_parser('evaluate'); comp=sub.add_parser('evaluate-predictions'); comp.add_argument('file')
    sub.add_parser('rescore'); sub.add_parser('sigma')
    args=parser.parse_args(); db=Store(args.db)
    try:
        if args.command=='serve':
            if args.demo:
                if not db.cases(): db.ingest(json.loads((ROOT/'fixtures/observations.json').read_text()))
            db.rescore()
            server=Server(('127.0.0.1',args.port),db)
            print(f'Selat Watch http://127.0.0.1:{server.server_port} (loopback only)',flush=True)
            server.serve_forever()
        elif args.command=='import':
            data=json.loads(Path(args.file).read_text()); print(json.dumps(db.ingest(ct_records(data,synthetic=args.synthetic) if args.ct else data),indent=2))
        elif args.command=='permutations': print(json.dumps(permutations(args.brand),indent=2))
        elif args.command=='digest': print(db.digest(args.date))
        elif args.command=='pack': Path(args.output).write_bytes(db.pack(args.domain)); print('Evidence pack written; not submitted')
        elif args.command=='evaluate-domains': print(json.dumps(domain_evaluation(),indent=2))
        elif args.command=='snapshot': Path(args.output).write_text(public_snapshot(db)); print('Read-only snapshot written; not published')
        elif args.command=='evaluate': print(json.dumps(evaluate(),indent=2))
        elif args.command=='evaluate-predictions':
            data=json.loads(Path(args.file).read_text()); print(json.dumps({'metrics':metrics([(x['truth'],x['prediction']) for x in data]),'provenance':'Imported predictions; no model invocation performed'},indent=2))
        elif args.command=='watch-ct': print(stream(db,args.url,args.seconds))
        elif args.command=='enrich':
            case=db.detail(args.domain)
            if case['latest'].get('synthetic'): raise ValueError('Synthetic cases cannot be sent to enrichment providers')
            data=enrich(args.domain,args.provider)
            record=dict(case['latest']); record['enrichment']=data; record['source']=args.provider; record['observed_at']=now(); print(json.dumps(db.ingest([record])))
            db.log_run(args.provider,'ok','Domain lookup stored')
        elif args.command=='rescore': db.rescore(); print('Scores refreshed')
        elif args.command=='sigma': print(db.sigma())
    except (ValueError,KeyError) as e:
        db.log_run(args.command,'error',str(e)); parser.exit(2,str(e)+'\n')
    except KeyboardInterrupt: pass
if __name__=='__main__': main()
