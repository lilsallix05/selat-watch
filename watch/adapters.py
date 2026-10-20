"""Passive provider adapters. No requests are made to observed domains."""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from .domain import normalize
from .store import now

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args): raise ValueError('Provider redirect rejected; verify endpoint configuration')

def request(url,headers=None,data=None,timeout=20):
    headers={'User-Agent':'SelatWatch/1.0 passive-domain-review',**(headers or {})}
    req=urllib.request.Request(url,headers=headers,data=data)
    try:
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=timeout) as response:
            body=response.read(5_000_001)
            if len(body)>5_000_000: raise ValueError('Provider response exceeded 5 MB')
            return json.loads(body)
    except urllib.error.HTTPError as e:
        retry=e.headers.get('Retry-After')
        raise ValueError(f'Provider HTTP {e.code}'+(f'; retry after {retry}' if retry else '')) from None
    except (urllib.error.URLError,TimeoutError): raise ValueError('Provider connection failed or timed out') from None

def ct_records(data,source='CertStream import',synthetic=False):
    events=data if isinstance(data,list) else [data]
    records=[]
    for event in events:
        if not isinstance(event,dict): raise ValueError('CT event must be an object')
        if event.get('message_type')=='heartbeat': continue
        if event.get('message_type')=='certificate_update':
            payload=event.get('data')
            if not isinstance(payload,dict) or not isinstance(payload.get('leaf_cert'),dict): raise ValueError('CT data and leaf_cert must be objects')
            leaf=payload['leaf_cert']
            domains=leaf.get('all_domains',[])
            if not isinstance(domains,list): raise ValueError('CT all_domains must be an array')
            ref=str(event.get('data',{}).get('cert_index','unknown'))
            certificate=leaf.get('not_before')
        elif 'name_value' in event:  # crt.sh export format, not a guaranteed polling service
            domains=str(event['name_value']).splitlines(); ref=str(event.get('id','unknown')); certificate=event.get('not_before')
        else: raise ValueError('Expected CertStream certificate_update or crt.sh export')
        for domain in domains:
            records.append(dict(domain=domain,source=source,source_ref=ref,certificate_not_before=certificate,synthetic=synthetic))
    return records

def enrich(domain,provider):
    domain=normalize(domain)
    if provider=='virustotal':
        key=os.environ.get('VT_API_KEY')
        if not key: raise ValueError('Set VT_API_KEY in the process environment')
        response=request('https://www.virustotal.com/api/v3/domains/'+urllib.parse.quote(domain,safe=''),{'x-apikey':key})
        data=response.get('data',{})
        if data.get('type')!='domain' or data.get('id')!=domain or not isinstance(data.get('attributes'),dict): raise ValueError('Unexpected VirusTotal response')
        attrs=data['attributes']
        return {'provider':provider,'queried_at':now(),'source':'VirusTotal domain report','domain':domain,'last_analysis_stats':attrs.get('last_analysis_stats',{}),'reputation':attrs.get('reputation'),'creation_date':attrs.get('creation_date'),'caution':'Provider reputation is evidence, not a phishing verdict'}
    if provider=='urlhaus':
        key=os.environ.get('URLHAUS_AUTH_KEY')
        if not key: raise ValueError('Set URLHAUS_AUTH_KEY in the process environment')
        response=request('https://urlhaus-api.abuse.ch/v1/host/',{'Auth-Key':key,'Content-Type':'application/x-www-form-urlencoded'},urllib.parse.urlencode({'host':domain}).encode())
        if response.get('query_status') not in ('ok','no_results'): raise ValueError('URLhaus query did not return a valid lookup result')
        return {'provider':provider,'queried_at':now(),'domain':domain,'query_status':response['query_status'],'url_count':response.get('url_count',0),'blacklists':response.get('blacklists',{}),'caution':'URLhaus tracks malware distribution; no_results does not mean safe'}
    raise ValueError('Unknown provider')

def stream(store,url,seconds=60):
    # Endpoint belongs to a CT service, never an observed domain. Configuration is CLI-only.
    if urllib.parse.urlsplit(url).scheme!='wss': raise ValueError('A wss:// CertStream service endpoint is required')
    if not 1<=seconds<=3600: raise ValueError('Watch duration must be 1..3600 seconds')
    import websocket
    end=time.monotonic()+seconds; count=0
    connection=None
    try:
        connection=websocket.create_connection(url,timeout=min(seconds,20))
        while time.monotonic()<end:
            connection.settimeout(max(0.1,min(10,end-time.monotonic())))
            try: data=json.loads(connection.recv())
            except websocket.WebSocketTimeoutException: continue
            result=store.ingest(ct_records(data,source='CertStream: '+urllib.parse.urlsplit(url).hostname))
            count+=result['added']
        store.log_run('CertStream','ok',f'{count} observations in bounded session')
    except Exception as e:
        store.log_run('CertStream','error',type(e).__name__)
        raise ValueError('CT stream ended with an error; see source health. No reconnect or continuity claim.') from None
    finally:
        if connection: connection.close()
    return count
