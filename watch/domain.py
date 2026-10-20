import json
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
import idna

ROOT = Path(__file__).resolve().parents[1]
# Narrow visual skeleton, not a claim of complete Unicode confusable detection.
CONFUSABLES = str.maketrans('аесорхуіјѕοα', 'aecopxyijs oa'.replace(' ', ''))
KEYWORDS = ['bantuan', 'semak', 'tebus', 'sumbangan', 'login', 'verify', 'secure', 'reward', 'parcel', 'claim', 'refund']

def brands():
    return json.loads((ROOT / 'fixtures/brands.json').read_text())

def normalize(value):
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() for c in value):
        raise ValueError('Use a domain or http(s) URL without whitespace')
    value = value.strip()
    if value.startswith('*.'): value = value[2:]
    if '://' in value:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password or not parsed.hostname:
            raise ValueError('Only plain http(s) URLs are accepted')
        value = parsed.hostname
    elif any(c in value for c in '/:@?#\\'):
        raise ValueError('Invalid domain syntax')
    try:
        value = idna.encode(value.rstrip('.'), uts46=True, transitional=False, std3_rules=True).decode('ascii').lower()
        ipaddress.ip_address(value)
    except idna.IDNAError as e:
        raise ValueError('Invalid IDNA domain') from e
    except ValueError:
        pass
    else:
        raise ValueError('Expected a domain, not an IP address')
    if '.' not in value or len(value) > 253: raise ValueError('Expected a fully qualified domain')
    return value

def distance(a, b):
    row = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        nxt = [i]
        for j, cb in enumerate(b, 1): nxt.append(min(nxt[-1]+1, row[j]+1, row[j-1]+(ca != cb)))
        row = nxt
    return row[-1]

def date_value(value):
    if not value: return None
    dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

def score(record, allowlist=(), now=None):
    domain = normalize(record['domain'])
    unicode = idna.decode(domain)
    now = now or datetime.now(timezone.utc)
    selected, match_points, reasons = None, 0, []
    for b in brands():
        if any(domain == d or domain.endswith('.'+d) for d in b['domains']):
            return dict(evaluated_at=now.isoformat(), rule_version="1.0", domain=domain, unicode=unicode, brand=b['name'], brand_id=b['id'], score=0, priority='allowlisted', reasons=['Configured official domain boundary'], age_days=None, keywords=[], warnings=[], official=True)
        skeleton = unicode.translate(CONFUSABLES).lower()
        for token in b['aliases']:
            labels = re.split(r'[.\-]', skeleton)
            points = 40 if token in skeleton else (32 if any(len(x)>3 and distance(x, token)<=1 for x in labels) else 0)
            if points > match_points:
                selected, match_points = b, points
                reasons = ['Brand token in non-official domain' if points==40 else 'One-edit brand lookalike']
    if domain in allowlist:
        return dict(evaluated_at=now.isoformat(), rule_version="1.0", domain=domain, unicode=unicode, brand=(selected or {}).get('name','Unmatched'), brand_id=(selected or {}).get('id',''), score=0, priority='allowlisted', reasons=['Analyst exact-domain allowlist'], age_days=None, keywords=[], warnings=[], official=False)
    points = match_points
    kws = [x for x in KEYWORDS if x in unicode.lower()]
    if kws and selected: points += min(20, len(kws)*10); reasons.append('Lure keywords: '+', '.join(kws))
    if selected and any(ord(c)>127 for c in unicode): points += 15; reasons.append('Unicode label; inspect A-label and visual spelling')
    age = None
    warnings = []
    if record.get('registered_at'):
        try:
            age = (now-date_value(record['registered_at'])).days
            if age < 0: warnings.append('Registration date is in the future'); age = None
            elif age < 30 and selected: points += 15; reasons.append(f'Registered {age} days before evaluation')
        except (ValueError, TypeError): warnings.append('Invalid registration date; age unknown')
    if age is None: warnings.append('Registration age unknown; certificate time is not registration time')
    hosting = record.get('hosting', {})
    if not isinstance(hosting, dict): raise ValueError('hosting must be an object')
    if hosting.get('flagged') is True and selected and hosting.get('source'):
        points += 10; reasons.append('Supplied hosting risk evidence: '+str(hosting['source'])[:160])
    elif not hosting: warnings.append('Hosting evidence not supplied')
    points = min(100, points)
    return dict(evaluated_at=now.isoformat(), rule_version="1.0", domain=domain, unicode=unicode, brand=(selected or {}).get('name','Unmatched'), brand_id=(selected or {}).get('id',''), score=points, priority='high' if points>=70 else 'medium' if points>=40 else 'low', reasons=reasons or ['No configured brand resemblance'], age_days=age, keywords=kws, warnings=warnings, official=False)

def permutations(brand_id):
    b = next((b for b in brands() if b['id']==brand_id), None)
    if not b: raise ValueError('Unknown brand')
    token = b['aliases'][0]
    rows = set()
    for i in range(len(token)):
        rows.add((token[:i]+token[i+1:]+'.example','omission'))
        rows.add((token[:i]+token[i]*2+token[i+1:]+'.example','repetition'))
        if i+1 < len(token): rows.add((token[:i]+token[i+1]+token[i]+token[i+2:]+'.example','transposition'))
    for word in KEYWORDS: rows.add((token+'-'+word+'.example','keyword'))
    for a, z in [('a','а'),('o','ο'),('i','і')]:
        if a in token: rows.add((normalize(token.replace(a,z,1)+'.example'),'homoglyph'))
    return [{'domain':d, 'method':m, 'purpose':'Unqueried synthetic candidate'} for d,m in sorted(rows)]
