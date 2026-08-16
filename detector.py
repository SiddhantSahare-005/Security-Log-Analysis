import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from db import init_db, insert_alert

FAILED_TERMS = ('failed login','login failed','authentication failed','invalid password','access denied','failed authentication')
SUCCESS_TERMS = ('successful login','login success','authentication success','logged in')
SUSPICIOUS_TERMS = ('malware','ransomware','privilege escalation','unauthorized','suspicious','blocked','denied','sql injection','command injection','brute force')

def _field(data, *keys, default=''):
    for key in keys:
        if key in data and data[key] not in (None, ''):
            return data[key]
    return default

def _timestamp(value):
    if not value: return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    value = str(value).strip()
    for fmt in ('%Y-%m-%d %H:%M:%S','%Y-%m-%dT%H:%M:%S','%Y-%m-%dT%H:%M:%S.%f','%Y-%m-%d %H:%M:%S.%f'):
        try: return datetime.strptime(value[:26], fmt).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError: pass
    return value

def _normalise(record):
    if isinstance(record, dict):
        msg = str(_field(record,'message','msg','description',default=''))
        event = str(_field(record,'event','event_type','action','type',default=''))
        status = str(_field(record,'status','result','outcome',default=''))
        return {'timestamp': _timestamp(_field(record,'timestamp','time','datetime','@timestamp')),
                'username': str(_field(record,'username','user','user_name','account',default='Unknown')),
                'ip_address': str(_field(record,'ip_address','source_ip','src_ip','ip','client_ip',default='Unknown')),
                'event': f'{event} {status} {msg}'.strip(),
                'raw': ' '.join(str(v) for v in record.values() if v is not None)}
    text = str(record).strip()
    tm = re.search(r'\[?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\]?', text)
    ip = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    user = re.search(r'(?:user(?:name)?|account)[=: ]+([A-Za-z0-9._@-]+)', text, re.I)
    return {'timestamp': _timestamp(tm.group(1) if tm else ''), 'username': user.group(1) if user else 'Unknown',
            'ip_address': ip.group(0) if ip else 'Unknown', 'event': text, 'raw': text}

def parse_log_file(path):
    text = Path(path).read_text(encoding='utf-8', errors='replace').strip()
    if not text: return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list): return [_normalise(x) for x in parsed]
        if isinstance(parsed, dict):
            for key in ('logs','events','records'):
                if isinstance(parsed.get(key), list): return [_normalise(x) for x in parsed[key]]
            return [_normalise(parsed)]
    except json.JSONDecodeError: pass
    records = []
    json_lines = True
    for line in text.splitlines():
        if not line.strip(): continue
        try: records.append(_normalise(json.loads(line)))
        except json.JSONDecodeError: json_lines = False; break
    if json_lines and records: return records
    return [_normalise(line) for line in text.splitlines() if line.strip()]

def _alert(record, attack_type, severity, description):
    data = {'timestamp':record['timestamp'],'username':record.get('username','Unknown'),'ip_address':record.get('ip_address','Unknown'),
            'attack_type':attack_type,'severity':severity,'description':description}
    raw = '|'.join(str(data[k]) for k in data)
    data['source_hash'] = hashlib.sha256(raw.encode()).hexdigest()
    return data

def analyze_records(records):
    init_db(); alerts=[]; failed=Counter()
    for r in records:
        text=f"{r.get('event','')} {r.get('raw','')}".lower()
        if any(t in text for t in FAILED_TERMS): failed[(r.get('username','Unknown'),r.get('ip_address','Unknown'))]+=1
    for (user,ip), count in failed.items():
        if count >= 5:
            alerts.append(_alert({'timestamp':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'username':user,'ip_address':ip},
                'Brute Force Attempt','HIGH',f'{count} failed authentication attempts detected for user {user} from IP {ip}.'))
    for r in records:
        text=f"{r.get('event','')} {r.get('raw','')}".lower()
        if any(t in text for t in SUSPICIOUS_TERMS):
            alerts.append(_alert(r,'Suspicious Activity','HIGH' if 'brute force' in text else 'MEDIUM',
                'Suspicious security activity detected in the supplied log entry.'))
        elif any(t in text for t in FAILED_TERMS):
            alerts.append(_alert(r,'Failed Authentication','MEDIUM','A failed authentication attempt was detected.'))
        elif any(t in text for t in SUCCESS_TERMS):
            try:
                if datetime.strptime(r['timestamp'][:19],'%Y-%m-%d %H:%M:%S').hour < 6:
                    alerts.append(_alert(r,'Unusual Login Time','LOW','A successful login was recorded during an unusual time window.'))
            except (ValueError, TypeError): pass
    inserted=sum(insert_alert(a) for a in alerts)
    return {'logs':len(records),'alerts':inserted}

def analyze_log_source(path):
    return analyze_records(parse_log_file(path))
