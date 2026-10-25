"""Independent implementation of pinned SETTLE_CORE_v0.md rev 0.8.

No reference settler or public expected values are imported. Section numbers
refer to the exact document distributed in sources/SETTLE_CORE_v0.md.
"""
import base64
import hashlib
import json
import re
from functools import lru_cache
from urllib.parse import urlsplit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

MAX = 2**53-1
L = 2**252+27742317777372353535851937790883648493
P = 2**255-19
D = -121665*pow(121666,P-2,P)%P
KINDS = {'a2a-execution-v0':'execution','a2a-revocation-v0':'revocation','a2a-revocation-ack-v0':'revocation_ack'}
def obj(v): return v if isinstance(v,dict) else {}
def arr(v): return v if isinstance(v,list) else []
def integer(v): return type(v) is int
def hx(v,n): return isinstance(v,str) and re.fullmatch('[0-9a-f]{%d}'%n,v) is not None
def action(v): return isinstance(v,str) and re.fullmatch('[a-z][a-z0-9_.:-]{0,63}',v) is not None
def nonempty(v): return isinstance(v,str) and bool(v)
def strings(v): return isinstance(v,list) and all(nonempty(x) for x in v)
def sha(v): return hashlib.sha256(v).hexdigest()
def digest(v): return hashlib.sha256(v).digest()
def canonical(v):
    return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8','backslashreplace')
def without(v,*keys): return {k:x for k,x in v.items() if k not in keys}
def cbytes(c): return b'a2a-contract-v0\n'+canonical(without(c,'signatures'))
def rbytes(r): return (r['schema']+'\n').encode()+canonical(without(r,'anchor','signatures'))
def body_digest(r): return digest(canonical(without(r,'anchor')))

def parse(text):
    depth=0;quoted=False;escape=False
    for c in text:
        if quoted:
            if escape: escape=False
            elif c=='\\': escape=True
            elif c=='"': quoted=False
        elif c=='"': quoted=True
        elif c in '[{':
            depth+=1
            if depth>512: raise ValueError('JSON nesting exceeds 512')
        elif c in ']}': depth-=1
    def pairs(xs):
        out={}
        for k,v in xs:
            if k in out: raise ValueError('duplicate JSON key')
            out[k]=v
        return out
    return json.loads(text,object_pairs_hook=pairs)

def strict(v,depth=0):
    if depth>512: return False
    if isinstance(v,str): return not any(ord(x)<32 or ord(x)==127 for x in v)
    if isinstance(v,dict): return all(isinstance(k,str) and k.isascii() and strict(k) and strict(x,depth+1) for k,x in v.items())
    if isinstance(v,list): return all(strict(x,depth+1) for x in v)
    if v is None or type(v) is bool: return True
    return integer(v) and abs(v)<=MAX

def contract_values(v):
    if isinstance(v,dict): return all(all(32<=ord(x)<=126 for x in k) and contract_values(z) for k,z in v.items())
    if isinstance(v,list): return all(contract_values(x) for x in v)
    if isinstance(v,(int,float)) and type(v) is not bool: return integer(v) and abs(v)<=MAX
    return True

def b64(v,n):
    if not isinstance(v,str): return None
    try:
        b=base64.b64decode(v,validate=True)
        return b if len(b)==n and base64.b64encode(b).decode()==v else None
    except (ValueError,TypeError): return None

def point_add(a,b):
    x,y,z,t=a;u,v,w,q=b
    aa=(y-x)*(v-u)%P;bb=(y+x)*(v+u)%P;cc=2*D*t*q%P;dd=2*z*w%P
    e=(bb-aa)%P;f=(dd-cc)%P;g=(dd+cc)%P;h=(bb+aa)%P
    return e*f%P,g*h%P,f*g%P,e*h%P

@lru_cache(maxsize=4096)
def good_point(raw):
    if len(raw)!=32: return False
    n=int.from_bytes(raw,'little');sign=n>>255;y=n&((1<<255)-1)
    if y>=P: return False
    yy=y*y%P;den=(D*yy+1)%P
    if not den: return False
    xx=(yy-1)*pow(den,P-2,P)%P;x=pow(xx,(P+3)//8,P)
    if x*x%P!=xx: x=x*pow(2,(P-1)//4,P)%P
    if x*x%P!=xx or (x==0 and sign): return False
    if x%2!=sign: x=P-x
    if x==0 and y==1: return False
    a=(x,y,1,x*y%P);acc=(0,1,1,0);n=L
    while n:
        if n&1: acc=point_add(acc,a)
        a=point_add(a,a);n>>=1
    return acc[0]%P==0 and (acc[1]-acc[2])%P==0

def sig_strict(raw): return raw is not None and int.from_bytes(raw[32:],'little')<L and good_point(raw[:32])
@lru_cache(maxsize=16384)
def verify(pk,sig,message):
    key=b64(pk,32);s=b64(sig,64)
    if key is None or s is None or not good_point(key): return None
    try: Ed25519PublicKey.from_public_bytes(key).verify(s,message);return True
    except (InvalidSignature,ValueError): return False

def target(bits):
    if bits&0x800000 or not bits&0x7fffff: return None
    e=bits>>24;m=bits&0x7fffff
    t=m<<(8*(e-3)) if e>=3 else m>>(8*(3-e))
    return t if t>0 else None
def bits_target(v): return target(int(v,16)) if hx(v,8) else None
def domain(v): return v.strip().lower().rstrip('.') if isinstance(v,str) else ''
def hostname(v): return len(v.split('.'))>=2 and all(re.fullmatch('[a-z0-9]([a-z0-9-]*[a-z0-9])?',x) for x in v.split('.'))
FORBIDDEN = r'\bperformed\b|\bdeliver(ed|y)\b|\bmoney (moved|was sent)\b|\bfunds? (moved|were sent|were transferred)\b|\bpaid\b(?!\s+for\s+(this|the)\s+record)|\bpayment (was|has been) (made|completed|settled|received)\b|\bcontract\b|\bbinding\b|\bguarantee|\bescrow\b|\bcustody\b|\bsolvent\b|\blawful\b|\bfair\b|\bcertified\b'

def door(c):
    """4.1 only. In particular, this never runs settleable-terms checks."""
    if not isinstance(c,dict) or c.get('schema')!='a2a-contract-v0': return False
    if not hx(c.get('contract_id'),32) or not hx(c.get('nonce'),32): return False
    ps=c.get('parties')
    if not isinstance(ps,list) or len(ps)!=2 or not all(isinstance(p,dict) for p in ps): return False
    if sorted(str(p.get('role')) for p in ps)!=['contractor','principal']: return False
    ds=[domain(p.get('domain')) for p in ps]
    if ds[0]==ds[1] or not all(hostname(d) for d in ds): return False
    for p in ps:
        u=p.get('key_url')
        if not isinstance(u,str): return False
        try:
            if urlsplit(u).scheme!='https' or not urlsplit(u).netloc: return False
        except ValueError: return False
        if b64(p.get('public_key_ed25519_b64'),32) is None: return False
    t=c.get('task');g=c.get('grant')
    if not isinstance(t,dict) or not nonempty(t.get('purpose')): return False
    if t.get('payload_digest') is not None and not hx(t['payload_digest'],64): return False
    if not isinstance(g,dict) or set(g)-set('authorized_actions prohibited_actions conditional delegation data_access max_hops privacy revocation finality witnesses expiry_height ordering approval_policy limits'.split()): return False
    if not strings(g.get('authorized_actions')) or not strings(g.get('prohibited_actions')): return False
    if set(g['authorized_actions'])&set(g['prohibited_actions']): return False
    for k,v in g.items():
        if v is None: continue
        if k=='data_access' and not strings(v): return False
        if k in ('max_hops','expiry_height') and not (integer(v) and v>=0): return False
        if k=='delegation' and not (isinstance(v,dict) and set(v)=={'allowed'} and strings(v['allowed'])): return False
        if k=='conditional':
            if not isinstance(v,list) or not all(isinstance(e,dict) and nonempty(e.get('action')) and ('requires' not in e or isinstance(e['requires'],str)) for e in v): return False
            if len({e['action'] for e in v})!=len(v): return False
        if k=='finality':
            if not isinstance(v,dict) or set(v)-{'depth','max_target_bits'}: return False
            if 'depth' in v and not (integer(v['depth']) and v['depth']>=1): return False
            if 'max_target_bits' in v and bits_target(v['max_target_bits']) is None: return False
        if k=='witnesses' and not (isinstance(v,list) and all(isinstance(e,dict) and nonempty(e.get('name')) and b64(e.get('public_key_ed25519_b64'),32) is not None for e in v)): return False
        if k=='privacy' and not nonempty(v): return False
        if k=='ordering' and not (isinstance(v,dict) and not set(v)-{'same_height'} and (v.get('same_height') is None or isinstance(v['same_height'],str))): return False
        if k=='revocation':
            if not isinstance(v,dict) or set(v)-{'effective_at','ack_window'} or v.get('effective_at') not in ('anchor','delivery_ack'): return False
            if 'ack_window' in v and not (integer(v['ack_window']) and v['ack_window']>=1): return False
        if k=='approval_policy':
            if not isinstance(v,dict) or set(v)-{'allow_unscoped','approvers'}: return False
            if 'allow_unscoped' in v and type(v['allow_unscoped']) is not bool: return False
    ap=obj(g.get('approval_policy'))
    if 'approvers' in ap:
        a=ap['approvers']; names=[];keys=[];cond={e['action'] for e in arr(g.get('conditional'))}
        if not isinstance(a,list) or not 1<=len(a)<=16: return False
        for e in a:
            if not isinstance(e,dict) or set(e)-{'name','public_key_ed25519_b64','actions'}: return False
            if not nonempty(e.get('name')) or b64(e.get('public_key_ed25519_b64'),32) is None or not strings(e.get('actions')) or not e['actions']: return False
            if len(set(e['actions']))!=len(e['actions']) or not set(e['actions'])<=cond: return False
            names.append(e['name']);keys.append(e['public_key_ed25519_b64'])
        if len(set(names))!=len(names) or len(set(keys))!=len(keys): return False
    if not contract_values(c): return False
    est=c.get('establishes');den=c.get('does_not_establish')
    if not isinstance(est,list) or not est or any(isinstance(x,str) and re.search(FORBIDDEN,x,re.I) for x in est): return False
    if not isinstance(den,list) or not den: return False
    joined=' '.join(x.lower() for x in den if isinstance(x,str))
    if not all(any(x in joined for x in xs) for xs in [('runtime','enforce'),('judge','liability','fault'),('deviat',),('legal',)]): return False
    ss=c.get('signatures')
    if not isinstance(ss,list): return False
    signed=set();msg=cbytes(c)
    for s in ss:
        if not isinstance(s,dict): continue
        d=domain(s.get('domain'))
        if d not in ds: return False
        p=ps[ds.index(d)]
        if verify(p.get('public_key_ed25519_b64'),s.get('signature'),msg) is not True: return False
        signed.add(d)
    return signed==set(ds)

def terms(c):
    g=c['grant'];r=set();ws=arr(g.get('witnesses'));ps=c['parties']
    acts=arr(g.get('authorized_actions'))+arr(g.get('prohibited_actions'))+[x['action'] for x in arr(g.get('conditional'))]
    if not all(action(a) for a in acts): r.add('grant_action_name_invalid')
    if len(ws)>32: r.add('too_many_witnesses')
    keys=[b64(p['public_key_ed25519_b64'],32) for p in ps+ws];names=[w['name'] for w in ws]
    if len(set(keys))<len(keys) or len(set(names))<len(names): r.add('key_conflict')
    if obj(g.get('ordering')).get('same_height') not in (None,'conservative'): r.add('tie_policy_refused')
    rev=obj(g.get('revocation'));w=rev.get('ack_window')
    if rev.get('effective_at')=='delivery_ack' and not (integer(w) and w>=1): r.add('ack_window_missing')
    k=obj(g.get('finality')).get('depth')
    if not(integer(k) and k>=1): r.add('finality_policy_missing')
    if obj(g.get('approval_policy')).get('allow_unscoped'): r.add('unscoped_approvals_refused')
    return r

def subset(c,p):
    C=c['grant'];P=p['grant'];ref=c.get('parent_contract')
    if not isinstance(ref,dict) or ref.get('contract_id')!=p.get('contract_id'): return False
    for k in ['authorized_actions','data_access']:
        if not set(arr(C.get(k)))<=set(arr(P.get(k))): return False
    if not set(P['prohibited_actions'])<=set(C['prohibited_actions']): return False
    if integer(P.get('max_hops')) and not(integer(C.get('max_hops')) and C['max_hops']<=P['max_hops']-1): return False
    if not set(arr(obj(C.get('delegation')).get('allowed')))<=set(arr(obj(P.get('delegation')).get('allowed'))): return False
    cc={e['action']:e.get('requires') for e in arr(C.get('conditional'))};pc={e['action']:e.get('requires') for e in arr(P.get('conditional'))}
    for a,r in pc.items():
        if a in C['prohibited_actions'] or (a not in C['authorized_actions'] and a not in cc): continue
        if a not in cc or cc[a]!=r: return False
    if not set(cc)<=set(P['authorized_actions'])|set(pc): return False
    if integer(P.get('expiry_height')) and not(integer(C.get('expiry_height')) and C['expiry_height']<=P['expiry_height']): return False
    if isinstance(P.get('revocation'),dict):
        a=P['revocation'];b=obj(C.get('revocation'));m=a['effective_at'];n=b.get('effective_at')
        if m=='anchor' and n!='anchor' or m=='delivery_ack' and n not in ('anchor','delivery_ack'): return False
        if m==n=='delivery_ack' and integer(a.get('ack_window')) and not(integer(b.get('ack_window')) and b['ack_window']<=a['ack_window']): return False
    if isinstance(P.get('finality'),dict):
        a=P['finality'];b=obj(C.get('finality'))
        if not isinstance(C.get('finality'),dict): return False
        if integer(a.get('depth')) and not(integer(b.get('depth')) and b['depth']>=a['depth']): return False
        ta=bits_target(a.get('max_target_bits'));tb=bits_target(b.get('max_target_bits'))
        if ta is not None and (tb is None or tb>ta): return False
    pw={e['public_key_ed25519_b64'] for e in arr(P.get('witnesses'))};cw={e['public_key_ed25519_b64'] for e in arr(C.get('witnesses'))}
    if not pw<=cw: return False
    for k in ('privacy','ordering'):
        if P.get(k) is not None and (C.get(k) is None or C[k]!=P[k]): return False
    pa=obj(P.get('approval_policy'));ca=obj(C.get('approval_policy'))
    if ca.get('allow_unscoped') is True and pa.get('allow_unscoped') is not True: return False
    return {canonical(e) for e in arr(pa.get('approvers'))}=={canonical(e) for e in arr(ca.get('approvers'))}

def view_check(c,v):
    r=set();hs=obj(v).get('headers');blocks={};floor=bits_target(obj(obj(c.get('grant')).get('finality')).get('max_target_bits'));lb=obj(c.get('lower_bound'))
    okay=floor is not None and integer(lb.get('height')) and hx(lb.get('hash'),64) and isinstance(hs,list) and bool(hs)
    prev=None;ph=None
    if okay:
        for h in hs:
            n=obj(h).get('height');s=obj(h).get('hex')
            if not integer(n) or n<0 or not isinstance(s,str) or re.fullmatch('[0-9a-f]{160}\n?',s) is None: okay=False;break
            raw=bytes.fromhex(s);bh=digest(digest(raw))[::-1].hex();t=target(int.from_bytes(raw[72:76],'little'))
            if prev is not None and (n!=prev+1 or raw[4:36][::-1].hex()!=ph): okay=False;break
            if t is None or t>floor or int(bh,16)>t: okay=False;break
            blocks[n]=(bh,raw[36:68]);prev=n;ph=bh
        if okay and (lb['height'] not in blocks or blocks[lb['height']][0]!=lb['hash']): okay=False
    if not okay: r.add('chain_view_rejected')
    elif len(hs)>200000: r.add('input_too_large');okay=False
    if isinstance(v,dict) and isinstance(hs,list) and (not strict(v) or not all(isinstance(h,dict) and integer(h.get('height')) and hx(h.get('hex'),160) for h in hs)): r.add('view_not_strict')
    return okay,blocks,r

def proof_ops(r):
    a=obj(r.get('anchor'));ops=a.get('proof');cur=body_digest(r)
    if not isinstance(ops,list) or not 1<=len(ops)<=512: return None
    for op in ops:
        if not isinstance(op,dict): return None
        kind=op.get('op')
        if kind=='sha256': cur=digest(cur)
        elif kind=='hexlify': cur=cur.hex().encode()
        elif kind in ('append','prepend'):
            s=op.get('hex')
            if not isinstance(s,str) or re.fullmatch('(?:[0-9a-f]{2})*',s) is None or len(s)>8192: return None
            b=bytes.fromhex(s);cur=cur+b if kind=='append' else b+cur
        else: return None
        if len(cur)>65536: return None
    return cur

def batch_ok(r):
    ops=obj(r.get('anchor')).get('proof');pos=[i for i,x in enumerate(arr(ops)) if obj(x).get('op')=='hexlify']
    if not pos: return True
    if pos!=[0]: return False
    pre=b'';post=b'';found=False
    try:
        for op in ops[1:]:
            if op.get('op')=='sha256': found=True;break
            b=bytes.fromhex(op['hex'])
            if op['op']=='append': post+=b
            elif op['op']=='prepend': pre=b+pre
            else: return False
        if not found: return False
        h=body_digest(r).hex();raw=pre+h.encode()+post;v=parse(raw.decode('utf-8'))
        # "strict JSON" here is the duplicate-key/depth reader (2.2), not
        # strict-value triage: the pinned text expressly allows a NaN token.
        if not isinstance(v,dict) or v.get('schema') not in ('nenrin-agreement-batch-v1','nenrin-witness-batch-v1','nenrin-trace-pin-batch-v0'): return False
        records=v.get('records')
        if not isinstance(records,list) or not all(isinstance(x,dict) for x in records): return False
        if 'count' in v and v['count']!=len(records): return False
        matching=[(i,x) for i,x in enumerate(records) if x.get('sha')==h]
        if len(matching)!=1: return False
        idx,e=matching[0]
        if v['schema']=='nenrin-agreement-batch-v1':
            if r['schema']!='a2a-execution-v0' or e.get('kind')!='execution' or ('schema' in e and e['schema']!=r['schema']): return False
        # Locate the *specific* records[idx].sha token using a small JSON
        # token walker, rather than searching for an unrelated digest string.
        tokens=list(re.finditer(r'"(?:[^"\\]|\\.)*"|[{}\[\]:,]|NaN|-?Infinity|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?',raw.decode('utf-8')))
        offsets=[];cursor=0
        def value(path):
            nonlocal cursor
            m=tokens[cursor];s=m.group();cursor+=1
            if s=='{':
                while tokens[cursor].group()!='}':
                    key=json.loads(tokens[cursor].group());cursor+=2;value(path+[key])
                    if tokens[cursor].group()==',': cursor+=1
                cursor+=1
            elif s=='[':
                j=0
                while tokens[cursor].group()!=']':
                    value(path+[j]);j+=1
                    if tokens[cursor].group()==',': cursor+=1
                cursor+=1
            elif path==['records',idx,'sha']:
                if s=='"'+h+'"': offsets.append(len(raw.decode('utf-8')[:m.start()+1].encode('utf-8')))
        value([])
        return offsets==[len(pre)]
    except (ValueError,KeyError,TypeError,IndexError,UnicodeError): return False

def anchor_height(r):
    h=obj(r.get('anchor')).get('height');return h if integer(h) and h>=0 else None
def valid_anchor(r,blocks):
    a=obj(r.get('anchor'));h=anchor_height(r)
    return h in blocks and a.get('block_hash')==blocks[h][0] and proof_ops(r)==blocks[h][1] and batch_ok(r)

def body_strict(r):
    if not strict(without(r,'anchor','signatures')): return False
    if 'nenrin_ref' in r and r['nenrin_ref'] is not None and not hx(r['nenrin_ref'],64): return False
    ref=obj(r.get('contract_ref'))
    for k in ('contract_sha256','payload_digest'):
        if k in ref and not hx(ref[k],64): return False
    if r['schema']=='a2a-execution-v0':
        for k in ('performed_actions','delegated_to'):
            if k in r and not(isinstance(r[k],list) and all(isinstance(x,str) for x in r[k])): return False
        if 'approvals' in r and not(isinstance(r['approvals'],list) and all(isinstance(x,dict) for x in r['approvals'])): return False
        for a in arr(r.get('approvals')):
            for k in ('sig_b64','signature'):
                raw=b64(a.get(k),64)
                if raw is not None and not sig_strict(raw): return False
    return True
def anchor_strict(r):
    if 'anchor' not in r: return True
    a=r['anchor']
    if not strict(a): return False
    if isinstance(a,dict):
        if 'block_hash' in a and not hx(a['block_hash'],64): return False
        for op in arr(a.get('proof')):
            if isinstance(op,dict) and 'hex' in op and (not isinstance(op['hex'],str) or re.fullmatch('(?:[0-9a-f]{2})*',op['hex']) is None): return False
    return True

def record_auth(c,r):
    parties={p.get('role'):p.get('public_key_ed25519_b64') for p in arr(c.get('parties')) if isinstance(p,dict)}
    witnesses={p.get('name'):p.get('public_key_ed25519_b64') for p in arr(obj(c.get('grant')).get('witnesses')) if isinstance(p,dict)}
    strict_signed=False;lax=False;contractor=False;msg=rbytes(r)
    for s in arr(r.get('signatures')):
        if not isinstance(s,dict): continue
        role=s.get('role');pk=None
        if r['schema']=='a2a-execution-v0':
            if role=='contractor': pk=parties.get(role)
            elif role=='witness': pk=witnesses.get(s.get('witness_name'))
        elif role==('principal' if r['schema']=='a2a-revocation-v0' else 'contractor'): pk=parties.get(role)
        if verify(pk,s.get('sig_b64'),msg) is True:
            lax=True
            if role=='contractor': contractor=True
            if strict(s) and sig_strict(b64(s.get('sig_b64'),64)): strict_signed=True
    return strict_signed,lax,contractor

ALLOWED={
'execution':set('schema contract_ref performed_actions approvals delegated_to nenrin_ref outcomes anchor signatures'.split()),
'revocation':set('schema contract_ref revoked_by anchor signatures'.split()),
'revocation_ack':set('schema contract_ref revocation_sha256 acked_by anchor signatures'.split())}
def nonconforming(r):
    kind=KINDS[r['schema']]
    if set(r)-ALLOWED[kind]: return True
    if kind!='execution': return False
    acts=r.get('performed_actions')
    if not isinstance(acts,list) or not all(isinstance(x,str) for x in acts) or len(acts)>256: return True
    if not all(action(a) for a in acts): return True
    if any(not action(a.get('action')) for a in arr(r.get('approvals')) if isinstance(a,dict)): return True
    out=r.get('outcomes')
    return out is not None and (not isinstance(out,dict) or any(k not in acts or v not in ('ok','error','timeout','partial') for k,v in out.items()))

def settle(c,events,view,walks=None,parent=None,trace=None):
    reasons=set();dev=set();dis={};eventset=[];accepted=[];orphaned=[]
    trace=trace if trace is not None else {}
    csha=sha(cbytes(c)) if isinstance(c,dict) else None
    def finish():
        verdict='underspecified' if reasons else 'deviation' if dev else 'within_grant' if eventset else 'nothing_to_settle'
        k=obj(obj(obj(c).get('grant')).get('finality')).get('depth',1)
        horizon=max(blocks,default=0)-k+1 if integer(k) else 0
        status='undetermined' if reasons else 'final' if all(anchor_height(r)<=horizon for r in accepted+orphaned) else 'provisional'
        bond=obj(c).get('bond');amount=obj(bond).get('amount')
        if not isinstance(bond,dict) or not amount: outcome='n/a'
        elif reasons: outcome='undetermined'
        elif status=='provisional': outcome='pending_finality'
        elif verdict=='deviation': outcome='forfeited'
        else: outcome='held'
        return dict(contract_sha256=csha,verdict=verdict,status=status,bond_outcome=outcome,deviation_codes=sorted(dev) if not reasons else [],underspecified_reasons=sorted(reasons),event_set=eventset,dispositions=dict(sorted(dis.items())))
    blocks={}
    if not isinstance(c,dict): reasons.add('contract_not_verified');return finish()
    if not isinstance(events,list): reasons.add('input_not_settleable');return finish()
    g=obj(c.get('grant'));ap=obj(g.get('approval_policy'));req=obj(c.get('requirements'))
    if any(k in req for k in ('spine','convergence')) or g.get('limits') is not None or req.get('admission') is not None or (door(c) and isinstance(ap.get('approvers'),list) and ap['approvers']):
        raise ValueError('out of core v0 scope; no conformance claimed')
    good=door(c);trace['contract_door']=good
    if not good: reasons.add('contract_not_verified')
    else: reasons.update(terms(c))
    for s in arr(c.get('signatures')):
        raw=b64(obj(s).get('signature'),64)
        if raw is not None and not sig_strict(raw): reasons.add('contract_signature_not_strict')
    bond=c.get('bond');amount=obj(bond).get('amount')
    if bond is not None and not(isinstance(bond,dict) and integer(amount) and 1<=amount<=MAX): reasons.add('bond_malformed')
    if c.get('parent_contract') is not None:
        if parent is None: reasons.add('parent_not_supplied')
        elif not door(parent) or not good or not subset(c,parent): reasons.add('parent_narrowing_failed')
    valid,blocks,vr=view_check(c,view);reasons.update(vr)
    fatal=not good or bool(terms(c) if good else set()) or not valid
    bound=[];seen=set();auth={}
    for r in events:
        if not isinstance(r,dict) or r.get('schema') not in KINDS: continue
        try: s=sha(canonical(r))
        except (ValueError,UnicodeError,RecursionError): continue
        if s in seen: continue
        seen.add(s);ref=obj(r.get('contract_ref'));h=ref.get('contract_sha256')
        if h is None:
            if ref.get('contract_id')==c.get('contract_id'): dis[s]='unbound'
            continue
        if not hx(h,64): dis[s]='inconsistent';continue
        if h!=csha: dis[s]='foreign';continue
        if ref.get('contract_id')!=c.get('contract_id') or (obj(c.get('task')).get('payload_digest') is not None and ref.get('payload_digest')!=c['task']['payload_digest']): dis[s]='inconsistent';continue
        auth[s]=record_auth(c,r);bound.append((s,r))
    kept=[];badanchors=[]
    for s,r in bound:
        signed,lax,_=auth[s];bs=body_strict(r)
        if not signed:
            dis[s]='record_not_strict' if not bs else 'signature_not_strict' if lax else 'rejected';continue
        if not bs: dis[s]='record_not_strict';reasons.add('record_not_strict');continue
        if not anchor_strict(r): badanchors.append((s,r));continue
        if r['schema']=='a2a-revocation-v0' and not isinstance(g.get('revocation'),dict): dis[s]='revocation_not_provided_for';continue
        kept.append((s,r))
    for s,r in badanchors:
        twin=valid and any(rbytes(x)==rbytes(r) and valid_anchor(x,blocks) for _,x in kept)
        if twin: dis[s]='anchor_not_strict'
        else:
            reasons.add('anchor_not_strict');dis[s]='anchor_not_strict'
            # This row fails closed but is not a set-aside row. It remains
            # available to collapse/anchor processing (6.0 table).
            if not (r['schema']=='a2a-revocation-v0' and not isinstance(g.get('revocation'),dict)): kept.append((s,r))
    if len(kept)>10000: reasons.add('input_too_large');fatal=True
    # Collapse is specified whenever the header view verified, even when
    # the contract door did not (6.4). Authentication precedes it.
    if valid:
        groups={}
        for s,r in kept: groups.setdefault(rbytes(r),[]).append((s,r))
        collapsed=[]
        for group in groups.values():
            anchors=[(s,r) for s,r in group if valid_anchor(r,blocks)]
            if len(group)>1 and anchors:
                chosen=min(anchors,key=lambda x:(anchor_height(x[1]),x[0]));collapsed.append(chosen)
                for s,r in group:
                    if s!=chosen[0]: dis[s]='duplicate_dropped'
            else: collapsed.extend(group)
        kept=collapsed
    if fatal: return finish()
    remaining=[]
    for s,r in kept:
        if r['schema']=='a2a-revocation-v0' and r.get('revoked_by')!='principal': dis[s]='ignored';continue
        if nonconforming(r):
            if r['schema']=='a2a-execution-v0' and auth[s][2]: dev.add('nonconforming_record')
            else: dis[s]='rejected';continue
        remaining.append((s,r))
    for s,r in remaining:
        h=anchor_height(r);a=obj(r.get('anchor'));code=None
        if h is None or not hx(a.get('block_hash'),64): code='anchor_incomplete'
        elif h<obj(c.get('lower_bound')).get('height',0): code='anchor_below_lower_bound'
        elif h not in blocks: code='anchor_beyond_observed_chain'
        elif a['block_hash']!=blocks[h][0]: code='orphaned';orphaned.append(r)
        elif proof_ops(r)!=blocks[h][1]: code='anchor_proof_invalid'
        elif not batch_ok(r): code='anchor_batch_leg_refused'
        else: code='accepted';accepted.append(r)
        dis[s]=code
        if code not in ('accepted','orphaned'): reasons.add(code)
    accepted.sort(key=lambda r:(anchor_height(r),sha(canonical(r))))
    eventset.extend(dict(kind=KINDS[r['schema']],sha256=sha(canonical(r)),height=anchor_height(r)) for r in accepted)
    approvals=[];pk=next((p.get('public_key_ed25519_b64') for p in arr(c.get('parties')) if p.get('role')=='principal'),None)
    for r in accepted:
        if r['schema']!='a2a-execution-v0': continue
        for a in arr(r.get('approvals')):
            okay=integer(a.get('valid_until_height')) and a['valid_until_height']>=0 and hx(a.get('nonce'),32) and type(a.get('single_use')) is bool
            v2={k:a.get(k) for k in ('contract_sha256','action','valid_until_height','nonce','single_use')};counted=False;recognized=False
            if okay and hx(a.get('contract_sha256'),64) and verify(pk,a.get('sig_b64'),b'a2a-approval-v2\n'+canonical(v2)) is True:
                recognized=True;counted=a['contract_sha256']==csha
            if not recognized:
                v0={'contract_id':c.get('contract_id'),'payload_digest':obj(c.get('task')).get('payload_digest'),'action':a.get('action')}
                v1={**v0,**{k:a.get(k) for k in ('valid_until_height','nonce','single_use')}}
                recognized=(okay and verify(pk,a.get('sig_b64'),b'a2a-approval-v1\n'+canonical(v1)) is True) or verify(pk,a.get('sig_b64'),b'a2a-approval-v0\n'+canonical(v0)) is True
            if not recognized: dev.add('forged_approval')
            if counted: approvals.append((r,a))
    revs=[];mode=obj(g.get('revocation')).get('effective_at')
    for r in accepted:
        if r['schema']!='a2a-revocation-v0': continue
        h=anchor_height(r);e=h
        if mode=='delivery_ack':
            names={sha(canonical(r)),body_digest(r).hex()}
            ah=[anchor_height(x) for x in accepted if x['schema']=='a2a-revocation-ack-v0' and x.get('revocation_sha256') in names]
            e=min([h+g['revocation']['ack_window']]+ah)
        revs.append(e)
    consumed=set();conditional={x['action'] for x in arr(g.get('conditional'))}
    for r in accepted:
        if r['schema']!='a2a-execution-v0': continue
        h=anchor_height(r);acts=arr(r.get('performed_actions'))
        if any(e<=h for e in revs):
            if acts: dev.add('revoked')
            continue
        for a in acts:
            if integer(g.get('expiry_height')) and h>g['expiry_height']: dev.add('after_expiry')
            if a in arr(g.get('prohibited_actions')): dev.add('prohibited')
            elif a in conditional:
                chosen=next((ap for carrier,ap in approvals if ap.get('action')==a and (carrier is r or anchor_height(carrier)<h) and h<=ap['valid_until_height'] and (not ap['single_use'] or ap['nonce'] not in consumed)),None)
                if chosen is None: dev.add('conditional')
                elif chosen['single_use']: consumed.add(chosen['nonce'])
            elif a not in arr(g.get('authorized_actions')): dev.add('unauthorized')
        if any(d not in arr(obj(g.get('delegation')).get('allowed')) for d in arr(r.get('delegated_to'))): dev.add('delegation')
    if isinstance(walks,list) and walks:
        index={};bad=set()
        for w in walks:
            wh=sha(canonical(w))
            if not strict(w): bad.add(wh)
            elif isinstance(w,dict): index[wh]=w
        for s,r in remaining:
            if r['schema']!='a2a-execution-v0': continue
            ref=r.get('nenrin_ref')
            if ref in bad: reasons.add('walk_not_strict')
            w=index.get(ref);ctx=obj(obj(w).get('context'))
            if ctx.get('contract_sha256') is not None and ctx['contract_sha256']!=csha: dev.add('evidence_names_other_contract')
    if not reasons and req.get('evidence')=='nenrin_required':
        if any(r['schema']=='a2a-execution-v0' and not hx(r.get('nenrin_ref'),64) for r in accepted): dev.add('evidence_missing')
    trace['kept_after_conformance']=[s for s,_ in remaining]
    trace['deviations_before_verdict']=sorted(dev)
    return finish()
