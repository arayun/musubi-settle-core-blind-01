"""Specification-derived checks, never the withheld or public expected set."""
import base64
import copy
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from impl.core import *

ROOT=Path(__file__).resolve().parent
checks=[]
def check(name,condition):
    checks.append({'check':name,'pass':bool(condition)})
    if not condition: raise AssertionError(name)
def main():
    # Fixed RFC8032 section 7.1, test 1: empty message. A general reference.
    pk=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
    sig=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f'+'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
    enc=lambda b:base64.b64encode(b).decode()
    check('RFC8032 test 1 verifies',verify(enc(pk),enc(sig),b'') is True)
    check('RFC8032 test 1 strict',sig_strict(sig))
    check('wrong message rejected',verify(enc(pk),enc(sig),b'x') is False)
    check('identity point rejected',not good_point(b'\x01'+b'\0'*31))
    check('zero small-order point rejected',not good_point(b'\0'*32))
    check('noncanonical point rejected',not good_point(P.to_bytes(32,'little')))
    check('S plus L rejected',not sig_strict(sig[:32]+(int.from_bytes(sig[32:],'little')+L).to_bytes(32,'little')))
    check('noncanonical base64 rejected',b64(enc(pk)+'\n',32) is None)
    check('strict bool distinguished from int',not integer(True))
    check('float tokens remain non-strict',not strict(parse('{"x":1e0}')))
    check('unsafe integer non-strict',not strict(2**53))
    check('NaN read not parse error',not strict(parse('{"x":NaN}')))
    check('surrogate canonicalization',canonical('\ud800')==b'"\\ud800"')
    for label,text in [('duplicate key','{"x":1,"x":2}'),('too deep','['*513+'0'+']'*513),('bad infinity','+Infinity')]:
        failed=False
        try: parse(text)
        except ValueError: failed=True
        check(label+' parse rejected',failed)
    d=ROOT/'sources/blind-01/inputs/b01';read=lambda p:parse(p.read_text())
    c=read(d/'contract.json');v=read(d/'view.json');events=[read(p) for p in sorted((d/'events').glob('*'))]
    base=settle(c,events,v)
    check('b01 independently derived verdict',base['verdict']=='within_grant' and base['status']=='final' and base['bond_outcome']=='held')
    check('b01 two accepted events',len(base['event_set'])==2 and set(base['dispositions'].values())=={'accepted'})
    check('b01 execution precedes revocation',[(e['kind'],e['height']) for e in base['event_set']]==[('execution',800002),('revocation',800003)])
    # The known bug was disclosed before development. This checks derivability
    # from the text; it is NOT a claim that we discovered the bug blindly.
    c=copy.deepcopy(c);c['grant']['approval_policy']={'allow_unscoped':True}
    keys=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in (7,9)]
    for p,k in zip(c['parties'],keys): p['public_key_ed25519_b64']=enc(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))
    def sign(c):
        c['signatures']=[{'domain':p['domain'],'signature':enc(k.sign(cbytes(c)))} for p,k in zip(c['parties'],keys)]
    sign(c);check('synthetic allow_unscoped control door accepts',door(c))
    valid=settle(c,[],v)
    check('4.2 runs for accepted door',valid['underspecified_reasons']==['unscoped_approvals_refused'])
    refused=copy.deepcopy(c);refused['signatures'][0]['signature']=enc(keys[0].sign(b'wrong bytes'))
    check('synthetic rejected control door refuses',not door(refused))
    invalid=settle(refused,[],v)
    check('4.2 skipped when 4.1 refuses',invalid['underspecified_reasons']==['contract_not_verified'])
    (ROOT/'tests').mkdir(exist_ok=True)
    (ROOT/'tests/gate-control-valid.json').write_text(json.dumps(c,sort_keys=True,indent=2)+'\n')
    (ROOT/'tests/gate-control-refused.json').write_text(json.dumps(refused,sort_keys=True,indent=2)+'\n')
    (ROOT/'tests/gate-results.json').write_text(json.dumps({'valid_door':valid,'refused_door':invalid},sort_keys=True,indent=2)+'\n')
    # All blind cases: order and identical copies are not semantic inputs.
    for d in sorted((ROOT/'sources/blind-01/inputs').iterdir()):
        c=read(d/'contract.json');v=read(d/'view.json');es=[read(p) for p in sorted((d/'events').glob('*'))];ws=[read(p) for p in sorted((d/'nenrin').glob('*'))];parent=read(d/'parent.json') if (d/'parent.json').exists() else None
        base=settle(c,es,v,ws,parent)
        check(d.name+' event order invariant',settle(c,list(reversed(es)),v,ws,parent)==base)
        check(d.name+' exact duplicate invariant',settle(c,es+es,v,ws,parent)==base)
    log={'checks':checks,'passed':len(checks),'failed':0,'source':'pinned specification and RFC8032 test 1; no corpus expected values'}
    (ROOT/'execution/selftest.json').write_text(json.dumps(log,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'passed':len(checks),'failed':0}))
if __name__=='__main__': main()
