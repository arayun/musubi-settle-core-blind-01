#!/usr/bin/env python3
"""Offline runner. Reproduction never fetches or imports other settlers."""
import argparse
import hashlib
import json
import platform
import sys
import time
from datetime import datetime,timezone
from pathlib import Path
import cryptography
from impl.core import parse,settle

ROOT=Path(__file__).resolve().parent
def dump(p,v):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=True)+'\n')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--case');ap.add_argument('--outputs',default='out');ap.add_argument('--log',default='execution/run.json');a=ap.parse_args()
    pub=ROOT/'sources/blind-01';manifest={}
    for line in (pub/'SHA256SUMS').read_text().splitlines():
        h,p=line.split('  ',1);actual=hashlib.sha256((pub/p).read_bytes()).hexdigest()
        if actual!=h: raise ValueError('input checksum mismatch: '+p)
        manifest[p]=actual
    actual_files={p.relative_to(pub).as_posix() for p in (pub/'inputs').rglob('*') if p.is_file()}
    if actual_files!=set(manifest): raise ValueError('input file inventory differs')
    spec=hashlib.sha256((ROOT/'sources/SETTLE_CORE_v0.md').read_bytes()).hexdigest()
    if spec!='3382374416254f85eec0c4f03699161748db5999794e75b68a00e7a4b7cf27c2': raise ValueError('spec identity differs')
    log={'started_utc':datetime.now(timezone.utc).isoformat(),'runtime':sys.version,'platform':platform.platform(),'cryptography':cryptography.__version__,'spec_sha256':spec,'checked_input_files':len(manifest),'cases':[]}
    for d in sorted((pub/'inputs').iterdir()):
        if a.case and d.name!=a.case: continue
        trace={};t=time.monotonic();error=None
        try:
            read=lambda p:parse(p.read_text(encoding='utf-8'))
            c=read(d/'contract.json');v=read(d/'view.json');events=[read(p) for p in sorted((d/'events').glob('*.json'))]
            walks=[read(p) for p in sorted((d/'nenrin').glob('*.json'))]
            parent=read(d/'parent.json') if (d/'parent.json').exists() else None
            result=settle(c,events,v,walks,parent,trace)
        except Exception as e:
            error=type(e).__name__+': '+str(e);result={'error':error}
        out=ROOT/a.outputs/(d.name+'.json');dump(out,result)
        row={'id':d.name,'success':error is None,'error':error,'elapsed_seconds':round(time.monotonic()-t,6),'inputs':{p:h for p,h in manifest.items() if p.startswith('inputs/'+d.name+'/')},'output_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'trace':trace}
        log['cases'].append(row)
        print(d.name,'ERROR '+error if error else result['verdict']+' / '+result['status'],flush=True)
    log['finished_utc']=datetime.now(timezone.utc).isoformat();log['success_count']=sum(r['success'] for r in log['cases']);dump(ROOT/a.log,log)
    return 0 if all(r['success'] for r in log['cases']) else 1
if __name__=='__main__': sys.exit(main())
