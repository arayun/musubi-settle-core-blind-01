#!/usr/bin/env python3
"""Check the archived payload, rerun offline in a temporary copy, compare bytes."""
import hashlib,json,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def main():
    meta=json.loads((ROOT/'FREEZE.json').read_text())
    for line in (ROOT/'PACKAGE_SHA256SUMS').read_text().splitlines():
        h,p=line.split('  ',1)
        if hashlib.sha256((ROOT/p).read_bytes()).hexdigest()!=h: raise ValueError('package hash mismatch '+p)
    lines=''.join(hashlib.sha256((ROOT/'out'/('b%02d.json'%i)).read_bytes()).hexdigest()+'  b%02d.json\n'%i for i in range(1,49))
    if hashlib.sha256(lines.encode()).hexdigest()!=meta['freeze_digest']: raise ValueError('freeze digest mismatch')
    with tempfile.TemporaryDirectory(prefix='musubi-independent-') as temp:
        dst=Path(temp)/'replay'
        shutil.copytree(ROOT,dst,ignore=shutil.ignore_patterns('.git','__pycache__','code.bundle','repeat-out','b01-first'))
        for args in ([sys.executable,'selftest.py'],[sys.executable,'run.py','--outputs','replayed','--log','execution/replayed.json']):
            subprocess.run(args,cwd=dst,check=True)
        for p in (ROOT/'out').glob('*.json'):
            if p.read_bytes()!=(dst/'replayed'/p.name).read_bytes(): raise ValueError('replay differs '+p.name)
        subprocess.run(['git','clone','--quiet',str(ROOT/'code.bundle'),str(Path(temp)/'git-replay')],check=True)
        for kind,want in [('HEAD',meta['code_commit']),('HEAD^{tree}',meta['code_tree'])]:
            got=subprocess.check_output(['git','rev-parse',kind],cwd=Path(temp)/'git-replay',text=True).strip()
            if got!=want: raise ValueError('Git identity differs')
    print('VERIFIED: package payload, code commit/tree, freeze digest, self-checks, and 48 byte-identical replay outputs')
if __name__=='__main__': main()
