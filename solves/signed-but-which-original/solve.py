#!/usr/bin/env python3
"""Solve CryoVault 'Signed, But Which Original?' (pip install cryptography).
Usage: python3 solve.py handout.zip
"""
import hashlib, json, sys, zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT='df2fd39adb32a812294cfe264c4a0ddc'
NONCE='d2705557b11d25f6a1607cfd'
CT='7bad7e996d62c88b017ef105997ca1235e513b8b24a724eb88a5204d1771614af735db56d5d02cc8177133b8d79101'
def canon(x): return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
def signed(pk,sig,msg):
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig,msg)
        return True
    except (ValueError,Exception): return False

def read_log(b):
    assert b[:8]==b'ISFCRLOG'
    p=8; out=[]
    while p<len(b):
        n=int.from_bytes(b[p:p+4],'big'); blob=b[p+4:p+4+n]; assert len(blob)==n
        kind=blob[0]; j=1; fields={}; unsigned=None
        while j<len(blob):
            t=blob[j]; length=int.from_bytes(blob[j+1:j+3],'big'); v=blob[j+3:j+3+length]
            assert len(v)==length and t not in fields
            if t==127: unsigned=blob[:j]
            fields[t]=v; j+=3+length
        assert j==len(blob) and len(fields[127])==64
        out.append((kind,fields,unsigned,blob)); p+=4+n
    return out

def merkle(raw):
    h=lambda b: hashlib.sha256(b).digest()
    leaf=[h(b'\x00'+p[3]) for p in raw]
    def sub(v):
        if len(v)==1:return v[0]
        k=1<<((len(v)-1).bit_length()-1)
        return h(b'\x01'+sub(v[:k])+sub(v[k:]))
    return sub(leaf).hex()

def main(archive):
    with zipfile.ZipFile(archive) as z:
        c=json.loads(z.read('signed-but-which-original/case.json'))
        rec=read_log(z.read('signed-but-which-original/entries.bin'))
    keyring={}
    for i,(typ,t,msg,_) in enumerate(rec):
        if typ==1 and t[126]==b'root' and signed(bytes.fromhex(c['root_key']),t[127],msg):
            keyring[t[1].decode()]=(t[2].decode(),t[4],i)
    checkpoints=[]
    for cp in c['checkpoints']:
        signer=keyring.get(cp['key_id']); n=cp['tree_size']
        good_sig=(signer is not None and signer[0]=='log-primary' and
            signed(signer[1],bytes.fromhex(cp['sig']),canon({k:cp[k] for k in ('key_id','root_hash','tree_size')})))
        good_root=n<=len(rec) and merkle(rec[:n])==cp['root_hash']
        print('checkpoint',n,'primary signature',good_sig,'Merkle root',good_root)
        if good_sig and good_root: checkpoints.append(cp)
    assert checkpoints,'no authenticated primary checkpoint'
    n=max(checkpoints,key=lambda cp:cp['tree_size'])['tree_size']; trusted=rec[:n]
    revoked={t[1].decode():int.from_bytes(t[7],'big') for i,(typ,t,msg,_) in enumerate(trusted)
        if typ==2 and t[126]==b'root' and signed(bytes.fromhex(c['root_key']),t[127],msg)}
    def trusted_signature(i,roles):
        typ,t,msg,_=trusted[i]; kid=t[126].decode(); credential=keyring.get(kid)
        if credential is None:return False
        role,pub,issued=credential
        if role not in roles or issued>=i or (kid in revoked and i>=revoked[kid]):return False
        return signed(pub,t[127],t[8] if typ==3 else msg)
    manifests={}
    for i,(typ,t,msg,_) in enumerate(trusted):
        if typ!=3:continue
        try:
            def distinct(pairs):
                d={}
                for k,v in pairs:
                    if k in d:raise ValueError('duplicate JSON key')
                    d[k]=v
                return d
            obj=json.loads(t[8],object_pairs_hook=distinct)
            if canon(obj)!=t[8]:continue
            role=['capture-north'] if obj['action']=='capture' else ['editor-desk']
            if trusted_signature(i,role):manifests[obj['asset_sha256']]=(i,obj)
        except (ValueError,KeyError,UnicodeError):continue
    incidents={t[10].hex() for i,(typ,t,msg,_) in enumerate(trusted)
        if typ==4 and t[9].decode()==c['target_incident_id'] and trusted_signature(i,['ingest-desk'])}
    for idx,last in manifests.values():
        if last['action']!=c['final_action']:continue
        chain=[(idx,last)]
        while len(chain)<c['max_chain']:
            parent=chain[-1][1]['parent_asset_sha256']
            if parent not in manifests:break
            prev=manifests[parent]
            if prev[0]>=chain[-1][0]:break
            chain.append(prev)
        chain=chain[::-1]
        if len(chain)!=c['max_chain']:continue
        if [x['action'] for _,x in chain]!=['capture']+c['intermediate_actions']+[c['final_action']]:continue
        if chain[0][1]['asset_sha256'] not in incidents:continue
        first=chain[0][1]
        fields=[last['asset_sha256'],last['manifest_id'],'>'.join(x['manifest_id'] for _,x in chain),
                first['asset_sha256'],c['target_incident_id'],str(n)]
        E=json.dumps(fields,ensure_ascii=True,separators=(',',':')).encode('ascii')
        key=hashlib.scrypt(b'isfcr-forensics\0'+E,salt=bytes.fromhex(SALT),n=131072,r=8,p=1,maxmem=2**28,dklen=32)
        try:result=AESGCM(key).decrypt(bytes.fromhex(NONCE),bytes.fromhex(CT),b'signed-but-which-original')
        except Exception:continue
        print('Evidence:',json.dumps(fields,indent=2)); print('Authenticated flag:',result.decode('ascii'))
        return
    raise SystemExit('No valid chain authenticated the ciphertext')
if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Usage: python3 solve.py handout.zip')
    main(sys.argv[1])
