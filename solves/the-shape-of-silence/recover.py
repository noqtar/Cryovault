"""Reconstruct the exact piecewise-linear model and return all 24 target values.

Usage: python3 recover.py data.json > answers.json
Needs Python 3 standard library only. No training or model access is needed.
"""
import json
import sys
from fractions import Fraction as Q

with open(sys.argv[1] if len(sys.argv)>1 else 'data.json', encoding='utf-8') as f:
    data=json.load(f)

def dot(a,b):
    return sum(x*y for x,y in zip(a,b))

def z(x):
    return [Q(v) for v in x]+[Q(1)]

def fit_affine(cloud):
    # Seven nearby observations uniquely identify the six slopes + intercept.
    rows=[z(p['x'])+[Q(p['y'])] for p in cloud]
    for j in range(7):
        pivot=next(k for k in range(j,7) if rows[k][j]!=0)
        rows[j],rows[pivot]=rows[pivot],rows[j]
        v=rows[j][j]
        rows[j]=[x/v for x in rows[j]]
        for k in range(7):
            if k!=j:
                v=rows[k][j]
                rows[k]=[a-v*b for a,b in zip(rows[k],rows[j])]
    return tuple(row[7] for row in rows)

def center(cloud):
    return tuple(sum((Q(p['x'][i]) for p in cloud),Q(0))/len(cloud) for i in range(6))+(Q(1),)

pairs=[]
for capture in data['captures']:
    if capture['model_version']!=data['model_version']:
        continue  # mixed-in observations from a stale model
    pairs.append([(fit_affine(cloud),center(cloud),cloud) for cloud in capture['clouds']])

hinges={}
for before,after in pairs:
    w0,c0,_=before
    w1,c1,_=after
    delta=tuple(b-a for a,b in zip(w0,w1))
    p0,p1=dot(delta,c0),dot(delta,c1)
    assert p0*p1<0, 'pair must straddle one hinge'
    sense=1 if p1>0 else -1
    assert delta not in hinges or hinges[delta]==sense
    hinges[delta]=sense

assert len(hinges)==9, len(hinges)

def gradient(delta,sense,point):
    return delta if sense*dot(delta,point)>0 else (Q(0),)*7

def relu_contribution(delta,sense,point):
    return sense*max(Q(0),sense*dot(delta,point))

ref,c0,_=pairs[0][0]
base=tuple(ref[i]-sum(gradient(d,s,c0)[i] for d,s in hinges.items()) for i in range(7))

def predict(x):
    point=z(x)
    return dot(base,point)+sum(relu_contribution(d,s,point) for d,s in hinges.items())

for pair in pairs:
    for local,loc,cloud in pair:
        recovered=tuple(base[i]+sum(gradient(d,s,loc)[i] for d,s in hinges.items()) for i in range(7))
        assert recovered==local, 'local affine map mismatch'
        for observation in cloud:
            assert predict(observation['x'])==Q(observation['y']), 'capture mismatch'

for anchor in data['anchors']:
    assert predict(anchor['x'])==Q(anchor['y']), 'anchor mismatch'

answers=[str(predict(target)) for target in data['targets']]
assert len(answers)==24
print(json.dumps(answers,separators=(',',':')))
print(f"Verified {sum(len(cloud) for pair in pairs for _,_,cloud in pair)} current captures, "
      f"{len(data['anchors'])} anchors and {len(hinges)} hinges.", file=sys.stderr)
