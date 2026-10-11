#!/usr/bin/env python3
"""Reconstruct acquisition-A records in CryoVault 'The Aggregate Remembers'.

Usage: unzip the_aggregate_remembers.zip; python3 recover_aggregate.py
Dependencies: numpy, scipy, cryptography (last is used by unlock.py).

This is a clean reproducibility implementation of the method described in the
writeup, produced from the supplied challenge data, not a claim about which
commands were originally run during the timed event.
"""
import json
from pathlib import Path
import numpy as np
from scipy.optimize import least_squares

D = json.loads(Path('data.json').read_text())
model = D['model']
checkpoints = {c['id']: np.array([float(x) for x in c['weights']])
               for c in model['checkpoints']}
eta = 1.0 / 8.0  # supplied lr
weight_decay = 1.0 / 64.0
rows = [r for r in D['updates'] if r['cohort'] == 'acquisition-A']
W = np.array([checkpoints[r['checkpoint']] for r in rows])
M = np.array([r['mix'] for r in rows], dtype=float)
M /= M.sum(axis=1, keepdims=True)
Y = np.array([-np.array([float(x) for x in r['delta']]) / eta
              - weight_decay * checkpoints[r['checkpoint']] for r in rows])
C = 3  # model.clients has three clients

# Per-checkpoint mixing regression yields each client's approximate gradient.
initial = []
all_weights = np.array(list(checkpoints.values()))
for client in range(C):
    grad_by_checkpoint = []
    for ckpt_id, w in checkpoints.items():
        inds = [i for i, row in enumerate(rows)
                if row['checkpoint'] == ckpt_id]
        g_by_client = np.linalg.lstsq(M[inds], Y[inds], rcond=None)[0]
        grad_by_checkpoint.append(g_by_client[client])
    G = np.column_stack(grad_by_checkpoint)

    # Rank two: g(w) = (w.m - 1)m + (w.d)d, with m[-1]=1, d[-1]=0.
    U, _, _ = np.linalg.svd(G, full_matrices=False)
    k = int(np.argmax(np.abs(G[-1])))
    m0 = G[:, k] / G[-1, k]
    direction = U[:, :2] @ np.array([-U[-1, 1], U[-1, 0]])
    direction[-1] = 0
    direction /= np.linalg.norm(direction)
    z = all_weights @ direction
    t = np.dot(z, G[-1] + 1 - all_weights @ m0) / np.dot(z, z)
    mean = m0 + t * direction
    resid = G - np.outer(mean, G[-1])
    variance = np.dot(z, direction @ resid) / np.dot(z, z)
    halfdiff = np.sqrt(abs(variance)) * direction
    initial.append([mean[:16], halfdiff[:16]])

# Fit the 3 client pairs jointly to all 60 mixed-client updates.
# The nuisance clients are needed to separate the target's contribution.
def components(flat):
    z = flat.reshape(C, 2, 16)
    mean = np.column_stack((z[:, 0, :], np.ones(C)))
    halfdiff = np.column_stack((z[:, 1, :], np.zeros(C)))
    a = W @ mean.T - 1
    b = W @ halfdiff.T
    grad = (a[:, :, None] * mean[None, :, :]
            + b[:, :, None] * halfdiff[None, :, :])
    prediction = np.einsum('rc,rcj->rj', M, grad)
    return mean, halfdiff, a, b, prediction

def residual(flat):
    return (components(flat)[-1] - Y).ravel()

def jacobian(flat):
    mean, halfdiff, a, b, _ = components(flat)
    J = np.zeros((len(rows), 17, C, 2, 16))
    I = np.eye(17)[:, :16]
    for c in range(C):
        J[:, :, c, 0, :] = M[:, c, None, None] * (
            np.einsum('j,ri->rji', mean[c], W[:, :16])
            + a[:, c, None, None] * I)
        J[:, :, c, 1, :] = M[:, c, None, None] * (
            np.einsum('j,ri->rji', halfdiff[c], W[:, :16])
            + b[:, c, None, None] * I)
    return J.reshape(len(rows) * 17, C * 2 * 16)

sol = least_squares(residual, np.array(initial).ravel(), jac=jacobian,
                    method='lm', max_nfev=120)
if not sol.success:
    raise RuntimeError('Least-squares did not converge')
pairs = sol.x.reshape(C, 2, 16)
target = model['clients'].index(model['target_client'])

recovered = []
for feature_vector in (pairs[target, 0] + pairs[target, 1],
                       pairs[target, 0] - pairs[target, 1]):
    raw = np.empty(16, dtype=int)
    for j, byte_index in enumerate(model['permutation']):
        val = feature_vector[j] * model['scale'][j] + model['center'][j]
        raw[byte_index] = int(np.rint(val))
    if not np.all((0 <= raw) & (raw <= 255)):
        raise ValueError('A byte fell out of range')
    recovered.append(bytes(raw.tolist()).hex())

answer = sorted(recovered)  # ASCII sort (the checker requires ordered list)
print('Recovered:', json.dumps(answer, separators=(',', ':')))
print('Mixed-gradient residual RMS:', f'{np.sqrt(np.mean(sol.fun**2)):.6f}')
try:
    import sys
    sys.path.insert(0, str(Path.cwd()))
    from unlock import unlock
    print('FLAG:', unlock(answer))
except ImportError:
    print('Place unlock.py alongside this script to check the flag.')