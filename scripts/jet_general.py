"""General (d, r) jet system for a UVW key: degree-d forms vanishing to order r
(all partial derivatives of order r-1 vanish) at every column of the shortened code.
Writes the system as uint16 to a file for the C ranker, and prints the predicted
dependency count  Delta = max(0,2r-d)*L + r*S1 + d*Z2 - d(k2-1) - 1
where L, S1, Z2 = numbers of twin pairs with 0, 1, 2 shortened coordinates.

usage: python3 jet_general.py q n k1 k2 k_l d r mode seed outfile
"""
import sys, itertools, numpy as np
from math import comb
from jet import shorten, make_key
from ff import GF

def build(q, n, k1, k2, kl, d, r, mode, seed, outfile):
    gf = GF(q); p = q
    rng = np.random.default_rng(seed)
    G, sk = make_key(gf, n, k1, k2, mode, rng)
    k = k1 + k2; m = n // 2; l = k - kl
    order = rng.permutation(n); Z = sorted(order[:l].tolist()); Zset = set(Z)
    Gs, keep = shorten(G, Z, p)
    assert Gs.shape[0] == kl, Gs.shape
    X = Gs.T % p                                   # n' x k_l
    npts = X.shape[0]
    # exponent matrix of degree-d monomials
    mons = list(itertools.combinations_with_replacement(range(kl), d))
    E = np.zeros((len(mons), kl), dtype=np.int64)
    for i, mon in enumerate(mons):
        for t in mon: E[i, t] += 1
    Nd = len(mons)
    # derivative multi-indices of order r-1
    ders = list(itertools.combinations_with_replacement(range(kl), r - 1))
    A = np.zeros((len(ders), kl), dtype=np.int64)
    for i, der in enumerate(ders):
        for t in der: A[i, t] += 1
    nder = len(ders)
    rows = npts * nder
    # falling factorial table FF[e][a] = e(e-1)...(e-a+1) mod p
    FF = np.ones((d + 1, d + 1), dtype=np.int64)
    for e in range(d + 1):
        for a in range(1, d + 1):
            FF[e, a] = (FF[e, a - 1] * (e - a + 1)) % p if a <= e else 0
    M = np.zeros((rows, Nd), dtype=np.uint16)
    for j in range(npts):
        x = X[j]
        PT = np.ones((kl, d + 1), dtype=np.int64)      # PT[t][a] = x_t^a
        for a in range(1, d + 1): PT[:, a] = (PT[:, a - 1] * x) % p
        for di in range(nder):
            a = A[di]
            valid = np.all(E >= a[None, :], axis=1)
            expo = np.clip(E - a[None, :], 0, d)
            coef = np.ones(Nd, dtype=np.int64)
            val = np.ones(Nd, dtype=np.int64)
            for t in range(kl):
                if a[t]:
                    coef = (coef * FF[E[:, t], a[t]]) % p
                val = (val * PT[t, expo[:, t]]) % p
            row = (coef * val) % p
            row[~valid] = 0
            M[j * nder + di] = row.astype(np.uint16)
    # pairing statistics for the prediction
    if sk is not None:
        perm = sk['perm']; sigma = np.argsort(perm)
        L = S1 = Z2 = 0
        for c in range(n):
            s = sigma[c]
            if s >= m: continue                         # count each pair once (first half)
            c2 = int(np.where(sigma == s + m)[0][0])
            z = (c in Zset) + (c2 in Zset)
            if z == 0: L += 1
            elif z == 1: S1 += 1
            else: Z2 += 1
        delta = max(0, 2 * r - d) * L + r * S1 + d * Z2 - d * (k2 - 1) - 1
        closed = (2 * r - d) * m + (d - r) * l - d * (k2 - 1) - 1
    else:
        L = S1 = Z2 = -1; delta = closed = 0
    generic = max(0, Nd - rows)
    with open(outfile, 'wb') as f:
        np.array([rows, Nd], dtype=np.int64).tofile(f)
        M.tofile(f)
    print(f"q={q} n={n} k1={k1} k2={k2} k_l={kl} (d,r)=({d},{r}) mode={mode} seed={seed} "
          f"rows={rows} monomials={Nd} generic_kernel={generic} pairs(L,S1,Z2)=({L},{S1},{Z2}) "
          f"predicted_deps={max(0,delta)} closed_form={closed} regime={'under' if Nd>=rows else 'OVER'}")

if __name__ == '__main__':
    q, n, k1, k2, kl, d, r = map(int, sys.argv[1:8]); mode = sys.argv[8]; seed = int(sys.argv[9]); out = sys.argv[10]
    build(q, n, k1, k2, kl, d, r, mode, seed, out)
