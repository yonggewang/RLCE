"""General local masking of a GRS code (hidden-pairing code of arbitrary widths)
and its (d, r) jet system, with the master-count prediction.

Secret generator  G_sk = [[A],[B]]  (k1 + k2 rows).  Hidden coordinate i has a
tuple of j_i public columns  (a_{i,c} ; b_{i,c}),  c = 1..j_i,  and secret mixing
coefficients lambda_{i,c} (all nonzero) with
      sum_c lambda_{i,c} a_{i,c} = 0            (U-part cancels)
      sum_c lambda_{i,c} b_{i,c} = beta_i gamma(alpha_i)   (GRS column appears)
so the hidden curve point lies in the span of the tuple with all coefficients
nonzero.  Width 1 = unmasked GRS column (a = 0, b = GRS column).  Width 2 with
lambda = (1,-1) and k1 > 0 is UVW1; RLCE is widths {1, 2} with k1 = 0.
Public key: S G_sk P.

usage: python3 jet_mask.py p k1 k2 widths k_l d r mode seed outfile
   widths : e.g. "2x50"  or  "1x40,2x20"  (width x count, comma separated)
   mode   : mask | uvw | ctrl_rand
Prints the survival profile of the tuples after shortening, the master-count
prediction  Delta = sum_i (j'_i r - (j'_i - 1) d)^+ - d(k2-1) - 1, the hierarchy
closed form  d(rho+1) - R - k_l - 1  (rho = n - k2, R = N - k), and the generic
pairwise baseline C(n',2)(2r-d-1)^+.  Writes rows,cols + uint16 matrix for rankp.
"""
import sys, numpy as np
from math import comb
from ff import GF
from jet_jway import shorten, jet_build

def parse_widths(spec):
    out = []
    for part in spec.split(','):
        w, cnt = part.lower().split('x'); out += [int(w)] * int(cnt)   # "2x50" = 50 tuples of width 2
    return out

def mask_key(gf, k1, k2, widths, mode, rng):
    p = gf.p; n = len(widths)
    al = rng.choice(np.arange(1, p), size=n, replace=False).astype(np.int64)
    be = rng.integers(1, p, size=n, dtype=np.int64)
    cols = []; tuples = []; sigma = rng.permutation(n)
    for i, j in enumerate(widths):
        gam = np.array([be[i] * pow(int(al[i]), e, p) % p for e in range(k2)], dtype=np.int64)
        if mode in ('uuvgen', 'uuvplain', 'uuvperm'):
            # Marquez-Corbella--Tillich (generalized) (U|U+V) with RS U (dim k1) and RS V (dim k2)
            # on a common support: columns (D1 gamma_U | D2 gamma_V) and (D3 gamma_U | D4 gamma_V).
            assert j == 2
            gU = np.array([pow(int(al[i]), e, p) for e in range(k1)], dtype=np.int64)
            aV = int(al[sigma[i]]) if mode == 'uuvperm' else int(al[i])   # uuvperm: V on a permuted support
            gV = np.array([pow(aV, e, p) for e in range(k2)], dtype=np.int64)
            if mode in ('uuvgen', 'uuvperm'):
                while True:
                    D = rng.integers(1, p, size=(2, 2), dtype=np.int64)
                    if (D[0, 0] * D[1, 1] - D[0, 1] * D[1, 0]) % p: break
            else:
                D = np.array([[1, 0], [1, 1]], dtype=np.int64)
            start = len(cols)
            for c in range(2):
                cols.append(np.concatenate([D[c, 0] * gU % p, D[c, 1] * gV % p]) % p)
            tuples.append([start, start + 1]); continue
        if mode == 'uvw':
            assert j == 2
            lam = np.array([1, p - 1], dtype=np.int64)
        else:
            lam = rng.integers(1, p, size=j, dtype=np.int64)
        A = rng.integers(0, p, size=(k1, j), dtype=np.int64) if j > 1 else np.zeros((k1, 1), dtype=np.int64)
        B = rng.integers(0, p, size=(k2, j), dtype=np.int64)
        inv = pow(int(lam[j - 1]), p - 2, p)
        if j > 1:
            A[:, j - 1] = (-(A[:, :j - 1] @ lam[:j - 1]) * inv) % p
        B[:, j - 1] = ((gam - (B[:, :j - 1] @ lam[:j - 1])) * inv) % p
        start = len(cols)
        for c in range(j):
            cols.append(np.concatenate([A[:, c], B[:, c]]) % p)
        tuples.append(list(range(start, start + j)))
    H = np.array(cols, dtype=np.int64).T % p         # k x N
    k, N = H.shape
    if mode == 'ctrl_rand':
        H = rng.integers(0, p, size=(k, N), dtype=np.int64)
    while True:
        S = rng.integers(0, p, size=(k, k), dtype=np.int64)
        if gf.rank(S) == k: break
    perm = rng.permutation(N)
    G = gf.matmul(S, H)[:, perm] % p
    inv_perm = np.argsort(perm)                      # public position of secret column c is inv_perm[c]
    pub_tuples = [[int(inv_perm[c]) for c in t] for t in tuples]
    return G, pub_tuples

def main():
    p, k1, k2 = map(int, sys.argv[1:4]); widths = parse_widths(sys.argv[4])
    kl, d, r = map(int, sys.argv[5:8]); mode = sys.argv[8]; seed = int(sys.argv[9]); out = sys.argv[10]
    gf = GF(p); rng = np.random.default_rng(seed)
    G, tuples = mask_key(gf, k1, k2, widths, mode, rng)
    k, N = G.shape; n = len(widths); l = k - kl
    assert 0 <= l <= k
    order = rng.permutation(N); Z = sorted(order[:l].tolist()); Zs = set(Z)
    Gs, keep = shorten(gf, G, Z)
    assert Gs.shape[0] == kl, Gs.shape
    X = Gs.T % p; npts = X.shape[0]
    M, rows, Nd = jet_build(gf, X, d, r)
    surv = [sum(1 for c in t if c not in Zs) for t in tuples]
    prof = {}
    for s in surv: prof[s] = prof.get(s, 0) + 1
    delta = sum(max(0, s * r - (s - 1) * d) for s in surv) - d * (k2 - 1) - 1
    rho = n - k2; R = N - k
    closed = d * (rho + 1) - R - kl - 1 if r == d - 1 else None
    baseline = comb(npts, 2) * max(0, 2 * r - d - 1)
    with open(out, 'wb') as f:
        np.array([rows, Nd], dtype=np.int64).tofile(f); M.tofile(f)
    print(f"p={p} k1={k1} k2={k2} widths={sys.argv[4]} N={N} k={k} n={n} rho={rho} R={R} k_l={kl} l={l} "
          f"(d,r)=({d},{r}) mode={mode} seed={seed} n'={npts} rows={rows} cols={Nd} "
          f"baseline={baseline} regime={'under' if Nd >= rows - baseline else 'OVER'} "
          f"profile={dict(sorted(prof.items()))} predicted_Delta={delta} hierarchy_closed={closed}")

if __name__ == '__main__':
    main()
