"""j-way mixing: each GRS column (curve point) is grouped with j-1 fresh random
columns and mixed by a secret j x j invertible matrix with all entries nonzero;
the decoder inverts the block and keeps the GRS coordinate (error weight still
non-increasing).  Length N = j*n0, hidden dimension k0, curve degree k0-1.
This is RLCE for j=2.  We measure at which (d,r) the hidden curve first forces
structural dependencies in the jet system.

usage: python3 jet_jway.py p n0 k0 j k_l d r mode seed outfile
  mode: jway | ctrl_rand | ctrl_block   (ctrl_block: GRS column replaced by random)
Writes rows,cols header + uint16 matrix for rankp.c; prints the generic baseline
C(n',2)*(2r-d-1)^+ and whether the system is underdetermined.
"""
import sys, itertools, numpy as np
from math import comb
from ff import GF

def rref_rows(gf, M):
    R, piv = gf.rref(M); return R[:len(piv)]

def left_null(gf, M):
    # basis of {y : y M = 0}
    p = gf.p
    Mt = (np.array(M, dtype=np.int64).T) % p
    return gf.nullspace(Mt)

def jway_key(gf, n0, k0, j, mode, rng):
    p = gf.p
    # curve points: gamma(alpha_l) in F_p^{k0}, alpha distinct nonzero
    al = rng.choice(np.arange(1, p), size=n0, replace=False).astype(np.int64)
    be = rng.integers(1, p, size=n0, dtype=np.int64)
    G = np.zeros((k0, n0), dtype=np.int64); row = be.copy()
    for i in range(k0):
        G[i] = row % p; row = (row * al) % p          # GRS columns beta*gamma(alpha)
    cols = []
    for l in range(n0):
        if mode == 'ctrl_block':
            grp = [rng.integers(0, p, size=k0, dtype=np.int64)]
        else:
            grp = [G[:, l].copy()]
        for _ in range(j - 1):
            grp.append(rng.integers(0, p, size=k0, dtype=np.int64))
        B = np.array(grp, dtype=np.int64).T                # k0 x j
        while True:
            A = rng.integers(1, p, size=(j, j), dtype=np.int64)  # all nonzero
            if gf.rank(A) == j: break
        cols.append(gf.matmul(B, A))                       # k0 x j mixed
    H = np.hstack(cols) % p                                 # k0 x (j n0)
    if mode == 'ctrl_rand':
        H = rng.integers(0, p, size=(k0, j * n0), dtype=np.int64)
    # scramble + permute
    while True:
        S = rng.integers(0, p, size=(k0, k0), dtype=np.int64)
        if gf.rank(S) == k0: break
    N = j * n0
    perm = rng.permutation(N)
    G_pub = gf.matmul(S, H)[:, perm] % p
    return G_pub, k0

def shorten(gf, G, Z):
    p = gf.p; k, N = G.shape
    L = left_null(gf, G[:, Z])                   # (k-|Z|) x k
    Gs = gf.matmul(L, G)
    keep = [c for c in range(N) if c not in set(Z)]
    return Gs[:, keep], keep

def jet_build(gf, X, d, r):
    p = gf.p; npts, kl = X.shape
    mons = list(itertools.combinations_with_replacement(range(kl), d))
    E = np.zeros((len(mons), kl), dtype=np.int64)
    for i, mon in enumerate(mons):
        for t in mon: E[i, t] += 1
    ders = list(itertools.combinations_with_replacement(range(kl), r - 1))
    A = np.zeros((len(ders), kl), dtype=np.int64)
    for i, der in enumerate(ders):
        for t in der: A[i, t] += 1
    Nd = len(mons); nder = len(ders); rows = npts * nder
    FF = np.ones((d + 1, d + 1), dtype=np.int64)
    for e in range(d + 1):
        for a in range(1, d + 1):
            FF[e, a] = (FF[e, a - 1] * (e - a + 1)) % p if a <= e else 0
    M = np.zeros((rows, Nd), dtype=np.uint16)
    for jp in range(npts):
        x = X[jp]
        PT = np.ones((kl, d + 1), dtype=np.int64)
        for a in range(1, d + 1): PT[:, a] = (PT[:, a - 1] * x) % p
        for di in range(nder):
            a = A[di]
            valid = np.all(E >= a[None, :], axis=1)
            expo = np.clip(E - a[None, :], 0, d)
            coef = np.ones(Nd, dtype=np.int64); val = np.ones(Nd, dtype=np.int64)
            for t in range(kl):
                if a[t]: coef = (coef * FF[E[:, t], a[t]]) % p
                val = (val * PT[t, expo[:, t]]) % p
            rowv = (coef * val) % p; rowv[~valid] = 0
            M[jp * nder + di] = rowv.astype(np.uint16)
    return M, rows, Nd

def main():
    p, n0, k0, j, kl, d, r = map(int, sys.argv[1:8]); mode = sys.argv[8]; seed = int(sys.argv[9]); out = sys.argv[10]
    gf = GF(p); rng = np.random.default_rng(seed)
    G, k = jway_key(gf, n0, k0, j, mode, rng)
    N = G.shape[1]; l = k - kl
    order = rng.permutation(N); Z = sorted(order[:l].tolist())
    Gs, keep = shorten(gf, G, Z)
    assert Gs.shape[0] == kl, Gs.shape
    X = Gs.T % p; npts = X.shape[0]
    M, rows, Nd = jet_build(gf, X, d, r)
    baseline = comb(npts, 2) * max(0, 2 * r - d - 1)
    with open(out, 'wb') as f:
        np.array([rows, Nd], dtype=np.int64).tofile(f); M.tofile(f)
    print(f"p={p} n0={n0} k0={k0} j={j} N={N} k_l={kl} (d,r)=({d},{r}) mode={mode} seed={seed} "
          f"rows={rows} cols={Nd} baseline={baseline} regime={'under' if Nd>=rows else 'OVER'}")

if __name__ == '__main__':
    main()
