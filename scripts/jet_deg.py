"""Order-2 jet at arbitrary degree d: count degree-d forms whose gradient vanishes
at every column of the shortened [n', k_l] public code.  Tests whether higher-degree
jets detect the hidden structure when the degree-3 jet does not (e.g. k1<k2).
usage: python3 jet_deg.py q n k1 k2 k_l d mode seed
"""
import sys, itertools, numpy as np
from jet import rank_mod_p, shorten, make_key
from ff import GF

def monomials(kl, d):
    # exponent multisets of size d over kl variables, as sorted tuples of indices
    return list(itertools.combinations_with_replacement(range(kl), d))

def deriv_rows(X, d, p):
    """Rows indexed by (point, variable t): partial_t of each degree-d monomial at x."""
    npts, kl = X.shape
    mons = monomials(kl, d)
    N = len(mons)
    M = np.zeros((npts * kl, N), dtype=np.int64)
    for j in range(npts):
        x = X[j]
        for mi, mon in enumerate(mons):
            # mon is a sorted tuple of d indices; monomial = prod x[mon]
            cnt = {}
            for a in mon: cnt[a] = cnt.get(a, 0) + 1
            for t, e in cnt.items():
                # d/dx_t = e * x_t^(e-1) * prod_{other} x^...
                val = e % p
                for a, ee in cnt.items():
                    pw = ee - 1 if a == t else ee
                    if pw: val = val * pow(int(x[a]), pw, p) % p
                M[j * kl + t, mi] = (M[j * kl + t, mi] + val) % p
    return M, N

def run(q, n, k1, k2, kl, d, mode, seed):
    gf = GF(q); p = q
    rng = np.random.default_rng(seed)
    G, sk = make_key(gf, n, k1, k2, mode, rng)
    k = k1 + k2; l = k - kl
    order = rng.permutation(n); Z = sorted(order[:l].tolist())
    Gs, keep = shorten(G, Z, p)
    assert Gs.shape[0] == kl, Gs.shape
    X = Gs.T % p
    M, N = deriv_rows(X, d, p)
    rows = M.shape[0]
    rk, _, _ = rank_mod_p(M, p)
    kernel = N - rk; generic = max(0, N - rows)
    print(f"q={q} n={n} k1={k1} k2={k2} k_l={kl} d={d} mode={mode} seed={seed} "
          f"rows={rows} monomials={N} rank={rk} kernel={kernel} generic={generic} "
          f"excess={kernel-generic} regime={'under' if N>=rows else 'OVER'}")
    return kernel - generic

if __name__ == '__main__':
    q, n, k1, k2, kl, d = map(int, sys.argv[1:7]); mode = sys.argv[7]; seed = int(sys.argv[8])
    run(q, n, k1, k2, kl, d, mode, seed)
