"""Structure of the row dependencies of the cubic-jet system on a UVW2 toy key:
blocks per surviving column, their ranks, twin grouping by shared coefficient vector,
and recovery of the scaling ratio delta_j/delta_i = -3a/b from lambda_i = a x_i + b x_j.
usage: python3 jet_structure.py q n k1 k2 k_l mode seed
"""
import sys, numpy as np
from jet import run, left_kernel, rank_mod_p
from ff import GF

def solve_in_plane(gf, lam, xi, xj):
    """Return (a,b) with lam = a xi + b xj, or None."""
    p = gf.p
    A = np.vstack([xi, xj, lam]) % p
    if gf.rank(A) != 2: return None
    # solve least: use rref on [xi; xj]^T | lam^T
    M = np.column_stack([xi, xj, lam]) % p
    R, piv = gf.rref(M)
    if piv[:2] != [0, 1]: return None
    return int(R[0, 2]), int(R[1, 2])

def main():
    q, n, k1, k2, kl = map(int, sys.argv[1:6]); mode = sys.argv[6]; seed = int(sys.argv[7])
    res = run(q, n, k1, k2, kl, mode, seed, verbose=True)
    gf = GF(q); p = q
    M, sk, keep, X, Z = res['M'], res['sk'], res['keep'], res['X'], res['Z']
    m = n // 2
    K = left_kernel(M, p)                      # deps x rows
    ndep = K.shape[0]
    print("dependencies:", ndep)
    if ndep == 0: return
    perm = sk['perm']; d = None
    # column c of G_pk = delta_c * (S G_sk)[:, sigma(c)], sigma = perm^{-1}
    sigma = np.argsort(perm)
    # delta: recover from P (diag scaling) : P[i,j] = d[j] at (i, perm[i])
    P = sk['P']; delta = np.array([P[perm_inv, j] for j, perm_inv in enumerate(sigma)], dtype=np.int64)
    def twin(c): return c if False else None
    secret_pos = {c: sigma[c] for c in range(n)}
    pair_of = {}
    for c in range(n):
        s = sigma[c]; t = s + m if s < m else s - m
        pair_of[c] = int(np.where(sigma == t)[0][0])
    Zset = set(Z)
    blocks = {}
    for idx, c in enumerate(keep):
        B = K[:, idx * kl:(idx + 1) * kl] % p
        blocks[c] = B
    stats = {'both_rank': [], 'single_rank': [], 'ratio_ok': 0, 'ratio_tested': 0,
             'shared_ok': 0, 'shared_tested': 0}
    seen = set()
    for c in keep:
        c2 = pair_of[c]
        B = blocks[c]
        rk = gf.rank(B)
        if c2 in Zset:
            stats['single_rank'].append(rk)
        else:
            stats['both_rank'].append(rk)
            if (c2, c) in seen: continue
            seen.add((c, c2))
            B2 = blocks[c2]
            # shared coefficient vector: column spaces of B and B2 (as deps x kl) equal, rank 1
            stats['shared_tested'] += 1
            if rk == 1 and gf.rank(B2) == 1 and gf.rank(np.hstack([B, B2])) == 1:
                stats['shared_ok'] += 1
            # ratio: lambda_c = row direction of B (any nonzero row), x_c, x_c2 from X
            ic, ic2 = keep.index(c), keep.index(c2)
            nzrow = next(r for r in range(ndep) if np.any(B[r] % p))
            lam = B[nzrow] % p
            ab = solve_in_plane(gf, lam, X[ic], X[ic2])
            if ab is not None:
                a, b = ab
                stats['ratio_tested'] += 1
                if b % p:
                    pred = (-3 * a * pow(b, p - 2, p)) % p          # delta_c2/delta_c
                    true = (delta[c2] * pow(int(delta[c]), p - 2, p)) % p
                    if pred == true: stats['ratio_ok'] += 1
    from collections import Counter
    print("both-surviving twin columns: block ranks", Counter(stats['both_rank']))
    print("single-surviving columns: block ranks", Counter(stats['single_rank']))
    print("twin pairs with shared rank-1 coefficient vector:", stats['shared_ok'], "/", stats['shared_tested'])
    print("scaling ratio recovered from block direction:", stats['ratio_ok'], "/", stats['ratio_tested'])
    # pairing by coefficient vector: group rank-1 columns by column-space direction
    groups = {}
    for c in keep:
        B = blocks[c]
        if gf.rank(B) != 1: continue
        col = next(B[:, t] for t in range(kl) if np.any(B[:, t] % p))
        # normalise
        f = next(v for v in col if v % p); col = (col * pow(int(f), p - 2, p)) % p
        groups.setdefault(tuple(col.tolist()), []).append(c)
    ok = sum(1 for g in groups.values() if len(g) == 2 and pair_of[g[0]] == g[1])
    bad = sum(1 for g in groups.values() if len(g) != 2 or pair_of[g[0]] != g[1])
    print("pairs read off from coefficient vectors: correct", ok, "incorrect/other groups", bad)

if __name__ == '__main__':
    main()
