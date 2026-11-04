"""Dependency structure of the cubic-jet system on a toy RLCE key (odd characteristic, q=257):
mixed pairs -> rank-1 blocks sharing a coefficient vector; GRS column direction recovered from
the block direction lambda_i = (s^3/3) x_i + s^2 t x_j, i.e. g = s x_i + t x_j with t/s = 3b/a.
usage: python3 jet_rlce_structure.py n k w k_l seed
"""
import sys, numpy as np
from collections import Counter
from jet import rank_mod_p, shorten, jet_system, left_kernel
import grlce
from ff import GF

def main():
    n, k, w, kl, seed = map(int, sys.argv[1:6])
    p = grlce.p; gf = GF(p)
    rng = np.random.default_rng(seed)
    G, sk = grlce.grlce(n, k, w, rng, hidden='grs')
    N = n + w; l = k - kl
    order = rng.permutation(N); Z = sorted(order[:l].tolist()); Zset = set(Z)
    Gs, keep = shorten(G, Z, p); X = Gs.T % p
    M, _ = jet_system(X, p)
    K = left_kernel(M, p); ndep = K.shape[0]
    rows, N3 = M.shape
    print(f"n={n} k={k} w={w} N={N} k_l={kl} rows={rows} monomials={N3} deps={ndep} "
          f"predicted>= {2*(n-k)-w-kl+2}")
    if ndep == 0: return
    perm2 = sk['perm2']; inv = np.argsort(perm2)      # secret position of public column j: inv[j]
    def secret(j): return int(inv[j])
    def mixed_partner(j):
        s = secret(j)
        if s < n - w: return None
        i = (s - (n - w)) // 2; other = n - w + 2 * i + (1 - (s - (n - w)) % 2)
        return int(perm2[other])
    blocks = {c: K[:, idx * kl:(idx + 1) * kl] % p for idx, c in enumerate(keep)}
    st = Counter(); shared_ok = shared_tested = dir_ok = dir_tested = 0; seen = set()
    for c in keep:
        B = blocks[c]; rk = gf.rank(B); partner = mixed_partner(c)
        if partner is None:
            st['unmixed_rank%d' % rk] += 1; continue
        if partner in Zset:
            st['single_rank%d' % rk] += 1; continue
        st['both_rank%d' % rk] += 1
        if (partner, c) in seen: continue
        seen.add((c, partner)); shared_tested += 1
        B2 = blocks[partner]
        if rk == 1 and gf.rank(B2) == 1 and gf.rank(np.hstack([B, B2])) == 1: shared_ok += 1
        # direction of the GRS column in the plane
        ic, ip = keep.index(c), keep.index(partner)
        r0 = next(r for r in range(ndep) if np.any(B[r] % p)); lam = B[r0] % p
        Mx = np.column_stack([X[ic], X[ip], lam]) % p
        R, piv = gf.rref(Mx)
        if piv[:2] == [0, 1] and len(piv) == 2:
            a, b = int(R[0, 2]), int(R[1, 2]); dir_tested += 1
            if a % p:
                t_over_s = (b * pow(3 * a % p, p - 2, p)) % p
                # truth: secret pair index i, A_i = [[a11,a12],[a21,a22]]; column c is first or second of pair?
                s_pos = secret(c); i = (s_pos - (n - w)) // 2; first = ((s_pos - (n - w)) % 2 == 0)
                A = sk['As'][i] % p
                a11, a12, a21, a22 = int(A[0, 0]), int(A[0, 1]), int(A[1, 0]), int(A[1, 1])
                # x_first = S(g a11 + r a21), x_second = S(g a12 + r a22); g ∝ a22 x_first - a21 x_second
                if first: true_ratio = (-a21 * pow(a22, p - 2, p)) % p if a22 % p else None
                else:     true_ratio = (-a22 * pow(a21, p - 2, p)) % p if a21 % p else None
                if true_ratio is not None and true_ratio == t_over_s: dir_ok += 1
    print(dict(st))
    print("mixed pairs (both surviving) with shared rank-1 coefficient vector:", shared_ok, "/", shared_tested)
    print("GRS column direction recovered from block direction:", dir_ok, "/", dir_tested)

if __name__ == '__main__':
    main()
