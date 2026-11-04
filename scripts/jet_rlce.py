"""Order-2 cubic jet count on toy RLCE public keys (hidden GRS [n,k], w mixed pairs, length N=n+w).
usage: python3 jet_rlce.py n k w k_l hidden seed     hidden in {grs, random}
Predicted (hidden=grs): excess >= 2(n-k) - w - k_l + 2 when positive.
"""
import sys, numpy as np
from jet import rank_mod_p, shorten, jet_system
import grlce

def run(n, k, w, kl, hidden, seed):
    p = grlce.p
    rng = np.random.default_rng(seed)
    G, sk = grlce.grlce(n, k, w, rng, hidden=hidden)
    N = n + w
    l = k - kl
    order = rng.permutation(N)
    Z = sorted(order[:l].tolist())
    Gs, keep = shorten(G, Z, p)
    assert Gs.shape[0] == kl
    X = Gs.T % p
    M, mons = jet_system(X, p)
    rows, N3 = M.shape
    rk, _, _ = rank_mod_p(M, p)
    kernel = N3 - rk; generic = max(0, N3 - rows)
    print(f"RLCE q={p} n={n} k={k} w={w} N={N} k_l={kl} hidden={hidden} seed={seed} rows={rows} "
          f"monomials={N3} rank={rk} kernel={kernel} generic={generic} excess={kernel-generic} "
          f"predicted>= {2*(n-k)-w-kl+2}")

if __name__ == '__main__':
    n, k, w, kl = map(int, sys.argv[1:5]); hidden = sys.argv[5]; seed = int(sys.argv[6])
    run(n, k, w, kl, hidden, seed)
