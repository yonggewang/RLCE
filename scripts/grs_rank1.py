import sys, numpy as np
from ff import GF
from jet_jway import shorten, jet_build
p, n, k, kl, d, r, seed = map(int, sys.argv[1:8]); out = sys.argv[8]
gf = GF(p); rng = np.random.default_rng(seed)
al = rng.choice(np.arange(1, p), size=n, replace=False); v = rng.integers(0, p, size=k)
lam = rng.integers(1, p, size=n)
G = np.array([[pow(int(a), e, p) for e in range(k)] for a in al]).T % p      # k x n GRS
G = (G + np.outer(v, lam)) % p
S = rng.integers(0, p, size=(k, k))
while gf.rank(S) < k: S = rng.integers(0, p, size=(k, k))
G = gf.matmul(S, G)[:, rng.permutation(n)] % p
l = k - kl; Z = sorted(rng.permutation(n)[:l].tolist()); Gs, keep = shorten(gf, G, Z)
M, rows, Nd = jet_build(gf, Gs.T % p, d, r)
with open(out, 'wb') as f: np.array([rows, Nd], dtype=np.int64).tofile(f); M.tofile(f)
print(f"GRS+rank1 n={n} k={k} k_l={kl} l={l} (d,r)=({d},{r}) n'={n-l} rows={rows} cols={Nd} predicted n-2k-k_l={n-2*k-kl}")
