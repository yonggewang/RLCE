"""Jet degree of an alternant code = F_p-subfield subcode of a GRS code over F_{p^m}.
H[i,j] = y_j alpha_j^i (i<deg, j<n) over F_{p^m}; alternant = {c in F_p^n : H c^T = 0}.
Build an F_p generator, shorten, and measure the (d,r) jet kernel against a random
[n,k] F_p code control. Reports excess = kernel_struct - kernel_rand for each (d,r).

usage: python3 jet_alternant.py p m n deg k_l d r seed     (field F_{p^m})
"""
import sys, itertools, numpy as np, galois
from math import comb

def jet_rank(Xint, p, d, r):
    """Rank over F_p of the (d,r) jet system of points Xint (n' x kl), entries ints."""
    GFp = galois.GF(p)
    npts, kl = Xint.shape
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
    M = np.zeros((rows, Nd), dtype=np.int64)
    for jp in range(npts):
        x = Xint[jp] % p
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
            rv = (coef * val) % p; rv[~valid] = 0
            M[jp * nder + di] = rv
    rk = np.linalg.matrix_rank(GFp(M.astype(np.int64) % p))
    return rows, Nd, Nd - int(rk)

def alternant_gen(p, m, n, deg, seed):
    GF = galois.GF(p ** m); GFp = galois.GF(p)
    rng = np.random.default_rng(seed)
    al = GF(rng.choice(np.arange(1, p ** m), size=n, replace=False))
    y = GF(rng.integers(1, p ** m, size=n))
    # H over F_{p^m}, deg x n
    H = GF.Zeros((deg, n)); row = y.copy()
    for i in range(deg):
        H[i] = row; row = row * al
    # expand each F_{p^m} entry into m F_p coords -> H' (m*deg) x n over F_p
    Hp = GFp(np.zeros((m * deg, n), dtype=int))
    for i in range(deg):
        for j in range(n):
            v = H[i, j]
            vec = np.array(v.vector())    # length-m F_p vector (galois)
            for t in range(m):
                Hp[i * m + t, j] = int(vec[t])
    # alternant code = right null space of Hp over F_p
    G = Hp.null_space()                   # k x n, k = n - rank(Hp)
    return np.array(G).astype(np.int64), G.shape[0]

def main():
    p, m, n, deg, kl, d, r = map(int, sys.argv[1:8]); seed = int(sys.argv[8])
    G, k = alternant_gen(p, m, n, deg, seed)
    rng = np.random.default_rng(seed + 1000)
    # shorten at l random positions over F_p
    GFp = galois.GF(p)
    l = k - kl
    order = rng.permutation(n); Z = sorted(order[:l].tolist()); keep = [c for c in range(n) if c not in set(Z)]
    Gg = GFp(G % p); L = Gg[:, Z].T.null_space(); Gs = np.array(L @ Gg).astype(np.int64)
    X = Gs[:, keep].T % p
    rows, Nd, kern = jet_rank(X, p, d, r)
    # random control [n,k] over F_p, shortened likewise
    Gr = GFp(rng.integers(0, p, size=(k, n)))
    Lr = Gr[:, Z].T.null_space(); Grs = np.array(Lr @ Gr).astype(np.int64)
    Xr = Grs[:, keep].T % p
    _, _, kernr = jet_rank(Xr, p, d, r)
    print(f"alternant F_{p}^{m} n={n} deg={deg} k={k} k_l={kl} (d,r)=({d},{r}) seed={seed} "
          f"rows={rows} cols={Nd} kernel_struct={kern} kernel_rand={kernr} excess={kern-kernr} "
          f"regime={'under' if Nd>=rows else 'OVER'}")

if __name__ == '__main__':
    main()
