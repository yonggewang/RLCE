"""UVW1 scheme (Yang-Zhang, eprint 2025/1149) toy implementation + diagnostics.

KeyGen (Alg 2):
  G_U random k1 x n/2,  G_W random k2 x n/2,  S random invertible k x k, P permutation n x n
  G_RS  = generator of [n/2,k2] Reed-Solomon code (can correct w errors), w <= n/2 - sqrt(n*k2/2)
  G_V = G_RS + G_W
  G_sk = [[G_U, G_U],[G_V, G_W]]
  G_pk = S * G_sk * P
"""
import numpy as np
from ff import GF, square_dim, schur_square_basis

def rs_generator(gf, n2, k2, alphas=None):
    """[n2,k2] RS generator: rows are alpha^0..alpha^{k2-1}."""
    p = gf.p
    if alphas is None:
        # distinct nonzero elements
        alphas = np.arange(1, n2 + 1, dtype=np.int64) % p
        assert len(set(alphas.tolist())) == n2, "need distinct nonzero alphas; pick q > n2"
    G = np.zeros((k2, n2), dtype=np.int64)
    G[0] = 1
    for i in range(1, k2):
        G[i] = (G[i - 1] * alphas) % p
    return G, alphas

def rand_full_rank(gf, r, c, rng):
    p = gf.p
    while True:
        M = rng.integers(0, p, size=(r, c), dtype=np.int64)
        if gf.rank(M) == min(r, c):
            return M

def rand_invertible(gf, k, rng):
    p = gf.p
    while True:
        M = rng.integers(0, p, size=(k, k), dtype=np.int64)
        if gf.rank(M) == k:
            return M

def rand_perm(n, rng):
    perm = rng.permutation(n)
    P = np.zeros((n, n), dtype=np.int64)
    for i, j in enumerate(perm):
        P[i, j] = 1
    return P, perm

def keygen(gf, n, k1, k2, rng, diag=False):
    assert n % 2 == 0
    n2 = n // 2
    k = k1 + k2
    G_U = rand_full_rank(gf, k1, n2, rng)
    G_W = rand_full_rank(gf, k2, n2, rng)
    G_RS, alphas = rs_generator(gf, n2, k2)
    G_V = (G_RS + G_W) % gf.p
    top = np.hstack([G_U, G_U])
    bot = np.hstack([G_V, G_W])
    G_sk = np.vstack([top, bot]) % gf.p
    S = rand_invertible(gf, k, rng)
    if diag:
        # UVW2: invertible diagonal-permutation D
        P, perm = rand_perm(n, rng)
        d = rng.integers(1, gf.p, size=n, dtype=np.int64)
        P = (P * d[None, :]) % gf.p   # column scaling -> diagonal*perm
    else:
        P, perm = rand_perm(n, rng)
    G_pk = gf.matmul(gf.matmul(S, G_sk), P)
    sk = dict(S=S, G_sk=G_sk, P=P, perm=perm, G_U=G_U, G_W=G_W, G_RS=G_RS,
              G_V=G_V, alphas=alphas, n2=n2, k1=k1, k2=k2)
    return G_pk, sk

def diagnostics(gf, n, k1, k2, seed=0, diag=False):
    rng = np.random.default_rng(seed)
    n2 = n // 2
    k = k1 + k2
    G_pk, sk = keygen(gf, n, k1, k2, rng, diag=diag)
    out = {}
    out['params'] = (gf.p, n, k1, k2, k)
    # 1. square dim of public code vs random
    out['sq_pub'] = square_dim(gf, G_pk)
    Grand = rng.integers(0, gf.p, size=(k, n), dtype=np.int64)
    out['sq_rand'] = square_dim(gf, Grand)
    out['sq_bound_random'] = min(n, k * (k + 1) // 2)
    # dual code
    H = gf.nullspace(G_pk)  # (n-k) x n
    out['dual_dim'] = H.shape[0]
    out['sq_dual'] = square_dim(gf, H) if H.shape[0] > 0 else 0
    return G_pk, sk, out

if __name__ == "__main__":
    # tiny sanity param, q prime > n2
    gf = GF(101)
    for (n, k1, k2) in [(40, 10, 10), (60, 15, 15), (80, 20, 20)]:
        G_pk, sk, out = diagnostics(gf, n, k1, k2, seed=1)
        print(out)
