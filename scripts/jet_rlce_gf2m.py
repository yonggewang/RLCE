"""Cubic-jet count on toy RLCE keys over GF(2^10) (characteristic 2), using the galois package.
usage: python3 jet_rlce_gf2m.py n k w k_l hidden seed    hidden in {grs, random, none}
  none: uniformly random [N,k] code of the same length
Predicted (hidden=grs): excess >= 2(n-k) - w - k_l + 2 when positive (odd-characteristic derivation).
"""
import sys, numpy as np, galois

def rlce_key(GF, n, k, w, rng, hidden):
    q = GF.order
    N = n + w
    if hidden == 'grs':
        x = GF(rng.choice(np.arange(1, q), size=n, replace=False))
        y = GF(rng.integers(1, q, size=n))
        Gs = GF.Zeros((k, n)); row = y.copy()
        for i in range(k):
            Gs[i] = row; row = row * x
    elif hidden == 'random':
        while True:
            Gs = GF(rng.integers(0, q, size=(k, n)))
            if np.linalg.matrix_rank(Gs) == k: break
    else:
        while True:
            G = GF(rng.integers(0, q, size=(k, N)))
            if np.linalg.matrix_rank(G) == k: return G
    R = GF(rng.integers(0, q, size=(k, w)))
    cols = [Gs[:, j] for j in range(n - w)]
    for i in range(w):
        cols.append(Gs[:, n - w + i]); cols.append(R[:, i])
    G1 = GF(np.column_stack([np.array(c) for c in cols]))
    A = GF.Identity(N)
    for i in range(w):
        a = n - w + 2 * i
        while True:
            Ai = GF(rng.integers(1, q, size=(2, 2)))
            if np.linalg.det(Ai) != 0: break
        A[a:a + 2, a:a + 2] = Ai
    perm = rng.permutation(N)
    P = GF.Zeros((N, N))
    for i, j in enumerate(perm): P[i, j] = 1
    while True:
        S = GF(rng.integers(0, q, size=(k, k)))
        if np.linalg.matrix_rank(S) == k: break
    return S @ G1 @ A @ P

def shorten(GF, G, Z):
    k, N = G.shape
    GZ = G[:, Z]
    L = GZ.T.null_space()          # rows r with r GZ = 0  (left null space of GZ)
    Gs = L @ G
    keep = [c for c in range(N) if c not in set(Z)]
    return Gs[:, keep], keep

def jet_system(GF, X):
    npts, kl = X.shape
    mons = [(a, b, c) for a in range(kl) for b in range(a, kl) for c in range(b, kl)]
    N3 = len(mons)
    M = GF.Zeros((npts * kl, N3))
    Xn = np.array(X)
    for j in range(npts):
        x = X[j]
        for mi, (a, b, c) in enumerate(mons):
            for (t, u, v) in ((a, b, c), (b, a, c), (c, a, b)):
                M[j * kl + t, mi] = M[j * kl + t, mi] + x[u] * x[v]
    return M

def run(n, k, w, kl, hidden, seed):
    GF = galois.GF(2 ** 10)
    rng = np.random.default_rng(seed)
    G = rlce_key(GF, n, k, w, rng, hidden)
    N = G.shape[1]
    l = k - kl
    order = rng.permutation(N)
    Z = sorted(order[:l].tolist())
    Gs, keep = shorten(GF, G, Z)
    assert Gs.shape[0] == kl, Gs.shape
    X = Gs.T
    M = jet_system(GF, X)
    rows, N3 = M.shape
    rk = np.linalg.matrix_rank(M)
    kernel = N3 - rk; generic = max(0, N3 - rows)
    print(f"RLCE GF(2^10) n={n} k={k} w={w} N={N} k_l={kl} hidden={hidden} seed={seed} rows={rows} "
          f"monomials={N3} rank={rk} kernel={kernel} generic={generic} excess={kernel-generic} "
          f"odd-char prediction>= {2*(n-k)-w-kl+2}")

if __name__ == '__main__':
    n, k, w, kl = map(int, sys.argv[1:5]); hidden = sys.argv[5]; seed = int(sys.argv[6])
    run(n, k, w, kl, hidden, seed)
