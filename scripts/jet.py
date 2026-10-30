"""Order-2 cubic jet distinguisher on UVW public keys (reproduction of ngcc.dev kem-38-8).

Shorten the public code at m - k_l random positions -> [n', k_l] code; treat the n'
columns as points of F_q^{k_l}; count cubic forms whose gradient vanishes at every
point.  Generic count: max(0, C(k_l+2,3) - n' k_l).

usage: python3 jet.py q n k1 k2 k_l mode seed
  mode uvw1 | uvw2 | ctrl_rand | ctrl_twin   (ctrl_twin: twin shape, RS block random)
"""
import sys, itertools, numpy as np
from ff import GF
from uvw import keygen, rand_full_rank, rand_invertible, rand_perm

def rank_mod_p(M, p):
    """Vectorised Gaussian elimination; returns (rank, reduced matrix, pivot cols)."""
    R = (np.array(M, dtype=np.int64) % p).copy()
    rows, cols = R.shape
    r = 0
    piv = []
    for c in range(cols):
        if r >= rows:
            break
        nz = np.nonzero(R[r:, c])[0]
        if nz.size == 0:
            continue
        i = r + nz[0]
        if i != r:
            R[[r, i]] = R[[i, r]]
        inv = pow(int(R[r, c]), p - 2, p)
        R[r] = (R[r] * inv) % p
        col = R[:, c].copy()
        col[r] = 0
        mask = col != 0
        if mask.any():
            R[mask] = (R[mask] - np.outer(col[mask], R[r])) % p
        piv.append(c)
        r += 1
    return r, R, piv

def left_kernel(M, p):
    """Basis of {y : y M = 0} (row dependencies)."""
    rk, R, piv = rank_mod_p(np.array(M).T, p)   # right kernel of M^T
    rows, cols = R.shape
    pivset = set(piv)
    free = [c for c in range(cols) if c not in pivset]
    basis = []
    for f in free:
        x = np.zeros(cols, dtype=np.int64)
        x[f] = 1
        for i, pc in enumerate(piv):
            x[pc] = (-R[i, f]) % p
        basis.append(x)
    return np.array(basis, dtype=np.int64).reshape(len(basis), cols)

def shorten(G, Z, p):
    """Generator of the code shortened at positions Z (list), and surviving positions."""
    k, n = G.shape
    # codewords vanishing on Z: left kernel of G[:, Z] applied to G
    GZ = G[:, Z]
    L = left_kernel(GZ, p)                 # rows r with r G[:,Z] = 0
    Gs = (L @ G) % p
    keep = [c for c in range(n) if c not in set(Z)]
    return Gs[:, keep], keep

def jet_system(X, p):
    """Rows (c,t): d/dx_t of each cubic monomial at point x_c.  X: n' x k_l."""
    npts, kl = X.shape
    mons = [(a, b, c) for a in range(kl) for b in range(a, kl) for c in range(b, kl)]
    N3 = len(mons)
    M = np.zeros((npts * kl, N3), dtype=np.int64)
    for j in range(npts):
        x = X[j]
        for mi, (a, b, c) in enumerate(mons):
            # derivative of x_a x_b x_c wrt x_t
            for (t, u, v) in ((a, b, c), (b, a, c), (c, a, b)):
                M[j * kl + t, mi] = (M[j * kl + t, mi] + x[u] * x[v]) % p
    return M, mons

def make_key(gf, n, k1, k2, mode, rng):
    p = gf.p
    if mode == 'uvw1':
        G, sk = keygen(gf, n, k1, k2, rng, diag=False); return G, sk
    if mode == 'uvw2':
        G, sk = keygen(gf, n, k1, k2, rng, diag=True); return G, sk
    if mode == 'uuv':   # (U|U+V) with V = RS: UVW1 with G_W = 0
        m = n // 2
        GU = rand_full_rank(gf, k1, m, rng)
        from uvw import rs_generator
        GR, _ = rs_generator(gf, m, k2)
        Gsk = np.vstack([np.hstack([GU, GU]), np.hstack([np.zeros((k2, m), dtype=np.int64), GR])]) % p
        S = rand_invertible(gf, k1 + k2, rng); P, perm = rand_perm(n, rng)
        return gf.matmul(gf.matmul(S, Gsk), P), None
    if mode == 'ctrl_rand':
        return rand_full_rank(gf, k1 + k2, n, rng), None
    if mode == 'ctrl_twin':
        m = n // 2
        GU = rand_full_rank(gf, k1, m, rng); GW = rand_full_rank(gf, k2, m, rng)
        GR = rng.integers(0, p, size=(k2, m), dtype=np.int64)   # random block instead of RS
        Gsk = np.vstack([np.hstack([GU, GU]), np.hstack([(GR + GW) % p, GW])]) % p
        S = rand_invertible(gf, k1 + k2, rng); P, perm = rand_perm(n, rng)
        d = rng.integers(1, p, size=n, dtype=np.int64); P = (P * d[None, :]) % p
        return gf.matmul(gf.matmul(S, Gsk), P), None
    raise ValueError(mode)

def run(q, n, k1, k2, kl, mode, seed, verbose=True):
    gf = GF(q); p = q
    rng = np.random.default_rng(seed)
    G, sk = make_key(gf, n, k1, k2, mode, rng)
    k = k1 + k2; m = n // 2
    l = k - kl
    order = rng.permutation(n)
    Z = sorted(order[:l].tolist())
    Gs, keep = shorten(G, Z, p)
    assert Gs.shape[0] == kl, (Gs.shape, kl)
    X = Gs.T % p                      # n' x k_l points
    M, mons = jet_system(X, p)
    rows, N3 = M.shape
    rk, _, _ = rank_mod_p(M, p)
    kernel = N3 - rk
    generic = max(0, N3 - rows)
    deps = rows - rk
    if verbose:
        print(f"q={q} n={n} k1={k1} k2={k2} k_l={kl} mode={mode} seed={seed} "
              f"rows={rows} monomials={N3} rank={rk} kernel={kernel} generic={generic} "
              f"excess={kernel-generic} row_deps={deps} predicted_excess={k2-kl+2}")
    return dict(rows=rows, N3=N3, rank=rk, kernel=kernel, generic=generic,
                excess=kernel - generic, deps=deps, G=G, sk=sk, Z=Z, keep=keep, X=X, M=M)

if __name__ == '__main__':
    q, n, k1, k2, kl = map(int, sys.argv[1:6]); mode = sys.argv[6]; seed = int(sys.argv[7])
    run(q, n, k1, k2, kl, mode, seed)
