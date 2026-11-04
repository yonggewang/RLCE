"""Full-size cubic-jet (3,2) system for an RLCE key over GF(2^m), written for the C ranker.
usage: python3 rlce_full.py m n k w k_l mode seed outfile     mode in {grs, random, none}
  grs    : RLCE key (hidden GRS [n,k], w mixed pairs with GL2 mixing, all entries nonzero, S, P2)
  random : same construction with the GRS block replaced by a random [n,k] code (control)
  none   : uniformly random [N,k] code (control)
Prints the predicted structural dependency count 2(n-k) - w - k_l + 2 (for mode grs).
File format: int64 rows, cols; then rows*cols uint16 field elements (galois integer repr).
"""
import sys, time, numpy as np, galois

def rlce_key(GF, n, k, w, rng, mode):
    q = GF.order; N = n + w
    if mode == 'none':
        while True:
            G = GF(rng.integers(0, q, size=(k, N)))
            if np.linalg.matrix_rank(G) == k: return G, None
    if mode == 'grs':
        x = GF(rng.choice(np.arange(1, q), size=n, replace=False))
        y = GF(rng.integers(1, q, size=n))
        Gs = GF.Zeros((k, n)); row = y.copy()
        for i in range(k):
            Gs[i] = row; row = row * x
    else:
        while True:
            Gs = GF(rng.integers(0, q, size=(k, n)))
            if np.linalg.matrix_rank(Gs) == k: break
    R = GF(rng.integers(0, q, size=(k, w)))
    cols = [np.array(Gs[:, j]) for j in range(n - w)]
    for i in range(w):
        cols.append(np.array(Gs[:, n - w + i])); cols.append(np.array(R[:, i]))
    G1 = GF(np.column_stack(cols))
    # block-diagonal mixing with all entries nonzero
    A = GF.Identity(N)
    As = []
    for i in range(w):
        a = n - w + 2 * i
        while True:
            Ai = GF(rng.integers(1, q, size=(2, 2)))
            if np.linalg.det(Ai) != 0: break
        A[a:a + 2, a:a + 2] = Ai; As.append(Ai)
    perm = rng.permutation(N)
    P = GF.Zeros((N, N))
    for i, j in enumerate(perm): P[i, j] = 1
    while True:
        S = GF(rng.integers(0, q, size=(k, k)))
        if np.linalg.matrix_rank(S) == k: break
    G = S @ G1 @ A @ P
    return G, dict(perm=perm, As=As)

def main():
    m, n, k, w, kl = map(int, sys.argv[1:6]); mode = sys.argv[6]; seed = int(sys.argv[7]); out = sys.argv[8]
    GF = galois.GF(2 ** m)
    rng = np.random.default_rng(seed)
    t0 = time.time()
    G, sk = rlce_key(GF, n, k, w, rng, mode)
    N = G.shape[1]; l = k - kl
    print(f"key generated in {time.time()-t0:.1f}s; N={N} k={k}", flush=True)
    order = rng.permutation(N); Z = sorted(order[:l].tolist()); Zset = set(Z)
    GZ = G[:, Z]                                   # k x l
    L = GZ.T.null_space()                          # rows r with r GZ = 0 : (k-l) x k
    assert L.shape[0] == kl, L.shape
    Gs = L @ G
    keep = [c for c in range(N) if c not in Zset]
    X = Gs[:, keep].T                              # n' x k_l (GF array)
    npts = X.shape[0]
    print(f"shortened in {time.time()-t0:.1f}s; n'={npts} k_l={kl}", flush=True)
    # cubic monomials
    mons = [(a, b, c) for a in range(kl) for b in range(a, kl) for c in range(b, kl)]
    A_ = np.array([t[0] for t in mons]); B_ = np.array([t[1] for t in mons]); C_ = np.array([t[2] for t in mons])
    Nm = len(mons); rows = npts * kl
    M = np.zeros((rows, Nm), dtype=np.uint16)
    for j in range(npts):
        x = X[j]
        T = np.array(np.outer(x, x))               # product table in GF, as ints
        for t in range(kl):
            c1 = np.where(A_ == t, T[B_, C_], 0)
            c2 = np.where(B_ == t, T[A_, C_], 0)
            c3 = np.where(C_ == t, T[A_, B_], 0)
            M[j * kl + t] = (c1 ^ c2 ^ c3).astype(np.uint16)   # char 2: field addition is XOR
    generic = max(0, Nm - rows)
    pred = 2 * (n - k) - w - kl + 2 if mode == 'grs' else 0
    with open(out, 'wb') as f:
        np.array([rows, Nm], dtype=np.int64).tofile(f); M.tofile(f)
    print(f"RLCE GF(2^{m}) n={n} k={k} w={w} N={N} k_l={kl} mode={mode} seed={seed} rows={rows} "
          f"monomials={Nm} generic_kernel={generic} predicted_excess>={pred} "
          f"regime={'under' if Nm>=rows else 'OVER'} built in {time.time()-t0:.1f}s", flush=True)

if __name__ == '__main__':
    main()
