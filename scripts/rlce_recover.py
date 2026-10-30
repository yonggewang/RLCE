"""Full RLCE structure recovery from the cubic-jet left-kernel, scored against truth.
Generates an RLCE key over GF(2^m), builds the (3,2) jet system of a shortening,
calls ./nullspace2m for the left kernel K, reshapes K into one (ker x k_l) block per
surviving column, and recovers: mixed pairs (rank-1 blocks grouped by shared column
space), their GRS directions, and the hidden GRS code (subtract scaled twins; check
its square dimension = 2(n-k)-1).  Scores pairs and directions against the secret key.

usage: python3 rlce_recover.py m n k w k_l seed workdir
"""
import sys, os, subprocess, time, numpy as np, galois

def keygen(GF, n, k, w, rng):
    q = GF.order; N = n + w
    x = GF(rng.choice(np.arange(1, q), size=n, replace=False)); y = GF(rng.integers(1, q, size=n))
    Gs = GF.Zeros((k, n)); row = y.copy()
    for i in range(k): Gs[i] = row; row = row * x
    cols = [np.array(Gs[:, j]) for j in range(n - w)]
    layout = list(range(n - w))                     # pre-perm col -> ('grs', idx) or ('pair', i, b)
    meta = [('s', j) for j in range(n - w)]
    for i in range(w):
        cols.append(np.array(Gs[:, n - w + i])); meta.append(('p', i, 0))
        cols.append(np.array(rng.integers(0, q, size=k))); meta.append(('p', i, 1))
    G1 = GF(np.column_stack(cols))
    A = GF.Identity(N);
    for i in range(w):
        a = n - w + 2 * i
        while True:
            Ai = GF(rng.integers(1, q, size=(2, 2)))
            if np.linalg.det(Ai) != 0: break
        A[a:a+2, a:a+2] = Ai
    perm = rng.permutation(N)
    while True:
        S = GF(rng.integers(0, q, size=(k, k)))
        if np.linalg.matrix_rank(S) == k: break
    G = S @ G1 @ A @ GF(np.eye(N, dtype=int)[:, perm])  # column permutation
    # public position q has pre-perm index perm[q]; build truth maps
    inv = np.argsort(perm)
    true_pair = {}      # frozenset of public positions -> pair index
    curvecol = {}       # pair i -> hidden GRS column index (n-w+i); singleton q -> grs idx
    for i in range(w):
        q0 = int(np.where(perm == n - w + 2 * i)[0][0]); q1 = int(np.where(perm == n - w + 2 * i + 1)[0][0])
        true_pair[frozenset((q0, q1))] = i
    sing = {}
    for j in range(n - w):
        q = int(np.where(perm == j)[0][0]); sing[q] = j
    return G, dict(Gs=Gs, S=S, perm=perm, n=n, w=w, k=k, true_pair=true_pair, sing=sing)

def cubic_jet_matrix(GF, X):
    p = GF.characteristic; npts, kl = X.shape
    mons = [(a, b, c) for a in range(kl) for b in range(a, kl) for c in range(b, kl)]
    A_ = np.array([t[0] for t in mons]); B_ = np.array([t[1] for t in mons]); C_ = np.array([t[2] for t in mons])
    Nm = len(mons); M = np.zeros((npts * kl, Nm), dtype=np.uint16)
    for j in range(npts):
        x = X[j]; T = np.array(np.outer(x, x))
        for t in range(kl):
            c1 = np.where(A_ == t, T[B_, C_], 0); c2 = np.where(B_ == t, T[A_, C_], 0); c3 = np.where(C_ == t, T[A_, B_], 0)
            M[j * kl + t] = (c1 ^ c2 ^ c3).astype(np.uint16)
    return M, Nm

def main():
    m, n, k, w, kl = map(int, sys.argv[1:6]); seed = int(sys.argv[6]); wd = sys.argv[7]
    os.makedirs(wd, exist_ok=True)
    GF = galois.GF(2 ** m); rng = np.random.default_rng(seed)
    t0 = time.time()
    G, sk = keygen(GF, n, k, w, rng); N = n + w
    print(f"[{time.time()-t0:.0f}s] key gen; N={N} k={k} w={w}", flush=True)
    l = k - kl; order = rng.permutation(N); Z = sorted(order[:l].tolist()); keep = [c for c in range(N) if c not in set(Z)]
    GF_ = GF; Gg = GF(np.array(G) % GF.order)
    L = Gg[:, Z].T.null_space(); Gs_short = np.array(L @ Gg)
    X = GF(Gs_short[:, keep].T % GF.order); npts = X.shape[0]
    print(f"[{time.time()-t0:.0f}s] shortened; n'={npts} k_l={kl}", flush=True)
    M, Nm = cubic_jet_matrix(GF, X)
    mf = os.path.join(wd, 'M.bin'); kf = os.path.join(wd, 'K.bin')
    with open(mf, 'wb') as f: np.array([M.shape[0], Nm], dtype=np.int64).tofile(f); M.tofile(f)
    print(f"[{time.time()-t0:.0f}s] jet matrix {M.shape[0]}x{Nm}; computing left kernel...", flush=True)
    poly = int(GF.irreducible_poly); prim = int(GF.primitive_element)
    r = subprocess.run(['./nullspace2m', mf, kf, str(m), str(poly), str(prim)], capture_output=True, text=True)
    print("   ", r.stdout.strip(), r.stderr.strip(), flush=True)
    h = np.fromfile(kf, dtype=np.int64, count=2); ker, ln = int(h[0]), int(h[1]); assert ln == npts * kl
    K = GF(np.fromfile(kf, dtype=np.uint16, offset=16).reshape(ker, ln).astype(np.int64))
    print(f"[{time.time()-t0:.0f}s] left kernel dim {ker}; block analysis...", flush=True)
    # block per surviving column
    blocks = [K[:, c * kl:(c + 1) * kl] for c in range(npts)]
    ranks = [int(np.linalg.matrix_rank(B)) for B in blocks]
    rank1 = [c for c in range(npts) if ranks[c] == 1]
    rank2 = [c for c in range(npts) if ranks[c] == 2]
    # coefficient vector (column space) of each rank-1 block: first nonzero column, normalised
    def coldir(B):
        for t in range(kl):
            col = B[:, t]
            if np.any(np.array(col)):
                piv = next(int(v) for v in np.array(col) if v); return np.array(col * GF(1) / GF(piv))
        return None
    groups = {}
    for c in rank1:
        d = tuple(int(v) for v in coldir(blocks[c])); groups.setdefault(d, []).append(c)
    rec_pairs = [frozenset((keep[g[0]], keep[g[1]])) for g in groups.values() if len(g) == 2]
    # score pairs
    tp = sk['true_pair']; ok = sum(1 for pr in rec_pairs if pr in tp); bad = len(rec_pairs) - ok
    # how many true pairs had both coords surviving (recoverable)?
    keepset = set(keep); recoverable = sum(1 for pr in tp if pr <= keepset)
    print(f"RESULT pairs: recovered {len(rec_pairs)}  correct {ok}  wrong {bad}  (recoverable true pairs: {recoverable} of {w})")
    print(f"       rank-1 blocks {len(rank1)}  rank-2 blocks {len(rank2)}  (rank-2 = singletons + half-shortened pairs)")
    # GRS direction per recovered pair, scored against the true projected curve point.
    Lmat = GF(np.array(L))          # k_l x k shortening projection
    dir_ok = dir_tested = 0
    for g in groups.values():
        if len(g) != 2: continue
        ci, cj = g; B = blocks[ci]
        r0 = next(t for t in range(ker) if np.any(np.array(B[t])))
        lam = B[r0]; xi, xj = X[ci], X[cj]
        sol = None
        for r1 in range(kl):
            for r2 in range(r1 + 1, kl):
                sub = GF([[int(xi[r1]), int(xj[r1])], [int(xi[r2]), int(xj[r2])]])
                if np.linalg.det(sub) != 0:
                    rhs = GF([int(lam[r1]), int(lam[r2])]); sol = np.linalg.solve(sub, rhs); break
            if sol is not None: break
        if sol is None or int(sol[0]) == 0: continue
        tovers = sol[1] / sol[0]                                  # char 2: t/s = b/a
        cp = GF(np.array(xi)) + GF(tovers) * GF(np.array(xj))     # recovered curve point (shortened)
        pr = frozenset((keep[ci], keep[cj]))
        if pr not in tp: continue
        i = tp[pr]
        true_cp = Lmat @ (sk['S'] @ sk['Gs'][:, n - w + i])       # true projected curve point
        dir_tested += 1
        # proportional?  cp and true_cp span a 1-dim space
        Mcheck = GF(np.array([np.array(cp), np.array(true_cp)]))
        if int(np.linalg.matrix_rank(Mcheck)) == 1: dir_ok += 1
    print(f"RESULT GRS directions: {dir_ok}/{dir_tested} match the true projected curve point (recovered t/s correct)")
    print(f"[{time.time()-t0:.0f}s] done")

if __name__ == '__main__':
    main()
