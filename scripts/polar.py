"""Binary polar code and the polarRLCE transform; square-code and cubic-jet tests.
Polar code of length N0=2^t: G = (rows of F^{⊗t} indexed by the information set I),
F=[[1,0],[1,1]].  Information set = N0-k rows of smallest Bhattacharyya param frozen;
for a structural test the ACTUAL reliability order doesn't matter much, but we pick
the standard one for a BEC(0.5) via Hamming-weight / Arikan recursion proxy:
we freeze the rows of smallest row-weight (a common, structurally faithful choice;
polar info sets are decreasing monomial / weight-based).  Over F_2.

polarRLCE: RLCE transform (insert w random cols, mix w pairs by 2x2 invertible over
F_2 -- but GL_2(F_2) 2x2 invertible with nonzero entries is limited; RLCE over F_2
uses invertible A_i) then S, P.

usage: python3 polar.py t k w k_l test seed    test: sq | jet
"""
import sys, itertools, numpy as np

def Fkron(t):
    F = np.array([[1, 0], [1, 1]], dtype=np.int64)
    G = np.array([[1]], dtype=np.int64)
    for _ in range(t):
        G = np.kron(G, F)
    return G  # 2^t x 2^t

def rank2(M):
    M = (np.array(M) & 1).astype(np.int64).copy()
    r = 0; rows, cols = M.shape
    for c in range(cols):
        piv = None
        for i in range(r, rows):
            if M[i, c]: piv = i; break
        if piv is None: continue
        M[[r, piv]] = M[[piv, r]]
        for i in range(rows):
            if i != r and M[i, c]: M[i] ^= M[r]
        r += 1
    return r

def polar_gen(t, k):
    """k x N0 generator: pick k rows of F^{⊗t} of LARGEST weight (most reliable, standard)."""
    N0 = 1 << t
    G = Fkron(t)
    wts = G.sum(axis=1)
    order = np.argsort(-wts, kind='stable')     # largest weight first
    I = sorted(order[:k].tolist())
    return G[I], I

def square_dim(G):
    k, n = G.shape
    rows = []
    for a in range(k):
        for b in range(a, k):
            rows.append((G[a] & G[b]) & 1)
    return rank2(np.array(rows, dtype=np.int64))

def rlce_transform_f2(G, w, rng):
    k, n = G.shape
    cols = [G[:, j].copy() for j in range(n - w)]
    for i in range(w):
        cols.append(G[:, n - w + i].copy())
        cols.append(rng.integers(0, 2, size=k))
    G1 = np.array(cols).T % 2
    N = n + w
    A = np.eye(N, dtype=np.int64)
    for i in range(w):
        a = (n - w) + 2 * i
        # invertible 2x2 over F2 with all entries nonzero: only [[1,1],[1,0]] & [[0,1],[1,1]] have a zero;
        # fully nonzero invertible over F2 doesn't exist (det of all-ones=0). Use invertible (RLCE allows).
        opts = [np.array([[1,1],[0,1]]), np.array([[1,0],[1,1]]), np.array([[0,1],[1,1]]), np.array([[1,1],[1,0]])]
        A[a:a+2, a:a+2] = opts[rng.integers(0, len(opts))]
    perm = rng.permutation(N)
    while True:
        S = rng.integers(0, 2, size=(k, k))
        if rank2(S) == k: break
    G = (S @ G1 @ A) % 2
    return G[:, perm] % 2

def jet32_deps_f2(X):
    """cubic (3,2) jet over F2: rows = gradient (order-1 derivs) of cubics at each point.
    In char 2, partial_t x^E = E_t x^{E-e_t} with E_t mod 2."""
    npts, kl = X.shape
    mons = list(itertools.combinations_with_replacement(range(kl), 3))
    E = np.zeros((len(mons), kl), dtype=np.int64)
    for i, mon in enumerate(mons):
        for t in mon: E[i, t] += 1
    Nd = len(mons); rows = npts * kl
    M = np.zeros((rows, Nd), dtype=np.int64)
    for jp in range(npts):
        x = X[jp]
        for t in range(kl):
            valid = E[:, t] >= 1
            coef = (E[:, t] & 1)
            expo = E.copy(); expo[:, t] -= 1
            val = np.ones(Nd, dtype=np.int64)
            for s in range(kl):
                val = val * (x[s] ** expo[:, s])
            M[jp * kl + t] = (coef * val * valid) & 1
    return rank2(M), rows, Nd

def main():
    t = int(sys.argv[1]); k = int(sys.argv[2]); w = int(sys.argv[3]); kl = int(sys.argv[4])
    test = sys.argv[5]; seed = int(sys.argv[6])
    rng = np.random.default_rng(seed)
    N0 = 1 << t
    G, I = polar_gen(t, k)
    sqd = square_dim(G)
    print(f"polar t={t} N0={N0} k={k}: dim(C^2)={sqd}  generic min(N0,C(k+1,2))={min(N0, k*(k+1)//2)}  "
          f"gap={min(N0,k*(k+1)//2)-sqd}")
    if test == 'sq':
        # square of the polarRLCE public key, shortened, vs random
        P = rlce_transform_f2(G, w, rng); N = P.shape[1]
        Pr = rng.integers(0, 2, size=(k, N))
        # shorten both to k_l and compare square dims
        def short_sq(M):
            Z = sorted(rng.permutation(N)[:k-kl].tolist())
            # left-kernel of M[:,Z]
            MZ = M[:, Z].T
            # nullspace over F2
            A = (MZ & 1).astype(np.int64).copy(); r=A.shape[0]; cc=A.shape[1]
            # row reduce to find kernel basis of M[:,Z] (vectors v: v M[:,Z]=0) == left null of M[:,Z]
            # compute via rank trick: basis of {y in F2^k : y·M[:,Z]=0}
            KK = left_null_f2(M[:, Z])
            Gs = (KK @ M) % 2
            keep=[c for c in range(N) if c not in set(Z)]
            return square_dim(Gs[:, keep])
        print(f"  shortened-square dim  polarRLCE={short_sq(P)}  random={short_sq(Pr)}  (k_l={kl})")
    else:
        P = rlce_transform_f2(G, w, rng); N = P.shape[1]
        Z = sorted(rng.permutation(N)[:k-kl].tolist())
        KK = left_null_f2(P[:, Z]); Gs=(KK@P)%2; keep=[c for c in range(N) if c not in set(Z)]
        X = Gs[:, keep].T % 2
        rk, rows, Nd = jet32_deps_f2(X)
        Pr = rng.integers(0,2,size=(k,N)); KKr=left_null_f2(Pr[:,Z]); Gsr=(KKr@Pr)%2
        Xr = Gsr[:, keep].T % 2; rkr,_,_ = jet32_deps_f2(Xr)
        print(f"  cubic-jet (3,2) over F2: polarRLCE deps={rows-rk}  random deps={rows-rkr}  rows={rows} cols={Nd}")

def left_null_f2(A):
    """basis of {y : y A = 0} over F2, A is k x m."""
    k, m = A.shape
    Aug = np.hstack([A.copy() % 2, np.eye(k, dtype=np.int64)])
    r = 0
    for c in range(m):
        piv=None
        for i in range(r,k):
            if Aug[i,c]: piv=i;break
        if piv is None: continue
        Aug[[r,piv]]=Aug[[piv,r]]
        for i in range(k):
            if i!=r and Aug[i,c]: Aug[i]^=Aug[r]
        r+=1
    # rows with zero in first m cols are left-null vectors
    basis=[Aug[i,m:] for i in range(k) if not Aug[i,:m].any()]
    return np.array(basis, dtype=np.int64) % 2 if basis else np.zeros((0,k),dtype=np.int64)

if __name__ == '__main__':
    main()
