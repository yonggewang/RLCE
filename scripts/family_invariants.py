"""Structural invariants for the 2x2 study {polar, LDPC} x {RLCE, UVW}, over F2.

Decisive measurement principle: we do NOT run a low-weight search (ISD). Instead, knowing the
secret, we compute the *image under the mask* of the underlying code's known structural object
and read off its weight:
  - polar: primal minimum-weight codewords (indicators of affine subspaces)  [BCDOT object]
  - LDPC : dual minimum-weight codewords (sparse parity checks, rows of H)    [OTD object]
If that image has weight far below the Gilbert-Varshamov bound of the corresponding (public or
dual) code, the public key is distinguishable from random and the object is exposed to the
matching recovery -- regardless of the Schur-square dimension.  This is existence by construction,
not by search, so it is a clean distinguisher measurement.

Reuses polar.py (rank2, left_null_f2, polar_gen, square_dim).
usage: see __main__ block.
"""
import sys, itertools, numpy as np
from polar import rank2, left_null_f2, polar_gen, square_dim, Fkron

# ---------- code families (binary) ----------

def polar_code(t, k):
    """k x n polar generator and the affine min-weight structure."""
    G, I = polar_gen(t, k)
    n = 1 << t
    # min weight generator rows = those of smallest row weight
    wts = (G & 1).sum(axis=1)
    dmin = int(wts.min())
    return G % 2, n, dmin

def ldpc_code(n, k, wrow, rng, tries=200):
    """Random binary [n,k] code with a sparse parity-check H of row weight ~wrow.
    Build H as (n-k) x n with each row weight wrow, full rank; G = right nullspace basis."""
    r = n - k
    for _ in range(tries):
        H = np.zeros((r, n), dtype=np.int64)
        for i in range(r):
            cols = rng.choice(n, size=wrow, replace=False)
            H[i, cols] = 1
        if rank2(H) == r:
            # generator = basis of right nullspace of H
            G = left_null_f2(H.T)          # vectors g with H g^T = 0  <=>  g in null(H)
            if G.shape[0] == k and rank2(G) == k:
                return G % 2, H % 2
    raise RuntimeError("ldpc_code: failed to build full-rank sparse H")

# ---------- masks ----------

def rlce_mask(G, w, rng):
    """General binary RLCE mask. Returns (G_pub, info) with info to map objects through it.
    info: perm (len N), mixed_preperm (set of 2w pre-perm indices), base=n-w, A blocks, S."""
    k, n = G.shape
    cols = [G[:, j].copy() for j in range(n - w)]
    origin = [('p', j) for j in range(n - w)]
    for i in range(w):
        j = n - w + i
        cols.append(G[:, j].copy()); origin.append(('p', j))
        cols.append(rng.integers(0, 2, size=k)); origin.append(('r', i))
    G1 = np.array(cols).T % 2
    N = n + w; base = n - w
    opts = [np.array([[1,1],[0,1]]), np.array([[1,0],[1,1]]),
            np.array([[0,1],[1,1]]), np.array([[1,1],[1,0]])]
    Ablocks = []
    Gcols = [G1[:, c].copy() for c in range(N)]
    for i in range(w):
        a = base + 2*i
        Aop = opts[rng.integers(0, len(opts))]; Ablocks.append(Aop)
        c0 = (Aop[0,0]*Gcols[a] + Aop[0,1]*Gcols[a+1]) % 2
        c1 = (Aop[1,0]*Gcols[a] + Aop[1,1]*Gcols[a+1]) % 2
        Gcols[a], Gcols[a+1] = c0, c1
    G1m = np.array(Gcols).T % 2
    perm = rng.permutation(N)
    while True:
        S = rng.integers(0, 2, size=(k, k))
        if rank2(S) == k: break
    Gpub = ((S @ G1m) % 2)[:, perm] % 2
    info = dict(perm=perm, base=base, n=n, w=w, N=N, Ablocks=Ablocks, S=S, origin=origin)
    return Gpub, info

def masked_dual_weight_of_check(h, info):
    """Image weight of an original sparse parity check h (in F2^n) in the RLCE public dual.
    (h,0) is a check of G1; applying A^{-T} affects only mixed pairs; permutation preserves weight."""
    n, w, base, N = info['n'], info['w'], info['base'], info['N']
    y = np.zeros(N, dtype=np.int64)
    # pre-perm layout: positions 0..base-1 are original unmixed cols j=0..base-1;
    # then pairs: pre-perm index base+2i = original col (base+i), base+2i+1 = inserted i.
    # (h,0): value h[j] on each original col j, 0 on inserted.
    hv = np.zeros(N, dtype=np.int64)
    for j in range(base):
        hv[j] = h[j]
    for i in range(w):
        hv[base+2*i] = h[base+i]   # original col base+i
        hv[base+2*i+1] = 0          # inserted
    # dual transforms by A^{-T}: y = A^{-T} (h,0).  Per 2x2 block B, inverse-transpose:
    for i in range(w):
        B = info['Ablocks'][i].astype(np.int64)
        det = (B[0,0]*B[1,1] - B[0,1]*B[1,0]) % 2
        # over F2 det=1 for invertible; inverse of [[a,b],[c,d]] = [[d,b],[c,a]] (since -1=1)
        Binv = np.array([[B[1,1], B[0,1]],[B[1,0], B[0,0]]]) % 2
        BinvT = Binv.T % 2
        a = base+2*i
        v = np.array([hv[a], hv[a+1]]) % 2
        hv[a], hv[a+1] = (BinvT @ v) % 2
    # unmixed and inserted positions unchanged; permutation preserves weight
    return int(hv.sum() % 1_000_000) if False else int(hv.sum())

def uvw_keygen(GC, k1, rng):
    """Binary UVW1 embedding of hidden code GC (k2 x n2). Returns (Gpub, info)."""
    k2, n2 = GC.shape
    n = 2*n2; k = k1 + k2
    GU = rng.integers(0, 2, size=(k1, n2))
    GW = rng.integers(0, 2, size=(k2, n2))
    GV = (GC + GW) % 2
    top = np.hstack([GU, GU]) % 2
    bot = np.hstack([GV, GW]) % 2
    Gsk = np.vstack([top, bot]) % 2
    while True:
        S = rng.integers(0, 2, size=(k, k))
        if rank2(S) == k: break
    perm = rng.permutation(n)
    Gpub = ((S @ Gsk) % 2)[:, perm] % 2
    info = dict(perm=perm, n2=n2, n=n, k1=k1, k2=k2, GU=GU, GW=GW, GC=GC, S=S)
    return Gpub, info

def gv_bound(N, kk):
    from math import lgamma, log2
    def lcomb(nn, rr):
        if rr<0 or rr>nn: return float('-inf')
        return (lgamma(nn+1)-lgamma(rr+1)-lgamma(nn-rr+1))/np.log(2)
    target = N - kk; acc=float('-inf'); d=0
    while d<=N:
        lc=lcomb(N-1,d)
        new = lc if acc==float('-inf') else (acc if lc==float('-inf') else np.logaddexp2(acc,lc))
        if new>=target and acc!=float('-inf'): return d
        acc=new; d+=1
    return N

# ---------- experiments ----------

def exp_ldpc_rlce(n, k, wrow, w, seed):
    rng = np.random.default_rng(seed)
    G, H = ldpc_code(n, k, wrow, rng)
    Gpub, info = rlce_mask(G, w, rng)
    N = info['N']
    # image weight of each sparse check (rows of H)
    wts = [masked_dual_weight_of_check(H[i] % 2, info) for i in range(H.shape[0])]
    wts = np.array(wts)
    gv_dual = gv_bound(N, N-k)      # a random [N, N-k] dual code's min weight ~ GV(N, N-k)
    survivors = int((wts == wrow).sum())
    print(f"[LDPC-RLCE] n={n} k={k} wrow={wrow} w={w} (k/2={k/2:.0f}) N={N} | "
          f"min masked-check wt={wts.min()} (orig {wrow}) | GV_dual(N,N-k)={gv_dual} | "
          f"survivors@{wrow}={survivors}/{H.shape[0]} | "
          f"{'LEAK' if wts.min() < gv_dual else 'clean'}")
    return wts.min(), gv_dual, survivors

def exp_uvw_square(family, n2, k1, k2, seed, **kw):
    """Square-dimension + pairing signature of a UVW public code with polar/LDPC hidden code."""
    rng = np.random.default_rng(seed)
    if family == 'polar':
        t = kw['t']; GC, _, dC = polar_code(t, k2); assert (1<<t)==n2
    else:
        GC, Hc = ldpc_code(n2, k2, kw['wrow'], rng)
    Gpub, info = uvw_keygen(GC, k1, rng)
    N = info['n']; k = k1+k2
    sq = square_dim_f2(Gpub)
    Grand = rng.integers(0,2,size=(k,N))
    sqr = square_dim_f2(Grand)
    print(f"[UVW-{family}] n={N} k={k} (k1={k1},k2={k2}) | sq(pub)={sq} sq(rand)={sqr} "
          f"gen-bound={min(N,k*(k+1)//2)} | defect={sqr-sq}")
    return sq, sqr

def exp_uvw_matching(family, n2, k1, k2, seed, **kw):
    """Hidden-code-INDEPENDENT UVW signature: matched-pair column XORs span only k2 dims
    (because columns i and i+n2 share their top-k1 part GU[:,i]), while random pairs span k.
    Rank gap = k1 distinguishes UVW from random regardless of the hidden code."""
    rng = np.random.default_rng(seed)
    if family == 'polar':
        t = kw['t']; GC, _, _ = polar_code(t, k2); assert (1<<t)==n2
    else:
        GC, _ = ldpc_code(n2, k2, kw['wrow'], rng)
    Gpub, info = uvw_keygen(GC, k1, rng)
    N = info['n']; k = k1+k2; perm = info['perm']
    cols = [Gpub[:, c].copy() for c in range(N)]
    # true matching: pre-perm columns i and i+n2 are a pair; find their post-perm positions
    inv = np.argsort(perm)  # inv[preperm]=postperm
    matched_xors = []
    for i in range(n2):
        a = int(inv[i]); b = int(inv[i+n2])
        matched_xors.append((cols[a] ^ cols[b]) & 1)
    rk_matched = rank2(np.array(matched_xors, dtype=np.int64))
    # random pairs
    rand_xors = []
    for _ in range(min(2*n2, 400)):
        a,b = rng.choice(N, size=2, replace=False)
        rand_xors.append((cols[a]^cols[b])&1)
    rk_rand = rank2(np.array(rand_xors, dtype=np.int64))
    # identifiability: is the planted U_bot (span of matched XORs) anomalously dense in
    # pairwise differences?  Count all C(N,2) column-pairs whose XOR lies in U_bot, vs the
    # expectation C(N,2)*2^{-k1} for a generic k2-subspace.
    Ubot = rank_basis_f2(np.array(matched_xors, dtype=np.int64))   # k2 x k basis
    allcols = np.array(cols, dtype=np.int64)
    incid = 0
    for i in range(N):
        for j in range(i+1, N):
            if in_span_f2(Ubot, (allcols[i]^allcols[j])&1): incid += 1
    import math
    expect_rand = math.comb(N,2) * (2.0**(-k1))
    print(f"[UVW-{family} matching] N={N} k={k} (k1={k1},k2={k2}) | "
          f"rank(matched)={rk_matched}(=k2) rank(random)={rk_rand}(=k) gap={rk_rand-rk_matched} | "
          f"pairs in U_bot: {incid} vs random-subspace expect {expect_rand:.1f} "
          f"(n2={n2}) {'IDENTIFIABLE' if incid>5*max(1,expect_rand) else '-'}")
    return rk_matched, rk_rand

def rank_basis_f2(M):
    """row-reduced basis of row space over F2."""
    M=(np.array(M)&1).astype(np.int64).copy(); r=0; rows,cols=M.shape; piv=[]
    for c in range(cols):
        pr=None
        for i in range(r,rows):
            if M[i,c]: pr=i;break
        if pr is None: continue
        M[[r,pr]]=M[[pr,r]]
        for i in range(rows):
            if i!=r and M[i,c]: M[i]^=M[r]
        piv.append(c); r+=1
    return M[:r]

def in_span_f2(basis, v):
    v=(np.array(v)&1).astype(np.int64).copy()
    for row in basis:
        # reduce v by leading col of row
        lead=np.argmax(row>0) if row.any() else -1
        if lead>=0 and v[lead]: v=(v^row)&1
    return not v.any()

def square_dim_f2(G):
    k,n=G.shape; rows=[]
    for a in range(k):
        for b in range(a,k):
            rows.append((G[a]&G[b])&1)
    return rank2(np.array(rows,dtype=np.int64))

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == 'ldpc_rlce':
        # sweep w vs k/2 at fixed sparse weight
        for (n,k,wrow) in [(64,32,6),(64,40,6),(128,64,8)]:
            for w in [4, k//4, k//2, (3*k)//4, k]:
                if w < 1 or w > n: continue
                exp_ldpc_rlce(n,k,wrow,w,1)
            print()
    elif mode == 'uvw':
        for (n2,k1,k2,t) in [(32,8,16,5),(64,16,32,6),(32,4,10,5),(64,8,20,6)]:
            exp_uvw_square('polar', n2, k1, k2, 1, t=t)
            exp_uvw_matching('polar', n2, k1, k2, 1, t=t)
        print()
        for (n2,k1,k2,wr) in [(32,8,16,6),(64,16,32,8),(32,4,10,6),(64,8,20,8)]:
            exp_uvw_square('ldpc', n2, k1, k2, 1, wrow=wr)
            exp_uvw_matching('ldpc', n2, k1, k2, 1, wrow=wr)
