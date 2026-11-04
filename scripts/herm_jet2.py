"""Vectorised cubic/(d,r) jet on HermitianRLCE toys over GF(2^m); C ranker.
Fits the structured excess vs the master count with AG composed dim d*alpha+1-g.
usage: python3 herm_jet2.py q alpha w k_l d r mode seed  [outfile]
"""
import sys, os, itertools, subprocess, numpy as np, galois
from hermitian import affine_points, herm_generator, rlce_transform

SCR = "/tmp/claude-0/-home-claude/eb45358c-0a59-5730-962a-e2da8f38d9ec/scratchpad/jet"

def shorten(GF, G, Z):
    k, N = G.shape
    L = G[:, Z].T.null_space()
    Gs = L @ G
    keep = [c for c in range(N) if c not in set(Z)]
    return np.array(Gs)[:, keep], keep

def jet_build(GF, X, d, r):
    """Vectorised: rows = order-(r-1) Hasse-free derivatives of degree-d monomials at each point."""
    p = GF.characteristic
    npts, kl = X.shape
    mons = list(itertools.combinations_with_replacement(range(kl), d))
    E = np.zeros((len(mons), kl), dtype=np.int64)
    for i, mon in enumerate(mons):
        for t in mon: E[i, t] += 1
    ders = list(itertools.combinations_with_replacement(range(kl), r - 1))
    D = np.zeros((len(ders), kl), dtype=np.int64)
    for i, der in enumerate(ders):
        for t in der: D[i, t] += 1
    Nd = len(mons); nder = len(ders); rows = npts * nder
    # falling factorial mod p
    FF = np.ones((d + 1, r), dtype=np.int64)
    for e in range(d + 1):
        for a in range(1, r):
            FF[e, a] = (FF[e, a - 1] * (e - a + 1)) % p if a <= e else 0
    M = GF.Zeros((rows, Nd))
    Xg = GF(np.array(X, dtype=np.int64))
    for jp in range(npts):
        x = Xg[jp]
        # powers PT[t] = [x_t^0 .. x_t^d] as a galois array
        PT = GF.Zeros((kl, d + 1)); PT[:, 0] = GF(1)
        for a in range(1, d + 1): PT[:, a] = PT[:, a - 1] * x
        for di in range(nder):
            a = D[di]
            valid = np.all(E >= a[None, :], axis=1)
            coef = np.ones(Nd, dtype=np.int64)
            for t in range(kl):
                if a[t]: coef = (coef * FF[E[:, t], a[t]]) % p
            row = GF(coef.astype(np.int64) % p)
            expo = E - a[None, :]
            for t in range(kl):
                row = row * PT[t, np.clip(expo[:, t], 0, d)]
            row[~valid] = GF(0); row[coef % p == 0] = GF(0)
            M[jp * nder + di] = row
    return M, rows, Nd

def run(q, alpha, w, kl, d, r, mode, seed):
    GF = galois.GF(q * q); g = q * (q - 1) // 2; m = int(round(np.log2(GF.order)))
    rng = np.random.default_rng(seed)
    pts = affine_points(GF, q)
    Gs, B = herm_generator(GF, q, alpha, pts); k, n = Gs.shape
    if mode == 'herm':
        G, sk = rlce_transform(GF, Gs, w, rng)
    elif mode == 'randhidden':
        G, sk = rlce_transform(GF, GF(rng.integers(0, q*q, size=(k, n))), w, rng)
    else:
        G = GF(rng.integers(0, q*q, size=(k, n + w)))
    N = G.shape[1]; l = k - kl
    order = rng.permutation(N); Z = sorted(order[:l].tolist())
    Gsh, keep = shorten(GF, G, Z)
    X = np.array(GF(np.array(Gsh).T))
    M, rows, Nd = jet_build(GF, X, d, r)
    f = f"{SCR}/hj_{os.getpid()}.bin"; os.makedirs(SCR, exist_ok=True)
    with open(f, 'wb') as fh:
        np.array([rows, Nd], dtype=np.int64).tofile(fh); np.array(M, dtype=np.uint16).tofile(fh)
    out = subprocess.run(['./rank2m', f, str(m), str(int(GF.irreducible_poly)),
                          str(int(GF.primitive_element))], capture_output=True, text=True)
    tok = dict(t.split('=') for t in out.stdout.split() if '=' in t)
    rk = int(tok['rank']); deps = rows - rk
    comp_ag = d * alpha + 1 - g
    # genus-0 RLCE-style prediction for [n,k] hidden with w pairs at (d,d-1):
    rlce = (d - 1) * (n - k) + (d - 1) - w - kl if r == d - 1 else None
    pred = (rlce - (d - 1) * g) if rlce is not None else None
    os.remove(f)
    print(f"q={q} g={g} alpha={alpha} [n={n},k={k}] w={w} N={N} k_l={kl} (d,r)=({d},{r}) {mode} s{seed}: "
          f"rows={rows} cols={Nd} rank={rk} EXCESS={deps}  compAG={comp_ag} "
          f"RLCEpred={rlce} RLCE-{(d-1)*g}(=(d-1)g)={pred}", flush=True)
    return deps

if __name__ == '__main__':
    a = sys.argv
    run(int(a[1]), int(a[2]), int(a[3]), int(a[4]), int(a[5]), int(a[6]), a[7], int(a[8]))
