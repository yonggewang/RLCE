"""Square-code endgame for RLCE recovery: once the jet rounds have brought the number of unknown
pairs w' below n-k-k_l, fold the known pairs into their curve points and finish with cheap
shortened-square-code rounds (CLT's regime).

Round: random Z of size k-k_l over the folded code; survivors X (n' x k_l). The Veronese images
nu(x) of the curve-point columns span a space V of dimension <= 2(deg Q)+1 < n'; a surviving column
of an unknown pair whose twin also survives is off the curve and raises the Veronese span by one:
  off-curve(c)  <=>  rank(nu(all)) - rank(nu(all minus c)) = 1.
For off-curve a, b: twins iff some rho has nu(x_a + rho x_b) in V (the pair plane meets the curve);
rho is then the ratio, and hidden column = g'_a + rho g'_b.
usage: python3 rlce_endgame_sq.py m n k w k_l seed workdir [max_rounds]   (reads/writes workdir/state.json)
"""
import sys, os, json, time, itertools, numpy as np, galois
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rlce_recover import keygen

def veronese(GF, X):
    npts, kl = X.shape; idx = [(a, b) for a in range(kl) for b in range(a, kl)]
    Xa = np.array(X)
    return GF(np.column_stack([np.array(GF(Xa[:, a]) * GF(Xa[:, b])) for a, b in idx]))

def main():
    m, n, k, w, kl = map(int, sys.argv[1:6]); seed = int(sys.argv[6]); wd = sys.argv[7]
    max_rounds = int(sys.argv[8]) if len(sys.argv) > 8 else 2000
    GF = galois.GF(2 ** m); rng = np.random.default_rng(seed); t0 = time.time()
    G, sk = keygen(GF, n, k, w, rng); N = n + w; l = k - kl
    rng2 = np.random.default_rng(int(os.environ.get('SQSEED', seed + 1000)))
    sfile = sys.argv[9] if len(sys.argv) > 9 else os.path.join(wd, 'state.json')
    st = json.load(open(sfile))
    known = {frozenset((i, j)): (i, j, rho) for (i, j, rho) in st['known']}
    tp = sk['true_pair']
    print(f"[{time.time()-t0:.0f}s] loaded {len(known)} known pairs; unknown {w-len(known)}; square-code endgame k_l={kl}", flush=True)
    rounds = 0; sq_rounds = 0
    while len(known) < w and rounds < max_rounds:
        rounds += 1
        paired = set()
        for (i, j, _) in known.values(): paired |= {i, j}
        labels = [('c', c) for c in range(N) if c not in paired] + [('p', key) for key in known]
        cols = [np.array(G[:, c]) for c in range(N) if c not in paired] + \
               [np.array(G[:, i] + GF(rho) * G[:, j]) for (i, j, rho) in known.values()]
        Gf = GF(np.column_stack(cols)); Nf = Gf.shape[1]
        Z = sorted(rng2.permutation(Nf)[:l].tolist()); keep = [c for c in range(Nf) if c not in set(Z)]
        L = Gf[:, Z].T.null_space()
        if L.shape[0] != kl: continue
        X = (L @ Gf)[:, keep].T; npts = X.shape[0]
        V = veronese(GF, X)
        Kl = V.T.null_space()                                   # left kernel of V: rows y with y V = 0
        D = npts - Kl.shape[0]
        used = np.any(np.array(Kl) != 0, axis=0) if Kl.shape[0] else np.zeros(npts, bool)
        off = [c for c in range(npts) if not used[c]]           # rows in no relation: off the curve
        # true exposure for scoring
        unknown_cols = [c for c in range(npts) if labels[keep[c]][0] == 'c']
        surv_unknown = set(labels[keep[c]][1] for c in range(npts) if labels[keep[c]][0] == 'c')
        exposed = sum(1 for pr in tp if pr not in known and pr <= surv_unknown)
        new = 0
        if off:
            curve_rows = [r for r in range(npts) if r not in set(off)]
            Vc = V[curve_rows]; A = Vc.null_space()             # rows z with Vc z = 0  -> annihilator basis (dim 325-Dc)
            A = A.T                                             # ncols x dimA
            for a, b in itertools.combinations(off, 2):
                xa, xb = X[a], X[b]
                nu_a = veronese(GF, GF(np.array([xa])))[0]; nu_b = veronese(GF, GF(np.array([xb])))[0]
                nu_ab = veronese(GF, GF(np.array([xa + xb])))[0] - nu_a - nu_b
                w0, w1, w2 = nu_a @ A, nu_ab @ A, nu_b @ A
                sols = [r for r in range(1, GF.order) if np.array_equal(np.array(w0 + GF(r) * w1 + GF(r) * GF(r) * w2), np.zeros(len(w0), dtype=int))]
                if len(sols) != 1: continue
                rho = sols[0]
                la, lb = labels[keep[a]], labels[keep[b]]
                if la[0] != 'c' or lb[0] != 'c': continue
                key = frozenset((la[1], lb[1]))
                if key in known: continue
                known[key] = (la[1], lb[1], rho); new += 1
                truth = key in tp
                print(f"    pair {la[1]},{lb[1]} rho={rho} [truth: {'correct' if truth else 'WRONG'}]", flush=True)
        if new or rounds % 50 == 0:
            print(f"[{time.time()-t0:.0f}s] round {rounds}: n'={npts} Veronese rank {D} (cols {V.shape[1]}), off-curve {len(off)}, exposed {exposed}, new {new}, known {len(known)}/{w}", flush=True)
        json.dump({'rounds': st['rounds'] + rounds, 'jet_rounds': st['rounds'], 'sq_rounds': rounds,
                   'known': [list(v) for v in known.values()], 'kernels': st.get('kernels', []), 'surv': st.get('surv', [])},
                  open(os.path.join(wd, 'state_sq.json'), 'w'))
    ok = sum(1 for p in known if p in tp)
    print(f"[{time.time()-t0:.0f}s] done: {len(known)} pairs after {rounds} square-code rounds; [truth] correct {ok}/{len(known)}", flush=True)
    print("SQSUMMARY", json.dumps(dict(sq_rounds=rounds, pairs=len(known), seconds=round(time.time()-t0))))

if __name__ == '__main__': main()
