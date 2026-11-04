"""Fast Stern exclusion of the Prange-feasible points of polar_closure.py.
At Prange's largest admissible w (w_m^P) the Stern-family message cost is at most the Prange one,
so the Stern-admissible w_m^S <= w_m^P, and the dual cost increases in w; hence
    Stern dual cost at (w_m^P, any y) < lambda   ==>   the point is excluded under Stern.
Points not excluded this way are passed to polar_closure_stern.py for the full computation.
usage: python3 polar_closure_fast.py lambda closure.out m
"""
import sys, re, numpy as np
from math import log2
from talvardy import synthetic_pe
from polar_closure import dists_from_I
from hirate_polarrlce import leak_cdf, prange_find
from cryptographic_estimators.SDEstimator import SDEstimator
from cryptographic_estimators.SDEstimator.SDAlgorithms import BJMM, BJMMplus, BJMMdw, BJMMpdw, MayOzerov, BothMay, Dumer, BallCollision, Prange
NOTSTERN = [BJMM, BJMMplus, BJMMdw, BJMMpdw, MayOzerov, BothMay, Dumer, BallCollision, Prange]
def sd(N, K, wt):
    """Stern alone (an upper bound on the family minimum, hence valid for exclusion)."""
    e = SDEstimator(n=N, k=K, w=wt, excluded_algorithms=NOTSTERN)
    return min(v['estimate']['time'] for v in e.estimate().values())

lam = int(sys.argv[1]); lines = open(sys.argv[2]).read().splitlines(); m = int(sys.argv[3]); n = 1 << m
pat = re.compile(r"m=(\d+) p=([\d.]+) R=([\d.]+) t=(\d+) .*dperp=(\d+) log2Ndp=(\d+) w_m=(\d+) N=(\d+): dual\(w_m\)=(\d+).*FEASIBLE")
pe_cache = {}; left = []
for L in lines:
    g = pat.search(L)
    if not g or int(g.group(1)) != m: continue
    p = float(g.group(2)); R = float(g.group(3)); t = int(g.group(4)); wm = int(g.group(7)); N = int(g.group(8))
    if p not in pe_cache:
        pe = synthetic_pe(m, p, 128); pe_cache[p] = (pe, np.argsort(pe, kind='stable'))
    pe, order = pe_cache[p]; k = int(R * n); I = np.sort(order[:k])
    d, Nd, dp, Ndp = dists_from_I(m, I)
    K = N - k; cdf = leak_cdf(n, wm, dp)
    # Prange argmin y
    y0 = min((y for y in range(dp + 1) if Ndp * cdf[y] >= 1), key=lambda y: prange_find(N, K, dp + y, log2(Ndp * cdf[y])))
    best = 1e9
    for y in sorted(set(max(0, min(dp, y0 + dy)) for dy in (-8, 0, 8))):
        mult = Ndp * cdf[y]
        if mult < 1: continue
        best = min(best, sd(N, K, dp + y) - log2(mult))
    verdict = 'excluded (Stern dual at w_m^P below target)' if best < lam else 'NOT excluded by the fast test'
    print(f"m={m} p={p} R={R:.2f} t={t} dperp={dp} log2Ndp={log2(Ndp):.0f} w_m^P={wm} N={N} k={k}: Stern dual <= {best:.1f} -> {verdict}", flush=True)
    if best >= lam: left.append(f"{p},{R:.2f}")
print("full re-pricing needed for:", " ".join(left) if left else "none")
