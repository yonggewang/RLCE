"""Stern-family re-pricing of the (m, p, R) points that pass the Prange necessary condition in
polar_closure.py.  For each point: information set = k best synthetic channels of BSC(p) under the
Tal-Vardy degrading construction; w_m^S = largest w <= n with SD_Stern(N, k, t) >= lambda; then the
leaked-dual cost at w_m^S, min over the leaked weight D = d_perp + y of
    SD_Stern(N, N-k, D) - log2( N_dperp * P[Y <= y] ).
Feasible iff that dual cost >= lambda (primal closure is re-checked as in window_search.py).
usage: python3 polar_closure_stern.py lambda dfr_exp  "p,R p,R ..." [m=14]
"""
import sys, numpy as np
from math import log2
from talvardy import synthetic_pe
from polar_closure import dists_from_I
from hirate_polarrlce import leak_cdf, prange_find, prange_msg
from nogo_analysis import gv
from cryptographic_estimators.SDEstimator import SDEstimator
from cryptographic_estimators.SDEstimator.SDAlgorithms import BJMM, BJMMplus, BJMMdw, BJMMpdw, MayOzerov, BothMay
SLOW = [BJMM, BJMMplus, BJMMdw, BJMMpdw, MayOzerov, BothMay]
_cache = {}
def sd(N, K, wt):
    key = (N, K, wt)
    if key not in _cache:
        e = SDEstimator(n=N, k=K, w=wt, excluded_algorithms=SLOW)
        _cache[key] = min(v['estimate']['time'] for v in e.estimate().values())
    return _cache[key]

def stern_dual(n, k, w, dp, Ndp, step=16):
    """min over the leaked weight D = dp + y of SD_Stern(N, N-k, D) - log2(Ndp * P[Y <= y]):
    coarse scan of y (step `step`), then refinement (step 1) around the coarse minimum."""
    N = n + w; K = N - k; cdf = leak_cdf(n, w, dp); memo = {}
    def cost(y):
        if y not in memo:
            mult = Ndp * cdf[y]
            memo[y] = (1e9, mult) if mult < 1 else (sd(N, K, dp + y) - log2(mult), mult)
        return memo[y]
    ys = sorted(set(list(range(0, dp + 1, step)) + [dp]))
    y0 = min(ys, key=lambda y: cost(y)[0])
    lo, hi = max(0, y0 - step), min(dp, y0 + step)
    while hi - lo > 2:                       # shrink the bracket by thirds (cost is unimodal in y)
        m1 = lo + (hi - lo) // 3; m2 = hi - (hi - lo) // 3
        if cost(m1)[0] <= cost(m2)[0]: hi = m2
        else: lo = m1
    for y in range(max(0, lo - 2), min(dp, hi + 2) + 1): cost(y)
    yb = min(memo, key=lambda y: memo[y][0])
    return (memo[yb][0], dp + yb, memo[yb][1])

def wmax_stern(n, k, t, lam):
    """largest w in [1, n] with SD_Stern(n+w, k, t) >= lam, or None."""
    if sd(n + 1, k, t) < lam: return None
    if sd(2 * n, k, t) >= lam: return n
    lo, hi = 1, n
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if sd(n + mid, k, t) >= lam: lo = mid
        else: hi = mid
    return lo

if __name__ == "__main__":
    lam = int(sys.argv[1]); dfr_exp = int(sys.argv[2]); pts = [tuple(map(float, s.split(','))) for s in sys.argv[3].split()]
    m = int(sys.argv[4]) if len(sys.argv) > 4 else 14; n = 1 << m; pe_cache = {}
    for (p, R) in pts:
        if p not in pe_cache:
            pe = synthetic_pe(m, p, 128); pe_cache[p] = (pe, np.argsort(pe, kind='stable'))
        pe, order = pe_cache[p]; t = int(p * n); k = int(R * n); I = np.sort(order[:k]); dfr = pe[I].sum()
        d, Nd, dp, Ndp = dists_from_I(m, I)
        wm = wmax_stern(n, k, t, lam)
        if wm is None:
            print(f"m={m} p={p} R={R:.2f} t={t} dfr=2^{log2(dfr):.0f}: Stern msg < {lam} at w=1 -> excluded", flush=True); continue
        N = n + wm; c, D, mult = stern_dual(n, k, wm, dp, Ndp)
        prim_ok = (d + wm // 2) >= gv(N, k)
        ok = c >= lam and prim_ok and dfr <= 2.0 ** (-dfr_exp)
        print(f"m={m} p={p} R={R:.2f} t={t} dfr=2^{log2(dfr):.0f} d={d} dperp={dp} log2Ndp={log2(Ndp):.0f} | Stern: w_m={wm} N={N} msg={sd(N,k,t):.1f} "
              f"dual={c:.1f} @D={D} mult=2^{log2(mult):.0f} primal={'closed' if prim_ok else 'OPEN'} key={k*(N-k)/8/2**20:.2f}MiB -> {'FEASIBLE' if ok else 'excluded'}", flush=True)
