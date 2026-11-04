"""Full Stern re-pricing of ALL Prange-feasible points of a polar_closure.py run, optimised for
speed and valid for exclusion:
  * Stern alone (an upper bound on the family minimum) on both sides: the Stern-only largest
    admissible w is >= the true one, the dual cost increases in w, and the Stern-only dual cost
    is >= the true one, so a Stern-only verdict "excluded" is a valid exclusion;
  * the leaked weight D = d_perp + y is minimised by a bracket search from the Prange argmin
    (the cost is unimodal in y), ~10 estimator calls instead of ~70.
usage: python3 polar_closure_stern2.py lambda closure.out m [shard nshards]
"""
import sys, re, numpy as np
from math import log2
from talvardy import synthetic_pe
from polar_closure import dists_from_I
from hirate_polarrlce import leak_cdf, prange_find
from nogo_analysis import gv
from cryptographic_estimators.SDEstimator import SDEstimator
from cryptographic_estimators.SDEstimator.SDAlgorithms import BJMM, BJMMplus, BJMMdw, BJMMpdw, MayOzerov, BothMay, Dumer, BallCollision, Prange
NOTSTERN = [BJMM, BJMMplus, BJMMdw, BJMMpdw, MayOzerov, BothMay, Dumer, BallCollision, Prange]
_cache = {}
def sd(N, K, wt):
    key = (N, K, wt)
    if key not in _cache:
        e = SDEstimator(n=N, k=K, w=wt, excluded_algorithms=NOTSTERN)
        _cache[key] = min(v['estimate']['time'] for v in e.estimate().values())
    return _cache[key]

def wmax(n, k, t, lam):
    if sd(n + 1, k, t) < lam: return None
    if sd(2 * n, k, t) >= lam: return n
    lo, hi = 1, n
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if sd(n + mid, k, t) >= lam: lo = mid
        else: hi = mid
    return lo

def dual(n, k, w, dp, Ndp):
    N = n + w; K = N - k; cdf = leak_cdf(n, w, dp); memo = {}
    def cost(y):
        if y not in memo:
            mult = Ndp * cdf[y]
            memo[y] = (1e9, mult) if mult < 1 else (sd(N, K, dp + y) - log2(mult), mult)
        return memo[y]
    ys = [y for y in range(dp + 1) if Ndp * cdf[y] >= 1]
    y0 = min(ys, key=lambda y: prange_find(N, K, dp + y, log2(Ndp * cdf[y])))
    step = 4; y = y0
    # walk downhill from the Prange argmin
    while True:
        c0 = cost(y)[0]; cm = cost(max(0, y - step))[0] if y - step >= 0 else 1e9; cp = cost(min(dp, y + step))[0] if y + step <= dp else 1e9
        if cm < c0 and cm <= cp: y = max(0, y - step)
        elif cp < c0: y = min(dp, y + step)
        else: break
    for yy in range(max(0, y - 3), min(dp, y + 3) + 1): cost(yy)
    yb = min(memo, key=lambda z: memo[z][0])
    return memo[yb][0], dp + yb, memo[yb][1]

if __name__ == "__main__":
    lam = int(sys.argv[1]); lines = open(sys.argv[2]).read().splitlines(); m = int(sys.argv[3]); n = 1 << m
    shard, nsh = (int(sys.argv[4]), int(sys.argv[5])) if len(sys.argv) > 5 else (0, 1)
    pat = re.compile(r"m=(\d+) p=([\d.]+) R=([\d.]+) t=(\d+) dfr=2\^(-?\d+) .*FEASIBLE")
    pts = [(float(g.group(2)), float(g.group(3)), int(g.group(4)), int(g.group(5))) for g in map(pat.search, lines) if g and int(g.group(1)) == m]
    pts = pts[shard::nsh]; pe_cache = {}; feas = []
    for (p, R, t, dfr) in pts:
        if p not in pe_cache:
            pe = synthetic_pe(m, p, 128); pe_cache[p] = np.argsort(pe, kind='stable')
        k = int(R * n); I = np.sort(pe_cache[p][:k]); d, Nd, dp, Ndp = dists_from_I(m, I)
        wm = wmax(n, k, t, lam)
        if wm is None:
            print(f"m={m} p={p} R={R:.2f} t={t} dfr=2^{dfr}: Stern msg < {lam} at w=1 -> excluded", flush=True); continue
        c, D, mult = dual(n, k, wm, dp, Ndp); N = n + wm; prim = (d + wm // 2) >= gv(N, k)
        ok = c >= lam and prim
        if ok: feas.append((p, R))
        print(f"m={m} p={p} R={R:.2f} t={t} dfr=2^{dfr} d={d} dperp={dp} log2Ndp={log2(Ndp):.0f} | Stern-only: w_m={wm} N={N} msg={sd(N,k,t):.1f} "
              f"dual={c:.1f} @D={D} mult=2^{log2(mult):.0f} primal={'closed' if prim else 'OPEN'} key={k*(N-k)/8/2**20:.2f}MiB -> {'NOT EXCLUDED' if ok else 'excluded'}", flush=True)
    print(f"shard {shard}/{nsh}: {len(pts)} points, {len(feas)} not excluded: {feas}")
