"""Is there ANY polarRLCE parameter set that (1) has a certified SC failure rate, (2) resists the
dual leak, and (3) resists message recovery?  For each (m, R, p):
  - information set I = the k best synthetic channels of BSC(p) under the Tal-Vardy degraded
    construction (the designer's own choice for that channel);
  - DFR <= sum_{i in I} P_e(W_i')  (rigorous upper bound, Bernoulli(p));  require <= 2^-dfr_exp;
  - t = floor(p n); d, d_perp, N_d, N_dperp from I (exact formulas);
  - dual cost (Prange, multiplicity credited) increases with w; message cost (Prange) decreases
    with w; primal closed once d + w/2 >= GV(N,k).  Feasible iff dual(w_m) >= lam where w_m is the
    largest w <= n with msg(w_m) >= lam.  Prange is generous to the designer, so an empty result is
    a valid exclusion.
usage: python3 polar_closure.py m dfr_exp lam
"""
import sys, numpy as np
from math import log2, ceil
from talvardy import synthetic_pe
from minweight_count import formula_count
from hirate_polarrlce import leak_cdf, prange_find, prange_msg
from nogo_analysis import gv

def dists_from_I(m, I):
    n = 1 << m; pc = lambda x: bin(x).count('1')
    Iset = set(int(i) for i in I); F = [i for i in range(n) if i not in Iset]
    d, Nd = formula_count(m, sorted(Iset), 2); J = [(n-1) ^ i for i in F]; dp, Ndp = formula_count(m, J, 2)
    return d, Nd, dp, Ndp

def dual_cost(n, k, w, dp, Ndp):
    N = n + w; K = N - k; cdf = leak_cdf(n, w, dp); best = 1e9
    for y in range(0, dp + 1, max(1, dp // 64)):
        mult = Ndp * cdf[y]
        if mult < 1: continue
        best = min(best, prange_find(N, K, dp + y, log2(mult)))
    return best

def scan(m, dfr_exp, lam):
    n = 1 << m; feas = []
    for p in (0.002, 0.003, 0.004, 0.006, 0.008, 0.010, 0.012, 0.016, 0.020, 0.025, 0.030):
        pe = synthetic_pe(m, p, 128); order = np.argsort(pe, kind='stable'); t = int(p * n)
        for R in np.arange(0.40, 0.95, 0.02):
            k = int(R * n); I = np.sort(order[:k]); dfr = pe[I].sum()
            if dfr > 2.0 ** (-dfr_exp): continue
            d, Nd, dp, Ndp = dists_from_I(m, I)
            # largest w with msg >= lam
            if prange_msg(n + 1, k, t) < lam:
                print(f"  m={m} p={p} R={R:.2f} t={t} dfr=2^{log2(dfr):.0f} dperp={dp}: msg<{lam} even at w=1 -> excluded", flush=True); continue
            lo, hi = 1, n
            if prange_msg(n + n, k, t) >= lam: wm = n
            else:
                while hi - lo > 1:
                    mid = (lo + hi) // 2
                    if prange_msg(n + mid, k, t) >= lam: lo = mid
                    else: hi = mid
                wm = lo
            dc = dual_cost(n, k, wm, dp, Ndp)
            N = n + wm; prim_ok = (d + wm // 2) >= gv(N, k)
            ok = dc >= lam and prim_ok
            print(f"  m={m} p={p} R={R:.2f} t={t} dfr=2^{log2(dfr):.0f} d={d} dperp={dp} log2Ndp={log2(Ndp):.0f} w_m={wm} N={N}: "
                  f"dual(w_m)={dc:.0f} msg={prange_msg(N,k,t):.0f} primal={'closed' if prim_ok else 'OPEN'} key={k*(N-k)/8/2**20:.2f}MiB -> {'FEASIBLE' if ok else 'excluded'}", flush=True)
            if ok: feas.append((m, p, R, t, wm, dc))
    print(f"m={m}: {len(feas)} feasible (Prange, DFR<=2^-{dfr_exp}, lambda={lam})")
    return feas

if __name__ == "__main__":
    m = int(sys.argv[1]); dfr_exp = int(sys.argv[2]); lam = int(sys.argv[3])
    scan(m, dfr_exp, lam)
