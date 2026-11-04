"""No-go analysis for masked polar / LDPC / MDPC trapdoors under RLCE and UVW.

Dual preservation: every dual word h of the inner code yields a public dual word of weight
  RLCE: <= wt(h) + |supp h  cap  mixed| <= 2 wt(h)   (for every w)
  UVW : exactly 2 wt(h)  (the word (h, -h) on paired coordinates, for every k1)
so the public dual distance is <= 2 d_perp(inner).  A uniform public code has dual distance
~ GV(N, N-k).  Hence the key is distinguishable whenever 2 d_perp < GV(N, N-k).

For fixed (n,k), GV(N, N-k) decreases as N grows (redundancy k fixed), so a very large number of
inserted columns could in principle escape the dual leak -- but the public code then has rate
k/N -> 0 and generic decoding of t errors becomes cheap: Prange needs about
C(N,t)/C(N-k,t) iterations, and t is capped by the inner decoder.  We search for parameters
escaping BOTH:
   (dual)   GV(N, N-k) <= 2 d_perp
   (primal) w >= max(n-k, ceil(k/2))       (RLCE square threshold + polar shortened subcode)
   (ISD)    log2(Prange iters) + 3 log2 N >= lambda     [an UPPER bound on attack cost]
with the inner error weight capped generously at capacity t <= n H^{-1}(1-k/n) (and for MDPC
also t*omega <= n).  Parameters failing any test are broken; the survivors are a superset of the
secure ones, and we report the smallest public key among them.

usage: python3 nogo_analysis.py [polar|ldpc|uvw|origsets]
"""
import sys, numpy as np
from math import log2, lgamma, ceil
from scipy.special import gammaln

LN2 = np.log(2.0)

def log2comb(n, k):
    if k < 0 or k > n: return float('-inf')
    return (lgamma(n+1) - lgamma(k+1) - lgamma(n-k+1)) / LN2

def gv(N, kk):
    """largest d with sum_{i<d} C(N-1,i) < 2^{N-kk} (log domain, vectorised)."""
    target = N - kk
    if target <= 0: return 1
    i = np.arange(0, N, dtype=np.float64)
    lc = (gammaln(N) - gammaln(i+1) - gammaln(N-1-i+1)) / LN2      # log2 C(N-1,i)
    cum = np.logaddexp.accumulate(lc*LN2) / LN2                     # log2 sum_{j<=i}
    idx = np.searchsorted(cum, target)      # first i with cum >= target  -> d = i (sum_{j<i} < 2^t)
    return int(idx)

def h2inv(y):
    lo, hi = 0.0, 0.5
    for _ in range(80):
        mid = (lo+hi)/2
        H = 0 if mid <= 0 else -mid*log2(mid) - (1-mid)*log2(1-mid)
        lo, hi = (mid, hi) if H < y else (lo, mid)
    return (lo+hi)/2

def prange_bits(N, k, t):
    return log2comb(N, t) - log2comb(N-k, t) + 3*log2(N)

from polar_reliab import dists as _dists
def polar_dists(m, k):
    return _dists(m, k)

def gv_le(N, k, D):
    """GV(N, N-k) <= D  <=>  log2 sum_{i<=D} C(N-1,i) >= k   (O(D) work)."""
    i = np.arange(0, min(D, N-1)+1, dtype=np.float64)
    lc = (gammaln(N) - gammaln(i+1) - gammaln(N-i)) / LN2
    return float(np.logaddexp.reduce(lc*LN2)/LN2) >= k

def nmin_dual(k, dperp, Nlo):
    """smallest N >= Nlo with GV(N, N-k) <= 2*dperp (GV nonincreasing in N for fixed k)."""
    D = 2*dperp
    if gv_le(Nlo, k, D): return Nlo
    lo, hi = Nlo, Nlo
    while not gv_le(hi, k, D):
        lo = hi; hi *= 2
        if hi > 1 << 60: return None
    while hi - lo > 1:
        mid = (lo+hi)//2
        if gv_le(mid, k, D): hi = mid
        else: lo = mid
    return hi

def search_polar(lam=128, ms=range(10, 21), rates=np.linspace(0.05, 0.95, 19)):
    best = None
    print(f"polarRLCE escape search, lambda={lam}: dual GV<=2d_perp, w>=max(n-k,k/2), Prange+3log2N>=lambda")
    print(f"{'m':>3}{'rate':>6}{'k':>9}{'d':>6}{'d_perp':>8}{'t_cap':>7}{'N_needed':>12}{'ISD@N':>8}  status")
    for m in ms:
        n = 1 << m
        for R in rates:
            k = int(round(R*n));  k = max(2, min(n-2, k))
            dp, dd = polar_dists(m, k)
            t = int(n * h2inv(1 - k/n))
            Nlo = n + max(n-k, ceil(k/2))
            Nd = nmin_dual(k, dd, Nlo)
            if Nd is None:
                print(f"{m:>3}{R:>6.2f}{k:>9}{dp:>6}{dd:>8}{t:>7}{'>2^60':>12}{'-':>8}  dual leak at any feasible N"); continue
            isd = prange_bits(Nd, k, t)
            ok = isd >= lam
            if ok:
                key = k*(Nd-k)/8
                if best is None or key < best[0]: best = (key, m, k, Nd, t, isd)
            print(f"{m:>3}{R:>6.2f}{k:>9}{dp:>6}{dd:>8}{t:>7}{Nd:>12}{isd:>8.1f}  "
                  f"{'NOT EXCLUDED' if ok else 'broken (ISD)'}")
    print("smallest non-excluded key:", None if best is None else
          f"{best[0]/2**30:.2f} GiB (m={best[1]},k={best[2]},N={best[3]},t={best[4]},ISD<={best[5]:.0f})")
    return best

def search_ldpc(lam=128, ns=(2**12, 2**14, 2**16, 2**18, 2**20), rates=(0.25, 0.5, 0.75)):
    """LDPC/MDPC inner code of check weight omega; decodable error weight t <= min(cap, n/omega)."""
    best = None
    print(f"\nLDPC/MDPC-RLCE escape search, lambda={lam}: t <= min(capacity, n/omega)")
    print(f"{'n':>9}{'rate':>6}{'omega':>8}{'t':>7}{'N_needed':>12}{'ISD@N':>8}  status")
    for n in ns:
        for R in rates:
            k = int(R*n)
            cap = int(n * h2inv(1-R))
            for omega in sorted(set([8, 16, 32, int(n**0.5), int(2*n**0.5), int(4*n**0.5), n//64, n//16])):
                if omega < 3 or omega > n//2: continue
                t = min(cap, n // omega)
                Nlo = n + (n - k)
                Nd = nmin_dual(k, omega, Nlo)
                if Nd is None:
                    print(f"{n:>9}{R:>6.2f}{omega:>8}{t:>7}{'>2^60':>12}{'-':>8}  dual leak"); continue
                isd = prange_bits(Nd, k, t)
                ok = isd >= lam
                if ok:
                    key = k*(Nd-k)/8
                    if best is None or key < best[0]: best = (key, n, k, omega, Nd, t, isd)
                print(f"{n:>9}{R:>6.2f}{omega:>8}{t:>7}{Nd:>12}{isd:>8.1f}  "
                      f"{'NOT EXCLUDED' if ok else 'broken (ISD)'}")
    print("smallest non-excluded key:", None if best is None else
          f"{best[0]/2**30:.2f} GiB (n={best[1]},k={best[2]},omega={best[3]},N={best[4]},t={best[5]},ISD<={best[6]:.0f})")
    return best

def uvw_table():
    """UVW over a polar inner code [n2,k2]: public [2n2, k1+k2]; leaked dual word (h,-h) weight 2 d_perp."""
    print("\nUVW with polar inner code: leaked dual weight 2*d_perp vs GV(N, N-k)")
    print(f"{'n2':>6}{'k1':>6}{'k2':>6}{'N':>7}{'k':>7}{'2d_perp':>8}{'GV_dual':>8}  verdict")
    for m in (9, 10, 11, 12):
        n2 = 1 << m
        for (f1, f2) in ((0.25, 0.25), (0.25, 0.5), (0.1, 0.5), (0.0, 0.5), (0.4, 0.3)):
            k1 = int(f1*n2); k2 = int(f2*n2)
            _, dd = polar_dists(m, k2)
            N = 2*n2; k = k1 + k2
            g = gv(N, N-k)
            print(f"{n2:>6}{k1:>6}{k2:>6}{N:>7}{k:>7}{2*dd:>8}{g:>8}  {'DUAL LEAK' if 2*dd < g else 'no leak'}")

def orig_sets():
    print("\nThe polarRLCE-1/3/5 sets of our earlier draft (w = n-k):")
    for (name, m, k, t) in (("polarRLCE-1", 12, 2458, 165), ("polarRLCE-3", 12, 2048, 335), ("polarRLCE-5", 13, 4096, 460)):
        n = 1 << m; dp, dd = polar_dists(m, k); w = n - k; N = n + w
        g = gv(N, N-k)
        print(f"  {name}: n={n} k={k} N={N}: d={dp} d_perp={dd} -> leaked dual weight <= {2*dd}, GV(N,N-k)={g}"
              f" -> {'BROKEN' if 2*dd < g else 'ok'}")

if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("origsets", "all"): orig_sets()
    if which in ("uvw", "all"): uvw_table()
    if which in ("polar", "all"): search_polar()
    if which in ("ldpc", "all"): search_ldpc()
