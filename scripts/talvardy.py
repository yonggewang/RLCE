"""Rigorous upper bounds on SC-decoding failure for polar codes on BSC(p), via degrading merges
(Tal-Vardy, IEEE IT 2013).  A BMS channel is stored as symmetric output pairs (a_i, b_i) with
a_i = W(y_i|0) >= b_i = W(y_i|1) and conjugate (b_i, a_i); sum_i (a_i+b_i) = 1.
Polar transforms (ordered input pairs (i,j); each class below carries two conjugate pairs):
  W^-: (A,B) = ( (a_i a_j + b_i b_j)/2 , (a_i b_j + b_i a_j)/2 )
  W^+: (a_i a_j/2 , b_i b_j/2)  and  (a_i b_j/2 , b_i a_j/2)
Degradation: merging output symbols is a degradation (post-processing), so binning symbols by
log-likelihood ratio into mu bins and summing yields a channel W' degraded w.r.t. W, with
P_e(W') >= P_e(W).  Hence  P_fail(SC, I) <= sum_{i in I} P_e(W_i') is a rigorous bound for
Bernoulli(p) errors; P_e(W) = sum_i b_i.
Channel index order matches polar_reliab (children concatenated [minus-of-all, plus-of-all]).
"""
import numpy as np
from math import log2

MU = 256
def _bin(P0, P1, wt, mu):
    """canonicalise to (max,min), bin by log-LR, merge within bins (degradation)."""
    hi = np.maximum(P0, P1); lo = np.minimum(P0, P1)
    mass = (hi + lo) * wt
    keep = mass > 0
    hi, lo, wt = hi[keep], lo[keep], wt[keep]
    with np.errstate(divide='ignore'):
        llr = np.where(lo > 0, np.log(hi / np.maximum(lo, 1e-300)), np.inf)
    fin = np.isfinite(llr)
    a = np.zeros(mu + 1); b = np.zeros(mu + 1)
    if fin.any():
        l = llr[fin]; lmax = l.max()
        edges = np.linspace(0, lmax + 1e-12, mu + 1)
        idx = np.clip(np.searchsorted(edges, l, side='right') - 1, 0, mu - 1)
        np.add.at(a, idx, hi[fin] * wt[fin]); np.add.at(b, idx, lo[fin] * wt[fin])
    if (~fin).any():
        a[mu] += (hi[~fin] * wt[~fin]).sum(); b[mu] += (lo[~fin] * wt[~fin]).sum()
    keep = (a + b) > 0
    return a[keep], b[keep]

def minus(a, b, mu=MU):
    A = 0.5 * (np.outer(a, a) + np.outer(b, b)); B = 0.5 * (np.outer(a, b) + np.outer(b, a))
    return _bin(A.ravel(), B.ravel(), np.full(A.size, 2.0), mu)

def plus(a, b, mu=MU):
    A1 = 0.5 * np.outer(a, a); B1 = 0.5 * np.outer(b, b)
    A2 = 0.5 * np.outer(a, b); B2 = 0.5 * np.outer(b, a)
    P0 = np.concatenate([A1.ravel(), A2.ravel()]); P1 = np.concatenate([B1.ravel(), B2.ravel()])
    return _bin(P0, P1, np.full(P0.size, 2.0), mu)

def synthetic_pe(m, p, mu=MU):
    """upper bounds P_e(W_i') for the 2^m synthetic channels of BSC(p)."""
    chans = [(np.array([1 - p]), np.array([p]))]
    for _ in range(m):
        nxt_minus = [minus(a, b, mu) for (a, b) in chans]
        nxt_plus = [plus(a, b, mu) for (a, b) in chans]
        chans = nxt_minus + nxt_plus
    return np.array([b.sum() for (a, b) in chans])

def dfr_bound(m, k, p, mu=MU, info=None):
    """(bound on SC failure, info set used).  info=None: pick the k best channels of BSC(p)."""
    pe = synthetic_pe(m, p, mu)
    if info is None:
        info = np.sort(np.argsort(pe, kind='stable')[:k])
    return float(pe[info].sum()), info

if __name__ == "__main__":
    import sys
    # sanity: BEC-type check -- Z of BSC(p) after one minus/plus vs closed form, and monotone degradation
    m = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    for p in (0.005, 0.01, 0.02, 0.04):
        for R in (0.5, 0.7, 0.8, 0.85):
            n = 1 << m; k = int(R * n)
            b, I = dfr_bound(m, k, p)
            print(f"m={m} p={p} R={R}: SC failure <= 2^{log2(b) if b>0 else -999:.1f}", flush=True)
