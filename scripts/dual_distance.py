"""Does the RLCE mask hide the polar code's DUAL low-weight object?

Polar codes are decreasing-monomial codes, so BOTH the code and its dual have minimum-weight
words that are affine indicators (BCDOT).  The RLCE mask is a primal column operation: by the
same argument that breaks LDPC-RLCE (a dual word (h,0) sets itself to 0 on the inserted columns
and survives for every w), the mask cannot lift a DUAL low-weight word above GV.  So polar-RLCE
is distinguishable via its dual whenever d_perp(polar) << GV(N, N-k), for EVERY w -- including
the repaired rate<=2/3, w=n-k regime.

For a polar code with information set I (indices of F^{otimes m} rows kept):
   d_primal = 2^{p_min},   p_min = min_{i in I} popcount(i)
   d_dual   = 2^{m - p_max_frozen},  p_max_frozen = max_{i notin I} popcount(i)
(the dual of C(I) is the decreasing-monomial code on the bit-complement of the frozen set).

We (1) verify both formulas on small enumerable codes against the true min distances, then
(2) evaluate d_primal, d_dual and the GV bounds at the paper's parameter sets.
"""
import sys, itertools, numpy as np
from polar import Fkron, rank2, left_null_f2

def bec_bhattacharyya(m):
    z = np.array([0.5])
    for _ in range(m):
        z = np.concatenate([2*z - z*z, z*z])
    return z

def info_set(m, k):
    z = bec_bhattacharyya(m)
    order = np.argsort(z, kind='stable')     # most reliable (smallest Z) first
    return sorted(order[:k].tolist())

def popcount(x): return bin(x).count('1')

def d_primal_formula(m, I):
    return 1 << min(popcount(i) for i in I)

def d_dual_formula(m, I):
    frozen = [i for i in range(1 << m) if i not in set(I)]
    pmax = max(popcount(i) for i in frozen)
    return 1 << (m - pmax)

def polar_gen_from_I(m, I):
    G = Fkron(m)
    return G[np.array(sorted(I))] % 2

def true_min_weight(G):
    """exact min distance by enumerating all 2^k codewords (small k only)."""
    k, n = G.shape
    rowsint = []
    for r in range(k):
        x = 0
        for c in range(n):
            if G[r, c] & 1: x |= (1 << c)
        rowsint.append(x)
    best = n + 1; acc = 0
    for i in range(1, 1 << k):
        b = (i & -i).bit_length() - 1
        acc ^= rowsint[b]
        w = acc.bit_count()
        if 0 < w < best: best = w
    return best

def gv_bound(N, kk):
    from math import lgamma
    def lcomb(nn, rr):
        if rr < 0 or rr > nn: return float('-inf')
        return (lgamma(nn+1)-lgamma(rr+1)-lgamma(nn-rr+1))/np.log(2)
    target = N - kk; acc = float('-inf'); d = 0
    while d <= N:
        lc = lcomb(N-1, d)
        new = lc if acc == float('-inf') else (acc if lc == float('-inf') else np.logaddexp2(acc, lc))
        if new >= target and acc != float('-inf'): return d
        acc = new; d += 1
    return N

def verify_small():
    print("=== verify d_primal / d_dual formulas vs exact enumeration (small m) ===")
    for m in (4, 5, 6):
        n = 1 << m
        for k in (n//4, n//2, (3*n)//4):
            if k < 2 or k > n-2: continue
            I = info_set(m, k)
            G = polar_gen_from_I(m, I)
            H = left_null_f2(G.T)            # dual generator (n-k x n)
            dp_f = d_primal_formula(m, I); dd_f = d_dual_formula(m, I)
            dp_t = true_min_weight(G)
            dd_t = true_min_weight(H) if H.shape[0] <= 20 else -1
            okp = "OK" if dp_f == dp_t else "MISMATCH"
            okd = "OK" if (dd_t == -1 or dd_f == dd_t) else "MISMATCH"
            print(f"  m={m} n={n} k={k}: d_primal formula={dp_f} true={dp_t} [{okp}] | "
                  f"d_dual formula={dd_f} true={dd_t} [{okd}]")

def crypto_table():
    print("\n=== polar primal/dual minimum distance vs GV at cryptographic sizes (w=n-k) ===")
    print(f"{'n':>5}{'k':>6}{'rate':>6}{'d_prim':>7}{'d_dual':>7}{'w':>6}{'N':>6}"
          f"{'GV(N,k)':>9}{'GVdual':>8} | verdict")
    for m in (10, 11, 12):
        n = 1 << m
        for rate in (0.9, 0.67, 0.6, 0.5, 0.4):
            k = int(round(rate*n)); I = info_set(m, k)
            dp = d_primal_formula(m, I); dd = d_dual_formula(m, I)
            w = n - k; N = n + w
            gvp = gv_bound(N, k)            # primal public code [N,k]
            gvd = gv_bound(N, N-k)          # public dual [N, N-k]
            prim_leak = dp < gvp            # closable by w>=k/2 (shortened subcode)
            dual_leak = 2*dd < gvd          # NOT closable by w
            verdict = "DUAL LEAK (broken any w)" if dual_leak else "dual ok"
            print(f"{n:>5}{k:>6}{rate:>6.2f}{dp:>7}{dd:>7}{w:>6}{N:>6}{gvp:>9}{gvd:>8} | {verdict}")
        print()

if __name__ == "__main__":
    verify_small()
    crypto_table()
