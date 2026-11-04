"""Rank of the order-2 jets (value+gradient) of cubic forms at m points of the rational
normal curve gamma(a) = (1, a, ..., a^{k2-1}) in F_p^{k2}: are m*k2 conditions independent?"""
import sys, itertools, numpy as np
from ff import GF
from jet_jway import jet_build
p = 101; gf = GF(p)
for k2 in (10, 15, 18, 20, 25):
    out = []
    for m in (k2 - 2, k2, k2 + 2, k2 + 5, k2 + 10, k2 + 20, 2 * k2 + 10, 3 * k2):
        rng = np.random.default_rng(m)
        al = rng.choice(np.arange(1, p), size=m, replace=False)
        X = np.array([[pow(int(a), e, p) for e in range(k2)] for a in al], dtype=np.int64)
        M, rows, Nd = jet_build(gf, X, 3, 2)
        rk = gf.rank(M.astype(np.int64))
        exp = min(rows, Nd)
        out.append(f"m={m}:{rk}/{exp}(-{exp-rk})")
    print(f"k2={k2} N3={Nd}:", "  ".join(out), flush=True)
