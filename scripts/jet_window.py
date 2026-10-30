"""Map the cubic-jet attack window: for fixed (q,n,k1,k2), scan k_l and report
excess and whether the system is in the informative (underdetermined) regime.
A parameter set is 'safe' only if NO k_l gives positive excess while C(k_l+2,3) >= rows.
usage: python3 jet_window.py q n k1 k2 mode seed [kl_lo kl_hi]
"""
import sys, numpy as np
from jet import run

def main():
    q, n, k1, k2 = map(int, sys.argv[1:5]); mode = sys.argv[5]; seed = int(sys.argv[6])
    k = k1 + k2
    lo = int(sys.argv[7]) if len(sys.argv) > 7 else 3
    hi = int(sys.argv[8]) if len(sys.argv) > 8 else k - 1
    print(f"# q={q} n={n} k1={k1} k2={k2} mode={mode} seed={seed}")
    print(f"#  k_l   rows  monos  kernel generic excess  regime")
    best = None
    for kl in range(lo, hi + 1):
        r = run(q, n, k1, k2, kl, mode, seed, verbose=False)
        under = r['N3'] >= r['rows']            # informative (kernel can exceed 0)
        reg = 'under' if under else 'OVER'
        flag = ''
        if r['excess'] > 0 and under:
            flag = ' <== attackable'
            if best is None or r['excess'] > best[1]: best = (kl, r['excess'])
        print(f"  {kl:4d} {r['rows']:6d} {r['N3']:6d} {r['kernel']:6d} {r['generic']:6d} "
              f"{r['excess']:6d}  {reg}{flag}")
    print(f"# best attackable k_l: {best}")

if __name__ == '__main__':
    main()
