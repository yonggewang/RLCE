"""Forcing law check: j points spanning P^{j-1} (coordinates = F_p^j), degree-d forms,
order-r jets (rows: all order-(r-1) derivatives; over p > d they span the lower orders).
   kernel dim  =  #{alpha : |alpha| = d, all alpha_a <= d - r}   (monomial count)
   Q forced    <=>  kernel = 0  <=>  j r > (j-1) d.
Q = a point of the span with all coordinates nonzero."""
import itertools, sys, numpy as np
from ff import GF
from jet_jway import jet_build
p = 101; gf = GF(p)
def moncount(j, d, r):
    return sum(1 for a in itertools.product(range(d - r + 1), repeat=j) if sum(a) == d)
bad = 0; n = 0; lines = []
for j in range(1, 7):
    for d in range(2, 9):
        for r in range(1, d + 1):
            rng = np.random.default_rng(1000 * j + 10 * d + r)
            while True:
                P = rng.integers(1, p, size=(j, j), dtype=np.int64)
                if gf.rank(P) == j: break
            M, rows, Nd = jet_build(gf, P, d, r)
            rk = gf.rank(M.astype(np.int64)); ker = Nd - rk
            c = rng.integers(1, p, size=j, dtype=np.int64); Q = (c @ P) % p
            # evaluation row at Q
            mons = list(itertools.combinations_with_replacement(range(j), d))
            ev = np.array([np.prod([Q[t] for t in mon]) % p for mon in mons], dtype=np.int64).reshape(1, -1)
            rk2 = gf.rank(np.vstack([M.astype(np.int64), ev]))
            forced = (rk2 == rk); law = (j * r > (j - 1) * d); mc = moncount(j, d, r)
            ok = (forced == law) and (ker == mc); bad += (not ok); n += 1
            if not ok or r == d - 1: lines.append(f"j={j} d={d} r={r}: kernel={ker} monomials={mc} forced={forced} law={law} {'OK' if ok else 'MISMATCH'}")
print("\n".join(lines)); print(f"checked {n} triples (j<=6, d<=8, 1<=r<=d): mismatches = {bad}")
