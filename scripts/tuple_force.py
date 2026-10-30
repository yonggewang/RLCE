"""Per-tuple extraction: for j general points spanning P^{j-1}, do the order-r jets
of degree-d forms FORCE the value at a general additional point Q (the hidden curve
point in the tuple's span)?  eval_Q is extractable iff it lies in the row span of the
jet functionals, i.e. iff every degree-d form vanishing to order r at the j points
also vanishes at Q.  We also report how many independent 'extra' functionals per tuple
are forced (eval + directional derivatives at Q), which is what makes composed
polynomials dependent across tuples.

For each (j,d,r): kernel K = degree-d forms with mult>=r at the j points; Q forced iff
all of K vanish at Q.  Prints: dimForms, #jetConditions, rank, kernelK, Q_forced,
and extra = (number of Hermite functionals at Q in the span) estimated by testing
eval and first derivatives at Q.
"""
import sys, itertools, numpy as np, galois
from math import comb

def forms_basis(jv, d):
    return list(itertools.combinations_with_replacement(range(jv), d))  # monomial exponents (as index multisets)

def eval_monomials(mons, x, p):
    # value of each monomial at point x (length jv) over F_p
    out = np.ones(len(mons), dtype=np.int64)
    for i, mon in enumerate(mons):
        v = 1
        for t in mon: v = v * int(x[t]) % p
        out[i] = v
    return out % p

def deriv_func(mons, x, order_idx, p):
    """Row = functional 'partial^{order_idx} evaluated at x' acting on each monomial.
    order_idx is a tuple of variable indices (the derivative multi-index)."""
    jv = len(x)
    row = np.zeros(len(mons), dtype=np.int64)
    from collections import Counter
    dcnt = Counter(order_idx)
    for i, mon in enumerate(mons):
        ecnt = Counter(mon)
        coef = 1; ok = True
        for t, dd in dcnt.items():
            if ecnt[t] < dd: ok = False; break
            for s in range(dd): coef = coef * (ecnt[t] - s) % p
        if not ok: continue
        # remaining monomial after differentiation, evaluated at x
        val = coef % p
        rem = list(mon)
        for t, dd in dcnt.items():
            for _ in range(dd): rem.remove(t)
        for t in rem: val = val * int(x[t]) % p
        row[i] = val % p
    return row

def jet_rows(mons, x, r, p):
    jv = len(x); rows = []
    for s in range(r):   # derivative orders 0..r-1
        for oi in itertools.combinations_with_replacement(range(jv), s):
            rows.append(deriv_func(mons, x, oi, p))
    return rows

def check(j, d, r, p=101, seed=0):
    GFp = galois.GF(p); rng = np.random.default_rng(seed)
    jv = j  # work in affine j coords (homogeneous degree d in j vars ~ P^{j-1})
    mons = forms_basis(jv, d)
    # j general points in F_p^j (representing the j columns), in general position
    while True:
        P = rng.integers(1, p, size=(j, jv), dtype=np.int64)
        if np.linalg.matrix_rank(GFp(P % p)) == j: break
    rows = []
    for a in range(j):
        rows += jet_rows(mons, P[a], r, p)
    J = GFp(np.array(rows, dtype=np.int64) % p)
    rk = int(np.linalg.matrix_rank(J))
    dimForms = len(mons)
    kerK = dimForms - rk
    # Q = general point in span of the j points (a 'curve point'): random combo
    c = rng.integers(1, p, size=j, dtype=np.int64)
    Q = (c @ P) % p
    evalQ = GFp(eval_monomials(mons, Q, p).reshape(1, -1) % p)
    # Q forced iff rank([J; evalQ]) == rank(J)
    rk2 = int(np.linalg.matrix_rank(np.vstack([np.array(J), np.array(evalQ)]) % p))
    forced = (rk2 == rk)
    # how many Hermite functionals at Q are already in rowspan (eval + first derivs)
    extra = 0
    cur = np.array(J) % p; base = rk
    for s in range(0, d + 1):
        added = False
        for oi in itertools.combinations_with_replacement(range(jv), s):
            row = deriv_func(mons, Q, oi, p).reshape(1, -1) % p
            stack = np.vstack([cur, row]) % p
            if int(np.linalg.matrix_rank(GFp(stack))) == base:
                extra += 1  # this Q-functional is in the span
        # stop climbing orders once an order contributes nothing new to the span
    return dict(j=j, d=d, r=r, dimForms=dimForms, jetConds=len(rows), rank=rk,
                kerK=kerK, Q_forced=forced, Q_funcs_in_span=extra)

if __name__ == '__main__':
    print("j d r | dimForms jetConds rank kerK | Q_forced  #Q-Hermite-in-span")
    grid = []
    for j in (2, 3, 4):
        for d in range(2, 7):
            for r in range(2, d + 1):
                grid.append((j, d, r))
    for (j, d, r) in grid:
        res = check(j, d, r, p=101, seed=j * 100 + d * 10 + r)
        print(f"{j} {d} {r} | {res['dimForms']:4d} {res['jetConds']:5d} {res['rank']:4d} {res['kerK']:4d} "
              f"| forced={str(res['Q_forced']):5s}  Qspan={res['Q_funcs_in_span']}")
