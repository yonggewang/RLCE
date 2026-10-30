"""Verify the simplex-form obstruction: for j general points x_1..x_j spanning
P^{j-1}, let H_a be the hyperplane through all points EXCEPT x_a, and
P = prod_a H_a (degree j).  Claim: P vanishes to order exactly j-1 at each x_b
(so P is a nonzero degree-j form in the kernel of the order-(j-1) jet system,
i.e. (d,r)=(j,j-1)), and P(Q) != 0 for a general point Q of the plane.  Hence
the curve point is NOT forced at degree j, proving jet degree >= j+1.
Also confirms the (j,j-1) jet kernel is exactly 1-dimensional (= span of P)."""
import itertools, numpy as np, galois

def hyperplane_through(points):
    # linear form (coeff vector) vanishing on all given points (j-1 points in F^j)
    GF = points.__class__
    A = points  # (j-1) x j
    ns = A.null_space()  # 1 x j
    return ns[0]

def vanish_order(coeffsP_as_poly, x, jv, p, upto):
    """order of vanishing of form P (given as dict monomial->coef) at point x:
    smallest s with some order-s derivative != 0."""
    from collections import Counter
    for s in range(upto + 1):
        for oi in itertools.combinations_with_replacement(range(jv), s):
            dcnt = Counter(oi); val = 0
            for mon, c in coeffsP_as_poly.items():
                ec = Counter(mon); coef = int(c); ok = True
                for t, dd in dcnt.items():
                    if ec[t] < dd: ok = False; break
                    for u in range(dd): coef = coef * (ec[t] - u) % p
                if not ok: continue
                rem = list(mon)
                for t, dd in dcnt.items():
                    for _ in range(dd): rem.remove(t)
                v = coef
                for t in rem: v = v * int(x[t]) % p
                val = (val + v) % p
            if val % p != 0:
                return s
    return upto + 1

def poly_mul(a, b, p):
    out = {}
    for ma, ca in a.items():
        for mb, cb in b.items():
            m = tuple(sorted(ma + mb)); out[m] = (out.get(m, 0) + ca * cb) % p
    return out

def check(j, p=101, seed=0):
    GF = galois.GF(p); rng = np.random.default_rng(seed)
    while True:
        X = GF(rng.integers(1, p, size=(j, j)))
        if np.linalg.matrix_rank(X) == j: break
    # hyperplane H_a omits point a
    P = {(): 1}  # constant 1
    for a in range(j):
        others = GF(np.array([np.array(X[b]) for b in range(j) if b != a]))
        h = hyperplane_through(others)  # length-j coeff vector
        lin = {(t,): int(h[t]) for t in range(j) if int(h[t]) != 0}
        P = poly_mul(P, lin, p)
    # vanishing order at each point
    ords = [vanish_order(P, np.array(X[b]), j, p, j) for b in range(j)]
    # value at a general Q in the span
    c = rng.integers(1, p, size=j, dtype=np.int64); Q = (GF(c) @ X)
    from collections import Counter
    valQ = 0
    for mon, co in P.items():
        v = int(co)
        for t in mon: v = v * int(Q[t]) % p
        valQ = (valQ + v) % p
    print(f"j={j}: deg(P)={sum(len(m) for m in [max(P,key=lambda k:len(k))])}={j}? "
          f"vanish-orders at the {j} points = {ords} (expect all {j-1}); "
          f"P(Q)={valQ} (expect !=0): {'OK' if all(o==j-1 for o in ords) and valQ!=0 else 'FAIL'}")

if __name__ == '__main__':
    for j in (2, 3, 4, 5, 6):
        check(j, seed=j)
