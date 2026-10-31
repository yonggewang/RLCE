"""One-point Hermitian AG code C(D, alpha*P_infty) over F_{q^2}, and the RLCE
transform applied to it (HermitianRLCE, Wang).  The Hermitian curve is
    y^q + y = x^{q+1}   over F_{q^2},
with q^3 affine F_{q^2}-rational points and one point P_infty.  Genus g=q(q-1)/2.
L(alpha P_infty) has basis { x^i y^j : 0<=j<=q-1, i*q + j*(q+1) <= alpha }.
Code dimension k = #basis = alpha + 1 - g  (for 2g-2 < alpha < n).

Builds the generator G_s (k x n) by evaluating the basis at the n affine points,
then the HermitianRLCE public key G = S G_1 A P2 with w random columns and w
secret 2x2 mixing blocks, exactly as RLCE.  Returns truth maps for scoring.

usage as a module: affine_points(GF,q), lspace_basis(q,alpha), herm_generator(...)
"""
import numpy as np, galois, itertools

def affine_points(GF, q):
    """All (x,y) in F_{q^2}^2 with y^q + y = x^{q+1}."""
    elts = [GF(i) for i in range(GF.order)]
    pts = []
    for x in elts:
        rhs = x ** (q + 1)
        for y in elts:
            if y ** q + y == rhs:
                pts.append((x, y))
    return pts   # length q^3

def lspace_basis(q, alpha):
    """Monomial exponents (i,j): pole order i*q + j*(q+1) <= alpha, 0<=j<=q-1."""
    B = []
    for j in range(q):
        for i in range(0, alpha + 1):
            if i * q + j * (q + 1) <= alpha:
                B.append((i, j))
    # sort by pole order (increasing) for a well-conditioned generator
    B.sort(key=lambda t: t[0] * q + t[1] * (q + 1))
    return B

def herm_generator(GF, q, alpha, pts):
    """k x n generator: rows = basis monomials, cols = affine points."""
    B = lspace_basis(q, alpha)
    n = len(pts); k = len(B)
    G = GF.Zeros((k, n))
    for r, (i, j) in enumerate(B):
        for c, (x, y) in enumerate(pts):
            G[r, c] = (x ** i) * (y ** j)
    return G, B

def rlce_transform(GF, Gs, w, rng):
    """Standard RLCE: insert w random columns next to the last w code columns,
    mix each pair by a secret invertible 2x2 with nonzero entries, scramble+perm.
    Returns G_pub (k x (n+w)), and truth: set of public-position pairs, singleton map."""
    q = GF.order
    k, n = Gs.shape
    cols = [np.array(Gs[:, j]) for j in range(n - w)]          # singletons
    meta = [('s', j) for j in range(n - w)]
    for i in range(w):
        cols.append(np.array(Gs[:, n - w + i])); meta.append(('p', i, 0))
        cols.append(np.array(rng.integers(0, q, size=k)));     meta.append(('p', i, 1))
    G1 = GF(np.column_stack(cols)); N = n + w
    A = GF(np.eye(N, dtype=int))
    for i in range(w):
        a = (n - w) + 2 * i
        while True:
            Ai = GF(rng.integers(1, q, size=(2, 2)))
            if np.linalg.det(Ai) != 0: break
        A[a:a+2, a:a+2] = Ai
    perm = rng.permutation(N)
    while True:
        S = GF(rng.integers(0, q, size=(k, k)))
        if np.linalg.matrix_rank(S) == k: break
    G = S @ G1 @ A @ GF(np.eye(N, dtype=int)[:, perm])
    inv = np.argsort(perm)
    true_pair = {}
    for i in range(w):
        q0 = int(np.where(perm == (n - w) + 2 * i)[0][0])
        q1 = int(np.where(perm == (n - w) + 2 * i + 1)[0][0])
        true_pair[frozenset((q0, q1))] = i
    sing = {int(np.where(perm == j)[0][0]): j for j in range(n - w)}
    return G, dict(S=S, perm=perm, true_pair=true_pair, sing=sing, n=n, w=w, k=k)

if __name__ == '__main__':
    import sys
    q = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    GF = galois.GF(q * q)
    pts = affine_points(GF, q)
    g = q * (q - 1) // 2
    print(f"q={q} F_{q*q} affine points={len(pts)} (expect {q**3}) genus g={g}")
    for alpha in (2 * g, 3 * g, 4 * g):
        B = lspace_basis(q, alpha)
        print(f"  alpha={alpha}: k=dim L={len(B)} (RR expects {alpha+1-g}); first basis {B[:4]}")
