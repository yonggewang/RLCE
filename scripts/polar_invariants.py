"""Structural invariants of polar codes and the polarRLCE public code, over F2.

We measure, by exact enumeration (small k), the quantities that decide whether the
RLCE mask hides the polar structure that Bardet-Chaulet-Dragoi-Otmani-Tillich
(PQCrypto 2016) exploit:

  (1) minimum distance and low-weight spectrum of the polar code C,
  (2) the same for the polarRLCE public code P = S G1 A pi  (G1 = [C | w random cols]),
  (3) a random [N,k] code baseline (expected min distance ~ GV bound),
  (4) for every public codeword at or just above the public minimum weight, whether
      its support -- after de-permuting with the (known, for the experiment) secret
      and dropping the mixed positions -- is an affine subspace of F2^m, i.e. the
      support signature BCDOT reads off decreasing-monomial min-weight words.

Enumeration is Gray-code over the 2^k message space; feasible for k<=22.

usage: python3 polar_invariants.py t k w seed [wt_margin]
"""
import sys, itertools, numpy as np
from polar import Fkron, polar_gen, rank2

def gray_spectrum(rows_int, k, wt_cap):
    """All codewords of the [*, k] code with rows given as Python-int bitmasks.
    Returns (min_weight, {weight: count} up to wt_cap, list of (weight,word) with weight<=wt_cap)."""
    acc = 0
    spec = {}
    low = []
    best = 10**9
    # message 0 -> codeword 0 (weight 0); skip the all-zero word for min distance
    for i in range(1, 1 << k):
        b = (i & -i).bit_length() - 1      # index of bit flipped in Gray sequence
        acc ^= rows_int[b]
        wt = acc.bit_count()
        if wt:
            if wt < best: best = wt
            if wt <= wt_cap:
                spec[wt] = spec.get(wt, 0) + 1
                if len(low) < 200000:
                    low.append((wt, acc))
    return best, spec, low

def rows_to_int(G):
    """k x N 0/1 array -> list of N-bit Python ints (LSB = column 0)."""
    k, N = G.shape
    out = []
    for r in range(k):
        x = 0
        for c in range(N):
            if G[r, c] & 1:
                x |= (1 << c)
        out.append(x)
    return out

def polarRLCE_public(G, w, rng):
    """Return (P, meta) where P is k x N public generator and meta records, per public
    column, its origin: ('polar', j) original polar col j, or ('rand',) inserted, with
    the applied permutation, so the experiment can de-permute.  Mirrors rlce_transform_f2
    but exposes the bookkeeping."""
    k, n = G.shape
    # build G1 = original n cols, then for the last w original cols insert a random twin
    cols = []
    origin = []
    for j in range(n - w):
        cols.append(G[:, j].copy()); origin.append(('p', j))
    for i in range(w):
        j = n - w + i
        cols.append(G[:, j].copy()); origin.append(('p', j))
        cols.append(rng.integers(0, 2, size=k)); origin.append(('r', i))
    G1 = np.array(cols).T % 2          # k x (n+w)
    N = n + w
    # pair-mix the 2w trailing columns with invertible 2x2 over F2
    opts = [np.array([[1,1],[0,1]]), np.array([[1,0],[1,1]]),
            np.array([[0,1],[1,1]]), np.array([[1,1],[1,0]])]
    Gcols = [G1[:, c].copy() for c in range(N)]
    base = n - w
    for i in range(w):
        a = base + 2*i
        Aop = opts[rng.integers(0, len(opts))]
        c0 = (Aop[0,0]*Gcols[a] + Aop[0,1]*Gcols[a+1]) % 2
        c1 = (Aop[1,0]*Gcols[a] + Aop[1,1]*Gcols[a+1]) % 2
        Gcols[a], Gcols[a+1] = c0, c1
    G1m = np.array(Gcols).T % 2
    perm = rng.permutation(N)
    while True:
        S = rng.integers(0, 2, size=(k, k))
        if rank2(S) == k: break
    P = (S @ G1m) % 2
    P = P[:, perm] % 2
    origin_perm = [origin[perm.tolist().index(c)] if c in perm else None for c in range(N)]
    # map public column -> origin: public col c came from pre-perm column perm_inv
    inv = np.argsort(perm)
    puborigin = [origin[inv_c] for inv_c, c in enumerate(perm)]  # not used; compute cleanly below
    # cleaner: public position p holds pre-perm column perm[p]? np.take: P[:,perm] means
    # public col p = G1m[:, perm[p]].  So origin of public col p is origin[perm[p]].
    puborigin = [origin[perm[p]] for p in range(N)]
    return P, {'perm': perm, 'puborigin': puborigin, 'base': base, 'n': n, 'w': w, 'N': N}

def is_affine_subspace(support_positions, mvecs):
    """support_positions: indices into the n polar coordinates (0..n-1).
    mvecs: for each polar coordinate, its point in F2^m (the evaluation point / column index bits).
    Return (is_affine, dim) : True if the set of points is a coset of a linear subspace."""
    pts = [mvecs[j] for j in support_positions]
    if len(pts) == 0: return (False, -1)
    base = pts[0]
    diffs = [p ^ base for p in pts]          # XOR in F2^m as ints
    # span of diffs
    span = set([0])
    basis = []
    for d in diffs:
        x = d
        for b in basis:
            x = min(x, x ^ b)
        if x:
            basis.append(x); basis.sort(reverse=True)
            newspan = set()
            for s in span: newspan.add(s); newspan.add(s ^ x)
            span = newspan
    size = 1 << len(basis)
    return (len(pts) == size and set(diffs) <= span and len(set(diffs)) == size, len(basis))

def main():
    t = int(sys.argv[1]); k = int(sys.argv[2]); w = int(sys.argv[3]); seed = int(sys.argv[4])
    margin = int(sys.argv[5]) if len(sys.argv) > 5 else 2
    rng = np.random.default_rng(seed)
    n = 1 << t
    G, I = polar_gen(t, k)                    # k x n polar generator; I = info monomials (row indices)
    # evaluation point of polar coordinate c is just the m-bit binary of c
    mvecs = list(range(n))                    # column c  <-> point c in F2^m (as int)

    # (1) polar code invariants  (single enumeration; cap generously then filter)
    cap = max(8, n // 2)
    dpol, specpol, lowpol = gray_spectrum(rows_to_int(G), k, wt_cap=cap)
    specpol = {wt: c for wt, c in specpol.items() if wt <= dpol + margin}
    lowpol = [(wt, x) for (wt, x) in lowpol if wt <= dpol + margin]
    print(f"[polar]  t={t} n={n} k={k} rate={k/n:.3f}  d={dpol}  N_d={specpol.get(dpol,0)}  spectrum<=d+{margin}: "
          + ", ".join(f"{wt}:{specpol[wt]}" for wt in sorted(specpol)))

    # (2) polarRLCE public code
    P, meta = polarRLCE_public(G, w, rng)
    N = meta['N']
    capN = max(8, N // 2)
    dpub, specpub, lowpub = gray_spectrum(rows_to_int(P), k, wt_cap=capN)
    specpub = {wt: c for wt, c in specpub.items() if wt <= dpub + margin}
    lowpub = [(wt, x) for (wt, x) in lowpub if wt <= dpub + margin]
    print(f"[public] N={N} k={k} rate={k/N:.3f} w={w}  d_pub={dpub}  N_dpub={specpub.get(dpub,0)}  "
          f"spectrum<=d+{margin}: " + ", ".join(f"{wt}:{specpub[wt]}" for wt in sorted(specpub)))

    # (3) random [N,k] baseline
    while True:
        R = rng.integers(0, 2, size=(k, N))
        if rank2(R) == k: break
    drand, specrand, _ = gray_spectrum(rows_to_int(R), k, wt_cap=max(8, N // 2))
    gv = drand
    print(f"[random] N={N} k={k}  d_rand={drand} (empirical GV for this length/dim)")

    # (4) affine-support signature of low-weight PUBLIC words
    # For each public low-weight word, map support back: drop mixed/inserted public positions,
    # keep positions whose origin is ('p', j) with j in an UNMIXED original column (j < base),
    # translate to polar coordinate j, and test affine-ness.
    base = meta['base']; pubo = meta['puborigin']
    # public position -> ('p', j)/('r', i); also whether that pre-perm column was in a mixed pair
    mixed_preperm = set(range(base, meta['n'] + w))   # pre-perm indices base..n+w-1 are the 2w mixed
    affine_hits = 0; tested = 0
    for wt, word in lowpub:
        if wt != dpub:        # focus on exact-minimum public words
            continue
        supp = [p for p in range(N) if (word >> p) & 1]
        # polar coordinates touched on UNMIXED positions:
        polar_coords = []
        touches_mixed = False
        for p in supp:
            o = pubo[p]
            preperm_idx = meta['perm'][p]
            if preperm_idx in mixed_preperm:
                touches_mixed = True
            if o[0] == 'p' and o[1] < base:
                polar_coords.append(o[1])
        tested += 1
        if not touches_mixed and len(polar_coords) == wt:
            isaff, dim = is_affine_subspace(polar_coords, mvecs)
            if isaff:
                affine_hits += 1
    print(f"[signature] exact-min public words tested={tested}  "
          f"untouched-by-mask & affine-support={affine_hits}  "
          f"(affine support => BCDOT orbit signature available)")

if __name__ == '__main__':
    main()
