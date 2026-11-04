"""End-to-end long-key RLCE key recovery from the public key alone, with a fresh-ciphertext
decryption check.  Companion to rlce_recover.py (which does one shortening round).

Pipeline (public key only; the secret key is used ONLY to score intermediate steps, marked [truth]):
  1. adaptive shortening rounds: Z = coordinates of known pairs, then never-rank-one columns
     ordered by number of survivals, then unseen columns; cubic gradient jet system of the
     shortened code; left kernel (nullspace2m); rank-one blocks -> pairs and ratios
     (Theorem "block structure": lambda_i = a x_i + b x_j, t/s = b/a in char 2); ratio
     transferred to the unshortened public columns: hidden column h = g_i + (b/a) g_j.
  2. fold: F = [singleton columns | hidden columns of the pairs]  (k x n); rowsp F = hidden GRS.
  3. Sidelnikov-Shestakov on F over GF(2^m): support alpha (projective normalisation
     alpha_1=0, alpha_2=1, one free Moebius parameter) and multipliers beta (via the dual).
  4. decrypt a fresh ciphertext c = mG + e, wt(e)=t: fold c along the pairs, divide by beta,
     Berlekamp-Welch, recover the codeword, invert the fold to get m; compare with m.
usage: python3 rlce_e2e.py m n k w k_l t seed workdir [max_rounds]
"""
import sys, os, json, time, subprocess, numpy as np, galois
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'rlce', 'scripts'))
from rlce_recover import keygen, cubic_jet_matrix

NULLSPACE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'rlce', 'scripts', 'nullspace2m')

def log(t0, msg): print(f"[{time.time()-t0:7.0f}s] {msg}", flush=True)

def left_kernel(GF, M, wd, m):
    mf = os.path.join(wd, 'M.bin'); kf = os.path.join(wd, 'K.bin')
    with open(mf, 'wb') as f: np.array([M.shape[0], M.shape[1]], dtype=np.int64).tofile(f); M.tofile(f)
    r = subprocess.run([NULLSPACE, mf, kf, str(m), str(int(GF.irreducible_poly)), str(int(GF.primitive_element))],
                       capture_output=True, text=True)
    h = np.fromfile(kf, dtype=np.int64, count=2); ker, ln = int(h[0]), int(h[1])
    K = GF(np.fromfile(kf, dtype=np.uint16, offset=16).reshape(ker, ln).astype(np.int64))
    return K, r.stderr.strip()

def solve_ratio(GF, lam, xi, xj, kl):
    """lam = a xi + b xj; return b/a (None if a=0 or inconsistent)."""
    A = GF(np.column_stack([np.array(xi), np.array(xj)]))
    # least-squares-free: find 2 independent rows
    for r1 in range(kl):
        for r2 in range(r1 + 1, kl):
            sub = A[[r1, r2], :]
            if np.linalg.det(sub) != 0:
                sol = np.linalg.solve(sub, GF([int(lam[r1]), int(lam[r2])]))
                a, b = sol[0], sol[1]
                if int(a) == 0: return None
                # consistency check on all rows
                if np.array_equal(np.array(A @ sol), np.array(lam)): return b / a
                return None
    return None

def one_round(GF, G, Z, t0, wd, m, kl):
    N = G.shape[1]; keep = [c for c in range(N) if c not in Z]
    L = G[:, sorted(Z)].T.null_space()                     # k_l x k
    assert L.shape[0] == kl, (L.shape, kl)
    X = (L @ G)[:, keep].T                                 # n' x k_l
    npts = X.shape[0]
    M, Nm = cubic_jet_matrix(GF, X)
    log(t0, f"  jet system {M.shape[0]}x{Nm}; left kernel...")
    K, info = left_kernel(GF, M, wd, m); log(t0, f"  {info}")
    ker = K.shape[0]
    blocks = [K[:, c * kl:(c + 1) * kl] for c in range(npts)]
    ranks = np.array([int(np.linalg.matrix_rank(B)) for B in blocks])
    rank1 = [c for c in range(npts) if ranks[c] == 1]
    def coldir(B):
        for t in range(kl):
            col = B[:, t]
            if np.any(np.array(col)):
                piv = next(int(v) for v in np.array(col) if v); return tuple(int(v) for v in (col / GF(piv)))
    groups = {}
    for c in rank1: groups.setdefault(coldir(blocks[c]), []).append(c)
    pairs = {}   # frozenset(public i, j) -> (i, j, rho) meaning hidden column = g_i + rho g_j
    for g in groups.values():
        if len(g) != 2: continue
        ci, cj = g; B = blocks[ci]
        r0 = next(t for t in range(ker) if np.any(np.array(B[t])))
        rho = solve_ratio(GF, B[r0], X[ci], X[cj], kl)
        if rho is None: continue
        pairs[frozenset((keep[ci], keep[cj]))] = (keep[ci], keep[cj], int(rho))
    return pairs, keep, ker, ranks, len(rank1)

def sidelnikov_shestakov(GF, F):
    """F: k x n generator of a GRS code over GF(q), n <= q-1. Returns alpha (n,), beta (n,)
    with rowsp F = {(beta_j P(alpha_j))_j : deg P < k}, or raises."""
    k, n = F.shape; q = GF.order
    R = F.row_reduce(); piv = []
    for i in range(k):
        nz = np.nonzero(np.array(R[i]))[0]; piv.append(int(nz[0]))
    assert len(set(piv)) == k
    A = R                                              # identity on pivot columns
    J = [j for j in range(n) if j not in set(piv)]
    r = np.array(A[0, J]) ; s = np.array(A[1, J])
    assert np.all(r) and np.all(s), "zero entries in systematic form (degenerate pivots)"
    ratio = GF(r) / GF(s)                              # c (alpha_j - 1)/alpha_j  (alpha_p0=0, alpha_p1=1)
    alpha = None
    for c in range(1, q):
        cG = GF(c); den = cG - ratio
        if np.any(np.array(den) == 0): continue
        aJ = cG / den
        vals = [int(v) for v in np.array(aJ)]
        if 0 in vals or 1 in vals or len(set(vals)) != len(vals): continue
        alpha = GF.Zeros(n); alpha[piv[0]] = 0; alpha[piv[1]] = 1
        for j, v in zip(J, vals): alpha[j] = v
        break
    assert alpha is not None, "no admissible Moebius parameter"
    # remaining pivot rows: A[0,j]/A[i,j] = c_i (alpha_j - alpha_i)/alpha_j  =>  (A0j/Aij) alpha_j = u alpha_j + v,  u=c_i, v=c_i alpha_i (char 2: -c_i alpha_i)
    for i in range(2, k):
        lhs = (GF(np.array(A[0, J])) / GF(np.array(A[i, J]))) * alpha[J]
        Mx = GF(np.column_stack([np.array(alpha[J]), np.ones(len(J), dtype=int)]))
        sol = np.linalg.solve(Mx[:2], lhs[:2]); u, v = sol[0], sol[1]
        assert np.array_equal(np.array(Mx @ sol), np.array(lhs)), f"row {i} inconsistent with GRS structure"
        alpha[piv[i]] = v / u
    assert len(set(int(a) for a in alpha)) == n, "support not distinct"
    # multipliers via the dual: sum_j f_j alpha_j^i beta'_j = 0 for i < n-k, all rows f
    rows_needed = min(k, (n - 1) // (n - k) + 2)
    eqs = []
    for i in range(rows_needed):
        f = F[i]; pw = GF.Ones(n)
        for e in range(n - k):
            eqs.append(np.array(f * pw)); pw = pw * alpha
    E = GF(np.array(eqs)); ns = E.null_space()
    assert ns.shape[0] == 1, f"dual multiplier space has dimension {ns.shape[0]}"
    bprime = ns[0]; assert np.all(np.array(bprime))
    beta = GF.Zeros(n)
    for j in range(n):
        prod = GF(1)
        for l in range(n):
            if l != j: prod = prod * (alpha[j] - alpha[l])
        beta[j] = GF(1) / (bprime[j] * prod)
    return alpha, beta, piv

def berlekamp_welch(GF, alpha, beta, y, k, t):
    """Decode y (n,) in GRS(alpha,beta) with <= t errors. Returns codeword or None."""
    n = len(y); yy = y / beta
    # unknowns: Q coeffs (k+t) and E coeffs e_0..e_{t-1} (E monic deg t):  Q(a) - yy E(a) = yy a^t
    cols = []
    pw = GF.Ones(n)
    for a in range(k + t): cols.append(np.array(pw)); pw = pw * alpha
    pw = GF.Ones(n)
    for b in range(t): cols.append(np.array(yy * pw)); pw = pw * alpha      # char 2: -yy = yy
    rhs = yy * pw
    Msys = GF(np.column_stack(cols))
    # solve (may be rank-deficient when fewer than t errors): use null space trick
    aug = GF(np.column_stack([np.array(Msys), np.array(rhs)]))
    ns = aug.null_space()
    sol = None
    for v in ns:
        if int(v[-1]) != 0: sol = v[:-1] / v[-1]; break
    if sol is None: return None
    Qc = galois.Poly(sol[:k + t][::-1], field=GF); Ec = galois.Poly(np.append(GF([1]), sol[k + t:][::-1]), field=GF)
    P, rem = divmod(Qc, Ec)
    if rem != 0: return None
    return beta * P(alpha)

def main():
    m, n, k, w, kl, t = map(int, sys.argv[1:7]); seed = int(sys.argv[7]); wd = sys.argv[8]
    max_rounds = int(sys.argv[9]) if len(sys.argv) > 9 else 200
    os.makedirs(wd, exist_ok=True); GF = galois.GF(2 ** m); rng = np.random.default_rng(seed); t0 = time.time()
    G, sk = keygen(GF, n, k, w, rng); N = n + w; l = k - kl
    log(t0, f"R key: m={m} n={n} k={k} w={w} N={N} t={t} k_l={kl} seed={seed}; predicted excess {2*(n-k)-w-kl+2}")
    # fresh ciphertext (public operation)
    msg = GF(rng.integers(0, GF.order, size=k)); e = GF.Zeros(N)
    epos = rng.choice(N, size=t, replace=False); e[epos] = GF(rng.integers(1, GF.order, size=t))
    ct = msg @ G + e
    # --- adaptive rounds ---
    known = {}; surv = np.zeros(N, int); everr1 = np.zeros(N, bool); rounds = 0; total_ker = []
    sf = os.path.join(wd, 'state.json')
    if os.path.exists(sf):
        st = json.load(open(sf)); rounds = st['rounds']; total_ker = st.get('kernels', [])
        for (i, j, rho) in st['known']: known[frozenset((i, j))] = (i, j, rho); everr1[i] = everr1[j] = True
        surv = np.array(st.get('surv', surv.tolist()))
        log(t0, f"resumed: {rounds} rounds done, {len(known)} pairs known")
    tp = sk['true_pair']
    while len(known) < w and rounds < max_rounds:
        rounds += 1
        if rounds == 1: Z = set(rng.permutation(N)[:l].tolist())
        else:
            Z = set(); kp = list(known.values()); rng.shuffle(kp)
            for (i, j, _) in kp:
                for c in (i, j):
                    if len(Z) < l: Z.add(c)
            cand = [c for c in range(N) if c not in Z and not everr1[c]]
            # randomized: survive with probability ~ exp(-surv/tau); deterministic ordering can lock
            # the two columns of an unknown pair into alternating cohorts that never survive together
            keys = surv[cand] / 2.0 + rng.gumbel(size=len(cand))      # larger key -> shortened first
            cand = [c for _, c in sorted(zip(-keys, cand))]
            for c in cand:
                if len(Z) >= l: break
                Z.add(c)
        log(t0, f"round {rounds}: known pairs {len(known)}/{w}")
        pairs, keep, ker, ranks, nr1 = one_round(GF, G, Z, t0, wd, m, kl)
        for c in keep: surv[c] += 1
        new = 0
        for key, val in pairs.items():
            everr1[val[0]] = True; everr1[val[1]] = True
            if key not in known: known[key] = val; new += 1
        both = sum(1 for pr in tp if pr <= set(keep)); wrong = sum(1 for pr in pairs if pr not in tp)
        log(t0, f"  kernel {ker} (excess {ker - (len(keep)*kl - cubic_cols(kl)) if len(keep)*kl>cubic_cols(kl) else ker}); rank-1 blocks {nr1}; pairs this round {len(pairs)} (new {new}); [truth] both-surviving true pairs {both}, wrong pairs {wrong}")
        total_ker.append(ker)
        json.dump({'rounds': rounds, 'known': [list(v) for v in known.values()], 'kernels': total_ker,
                   'surv': surv.tolist()}, open(sf, 'w'))
    log(t0, f"pairing complete after {rounds} rounds: {len(known)} pairs")
    # [truth] ratios
    ok = 0
    for (i, j, rho) in known.values():
        if frozenset((i, j)) not in tp: continue
        h = G[:, i] + GF(rho) * G[:, j]; idx = tp[frozenset((i, j))]
        true_h = sk['S'] @ sk['Gs'][:, n - w + idx]
        if int(np.linalg.matrix_rank(GF(np.array([np.array(h), np.array(true_h)])))) == 1: ok += 1
    log(t0, f"[truth] pairs correct {sum(1 for p in known if p in tp)}/{len(known)}, hidden GRS directions correct {ok}/{len(known)}")
    # --- fold ---
    paired = set();
    for (i, j, _) in known.values(): paired |= {i, j}
    singles = [c for c in range(N) if c not in paired]
    assert len(singles) == n - w, (len(singles), n - w)
    hid_cols = [np.array(G[:, c]) for c in singles] + [np.array(G[:, i] + GF(rho) * G[:, j]) for (i, j, rho) in known.values()]
    F = GF(np.column_stack(hid_cols))
    log(t0, f"fold matrix F {F.shape}, rank {int(np.linalg.matrix_rank(F))}")
    # --- Sidelnikov-Shestakov ---
    alpha, beta, piv = sidelnikov_shestakov(GF, F)
    log(t0, f"Sidelnikov-Shestakov done: support of {len(set(int(a) for a in alpha))} distinct points, multipliers nonzero: {bool(np.all(np.array(beta)))}")
    # check: every row of F is a GRS codeword
    Vk = GF(np.array([np.array(alpha ** i) for i in range(k)])) * beta     # k x n generator of GRS(alpha,beta)
    chk = int(np.linalg.matrix_rank(GF(np.vstack([np.array(Vk), np.array(F)]))))
    log(t0, f"rowsp F == GRS(alpha,beta): {chk == k} (rank of stacked generators {chk})")
    # --- decrypt the fresh ciphertext ---
    folded = GF(np.array([int(ct[c]) for c in singles] + [int(ct[i] + GF(rho) * ct[j]) for (i, j, rho) in known.values()]))
    cw = berlekamp_welch(GF, alpha, beta, folded, k, t)
    if cw is None: log(t0, "DECODE FAILED"); return
    # m from cw = m F : use pivot columns of F
    Fp = F[:, piv]; m_rec = np.linalg.solve(Fp.T, cw[piv])
    log(t0, f"fresh ciphertext decrypted; recovered message equals plaintext: {bool(np.array_equal(np.array(m_rec), np.array(msg)))}; "
            f"re-encryption error weight {int(np.count_nonzero(np.array(m_rec @ G + ct)))} (expected {t})")
    print("SUMMARY", json.dumps(dict(m=m, n=n, k=k, w=w, kl=kl, t=t, seed=seed, rounds=rounds, kernels=total_ker,
                                       pairs=len(known), decrypt_ok=bool(np.array_equal(np.array(m_rec), np.array(msg))),
                                       seconds=round(time.time() - t0))))

def cubic_cols(kl): return kl * (kl + 1) * (kl + 2) // 6

if __name__ == '__main__':
    main()
