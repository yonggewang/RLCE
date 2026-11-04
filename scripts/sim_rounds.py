"""Simulate adaptive-shortening rounds for RLCE recovery (no algebra; survival model only).
A pair is recovered in a round iff both its coordinates survive.
Z policy: all coordinates of known pairs, then never-rank-1 columns ordered by #survivals (desc),
then columns never seen, random. Half-shortened survivors and singletons both show rank 2."""
import numpy as np, sys
def sim(n, k, w, kl, seed, policy='adaptive'):
    rng = np.random.default_rng(seed); N = n + w; l = k - kl
    # columns 0..n-w-1 singletons; pairs (n-w+2i, n-w+2i+1)
    pair_of = -np.ones(N, int)
    for i in range(w): pair_of[n - w + 2 * i] = i; pair_of[n - w + 2 * i + 1] = i
    known = set(); surv = np.zeros(N, int); everr1 = np.zeros(N, bool); rounds = 0
    while len(known) < w:
        rounds += 1
        if policy == 'random' or rounds == 1:
            Z = set(rng.permutation(N)[:l].tolist())
        else:
            Z = set(c for c in range(N) if pair_of[c] in known)
            cand = [c for c in range(N) if c not in Z and not everr1[c]]
            rng.shuffle(cand); cand.sort(key=lambda c: -surv[c])
            for c in cand:
                if len(Z) >= l: break
                Z.add(c)
        keep = [c for c in range(N) if c not in Z]
        for c in keep: surv[c] += 1
        found = set()
        for c in keep:
            p = pair_of[c]
            if p >= 0 and p not in known:
                tw = n - w + 2 * p + (1 - (c - (n - w)) % 2)
                if tw in Z: pass
                else: found.add(p); everr1[c] = True
        known |= found
        if rounds > 500: break
    return rounds
n, k, w, kl = 846, 732, 114, 39
for pol in ['random', 'adaptive']:
    r = [sim(n, k, w, kl, s, pol) for s in range(20)]
    print(pol, 'rounds: mean', np.mean(r), 'min', min(r), 'max', max(r))
# ID0
n, k, w, kl = 630, 470, 160, 46
for pol in ['random', 'adaptive']:
    r = [sim(n, k, w, kl, s, pol) for s in range(20)]
    print('ID0', pol, 'rounds: mean', np.mean(r), 'min', min(r), 'max', max(r))
