End-to-end long-key RLCE key recovery (Sect. "End-to-end key recovery of long-key RLCE at full size")
======================================================================================================

Files (to be placed in RLCE/scripts next to rlce_recover.py, rank2m.c, nullspace2m.c):
  rlce_e2e.py          jet stage (adaptive shortening rounds, read-off, ratios), fold, Sidelnikov-Shestakov
                       over GF(2^m), Berlekamp-Welch decryption of a fresh ciphertext. Resumable via workdir/state.json.
  rlce_endgame_sq.py   square-code stage on the folded code (CLT's regime once w' < n-k-k_l+1):
                       shortened Veronese matrix, left kernel, off-curve columns, pair planes meeting the curve.
  sim_rounds.py        survival-model simulation of the number of jet rounds (random vs adaptive shortening).
  logs_r1/             logs of the run reported in Table "End-to-end recovery" (R-1, key seed 1).

Dependencies: python3 >= 3.10, numpy, galois 0.4.11 (pulls numba), gcc with OpenMP.
  pip install galois
  gcc -O3 -march=native -fopenmp -o nullspace2m nullspace2m.c

The secret key is generated from the key seed and used ONLY to score rounds ([truth] lines); nothing from it
enters the recovery, which reads the public key G alone.

Reproducing the R-1 run (n=846, k=732, w=114, t=57, GF(2^10)), two cores:

  # jet stage, k_l = 39, key seed 1 (rounds 1-15 deterministic ordering; rounds 16-17 randomized -- the
  # script now always randomizes from round 2 on, see the gumbel line)
  python3 rlce_e2e.py 10 846 732 114 39 57 1 r1 17          # stops after 17 rounds (max_rounds); ~90 min
  # square-code stage from the saved state (101 pairs) with k_l = 25, shortening seed 2002
  SQSEED=2002 python3 rlce_endgame_sq.py 10 846 732 114 25 1 r1 1500 r1/state.json   # writes r1/state_sq.json
  # back end: fold, Sidelnikov-Shestakov, decryption (resumes with all pairs known, skips the rounds)
  cp r1/state_sq.json r1/state.json && python3 rlce_e2e.py 10 846 732 114 39 57 1 r1

Early handover (two jet rounds, then square code with k_l = 21, shortening seed 7):
  python3 rlce_e2e.py 10 846 732 114 39 57 1 r1b 2
  SQSEED=7 python3 rlce_endgame_sq.py 10 846 732 114 21 1 r1b 1500 r1b/state.json
  cp r1b/state_sq.json r1b/state.json && python3 rlce_e2e.py 10 846 732 114 39 57 1 r1b

Toy check (seconds): python3 rlce_e2e.py 10 60 30 30 21 15 1 toy

Notes
  * The state file keeps the pairs in order of recovery, so "the 24 pairs of rounds 1-2" is state['known'][:24].
  * Square-code window: k_l must satisfy C(k_l+1,2) >= n' = N'-k+k_l (k_l >= 21 for R-1) and
    w' < n-k-k_l+1 for the deficiency to be visible.
  * The logs in logs_r1 were produced with the nullspace2m binary at two OpenMP threads; timings vary with load.
